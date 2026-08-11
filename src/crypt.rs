//! age identity handling and encrypt/decrypt. The identity file uses the
//! standard age format so `age` and `rage` can read the store directly.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519;
use anyhow::{Context, anyhow, bail};

pub(crate) enum IdentitySource {
    Created,
    Existed,
}

/// Load the identity, generating one on first use. The caller reports
/// creation to the user; this module never prints.
pub(crate) fn load_or_create_identity(
    path: &Path,
) -> anyhow::Result<(x25519::Identity, IdentitySource)> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let identity = parse_identity(&contents)
                .with_context(|| format!("reading identity {}", path.display()))?;
            Ok((identity, IdentitySource::Existed))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            generate_identity(path).with_context(|| format!("creating identity {}", path.display()))
        }
        Err(err) => Err(err).with_context(|| format!("reading identity {}", path.display())),
    }
}

/// For reads. A missing identity cannot decrypt anything, so generating one
/// here would only bury the real problem under a key-mismatch error.
pub(crate) fn load_identity(path: &Path) -> anyhow::Result<x25519::Identity> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("no identity at {}", path.display()))?;
    parse_identity(&contents).with_context(|| format!("reading identity {}", path.display()))
}

fn generate_identity(path: &Path) -> anyhow::Result<(x25519::Identity, IdentitySource)> {
    let identity = x25519::Identity::generate();
    match write_identity_file(path, &identity) {
        Ok(()) => Ok((identity, IdentitySource::Created)),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok((load_identity(path)?, IdentitySource::Existed))
        }
        Err(err) => Err(err.into()),
    }
}

/// Write an identity file atomically, 0600 from the first byte: the key must
/// never be readable by others, not even between write and chmod. Refuses an
/// existing file; the caller decides what one means.
pub(crate) fn write_identity_file(path: &Path, identity: &x25519::Identity) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::other("identity path has no parent"));
    };
    create_private_dirs(parent)?;
    let mut file = tempfile::Builder::new()
        .prefix(".keyjar-")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(parent)?;
    writeln!(file, "# created by keyjar")?;
    writeln!(file, "# public key: {}", identity.to_public())?;
    writeln!(file, "{}", identity.to_string().expose_secret())?;
    file.flush()?;
    file.persist_noclobber(path)
        .map(|_| ())
        .map_err(|err| err.error)
}

/// Directories that hold key material are 0700. create_dir_all applies the
/// mode only to directories it creates; existing ones are left alone.
pub(crate) fn create_private_dirs(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir)
}

/// Lines, `#` comments, first AGE-SECRET-KEY line wins. Hand-parsed to stay
/// compatible with rage-keygen output without pulling in age's identity-file
/// machinery.
fn parse_identity(contents: &str) -> anyhow::Result<x25519::Identity> {
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        return x25519::Identity::from_str(line).map_err(|e| anyhow!(e));
    }
    bail!("no identity line found");
}

pub(crate) fn encrypt(identity: &x25519::Identity, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    age::encrypt(&identity.to_public(), plaintext).context("encrypting")
}

pub(crate) fn decrypt(identity: &x25519::Identity, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    age::decrypt(identity, ciphertext).context("decrypting")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn a_generated_identity_loads_back_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyjar/identity");
        let (created, source) = load_or_create_identity(&path).unwrap();
        assert!(matches!(source, IdentitySource::Created));
        let (loaded, source) = load_or_create_identity(&path).unwrap();
        assert!(matches!(source, IdentitySource::Existed));

        let ciphertext = encrypt(&created, b"secret").unwrap();
        assert_eq!(decrypt(&loaded, &ciphertext).unwrap(), b"secret");
    }

    // Key material readable by group or others defeats the whole design.
    #[test]
    fn the_identity_file_and_directory_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyjar/identity");
        load_or_create_identity(&path).unwrap();
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            path.parent().unwrap().metadata().unwrap().mode() & 0o777,
            0o700
        );
    }

    // rage-keygen writes comments and a trailing newline; keyjar must accept
    // its files unchanged.
    #[test]
    fn parsing_skips_comments_and_blank_lines() {
        let identity = x25519::Identity::generate();
        let contents = format!(
            "# comment\n\n# public key: {}\n{}\n",
            identity.to_public(),
            identity.to_string().expose_secret()
        );
        let parsed = parse_identity(&contents).unwrap();
        let ciphertext = encrypt(&parsed, b"x").unwrap();
        assert_eq!(decrypt(&identity, &ciphertext).unwrap(), b"x");
    }

    #[test]
    fn garbage_identity_contents_are_an_error() {
        assert!(parse_identity("").is_err());
        assert!(parse_identity("# only comments\n").is_err());
        assert!(parse_identity("AGE-SECRET-KEY-NOT-A-KEY").is_err());
    }

    #[test]
    fn decrypting_with_the_wrong_identity_fails() {
        let a = x25519::Identity::generate();
        let b = x25519::Identity::generate();
        let ciphertext = encrypt(&a, b"secret").unwrap();
        assert!(decrypt(&b, &ciphertext).is_err());
    }

    // Whoever loses the race must return the winner's key, not its own. A
    // second identity here would silently orphan the first writer's entries.
    #[test]
    fn concurrent_creation_returns_one_identity() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("keyjar/identity"));
        let barrier = Arc::new(Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_identity(&path).unwrap()
                })
            })
            .collect();
        let identities: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();

        let public = identities[0].0.to_public().to_string();
        assert!(
            identities
                .iter()
                .all(|(identity, _)| identity.to_public().to_string() == public)
        );
        assert_eq!(
            identities
                .iter()
                .filter(|(_, source)| matches!(source, IdentitySource::Created))
                .count(),
            1
        );
    }
}
