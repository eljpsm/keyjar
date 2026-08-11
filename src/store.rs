//! Ciphertext files and store metadata. Entry writes are atomic. Store locks
//! make bulk reads stable and bind every entry to one age recipient.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::x25519;
use anyhow::{Context, bail};

use crate::crypt::create_private_dirs;
use crate::name::{Name, Namespace};

const SUFFIX: &str = ".age";
const LOCK_FILE: &str = ".keyjar.lock";
const RECIPIENT_FILE: &str = ".keyjar-recipient";

/// A store directory. One entry per file, name to relative path.
///
/// Two invariants hold across every method. A non-empty store carries a
/// recipient marker, and every method that touches entries holds the store
/// lock while it does. Methods named `_unlocked` assume the caller already
/// holds it.
pub(crate) struct Store {
    dir: PathBuf,
}

impl Store {
    /// No filesystem side effects; directories appear on first write.
    pub(crate) fn open(dir: PathBuf) -> Self {
        Store { dir }
    }

    /// Existence without decryption, so `rm` works with no identity at hand.
    pub(crate) fn contains(&self, name: &Name) -> anyhow::Result<bool> {
        if !self.dir.exists() {
            return Ok(false);
        }
        let _lock = self.lock(LockMode::Shared)?;
        self.check_marker_exists(&self.list_unlocked()?)?;
        Ok(self.read_unlocked(name)?.is_some())
    }

    /// Read one ciphertext after checking that the selected identity belongs
    /// to this store.
    pub(crate) fn read(
        &self,
        name: &Name,
        recipient: &x25519::Recipient,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if !self.dir.exists() {
            return Ok(None);
        }
        let _lock = self.lock(LockMode::Shared)?;
        self.check_recipient(recipient)?;
        self.read_unlocked(name)
    }

    /// Overwrite an entry, creating the store on the first call. The first
    /// write to an empty store binds it to this recipient.
    pub(crate) fn write(
        &self,
        name: &Name,
        recipient: &x25519::Recipient,
        ciphertext: &[u8],
    ) -> anyhow::Result<()> {
        create_private_dirs(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        let _lock = self.lock(LockMode::Exclusive)?;
        self.bind_recipient(recipient)?;
        self.write_entry_unlocked(name, ciphertext)
    }

    fn write_entry_unlocked(&self, name: &Name, ciphertext: &[u8]) -> anyhow::Result<()> {
        let path = self.entry_path(name);
        let parent = path.parent().expect("entry paths always have a parent");
        create_private_dirs(parent).with_context(|| format!("creating {}", parent.display()))?;
        // Write beside the entry and rename over it. A reader outside the lock
        // (age, a backup job) sees the old bytes or the new ones, never half.
        let mut file = tempfile::Builder::new()
            .prefix(".keyjar-")
            .permissions(std::fs::Permissions::from_mode(0o600))
            .tempfile_in(parent)
            .with_context(|| format!("creating temp file in {}", parent.display()))?;
        file.write_all(ciphertext)?;
        file.flush()?;
        file.persist(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// False means the entry did not exist. Empty parent directories are
    /// pruned so a removed subtree leaves no husk behind.
    pub(crate) fn remove(&self, name: &Name) -> anyhow::Result<bool> {
        if !self.dir.exists() {
            return Ok(false);
        }
        let _lock = self.lock(LockMode::Exclusive)?;
        self.check_marker_exists(&self.list_unlocked()?)?;
        let path = self.entry_path(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(err).with_context(|| format!("removing {}", path.display()));
            }
        }
        self.prune_empty_parents(&path);
        Ok(true)
    }

    /// remove_dir fails on a non-empty directory, so the walk stops at the
    /// first parent that still holds something.
    fn prune_empty_parents(&self, path: &Path) {
        let mut parent = path.parent();
        while let Some(dir) = parent {
            if dir == self.dir || std::fs::remove_dir(dir).is_err() {
                break;
            }
            parent = dir.parent();
        }
    }

    /// Move an entry's ciphertext unchanged; the whole store shares one
    /// recipient, so no identity is needed. False means the source did not
    /// exist. Refuses an existing destination unless `overwrite`.
    pub(crate) fn rename(&self, old: &Name, new: &Name, overwrite: bool) -> anyhow::Result<bool> {
        if !self.dir.exists() {
            return Ok(false);
        }
        let _lock = self.lock(LockMode::Exclusive)?;
        self.check_marker_exists(&self.list_unlocked()?)?;
        let old_path = self.entry_path(old);
        if !old_path.exists() {
            return Ok(false);
        }
        let new_path = self.entry_path(new);
        // The recheck under the lock backs the caller's prompt: a destination
        // that appeared since was never confirmed for overwrite.
        if !overwrite && new_path.exists() {
            bail!("an entry named {new} already exists");
        }
        let parent = new_path.parent().expect("entry paths always have a parent");
        create_private_dirs(parent).with_context(|| format!("creating {}", parent.display()))?;
        std::fs::rename(&old_path, &new_path)
            .with_context(|| format!("renaming {}", old_path.display()))?;
        self.prune_empty_parents(&old_path);
        Ok(true)
    }

    /// Rotate every entry to a new recipient under one exclusive lock.
    /// `transform` maps each entry's ciphertext under `old` to ciphertext
    /// under `new`; every transform runs before anything is written, so a bad
    /// entry aborts with the store untouched. `checkpoint` runs between the
    /// last transform and the first rewrite; the caller persists the new key
    /// there, so at every crash point a key for every entry is on disk. The
    /// marker is written last, which makes a finished-but-not-installed rekey
    /// detectable from the outside.
    pub(crate) fn rekey(
        &self,
        old: &x25519::Recipient,
        new: &x25519::Recipient,
        transform: impl Fn(&Name, &[u8]) -> anyhow::Result<Vec<u8>>,
        checkpoint: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<usize> {
        if !self.dir.exists() {
            bail!("store is empty; nothing to rekey");
        }
        let _lock = self.lock(LockMode::Exclusive)?;
        self.check_recipient(old)?;
        let names = self.list_unlocked()?;
        // A marker with zero entries still rekeys: the marker binds the store
        // and must follow the identity.
        if names.is_empty() && !self.dir.join(RECIPIENT_FILE).exists() {
            bail!("store is empty; nothing to rekey");
        }
        let mut rewritten = Vec::with_capacity(names.len());
        for name in names {
            let ciphertext = self
                .read_unlocked(&name)?
                .context("entry vanished while the store was locked")?;
            let ciphertext =
                transform(&name, &ciphertext).with_context(|| format!("entry {name}"))?;
            rewritten.push((name, ciphertext));
        }
        checkpoint()?;
        for (name, ciphertext) in &rewritten {
            self.write_entry_unlocked(name, ciphertext)?;
        }
        self.write_marker_unlocked(new)?;
        Ok(rewritten.len())
    }

    /// Sorted names. A missing store directory lists as empty: on a fresh
    /// machine `ls` should say nothing, not fail.
    pub(crate) fn list(&self, prefix: Option<&Name>) -> anyhow::Result<Vec<Name>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let _lock = self.lock(LockMode::Shared)?;
        let names = self.list_unlocked()?;
        self.check_marker_exists(&names)?;
        Ok(names
            .into_iter()
            .filter(|name| prefix.is_none_or(|prefix| name.is_at_or_below(prefix)))
            .collect())
    }

    pub(crate) fn list_namespace(
        &self,
        namespace: Option<&Namespace>,
    ) -> anyhow::Result<Vec<Name>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let _lock = self.lock(LockMode::Shared)?;
        let names = self.list_unlocked()?;
        self.check_marker_exists(&names)?;
        Ok(names
            .into_iter()
            .filter(|name| namespace.is_none_or(|namespace| namespace.contains(name)))
            .collect())
    }

    /// Capture names and ciphertext under one shared lock.
    pub(crate) fn snapshot(
        &self,
        namespace: Option<&Namespace>,
        recipient: &x25519::Recipient,
    ) -> anyhow::Result<Vec<(Name, Vec<u8>)>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let _lock = self.lock(LockMode::Shared)?;
        self.check_recipient(recipient)?;
        self.list_unlocked()?
            .into_iter()
            .filter(|name| namespace.is_none_or(|namespace| namespace.contains(name)))
            .map(|name| {
                let ciphertext = self
                    .read_unlocked(&name)?
                    .context("entry vanished while the store was locked")?;
                Ok((name, ciphertext))
            })
            .collect()
    }

    /// Walk the tree for entry names. Anything that is not a `.age` file with
    /// a valid name is skipped: the store may sit next to unrelated files, and
    /// a stray one is not worth failing a listing over.
    fn list_unlocked(&self) -> anyhow::Result<Vec<Name>> {
        let mut names = Vec::new();
        let mut stack = vec![self.dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(err).with_context(|| format!("listing {}", dir.display()));
                }
            };
            for entry in entries {
                let entry = entry?;
                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    continue;
                };
                if file_name.starts_with('.') {
                    continue;
                }
                let path = entry.path();
                if entry.file_type()?.is_dir() {
                    stack.push(path);
                } else if file_name.ends_with(SUFFIX) {
                    if let Some(name) = self.name_of(&path) {
                        names.push(name);
                    }
                }
            }
        }
        names.sort();
        Ok(names)
    }

    fn read_unlocked(&self, name: &Name) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.entry_path(name);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn entry_path(&self, name: &Name) -> PathBuf {
        self.dir.join(format!("{name}{SUFFIX}"))
    }

    fn name_of(&self, path: &Path) -> Option<Name> {
        let relative = path.strip_prefix(&self.dir).ok()?.to_str()?;
        relative.strip_suffix(SUFFIX)?.parse().ok()
    }

    /// Take the store lock. The lock file is created on demand and never
    /// removed: unlinking it would let the next process lock a different
    /// inode and walk straight past a live holder.
    fn lock(&self, mode: LockMode) -> anyhow::Result<StoreLock> {
        let path = self.dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("opening store lock {}", path.display()))?;
        let operation = match mode {
            LockMode::Shared => libc::LOCK_SH,
            LockMode::Exclusive => libc::LOCK_EX,
        };
        // flock blocks, so a signal can interrupt the wait. Retry on EINTR;
        // anything else is a real failure.
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
                return Ok(StoreLock { _file: file });
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err).with_context(|| format!("locking store {}", self.dir.display()));
            }
        }
    }

    /// The recipient this store is bound to, if a marker exists.
    pub(crate) fn bound_recipient(&self) -> anyhow::Result<Option<x25519::Recipient>> {
        if !self.dir.exists() {
            return Ok(None);
        }
        let _lock = self.lock(LockMode::Shared)?;
        self.read_marker()
    }

    fn read_marker(&self) -> anyhow::Result<Option<x25519::Recipient>> {
        let path = self.dir.join(RECIPIENT_FILE);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err).with_context(|| format!("reading {}", path.display()));
            }
        };
        let line = contents
            .strip_suffix('\n')
            .filter(|line| !line.is_empty() && !line.contains('\n'))
            .context("malformed store recipient marker")?;
        let stored = x25519::Recipient::from_str(line)
            .map_err(|e| anyhow::anyhow!(e))
            .context("malformed store recipient marker")?;
        Ok(Some(stored))
    }

    /// Reject an identity that does not own this store. Without the check a
    /// second identity would write entries nothing can decrypt as a set, and
    /// reads would fail one entry at a time instead of saying why.
    ///
    /// A missing marker over an empty store is the fresh case, and callers
    /// that go on to write bind it. A missing marker over entries means the
    /// store was tampered with or half copied, so refuse.
    fn check_recipient(&self, recipient: &x25519::Recipient) -> anyhow::Result<()> {
        match self.read_marker()? {
            Some(stored) if &stored == recipient => Ok(()),
            Some(_) => bail!("selected identity does not match the store recipient"),
            None => {
                if self.list_unlocked()?.is_empty() {
                    return Ok(());
                }
                bail!("store has entries but no recipient marker");
            }
        }
    }

    /// The same invariant for operations that never see an identity (`ls`,
    /// `rm`, `contains`). They cannot compare recipients, but they still must
    /// not treat an unmarked pile of ciphertext as a keyjar store.
    fn check_marker_exists(&self, names: &[Name]) -> anyhow::Result<()> {
        if !names.is_empty() && !self.dir.join(RECIPIENT_FILE).exists() {
            bail!("store has entries but no recipient marker");
        }
        Ok(())
    }

    /// Overwrite the marker. Only rekey may do this, under the exclusive
    /// lock; every other writer goes through bind_recipient's noclobber.
    fn write_marker_unlocked(&self, recipient: &x25519::Recipient) -> anyhow::Result<()> {
        let path = self.dir.join(RECIPIENT_FILE);
        let mut file = tempfile::Builder::new()
            .prefix(".keyjar-")
            .permissions(std::fs::Permissions::from_mode(0o600))
            .tempfile_in(&self.dir)
            .with_context(|| format!("creating temp file in {}", self.dir.display()))?;
        writeln!(file, "{recipient}")?;
        file.flush()?;
        file.persist(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Claim an empty store for this recipient, or confirm an existing claim.
    /// The exclusive lock already serializes writers; persist_noclobber is the
    /// backstop for where flock does not (a store on a network filesystem).
    /// Either way the loser rechecks instead of overwriting the marker.
    fn bind_recipient(&self, recipient: &x25519::Recipient) -> anyhow::Result<()> {
        let path = self.dir.join(RECIPIENT_FILE);
        if path.exists() {
            return self.check_recipient(recipient);
        }
        if !self.list_unlocked()?.is_empty() {
            bail!("store has entries but no recipient marker");
        }
        let mut file = tempfile::Builder::new()
            .prefix(".keyjar-")
            .permissions(std::fs::Permissions::from_mode(0o600))
            .tempfile_in(&self.dir)
            .with_context(|| format!("creating temp file in {}", self.dir.display()))?;
        writeln!(file, "{recipient}")?;
        file.flush()?;
        match file.persist_noclobber(&path) {
            Ok(_) => Ok(()),
            Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.check_recipient(recipient)
            }
            Err(err) => Err(err.error).with_context(|| format!("writing {}", path.display())),
        }
    }
}

enum LockMode {
    Shared,
    Exclusive,
}

/// Holds the flock. Closing the file releases it, so an early return or a
/// panic unlocks the store on the way out.
struct StoreLock {
    _file: File,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::sync::mpsc;
    use std::time::Duration;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("store"));
        (dir, store)
    }

    fn name(value: &str) -> Name {
        value.parse().unwrap()
    }

    fn names(values: &[&str]) -> Vec<Name> {
        values.iter().map(|value| name(value)).collect()
    }

    fn recipient() -> x25519::Recipient {
        x25519::Identity::generate().to_public()
    }

    #[test]
    fn a_write_reads_back_and_a_missing_entry_is_none() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store
            .write(&name("work/aws"), &recipient, b"cipher")
            .unwrap();
        assert_eq!(
            store.read(&name("work/aws"), &recipient).unwrap().unwrap(),
            b"cipher"
        );
        assert_eq!(store.read(&name("missing"), &recipient).unwrap(), None);
    }

    #[test]
    fn entries_and_created_directories_are_private() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("work/aws"), &recipient, b"c").unwrap();
        let root = store.dir.metadata().unwrap();
        let sub = store.dir.join("work").metadata().unwrap();
        let file = store.dir.join("work/aws.age").metadata().unwrap();
        let marker = store.dir.join(RECIPIENT_FILE).metadata().unwrap();
        let lock = store.dir.join(LOCK_FILE).metadata().unwrap();
        assert_eq!(root.mode() & 0o777, 0o700);
        assert_eq!(sub.mode() & 0o777, 0o700);
        assert_eq!(file.mode() & 0o777, 0o600);
        assert_eq!(marker.mode() & 0o777, 0o600);
        assert_eq!(lock.mode() & 0o777, 0o600);
    }

    // The identity must never appear in a listing even if a user points the
    // store at their config directory, and editor droppings must not either.
    #[test]
    fn listing_skips_strays_and_dot_files() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("openai"), &recipient, b"c").unwrap();
        store.write(&name("work/aws"), &recipient, b"c").unwrap();
        std::fs::write(store.dir.join("identity"), b"key").unwrap();
        std::fs::write(store.dir.join("bad name.age"), b"c").unwrap();
        std::fs::write(store.dir.join(".keyjar-stray.tmp"), b"x").unwrap();
        std::fs::create_dir(store.dir.join(".git")).unwrap();
        assert_eq!(store.list(None).unwrap(), names(&["openai", "work/aws"]));
    }

    #[test]
    fn listing_filters_by_component_prefix() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        for value in ["work/aws", "work/db", "workshop/key", "openai"] {
            store.write(&name(value), &recipient, b"c").unwrap();
        }
        assert_eq!(
            store.list(Some(&name("work"))).unwrap(),
            names(&["work/aws", "work/db"])
        );
    }

    #[test]
    fn namespace_listing_excludes_the_exact_entry() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        for value in ["work", "work/aws", "workshop/key"] {
            store.write(&name(value), &recipient, b"c").unwrap();
        }
        let namespace: Namespace = "work".parse().unwrap();
        assert_eq!(
            store.list_namespace(Some(&namespace)).unwrap(),
            names(&["work/aws"])
        );
    }

    #[test]
    fn a_missing_store_directory_lists_empty() {
        let (_dir, store) = temp_store();
        assert_eq!(store.list(None).unwrap(), Vec::<Name>::new());
    }

    // Before the first write there is no directory. Reads answer "empty"
    // rather than failing, and none of them create anything on the way.
    #[test]
    fn a_missing_store_is_empty_for_every_read_operation() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        let namespace: Namespace = "work".parse().unwrap();

        assert!(!store.contains(&name("key")).unwrap());
        assert_eq!(store.read(&name("key"), &recipient).unwrap(), None);
        assert!(!store.remove(&name("key")).unwrap());
        assert!(store.list_namespace(Some(&namespace)).unwrap().is_empty());
        assert!(
            store
                .snapshot(Some(&namespace), &recipient)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn listing_skips_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt;

        let (_dir, store) = temp_store();
        create_private_dirs(&store.dir).unwrap();
        let filename = std::ffi::OsString::from_vec(b"bad-\xff.age".to_vec());
        std::fs::write(store.dir.join(filename), b"c").unwrap();

        assert!(store.list(None).unwrap().is_empty());
    }

    #[test]
    fn removing_prunes_empty_parents_but_not_the_root() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store
            .write(&name("work/deep/key"), &recipient, b"c")
            .unwrap();
        store.write(&name("work/other"), &recipient, b"c").unwrap();
        assert!(store.remove(&name("work/deep/key")).unwrap());
        // `deep` emptied out; `work` still holds `other`.
        assert!(!store.dir.join("work/deep").exists());
        assert!(store.dir.join("work/other.age").exists());
        assert!(store.remove(&name("work/other")).unwrap());
        assert!(!store.dir.join("work").exists());
        assert!(store.dir.exists());
        assert!(store.dir.join(RECIPIENT_FILE).exists());
        assert!(!store.remove(&name("work/other")).unwrap());
    }

    #[test]
    fn rename_moves_ciphertext_and_prunes_empty_parents() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store
            .write(&name("work/deep/key"), &recipient, b"cipher")
            .unwrap();
        assert!(
            store
                .rename(&name("work/deep/key"), &name("personal/key"), false)
                .unwrap()
        );
        assert_eq!(
            store
                .read(&name("personal/key"), &recipient)
                .unwrap()
                .unwrap(),
            b"cipher"
        );
        assert!(!store.dir.join("work").exists());
        assert!(store.dir.join(RECIPIENT_FILE).exists());
    }

    #[test]
    fn rename_of_a_missing_source_returns_false() {
        let (_dir, store) = temp_store();
        assert!(!store.rename(&name("a"), &name("b"), false).unwrap());
        store.write(&name("x"), &recipient(), b"c").unwrap();
        assert!(!store.rename(&name("a"), &name("b"), false).unwrap());
    }

    #[test]
    fn rename_refuses_an_existing_destination_without_overwrite() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("a"), &recipient, b"one").unwrap();
        store.write(&name("b"), &recipient, b"two").unwrap();
        assert!(store.rename(&name("a"), &name("b"), false).is_err());
        assert_eq!(store.read(&name("a"), &recipient).unwrap().unwrap(), b"one");
        assert_eq!(store.read(&name("b"), &recipient).unwrap().unwrap(), b"two");
    }

    #[test]
    fn rename_overwrites_when_asked() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("a"), &recipient, b"one").unwrap();
        store.write(&name("b"), &recipient, b"two").unwrap();
        assert!(store.rename(&name("a"), &name("b"), true).unwrap());
        assert_eq!(store.read(&name("a"), &recipient).unwrap(), None);
        assert_eq!(store.read(&name("b"), &recipient).unwrap().unwrap(), b"one");
    }

    #[test]
    fn rekey_rewrites_every_entry_and_the_marker() {
        let (_dir, store) = temp_store();
        let old = recipient();
        let new = recipient();
        store.write(&name("a"), &old, b"a-old").unwrap();
        store.write(&name("w/b"), &old, b"b-old").unwrap();
        let count = store
            .rekey(
                &old,
                &new,
                |_, ciphertext| Ok([b"new-", ciphertext].concat()),
                || Ok(()),
            )
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(store.read(&name("a"), &new).unwrap().unwrap(), b"new-a-old");
        assert_eq!(
            store.read(&name("w/b"), &new).unwrap().unwrap(),
            b"new-b-old"
        );
        assert!(store.read(&name("a"), &old).is_err());
        assert_eq!(store.bound_recipient().unwrap(), Some(new));
    }

    #[test]
    fn rekey_runs_the_checkpoint_after_transforms_and_before_writes() {
        let (_dir, store) = temp_store();
        let old = recipient();
        let path = store.dir.join("a.age");
        store.write(&name("a"), &old, b"old-bytes").unwrap();
        let transformed = std::cell::Cell::new(false);
        store
            .rekey(
                &old,
                &recipient(),
                |_, _| {
                    transformed.set(true);
                    Ok(b"new-bytes".to_vec())
                },
                || {
                    assert!(transformed.get());
                    assert_eq!(std::fs::read(&path).unwrap(), b"old-bytes");
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new-bytes");
    }

    #[test]
    fn a_failing_transform_leaves_the_store_untouched_and_skips_the_checkpoint() {
        let (_dir, store) = temp_store();
        let old = recipient();
        store.write(&name("a"), &old, b"one").unwrap();
        store.write(&name("b"), &old, b"two").unwrap();
        let checkpointed = std::cell::Cell::new(false);
        let err = store
            .rekey(
                &old,
                &recipient(),
                |name, _| anyhow::bail!("cannot read {name}"),
                || {
                    checkpointed.set(true);
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("entry a"), "{err:#}");
        assert!(!checkpointed.get());
        assert_eq!(store.read(&name("a"), &old).unwrap().unwrap(), b"one");
        assert_eq!(store.read(&name("b"), &old).unwrap().unwrap(), b"two");
    }

    #[test]
    fn a_failing_checkpoint_leaves_the_store_untouched() {
        let (_dir, store) = temp_store();
        let old = recipient();
        store.write(&name("a"), &old, b"one").unwrap();
        let result = store.rekey(
            &old,
            &recipient(),
            |_, _| Ok(b"new".to_vec()),
            || anyhow::bail!("no key written"),
        );
        assert!(result.is_err());
        assert_eq!(store.read(&name("a"), &old).unwrap().unwrap(), b"one");
    }

    #[test]
    fn rekey_rejects_the_wrong_old_recipient() {
        let (_dir, store) = temp_store();
        store.write(&name("a"), &recipient(), b"c").unwrap();
        let transformed = std::cell::Cell::new(false);
        let result = store.rekey(
            &recipient(),
            &recipient(),
            |_, ciphertext| {
                transformed.set(true);
                Ok(ciphertext.to_vec())
            },
            || Ok(()),
        );
        assert!(result.is_err());
        assert!(!transformed.get());
    }

    #[test]
    fn rekey_with_a_marker_but_no_entries_still_updates_the_marker() {
        let (_dir, store) = temp_store();
        let old = recipient();
        let new = recipient();
        store.write(&name("a"), &old, b"c").unwrap();
        assert!(store.remove(&name("a")).unwrap());
        let count = store
            .rekey(&old, &new, |_, c| Ok(c.to_vec()), || Ok(()))
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(store.bound_recipient().unwrap(), Some(new.clone()));
        assert!(store.write(&name("b"), &old, b"c").is_err());
        store.write(&name("b"), &new, b"c").unwrap();
    }

    #[test]
    fn rekey_of_an_empty_store_is_an_error() {
        let (_dir, store) = temp_store();
        let err = store
            .rekey(&recipient(), &recipient(), |_, c| Ok(c.to_vec()), || Ok(()))
            .unwrap_err();
        assert!(err.to_string().contains("empty"), "{err:#}");
        create_private_dirs(&store.dir).unwrap();
        assert!(
            store
                .rekey(&recipient(), &recipient(), |_, c| Ok(c.to_vec()), || Ok(()))
                .is_err()
        );
    }

    #[test]
    fn rekey_blocks_concurrent_readers_until_it_finishes() {
        let (_dir, store) = temp_store();
        let old = recipient();
        let new = recipient();
        store.write(&name("a"), &old, b"old").unwrap();

        let (entered_sender, entered) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let rekey_store = Store::open(store.dir.clone());
        let rekey_new = new.clone();
        let rekeyer = std::thread::spawn(move || {
            rekey_store
                .rekey(
                    &old,
                    &rekey_new,
                    move |_, _| {
                        entered_sender.send(()).unwrap();
                        released.recv().unwrap();
                        Ok(b"rotated".to_vec())
                    },
                    || Ok(()),
                )
                .unwrap();
        });
        entered.recv_timeout(Duration::from_secs(1)).unwrap();

        let reader_store = Store::open(store.dir.clone());
        let reader_new = new.clone();
        let (sent, received) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let snapshot = reader_store.snapshot(None, &reader_new).unwrap();
            sent.send(snapshot).unwrap();
        });

        // The reader must be stuck behind rekey's exclusive lock.
        assert!(received.recv_timeout(Duration::from_millis(50)).is_err());
        release.send(()).unwrap();
        let snapshot = received.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(snapshot, [(name("a"), b"rotated".to_vec())]);
        rekeyer.join().unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn a_store_rejects_a_different_recipient() {
        let (_dir, store) = temp_store();
        let first = recipient();
        let second = recipient();
        store.write(&name("key"), &first, b"c").unwrap();

        assert!(store.read(&name("key"), &second).is_err());
        assert!(store.write(&name("other"), &second, b"c").is_err());
        assert!(!store.dir.join("other.age").exists());
    }

    #[test]
    fn a_malformed_recipient_marker_is_rejected() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("key"), &recipient, b"c").unwrap();
        std::fs::write(store.dir.join(RECIPIENT_FILE), b"not-a-recipient\n").unwrap();

        let err = store.read(&name("key"), &recipient).unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err:#}");
        assert!(store.write(&name("other"), &recipient, b"c").is_err());
    }

    #[test]
    fn an_empty_or_multiline_recipient_marker_is_rejected() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("key"), &recipient, b"c").unwrap();

        for contents in [b"".as_slice(), b"\n", b"not-a-key\nextra\n"] {
            std::fs::write(store.dir.join(RECIPIENT_FILE), contents).unwrap();
            let err = store.read(&name("key"), &recipient).unwrap_err();
            assert!(err.to_string().contains("malformed"), "{err:#}");
        }
    }

    #[test]
    fn entry_paths_with_the_wrong_file_type_are_errors() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        let entry = store.dir.join("key.age");
        store.write(&name("key"), &recipient, b"c").unwrap();
        std::fs::remove_file(&entry).unwrap();
        std::fs::create_dir(&entry).unwrap();

        assert!(store.read(&name("key"), &recipient).is_err());
        assert!(store.remove(&name("key")).is_err());
    }

    // Two identities racing for a fresh store. Exactly one may win, and the
    // loser must write nothing: a store bound to a key that lost is a store
    // nobody can read.
    #[test]
    fn competing_first_recipients_bind_once() {
        use std::sync::{Arc, Barrier};

        let (dir, store) = temp_store();
        let path = store.dir.clone();
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|entry| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let recipient = recipient();
                    barrier.wait();
                    let result = Store::open(path).write(&name(entry), &recipient, b"c");
                    (entry, recipient, result)
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|(_, _, result)| result.is_ok())
                .count(),
            1
        );
        let (entry, recipient, _) = results
            .iter()
            .find(|(_, _, result)| result.is_ok())
            .unwrap();
        assert_eq!(
            Store::open(path)
                .read(&name(entry), recipient)
                .unwrap()
                .unwrap(),
            b"c"
        );
        drop(dir);
    }

    // Ciphertext with no marker is not a keyjar store. Adopting it would bind
    // whatever identity showed up first to files it cannot decrypt.
    #[test]
    fn an_unmarked_nonempty_store_is_rejected() {
        let (_dir, store) = temp_store();
        create_private_dirs(&store.dir).unwrap();
        std::fs::write(store.dir.join("old.age"), b"c").unwrap();
        let recipient = recipient();

        assert!(store.read(&name("old"), &recipient).is_err());
        assert!(store.write(&name("new"), &recipient, b"c").is_err());
        assert!(store.list(None).is_err());
        assert!(store.remove(&name("old")).is_err());
        assert!(store.rename(&name("old"), &name("new"), false).is_err());
        assert!(
            store
                .rekey(&recipient, &recipient, |_, c| Ok(c.to_vec()), || Ok(()))
                .is_err()
        );
        assert!(!store.dir.join(RECIPIENT_FILE).exists());
    }

    #[test]
    fn a_shared_lock_blocks_a_writer() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("first"), &recipient, b"c").unwrap();
        let lock = store.lock(LockMode::Shared).unwrap();
        let writer_store = Store::open(store.dir.clone());
        let (sent, received) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_store
                .write(&name("second"), &recipient, b"c")
                .unwrap();
            sent.send(()).unwrap();
        });

        assert!(received.recv_timeout(Duration::from_millis(50)).is_err());
        drop(lock);
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn an_exclusive_lock_blocks_a_snapshot() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("first"), &recipient, b"c").unwrap();
        let lock = store.lock(LockMode::Exclusive).unwrap();
        let reader_store = Store::open(store.dir.clone());
        let (sent, received) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            reader_store.snapshot(None, &recipient).unwrap();
            sent.send(()).unwrap();
        });

        assert!(received.recv_timeout(Duration::from_millis(50)).is_err());
        drop(lock);
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn a_snapshot_captures_selected_ciphertexts() {
        let (_dir, store) = temp_store();
        let recipient = recipient();
        store.write(&name("work/a"), &recipient, b"a").unwrap();
        store.write(&name("work/b"), &recipient, b"b").unwrap();
        store.write(&name("other"), &recipient, b"x").unwrap();
        let namespace: Namespace = "work".parse().unwrap();

        assert_eq!(
            store.snapshot(Some(&namespace), &recipient).unwrap(),
            [
                (name("work/a"), b"a".to_vec()),
                (name("work/b"), b"b".to_vec())
            ]
        );
    }

    // A lock leaked on the error path would wedge the store until the process
    // died, and every later command would hang with no explanation.
    #[test]
    fn an_error_releases_its_lock() {
        let (_dir, store) = temp_store();
        let first = recipient();
        store.write(&name("first"), &first, b"c").unwrap();
        assert!(store.read(&name("first"), &recipient()).is_err());
        store.write(&name("second"), &first, b"c").unwrap();
    }
}
