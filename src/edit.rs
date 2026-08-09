//! The $EDITOR round trip. Plaintext lives in a private temporary workspace.
//! Cleanup is best effort because editors and abrupt process death are outside
//! keyjar's control.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, bail};

/// Unchanged is distinct from Changed with equal bytes: it means keyjar leaves
/// the ciphertext alone rather than re-encrypting to a new file.
pub(crate) enum EditOutcome {
    Changed(Vec<u8>),
    Unchanged,
}

pub(crate) fn edit_with_editor(editor: &str, initial: &[u8]) -> anyhow::Result<EditOutcome> {
    edit_with_editor_in(editor, initial, std::env::var_os("XDG_RUNTIME_DIR"))
}

fn edit_with_editor_in(
    editor: &str,
    initial: &[u8],
    xdg_runtime: Option<OsString>,
) -> anyhow::Result<EditOutcome> {
    let mut words = editor.split_whitespace();
    let Some(program) = words.next() else {
        bail!("EDITOR is empty");
    };
    let args: Vec<&str> = words.collect();

    let workspace = workspace(xdg_runtime)?;
    let mut file = tempfile::Builder::new()
        .prefix(".keyjar-edit-")
        .suffix(".txt")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(workspace.path())
        .with_context(|| format!("creating temp file in {}", workspace.path().display()))?;
    file.write_all(initial)?;
    file.flush()?;

    // EDITOR is split on whitespace, not run through a shell. That handles
    // `code --wait` and `emacsclient -t`; a quoted path with spaces does
    // not survive, the same tradeoff sudoedit makes.
    let status = std::process::Command::new(program)
        .args(&args)
        .arg(file.path())
        .status()
        .with_context(|| format!("running editor {program}"))?;
    if !status.success() {
        bail!("editor exited with {status}; value unchanged");
    }

    // Re-read by path, not the held handle: vim and friends replace the
    // file by rename, leaving the original inode stale.
    let edited = std::fs::read(file.path()).context("reading edited value")?;
    if edited == initial {
        Ok(EditOutcome::Unchanged)
    } else {
        Ok(EditOutcome::Changed(edited))
    }
}

/// Prefer XDG_RUNTIME_DIR: it is a per-user tmpfs, so the plaintext stays off
/// disk and dies with the session. Fall back to the system temp dir when it is
/// unset, relative, or unwritable, since failing the edit outright would be
/// worse than the weaker location.
fn workspace(xdg_runtime: Option<OsString>) -> anyhow::Result<tempfile::TempDir> {
    if let Some(runtime) = xdg_runtime.map(std::path::PathBuf::from) {
        if runtime.is_absolute() {
            if let Ok(workspace) = tempfile::Builder::new()
                .prefix("keyjar-")
                .tempdir_in(runtime)
            {
                return Ok(workspace);
            }
        }
    }
    tempfile::Builder::new()
        .prefix("keyjar-")
        .tempdir()
        .context("creating editor workspace")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn the_runtime_dir_wins_when_usable() {
        let runtime = tempfile::tempdir().unwrap();
        let dir = workspace(Some(runtime.path().as_os_str().to_owned())).unwrap();
        assert_eq!(dir.path().parent(), Some(runtime.path()));
    }

    #[test]
    fn a_relative_runtime_dir_uses_the_system_temp_dir() {
        let dir = workspace(Some(OsString::from("relative"))).unwrap();
        assert!(dir.path().is_absolute());
        assert_ne!(dir.path().parent(), Some(Path::new("relative")));
    }

    fn no_residue(base: &Path) {
        let leftovers: Vec<_> = std::fs::read_dir(base)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(leftovers.is_empty(), "leftovers: {leftovers:?}");
    }

    // A script stands in for a real editor, run as `sh SCRIPT` so exec never
    // touches the freshly written file (a concurrent test's fork can hold
    // its write fd open, and exec on it would fail with ETXTBSY). This also
    // covers the multi-word EDITOR split. The script rename-replaces,
    // covering the stale-inode case.
    #[test]
    fn an_appending_editor_returns_the_new_bytes_and_cleans_up() {
        let scripts = tempfile::tempdir().unwrap();
        let script = scripts.path().join("editor");
        std::fs::write(
            &script,
            "cp \"$1\" \"$1.new\"\necho added >> \"$1.new\"\nmv \"$1.new\" \"$1\"\n",
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let editor = format!("sh {}", script.display());
        let EditOutcome::Changed(bytes) =
            edit_with_editor_in(&editor, b"start\n", Some(dir.path().as_os_str().to_owned()))
                .unwrap()
        else {
            panic!("expected a change");
        };
        assert_eq!(bytes, b"start\nadded\n");
        no_residue(dir.path());
    }

    #[test]
    fn an_untouched_file_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let outcome =
            edit_with_editor_in("true", b"same", Some(dir.path().as_os_str().to_owned())).unwrap();
        assert!(matches!(outcome, EditOutcome::Unchanged));
        no_residue(dir.path());
    }

    #[test]
    fn a_failing_editor_aborts_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            edit_with_editor_in("false", b"same", Some(dir.path().as_os_str().to_owned())).is_err()
        );
        no_residue(dir.path());
    }

    #[test]
    fn a_missing_editor_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Some(dir.path().as_os_str().to_owned());
        assert!(edit_with_editor_in("keyjar-no-such-editor", b"", runtime.clone()).is_err());
        assert!(edit_with_editor_in("", b"", runtime).is_err());
        no_residue(dir.path());
    }
}
