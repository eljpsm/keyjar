//! Command dispatch. The only module that prints and the only module that
//! decides exit codes. Values go to stdout; everything keyjar says goes to
//! stderr, and --quiet silences the non-error part of that.

use std::io::{IsTerminal, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::process::ExitCode;

use anyhow::{Context, bail};

use crate::cli::{Cli, Command};
use crate::crypt::{self, IdentitySource};
use crate::edit::{self, EditOutcome};
use crate::name::{self, Name, Namespace};
use crate::paths;
use crate::store::Store;
use crate::tty;

/// The single place errors become output. Every command returns a Result and
/// its message is printed here, prefixed once, with the whole `anyhow` chain.
pub fn run(cli: Cli) -> ExitCode {
    match execute(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("keyjar: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> anyhow::Result<ExitCode> {
    let quiet = cli.quiet;
    let store = Store::open(paths::store_dir(cli.store)?);
    match cli.command {
        Command::Set { name, multiline } => set(&store, &name, multiline, quiet),
        Command::Get {
            name,
            force,
            newline,
        } => get(&store, &name, force, newline),
        Command::Show { name } => show(&store, &name),
        Command::Ls { prefix } => ls(&store, prefix.as_ref()),
        Command::Rm { name, force } => rm(&store, &name, force, quiet),
        Command::Edit { name } => edit(&store, &name, quiet),
        Command::Env { prefix } => env(&store, prefix.as_ref()),
        Command::Run { prefix, cmd } => run_cmd(&store, prefix.as_ref(), &cmd),
    }
}

fn set(store: &Store, name: &Name, multiline: bool, quiet: bool) -> anyhow::Result<ExitCode> {
    let value = tty::read_secret(name.as_str(), multiline, quiet)?;
    let identity = identity(quiet)?;
    store.write(
        name,
        &identity.to_public(),
        &crypt::encrypt(&identity, &value)?,
    )?;
    notice(quiet, format_args!("stored {name}"));
    Ok(ExitCode::SUCCESS)
}

fn get(store: &Store, name: &Name, force: bool, newline: bool) -> anyhow::Result<ExitCode> {
    if let Some(refusal) = get_refusal(std::io::stdout().is_terminal(), force) {
        bail!("{refusal}");
    }
    let value = read_entry(store, name)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&value)?;
    if newline {
        stdout.write_all(b"\n")?;
    }
    Ok(ExitCode::SUCCESS)
}

/// The guard as a pure decision so it is testable without a pty.
fn get_refusal(stdout_is_tty: bool, force: bool) -> Option<&'static str> {
    if stdout_is_tty && !force {
        Some("stdout is a terminal; use `keyjar show` or --force")
    } else {
        None
    }
}

fn show(store: &Store, name: &Name) -> anyhow::Result<ExitCode> {
    let value = read_entry(store, name)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&value)?;
    if needs_final_newline(&value) {
        stdout.write_all(b"\n")?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Multiline values usually end with their own newline; adding another
/// would print a blank line.
fn needs_final_newline(value: &[u8]) -> bool {
    value.last() != Some(&b'\n')
}

fn ls(store: &Store, prefix: Option<&Name>) -> anyhow::Result<ExitCode> {
    let mut stdout = std::io::stdout().lock();
    for name in store.list(prefix)? {
        writeln!(stdout, "{name}")?;
    }
    Ok(ExitCode::SUCCESS)
}

fn rm(store: &Store, name: &Name, force: bool, quiet: bool) -> anyhow::Result<ExitCode> {
    // Check first so the prompt never names an entry that is not there. The
    // store can change while the user reads it, hence the second check below.
    if !store.contains(name)? {
        bail!("no entry named {name}");
    }
    if !force {
        if !std::io::stdin().is_terminal() {
            bail!("refusing to remove {name} without --force when stdin is not a terminal");
        }
        if !tty::confirm(&format!("keyjar: remove {name}? [y/N] "))? {
            // Declining is not an error.
            return Ok(ExitCode::SUCCESS);
        }
    }
    if !store.remove(name)? {
        bail!("no entry named {name}");
    }
    notice(quiet, format_args!("removed {name}"));
    Ok(ExitCode::SUCCESS)
}

fn edit(store: &Store, name: &Name, quiet: bool) -> anyhow::Result<ExitCode> {
    let editor = std::env::var("EDITOR")
        .ok()
        .filter(|e| !e.trim().is_empty())
        .context("EDITOR is not set")?;
    let identity = identity(quiet)?;
    // A missing entry starts empty and is created on save; the editor is
    // the only ergonomic way to enter a multiline secret by hand.
    let initial = match store.read(name, &identity.to_public())? {
        Some(ciphertext) => {
            crypt::decrypt(&identity, &ciphertext).with_context(|| format!("entry {name}"))?
        }
        None => Vec::new(),
    };
    match edit::edit_with_editor(&editor, &initial)? {
        EditOutcome::Unchanged => notice(quiet, format_args!("{name} unchanged")),
        EditOutcome::Changed(value) => {
            store.write(
                name,
                &identity.to_public(),
                &crypt::encrypt(&identity, &value)?,
            )?;
            notice(quiet, format_args!("stored {name}"));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn env(store: &Store, namespace: Option<&Namespace>) -> anyhow::Result<ExitCode> {
    let mut stdout = std::io::stdout().lock();
    for (var, _, value) in decrypted_pairs(store, namespace)? {
        let value = String::from_utf8(value)
            .map_err(|e| anyhow::anyhow!("value for {var} is not valid UTF-8: {e}"))?;
        writeln!(stdout, "export {var}={}", name::shell_quote(&value))?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Secrets reach the child through its environment and nowhere else. exec
/// replaces this process, so there is no keyjar left holding plaintext and no
/// wrapper to translate the child's exit status or signal. Returning at all
/// means exec failed.
fn run_cmd(
    store: &Store,
    namespace: Option<&Namespace>,
    cmd: &[String],
) -> anyhow::Result<ExitCode> {
    let pairs = decrypted_pairs(store, namespace)?;
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]).envs(
        pairs
            .into_iter()
            .map(|(var, _, value)| (var, std::ffi::OsString::from_vec(value))),
    );
    Err(command.exec()).with_context(|| format!("running {}", cmd[0]))
}

/// (VAR, name, value) triples for env and run. Errors instead of skipping:
/// a NUL byte cannot cross the environment.
fn decrypted_pairs(
    store: &Store,
    namespace: Option<&Namespace>,
) -> anyhow::Result<Vec<(String, Name, Vec<u8>)>> {
    // Nothing selected means nothing to decrypt, so do not demand an identity.
    // `keyjar run -- cmd` stays usable before the first secret exists.
    if store.list_namespace(namespace)?.is_empty() {
        return Ok(Vec::new());
    }
    let identity = existing_identity()?;
    let entries = store.snapshot(namespace, &identity.to_public())?;
    let names: Vec<_> = entries.iter().map(|(name, _)| name.clone()).collect();
    let pairs = name::env_pairs(&names, namespace)?;
    let mut entries: std::collections::BTreeMap<_, _> = entries.into_iter().collect();
    pairs
        .into_iter()
        .map(|(var, name)| {
            let ciphertext = entries
                .remove(&name)
                .expect("environment pairs came from the store snapshot");
            let value =
                crypt::decrypt(&identity, &ciphertext).with_context(|| format!("entry {name}"))?;
            if value.contains(&0) {
                bail!("value for {name} contains a NUL byte");
            }
            Ok((var, name, value))
        })
        .collect()
}

fn read_entry(store: &Store, name: &Name) -> anyhow::Result<Vec<u8>> {
    let identity = existing_identity()?;
    let Some(ciphertext) = store.read(name, &identity.to_public())? else {
        bail!("no entry named {name}");
    };
    crypt::decrypt(&identity, &ciphertext).with_context(|| format!("entry {name}"))
}

/// For set and edit, which may be the first use ever.
fn identity(quiet: bool) -> anyhow::Result<age::x25519::Identity> {
    let path = paths::identity_path()?;
    let (identity, source) = crypt::load_or_create_identity(&path)?;
    if matches!(source, IdentitySource::Created) {
        notice(
            quiet,
            format_args!("created identity at {}", path.display()),
        );
    }
    Ok(identity)
}

/// For reads. Entries exist, so the identity must too.
fn existing_identity() -> anyhow::Result<age::x25519::Identity> {
    crypt::load_identity(&paths::identity_path()?)
}

fn notice(quiet: bool, message: std::fmt::Arguments) {
    if !quiet {
        eprintln!("keyjar: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests never have a tty, so the guard decision is only
    // testable here as a pure function.
    #[test]
    fn get_refuses_a_tty_without_force() {
        assert!(get_refusal(true, false).is_some());
        assert!(get_refusal(true, true).is_none());
        assert!(get_refusal(false, false).is_none());
        assert!(get_refusal(false, true).is_none());
    }

    #[test]
    fn show_adds_a_newline_only_when_missing() {
        assert!(needs_final_newline(b"value"));
        assert!(!needs_final_newline(b"line\n"));
        assert!(needs_final_newline(b""));
    }
}
