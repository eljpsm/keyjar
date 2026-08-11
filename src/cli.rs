//! The clap surface. Doc comments here are the --help text, so they speak to
//! the user. Maintainer notes belong in app.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::name::{Name, Namespace};

/// A minimal CLI stash for API keys and small secrets.
#[derive(Debug, Parser)]
#[command(name = "keyjar", version)]
pub struct Cli {
    /// Store directory (default: $KEYJAR_STORE, then $XDG_DATA_HOME/keyjar).
    #[arg(long, global = true, value_name = "PATH")]
    pub store: Option<PathBuf>,

    /// Suppress status messages on stderr.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Store a value read from stdin, without echo on a terminal. Overwrites.
    Set {
        name: Name,
        /// Read until EOF instead of a single line.
        #[arg(short, long)]
        multiline: bool,
    },
    /// Print a value to stdout with no trailing newline. Refuses a terminal.
    Get {
        name: Name,
        /// Print even when stdout is a terminal.
        #[arg(short, long)]
        force: bool,
        /// Append a trailing newline.
        #[arg(short, long)]
        newline: bool,
    },
    /// Print a value for terminal viewing, with a trailing newline.
    Show { name: Name },
    /// List entry names, never values.
    Ls { prefix: Option<Name> },
    /// Delete an entry. Asks on a terminal unless --force.
    Rm {
        name: Name,
        /// Delete without confirming.
        #[arg(short, long)]
        force: bool,
    },
    /// Rename an entry. Asks before overwriting an existing destination.
    Mv {
        old: Name,
        new: Name,
        /// Overwrite an existing destination without confirming.
        #[arg(short, long)]
        force: bool,
    },
    /// Edit a value in $EDITOR. Creates the entry if it does not exist.
    Edit { name: Name },
    /// Print export lines for eval.
    Env {
        /// Select strict descendants of this namespace.
        prefix: Option<Namespace>,
    },
    /// Run a command with secrets added to its environment only.
    Run {
        /// Select strict descendants of this namespace.
        prefix: Option<Namespace>,
        /// The command, after --.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Re-encrypt every entry to a freshly generated identity.
    Rekey {
        /// Rekey without confirming.
        #[arg(short, long)]
        force: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    // The optional prefix before -- is the one parse that could go wrong.
    // last = true must keep the command words out of the prefix slot.
    #[test]
    fn run_with_a_prefix_and_separator_fills_both() {
        let cli = parse(&["keyjar", "run", "work", "--", "env", "-i"]).unwrap();
        let Command::Run { prefix, cmd } = cli.command else {
            panic!("not run");
        };
        assert_eq!(prefix.unwrap().to_string(), "work");
        assert_eq!(cmd, ["env", "-i"]);
    }

    #[test]
    fn run_without_a_prefix_leaves_it_empty() {
        let cli = parse(&["keyjar", "run", "--", "env"]).unwrap();
        let Command::Run { prefix, cmd } = cli.command else {
            panic!("not run");
        };
        assert_eq!(prefix, None);
        assert_eq!(cmd, ["env"]);
    }

    // Guessing which token starts the command would run the wrong program.
    #[test]
    fn run_without_the_separator_is_rejected() {
        assert!(parse(&["keyjar", "run", "work", "env"]).is_err());
    }

    #[test]
    fn run_with_an_empty_command_is_rejected() {
        assert!(parse(&["keyjar", "run", "--"]).is_err());
        assert!(parse(&["keyjar", "run", "work", "--"]).is_err());
    }

    #[test]
    fn global_flags_parse_after_the_subcommand() {
        let cli = parse(&["keyjar", "get", "openai", "--store", "/s", "-q"]).unwrap();
        assert_eq!(cli.store.as_deref(), Some(std::path::Path::new("/s")));
        assert!(cli.quiet);
    }

    #[test]
    fn every_subcommand_parses() {
        for args in [
            vec!["keyjar", "set", "openai"],
            vec!["keyjar", "set", "openai", "-m"],
            vec!["keyjar", "get", "openai", "-f", "-n"],
            vec!["keyjar", "show", "openai"],
            vec!["keyjar", "ls"],
            vec!["keyjar", "ls", "work"],
            vec!["keyjar", "rm", "openai", "-f"],
            vec!["keyjar", "mv", "openai", "work/openai"],
            vec!["keyjar", "mv", "openai", "work/openai", "-f"],
            vec!["keyjar", "edit", "openai"],
            vec!["keyjar", "env"],
            vec!["keyjar", "env", "work"],
            vec!["keyjar", "rekey"],
            vec!["keyjar", "rekey", "-f"],
        ] {
            parse(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }
}
