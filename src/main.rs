//! keyjar stashes API keys and small secrets for shells and scripts.
//!
//! Entries are individual age-encrypted files under the store directory.
//! The identity lives apart from the store, so a copy of the store alone
//! stays sealed.
//!
//! Exit codes: 0 success, 1 runtime error, 2 usage error. `run` propagates
//! the child's exit code.
//!
//! Unix only: input hiding, file modes, store locks, and exec matter. Bulk reads
//! are stable. Separate writes are last-writer-wins. Non-goals: atomic
//! multi-entry writes and in-memory zeroization.

use std::process::ExitCode;

use clap::Parser;

mod app;
mod cli;
mod crypt;
mod edit;
mod name;
mod paths;
mod store;
mod tty;

fn main() -> ExitCode {
    app::run(cli::Cli::parse())
}
