# AGENTS.md

## What this is

A minimal CLI stash for API keys and small secrets. It is built for shells and
scripts rather than logins.

## Commands

Common tasks live in the [Makefile](Makefile).

To run unit tests matching a name, use cargo directly: `cargo test NAME`.

## Releases

Bump the version in Cargo.toml, commit, then `make release`. It tags
`v<version>` and pushes the tag. CI runs goreleaser, which cross-compiles with
cargo-zigbuild and attaches the binaries to a GitHub release. The changelog is
the commit log since the last tag, so no CHANGELOG.md exists.

## Writing style

Applies to code comments, commit messages, and any prose you add (docs, READMEs,
this file).

- Aim for brutal simplicity. Say the thing in the fewest words that still carry
  it. Cut any sentence that does not change what the reader does.
- No em-dashes. Use a period, a comma, or parentheses.
- Plain ASCII only. No smart quotes, no arrows, no box-drawing or decorative
  characters. A hyphen is a hyphen.
- No ASCII section dividers in comments. Drop rules of dashes or equals signs
  (`// -----`, `// =====`) and `--- wrapped ---` headers. Start the text
  directly.
- Comment on why, not what. The code already says what it does. Skip comments
  that restate the next line.
- No filler. Drop "simply", "just", "basically", "of course", "note that", and
  similar throat-clearing.
- State facts flat. Skip hype words like "powerful", "seamless", "robust",
  "blazing fast".
- One idea per sentence. Short sentences over long ones joined by commas.
