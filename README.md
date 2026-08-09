# keyjar

A minimal CLI stash for API keys and small secrets, built for shells and scripts
rather than logins. Unix only.

## Install

```bash
# Straight from GitHub:
cargo install --git https://github.com/eljpsm/keyjar

# With Nix:
nix run github:eljpsm/keyjar

# From a clone (installs to ~/.cargo/bin):
make install
```

## Use

```bash
# Set a value.
keyjar set openai               # prompts, input hidden

# Set a nested value.
keyjar set work/aws-access-key  # names nest with /

# Get a value.
keyjar get openai
# Show a value.
keyjar show openai
# List values.
keyjar ls work

# Remove a value.
keyjar rm openai
# Edit a value.
keyjar edit personal/notes


# Inject environment variables.
eval "$(keyjar env work)"       # exports AWS_ACCESS_KEY=...
# Run a command with injected environment variables.
keyjar run work -- terraform plan
```

| Exit code | Description                                                    |
| --------- | -------------------------------------------------------------- |
| `0`       | Success.                                                       |
| `1`       | Runtime error (missing entry, wrong identity, failed decrypt). |
| `2`       | Usage error (invalid name or arguments).                       |

`run` replaces itself with the command, so its exit code and signals are the
command's own. `get` prints no trailing newline and refuses a terminal; use
`show` to read a value yourself.

`env` and `run` uppercase each name into a variable and replace anything else
with `_`. A prefix is stripped first, so `work/aws-access-key` becomes
`AWS_ACCESS_KEY` under `keyjar env work` and `WORK_AWS_ACCESS_KEY` without one.

## Storage

Entries are individual [age](https://age-encryption.org) encrypted files under
`$XDG_DATA_HOME/keyjar` (override with `KEYJAR_STORE` or `--store`). The key is
generated on first use at `$XDG_CONFIG_HOME/keyjar/identity` (override with
`KEYJAR_IDENTITY`).

It is a standard age identity, so `age -d -i ~/.config/keyjar/identity FILE.age`
also works. A store belongs to the identity that first wrote to it. Copy the
directory whole to move or back it up.

> [!WARNING]
> Secret values are encrypted. Entry names, directory structure, file sizes, and
> change history are not.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
