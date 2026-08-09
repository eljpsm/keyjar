//! Store and identity path resolution. Every path keyjar touches starts
//! here. The pure inner functions take the environment as arguments because
//! setting env vars in a test would race every other test in the process.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::bail;

pub(crate) fn store_dir(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    store_dir_from(
        flag,
        std::env::var_os("KEYJAR_STORE"),
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("HOME"),
    )
}

pub(crate) fn identity_path() -> anyhow::Result<PathBuf> {
    identity_path_from(
        std::env::var_os("KEYJAR_IDENTITY"),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn store_dir_from(
    flag: Option<PathBuf>,
    keyjar_store: Option<OsString>,
    xdg_data: Option<OsString>,
    home: Option<OsString>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path);
    }
    if let Some(path) = keyjar_store.filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    xdg_join(xdg_data, home, ".local/share", "keyjar")
}

fn identity_path_from(
    keyjar_identity: Option<OsString>,
    xdg_config: Option<OsString>,
    home: Option<OsString>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = keyjar_identity.filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    Ok(xdg_join(xdg_config, home, ".config", "keyjar")?.join("identity"))
}

/// The XDG spec says a relative XDG_* value must be ignored.
fn xdg_join(
    xdg: Option<OsString>,
    home: Option<OsString>,
    home_fallback: &str,
    name: &str,
) -> anyhow::Result<PathBuf> {
    let xdg = xdg.map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(base) = xdg {
        return Ok(base.join(name));
    }
    let Some(home) = home.filter(|h| !h.is_empty()) else {
        bail!("HOME is not set");
    };
    Ok(Path::new(&home).join(home_fallback).join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn the_store_flag_beats_the_env_var() {
        let dir = store_dir_from(
            Some(PathBuf::from("/flag")),
            os("/env"),
            os("/xdg"),
            os("/home"),
        )
        .unwrap();
        assert_eq!(dir, PathBuf::from("/flag"));
    }

    #[test]
    fn keyjar_store_beats_xdg() {
        let dir = store_dir_from(None, os("/env"), os("/xdg"), os("/home")).unwrap();
        assert_eq!(dir, PathBuf::from("/env"));
    }

    #[test]
    fn xdg_data_home_beats_the_home_fallback() {
        let dir = store_dir_from(None, None, os("/xdg"), os("/home")).unwrap();
        assert_eq!(dir, PathBuf::from("/xdg/keyjar"));
    }

    // A relative XDG value is invalid per the spec; honoring it would drop
    // the store wherever the process happens to run.
    #[test]
    fn a_relative_xdg_value_is_ignored() {
        let dir = store_dir_from(None, None, os("rel"), os("/home")).unwrap();
        assert_eq!(dir, PathBuf::from("/home/.local/share/keyjar"));
    }

    #[test]
    fn an_empty_keyjar_store_is_ignored() {
        let dir = store_dir_from(None, os(""), None, os("/home")).unwrap();
        assert_eq!(dir, PathBuf::from("/home/.local/share/keyjar"));
    }

    #[test]
    fn no_home_at_all_is_an_error() {
        assert!(store_dir_from(None, None, None, None).is_err());
        assert!(identity_path_from(None, None, None).is_err());
    }

    #[test]
    fn keyjar_identity_overrides_everything() {
        let path = identity_path_from(os("/id"), os("/xdg"), os("/home")).unwrap();
        assert_eq!(path, PathBuf::from("/id"));
    }

    #[test]
    fn the_identity_defaults_under_the_config_dir() {
        let path = identity_path_from(None, None, os("/home")).unwrap();
        assert_eq!(path, PathBuf::from("/home/.config/keyjar/identity"));
    }
}
