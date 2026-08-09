//! Secret-name rules. Validated names cannot escape the store directory: the
//! charset is a whitelist and dot components are rejected, so traversal is
//! structurally impossible.

use std::fmt;
use std::str::FromStr;

/// Names are relative paths: components of `[A-Za-z0-9._-]` joined by `/`,
/// no dot-prefixed components.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Name(String);

impl Name {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Prefix match on whole components, so `work` covers `work/aws` but not
    /// `workshop`. `ls work` must not sweep in a neighboring name.
    pub(crate) fn is_at_or_below(&self, prefix: &Name) -> bool {
        self == prefix
            || self
                .as_str()
                .strip_prefix(prefix.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl FromStr for Name {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        validate(name)?;
        Ok(Name(name.to_string()))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A namespace is the strict descendants of one valid name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Namespace(Name);

impl Namespace {
    pub(crate) fn contains(&self, name: &Name) -> bool {
        self.strip(name).is_some()
    }

    /// The part of the name below the namespace, or None if it is outside.
    /// Requiring the `/` is what makes membership strict: the namespace's own
    /// name has no remainder, so it would map to an empty variable.
    fn strip<'a>(&self, name: &'a Name) -> Option<&'a str> {
        name.as_str()
            .strip_prefix(self.0.as_str())?
            .strip_prefix('/')
    }
}

impl FromStr for Namespace {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Namespace)
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The one gate between user input and a path under the store. Rejecting a
/// leading dot per component covers `.` and `..` and keeps names off keyjar's
/// own dot files, so no later code has to canonicalize anything.
fn validate(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty name".to_string());
    }
    for component in name.split('/') {
        if component.is_empty() {
            return Err(format!("invalid name {name:?}: empty path component"));
        }
        if component.starts_with('.') {
            return Err(format!(
                "invalid name {name:?}: components must not start with a dot"
            ));
        }
        if let Some(c) = component
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "invalid name {name:?}: character {c:?} not allowed"
            ));
        }
    }
    Ok(())
}

/// Map names to environment variable names, stripping the prefix when given.
/// Returns (VAR, name) pairs sorted by VAR. Collisions and digit-leading
/// variables are errors: silently dropping a secret is worse than stopping.
pub(crate) fn env_pairs(
    names: &[Name],
    namespace: Option<&Namespace>,
) -> anyhow::Result<Vec<(String, Name)>> {
    let mut pairs = Vec::new();
    for name in names {
        let stripped = match namespace {
            Some(namespace) => namespace
                .strip(name)
                .expect("store namespace selection returns strict descendants"),
            None => name.as_str(),
        };
        let var: String = stripped
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();
        if var.starts_with(|c: char| c.is_ascii_digit()) {
            anyhow::bail!("{name} maps to variable {var}, which starts with a digit");
        }
        if let Some((_, other)) = pairs.iter().find(|(v, _)| *v == var) {
            anyhow::bail!("{other} and {name} both map to {var}");
        }
        pairs.push((var, name.clone()));
    }
    pairs.sort();
    Ok(pairs)
}

/// Single quotes preserve newlines and every shell metacharacter, so values
/// survive `eval "$(keyjar env ...)"` byte for byte.
pub(crate) fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_nested_names_are_accepted() {
        for name in ["openai", "work/aws-access-key", "a/b/c", "v1.key", "A_B-9"] {
            name.parse::<Name>()
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    // Every rejected shape here is a path that could leave the store or
    // collide with hidden files like the identity.
    #[test]
    fn traversal_and_hidden_shapes_are_rejected() {
        for name in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            ".hidden",
            "work/.key",
            "a\\b",
            "a b",
            "a\nb",
            "a\0b",
        ] {
            assert!(name.parse::<Name>().is_err(), "{name:?} accepted");
        }
    }

    #[test]
    fn a_name_prefix_includes_itself_and_descendants() {
        let work: Name = "work".parse().unwrap();
        assert!("work".parse::<Name>().unwrap().is_at_or_below(&work));
        assert!("work/aws".parse::<Name>().unwrap().is_at_or_below(&work));
        assert!(!"workshop".parse::<Name>().unwrap().is_at_or_below(&work));
    }

    #[test]
    fn a_namespace_contains_strict_descendants_only() {
        let work: Namespace = "work".parse().unwrap();
        assert!(!work.contains(&"work".parse().unwrap()));
        assert!(work.contains(&"work/aws".parse().unwrap()));
        assert!(!work.contains(&"workshop".parse().unwrap()));
    }

    #[test]
    fn the_prefix_is_stripped_from_variable_names() {
        let names = [
            "work/aws-access-key".parse().unwrap(),
            "work/db/url".parse().unwrap(),
        ];
        let namespace: Namespace = "work".parse().unwrap();
        let pairs = env_pairs(&names, Some(&namespace)).unwrap();
        assert_eq!(
            pairs[0],
            (
                "AWS_ACCESS_KEY".to_string(),
                "work/aws-access-key".parse().unwrap()
            )
        );
        assert_eq!(
            pairs[1],
            ("DB_URL".to_string(), "work/db/url".parse().unwrap())
        );
    }

    #[test]
    fn without_a_prefix_the_full_name_is_used() {
        let names = vec!["work/aws-access-key".parse().unwrap()];
        let pairs = env_pairs(&names, None).unwrap();
        assert_eq!(pairs[0].0, "WORK_AWS_ACCESS_KEY");
    }

    #[test]
    fn a_collision_names_both_entries() {
        let names = vec!["aws-key".parse().unwrap(), "aws_key".parse().unwrap()];
        let err = env_pairs(&names, None).unwrap_err().to_string();
        assert!(err.contains("aws-key") && err.contains("aws_key"), "{err}");
    }

    #[test]
    fn a_digit_leading_variable_is_an_error() {
        let names = vec!["2fa-token".parse().unwrap()];
        let err = env_pairs(&names, None).unwrap_err().to_string();
        assert!(err.contains("digit"), "{err}");
    }

    #[test]
    fn quoting_survives_quotes_newlines_and_dollars() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("a\nb$`"), "'a\nb$`'");
    }
}
