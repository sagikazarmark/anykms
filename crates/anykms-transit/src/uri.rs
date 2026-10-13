//! Transit key URIs:
//!
//! ```text
//! hashivault://[alias]/<mount path>/keys/<name>[?namespace=<ns>]
//! openbao://[alias]/<mount path>/keys/<name>[?namespace=<ns>]
//! ```
//!
//! `hashivault` and `openbao` are synonyms; the flavor comes from the configured server. The alias
//! names a configured server and can never introduce a network address.
//!
//! Mount paths never contain a reserved segment (`sys`, `auth`, `identity`, `cubbyhole`): those
//! are Vault's system, auth and token-scoped backends, not transit mounts. A mount path with more
//! than one segment (`team-a/transit`) is accepted by the parser but opened only when listed in
//! [`ServerConfig::allowed_mounts`](crate::ServerConfig::allowed_mounts): Vault Enterprise
//! resolves leading path segments as namespaces, so `team-b/transit` would reach namespace
//! `team-b` without the `allowed_namespaces` check.

use anykms_core::{Error, ErrorKind, KeyUri, Operation, Result};

use crate::BACKEND;

/// URI schemes routed to the transit provider.
pub const SCHEMES: &[&str] = &["hashivault", "openbao"];

/// Mount path segments that are never transit mounts: Vault's system backend (which also covers
/// `sys/mounts`, `sys/raw`, policies, ...), auth methods, the identity store and the per-token
/// cubbyhole. Refused in every position, since with Enterprise path namespaces `team/sys` is the
/// `sys` backend of namespace `team`. Compared case-insensitively.
pub(crate) const RESERVED_MOUNT_SEGMENTS: &[&str] = &["sys", "auth", "identity", "cubbyhole"];

pub(crate) fn reserved_segment(s: &str) -> bool {
    RESERVED_MOUNT_SEGMENTS
        .iter()
        .any(|r| r.eq_ignore_ascii_case(s))
}

/// A parsed transit key reference.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransitKeyRef {
    pub(crate) alias: String,
    pub(crate) mount: String,
    pub(crate) name: String,
    pub(crate) namespace: Option<String>,
}

/// A URI that does not parse: `Configuration` (A3(c)), since key URIs come from configuration.
/// Input versions (`public_key_version`, a token's `vault:vN:` prefix) are parsed elsewhere and
/// are `InvalidArgument`.
fn bad(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::ParseUri, m)
}

pub(crate) fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn alias_ok(s: &str) -> bool {
    s.is_empty()
        || s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub(crate) fn namespace_ok(s: &str) -> bool {
    !s.is_empty() && s.split('/').all(segment_ok)
}

impl TransitKeyRef {
    /// Server alias (empty = default server).
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Mount path, e.g. `transit` or `team-a/transit`.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    /// Key name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Namespace from the URI, if any.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Whether the mount path has more than one segment (see the [crate docs](crate)).
    pub fn is_multi_segment_mount(&self) -> bool {
        self.mount.contains('/')
    }

    /// Parses a transit key URI.
    pub fn parse(uri: &KeyUri) -> Result<Self> {
        if !SCHEMES.contains(&uri.scheme()) {
            return Err(bad("not a hashivault:// or openbao:// URI"));
        }
        let rest = uri
            .rest()
            .strip_prefix("//")
            .ok_or_else(|| bad("expected <scheme>://[alias]/<mount>/keys/<name>"))?;
        if rest.contains('#') || rest.contains('%') {
            return Err(bad(
                "fragments and percent-encoding are not allowed in key URIs",
            ));
        }
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };
        let (alias, path) = path
            .split_once('/')
            .ok_or_else(|| bad("expected <scheme>://[alias]/<mount>/keys/<name>"))?;
        if alias.contains('@') || alias.contains(':') {
            return Err(bad(
                "key URIs cannot carry user info or addresses; the authority is a server alias",
            ));
        }
        if !alias_ok(alias) {
            return Err(bad("invalid server alias"));
        }
        let segments: Vec<&str> = path.split('/').collect();
        if !alias.is_empty() && segments.first() == Some(&"keys") {
            return Err(bad(
                "expected <mount>/keys/<name>; the authority is a server alias, so use \
                 hashivault:///transit/keys/<name> (three slashes) for the default server",
            ));
        }
        if segments.len() < 3 {
            return Err(bad("expected <mount>/keys/<name>"));
        }
        if !segments.iter().all(|s| segment_ok(s)) {
            return Err(bad(
                "invalid mount or key name segment (allowed: A-Z a-z 0-9 _ . -)",
            ));
        }
        let n = segments.len();
        if segments[n - 2] != "keys" {
            return Err(bad("expected <mount>/keys/<name>"));
        }
        if segments[..n - 2].iter().any(|s| reserved_segment(s)) {
            return Err(bad(
                "mount path uses a reserved segment (sys, auth, identity, cubbyhole); \
                 those are not transit mounts",
            ));
        }
        let mut namespace = None;
        if let Some(q) = query {
            for pair in q.split('&') {
                match pair.split_once('=') {
                    Some(("namespace", v)) if namespace_ok(v) && namespace.is_none() => {
                        namespace = Some(v.to_owned())
                    }
                    _ => {
                        return Err(bad(
                            "unknown or invalid query parameter (only namespace=<ns> is allowed)",
                        ));
                    }
                }
            }
        }
        Ok(Self {
            alias: alias.to_owned(),
            mount: segments[..n - 2].join("/"),
            name: segments[n - 1].to_owned(),
            namespace,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<TransitKeyRef> {
        TransitKeyRef::parse(&s.parse().unwrap())
    }

    #[test]
    fn parses() {
        let r = p("hashivault:///transit/keys/app-kek").unwrap();
        assert_eq!(
            (r.alias(), r.mount(), r.name(), r.namespace()),
            ("", "transit", "app-kek", None)
        );
        let r = p("openbao://prod/team-a/transit/keys/k1?namespace=team-a/child").unwrap();
        assert_eq!(
            (r.alias(), r.mount(), r.namespace()),
            ("prod", "team-a/transit", Some("team-a/child"))
        );
    }

    #[test]
    fn rejects() {
        for s in [
            "hashivault://transit/keys/k",
            "hashivault:///keys/k",
            "hashivault:///transit/keys/",
            "hashivault:///transit/keys/a/b",
            "hashivault:///transit/../keys/k",
            "hashivault:///transit/keys/k%2f",
            "hashivault://user@host/transit/keys/k",
            "hashivault://host:8200/transit/keys/k",
            "hashivault:///transit/keys/k?foo=bar",
            "hashivault:///transit/keys/k?namespace=a&namespace=b",
            "hashivault:///transit/keys/k#frag",
            "hashivault:///transit//keys/k",
            "aws-kms:///transit/keys/k",
            // Reserved (non-transit) backends, in any mount position.
            "hashivault:///sys/keys/k",
            "hashivault:///SYS/keys/k",
            "hashivault:///sys/mounts/transit/keys/k",
            "hashivault:///auth/token/keys/k",
            "hashivault:///identity/keys/k",
            "hashivault:///cubbyhole/keys/k",
            "hashivault:///team-b/sys/keys/k",
            "hashivault:///team-b/cubbyhole/keys/k",
        ] {
            assert!(p(s).is_err(), "{s}");
        }
        let e = p("hashivault://transit/keys/k").unwrap_err();
        assert!(e.message().contains("three slashes"), "{e}");
        let e = p("hashivault:///sys/keys/k").unwrap_err();
        assert!(e.message().contains("reserved"), "{e}");
    }

    #[test]
    fn reserved_names_are_fine_as_key_names_and_with_dashes() {
        // Only mount segments are reserved; dashed single-segment mounts are ordinary.
        let r = p("hashivault:///transit-envelope/keys/sys").unwrap();
        assert_eq!((r.mount(), r.name()), ("transit-envelope", "sys"));
        assert!(!r.is_multi_segment_mount());
        assert!(p("hashivault:///sys-transit/keys/k").is_ok());
        assert!(
            p("hashivault:///team-b/transit/keys/k")
                .unwrap()
                .is_multi_segment_mount()
        );
    }
}
