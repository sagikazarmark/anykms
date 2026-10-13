//! GCP key URIs: Cloud KMS resource names under the `gcp-kms` scheme (Tink's spelling).
//!
//! ```text
//! gcp-kms://projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>[/cryptoKeyVersions/<n>]
//! ```
//!
//! - project: `[a-z][a-z0-9-]{4,28}[a-z0-9]`, optionally prefixed with a legacy domain scope
//!   (`example.com:my-project`);
//! - location: `[a-z0-9-]{1,63}`;
//! - key ring and key: `[A-Za-z0-9_-]{1,63}`;
//! - version: `[1-9][0-9]*`, at most `u64::MAX`.
//!
//! A query, a fragment, percent-encoding, empty segments, `.` and `..` are refused. The resource
//! name never selects a host: the endpoint comes from the provider configuration (for regional
//! endpoints, from the location in the URI, never from caller text).

use std::fmt;

use anykms_core::{Error, ErrorKind, KeyUri, Operation, Result};

use crate::BACKEND;

/// The URI scheme routed to the GCP provider.
pub const SCHEME: &str = "gcp-kms";

/// URI schemes routed to the GCP provider.
pub const SCHEMES: &[&str] = &[SCHEME];

/// A URI that does not parse: `Configuration` (A3(c)), since key URIs come from configuration.
/// Input versions (a signature's, a tag's, `public_key_version`) never come through here: they
/// go through [`parse_version`], which returns an `Option`.
fn bad(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::ParseUri, m)
}

/// A parsed Cloud KMS key reference.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GcpKeyRef {
    project: String,
    location: String,
    key_ring: String,
    key: String,
    version: Option<u64>,
}

impl fmt::Debug for GcpKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GcpKeyRef({})", self.resource_name())
    }
}

impl fmt::Display for GcpKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}://{}", self.resource_name())
    }
}

pub(crate) fn project_ok(s: &str) -> bool {
    let id = match s.rsplit_once(':') {
        Some((domain, id)) => {
            let domain_ok = domain.len() <= 253
                && domain.contains('.')
                && domain.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && l.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                });
            if !domain_ok {
                return false;
            }
            id
        }
        None => s,
    };
    let b = id.as_bytes();
    (6..=30).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[b.len() - 1] != b'-'
}

pub(crate) fn location_ok(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn id_ok(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A decimal key version: `[1-9][0-9]*`, fitting in a `u64`.
pub(crate) fn parse_version(s: &str) -> Option<u64> {
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl GcpKeyRef {
    /// This key at `version`.
    pub(crate) fn at_version(&self, version: u64) -> Self {
        Self {
            version: Some(version),
            ..self.clone()
        }
    }

    /// Parses a `gcp-kms://projects/...` URI.
    pub fn parse(uri: &KeyUri) -> Result<Self> {
        if uri.scheme() != SCHEME {
            return Err(bad("not a gcp-kms:// URI"));
        }
        Self::parse_rest(uri.rest())
    }

    /// Parses the part after `gcp-kms:`.
    pub(crate) fn parse_rest(rest: &str) -> Result<Self> {
        if rest.contains('?') || rest.contains('#') {
            return Err(bad("GCP key URIs take no query or fragment"));
        }
        if rest.contains('%') {
            return Err(bad("GCP key URIs must not be percent-encoded"));
        }
        if rest.starts_with("///") {
            return Err(bad(
                "GCP key URIs have no authority: write gcp-kms://projects/..., not gcp-kms:///projects/...",
            ));
        }
        let name = rest
            .strip_prefix("//")
            .ok_or_else(|| bad("GCP key URIs start with gcp-kms://projects/"))?;
        Self::parse_name(name)
    }

    /// Parses a resource name (`projects/.../cryptoKeys/k[/cryptoKeyVersions/n]`).
    pub(crate) fn parse_name(name: &str) -> Result<Self> {
        let parts: Vec<&str> = name.split('/').collect();
        let fixed = |i: usize, want: &str| parts.get(i).is_some_and(|p| *p == want);
        let shape = (parts.len() == 8 || parts.len() == 10)
            && fixed(0, "projects")
            && fixed(2, "locations")
            && fixed(4, "keyRings")
            && fixed(6, "cryptoKeys")
            && (parts.len() == 8 || fixed(8, "cryptoKeyVersions"));
        if !shape {
            return Err(bad(
                "expected gcp-kms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>[/cryptoKeyVersions/<n>]",
            ));
        }
        if !project_ok(parts[1]) {
            return Err(bad(
                "invalid GCP project ID: 6 to 30 lowercase letters, digits and hyphens, starting \
                 with a letter and not ending with a hyphen (domain-scoped: <domain>:<id>)",
            ));
        }
        if !location_ok(parts[3]) {
            return Err(bad(
                "invalid GCP location: 1 to 63 lowercase letters, digits and hyphens (e.g. global, \
                 us-east1)",
            ));
        }
        if !id_ok(parts[5]) {
            return Err(bad(
                "invalid key ring name: 1 to 63 letters, digits, underscores and hyphens",
            ));
        }
        if !id_ok(parts[7]) {
            return Err(bad(
                "invalid key name: 1 to 63 letters, digits, underscores and hyphens",
            ));
        }
        let version = match parts.get(9) {
            None => None,
            Some(v) => Some(
                parse_version(v)
                    .ok_or_else(|| bad("invalid key version: a positive decimal number"))?,
            ),
        };
        Ok(Self {
            project: parts[1].to_owned(),
            location: parts[3].to_owned(),
            key_ring: parts[5].to_owned(),
            key: parts[7].to_owned(),
            version,
        })
    }

    /// The project ID.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The location (`global`, `europe-west1`, ...).
    pub fn location(&self) -> &str {
        &self.location
    }

    /// The key ring.
    pub fn key_ring(&self) -> &str {
        &self.key_ring
    }

    /// The key (`cryptoKeys/<key>`).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The version, if the URI names one.
    pub fn version(&self) -> Option<u64> {
        self.version
    }

    /// The key's resource name, without a version.
    pub fn key_name(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.project, self.location, self.key_ring, self.key
        )
    }

    /// The resource name of version `v` of this key.
    pub fn version_name(&self, v: u64) -> String {
        format!("{}/cryptoKeyVersions/{v}", self.key_name())
    }

    /// The resource name as written: with the version when the URI names one.
    pub fn resource_name(&self) -> String {
        match self.version {
            Some(v) => self.version_name(v),
            None => self.key_name(),
        }
    }

    /// The path segments of [`key_name`](Self::key_name), for building request URLs.
    pub(crate) fn key_segments(&self) -> [&str; 8] {
        [
            "projects",
            &self.project,
            "locations",
            &self.location,
            "keyRings",
            &self.key_ring,
            "cryptoKeys",
            &self.key,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<GcpKeyRef> {
        GcpKeyRef::parse(&s.parse::<KeyUri>()?)
    }

    #[test]
    fn parses_keys_and_versions() {
        let r = parse("gcp-kms://projects/my-project/locations/global/keyRings/r_1/cryptoKeys/K-2")
            .unwrap();
        assert_eq!(r.project(), "my-project");
        assert_eq!(r.location(), "global");
        assert_eq!(r.key_ring(), "r_1");
        assert_eq!(r.key(), "K-2");
        assert_eq!(r.version(), None);
        assert_eq!(
            r.key_name(),
            "projects/my-project/locations/global/keyRings/r_1/cryptoKeys/K-2"
        );
        let v = parse(
            "gcp-kms://projects/example.com:my-project/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/18446744073709551615",
        )
        .unwrap();
        assert_eq!(v.project(), "example.com:my-project");
        assert_eq!(v.version(), Some(u64::MAX));
        assert_eq!(
            v.to_string(),
            "gcp-kms://projects/example.com:my-project/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/18446744073709551615"
        );
    }

    #[test]
    fn rejects_malformed_uris() {
        let ok = "projects/my-project/locations/global/keyRings/r/cryptoKeys/k";
        for bad in [
            format!("gcp-kms:///{ok}"),
            format!("gcp-kms:{ok}"),
            format!("gcp-kms://{ok}?x=1"),
            format!("gcp-kms://{ok}#f"),
            format!("gcp-kms://{ok}/"),
            format!("gcp-kms://{ok}/cryptoKeyVersions/0"),
            format!("gcp-kms://{ok}/cryptoKeyVersions/01"),
            format!("gcp-kms://{ok}/cryptoKeyVersions/18446744073709551616"),
            format!("gcp-kms://{ok}/cryptoKeyVersions/"),
            format!("gcp-kms://{ok}/cryptoKeyVersions/1/x"),
            format!("gcp-kms://{ok}/versions/1"),
            "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k%2F".into(),
            "gcp-kms://projects/My-project/locations/global/keyRings/r/cryptoKeys/k".into(),
            "gcp-kms://projects/short/locations/global/keyRings/r/cryptoKeys/k".into(),
            "gcp-kms://projects/my-project-/locations/global/keyRings/r/cryptoKeys/k".into(),
            "gcp-kms://projects/1234567/locations/global/keyRings/r/cryptoKeys/k".into(),
            "gcp-kms://projects/:my-project/locations/global/keyRings/r/cryptoKeys/k".into(),
            "gcp-kms://projects/my-project/locations/Global/keyRings/r/cryptoKeys/k".into(),
            "gcp-kms://projects/my-project/locations//keyRings/r/cryptoKeys/k".into(),
            "gcp-kms://projects/my-project/locations/global/keyRings/../cryptoKeys/k".into(),
            "gcp-kms://projects/my-project/locations/global/keyRings/./cryptoKeys/k".into(),
            "gcp-kms://projects/my-project/locations/global/keyRings/r.x/cryptoKeys/k".into(),
            format!(
                "gcp-kms://projects/my-project/locations/global/keyRings/{}/cryptoKeys/k",
                "r".repeat(64)
            ),
            "gcp-kms://host/projects/my-project/locations/global/keyRings/r/cryptoKeys/k".into(),
            "aws-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k".into(),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
        let e = parse(&format!("gcp-kms:///{ok}")).unwrap_err();
        assert!(e.to_string().contains("no authority"), "{e}");
        assert_eq!(e.kind(), ErrorKind::Configuration);
        // The crate's own grammar too (A3(c)).
        let e = parse(&format!("gcp-kms://{ok}/cryptoKeyVersions/0")).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert_eq!(e.operation(), Operation::ParseUri);
        assert!(e.is_config_error());
    }
}
