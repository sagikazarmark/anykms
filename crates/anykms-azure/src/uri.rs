//! `azure-kv://<host>/keys/<name>[/<version>]` key URIs and Key Vault key identifiers.
//!
//! The grammar is strict (fuzzed by `fuzz_targets/azure_uri.rs`):
//!
//! ```text
//! azure-kv://<host>/keys/<name>[/<version>]
//!   host    = DNS labels [a-z0-9-] separated by dots, lowercased; an optional :port is accepted
//!             only by the parser, and only a configured test host may carry one
//!   name    = [0-9A-Za-z-]{1,127}
//!   version = 32 hex characters, case-insensitive, normalized to lowercase
//! ```
//!
//! Query strings, fragments, percent-encoding, userinfo, trailing slashes, `.`/`..` segments and
//! other path shapes (`/secrets/...`, `/deletedkeys/...`) are refused. Whether a host may receive
//! a token is decided separately by the provider's host policy (see
//! [`AzureProviderBuilder`](crate::AzureProviderBuilder)).

use std::fmt;

use anykms_core::{Error, ErrorKind, IntoKeyUri, KeyUri, Operation, Result};

use crate::BACKEND;

/// The URI scheme this backend owns.
pub const SCHEME: &str = "azure-kv";

/// The URI schemes this backend owns.
pub const SCHEMES: &[&str] = &[SCHEME];

const MAX_NAME_LEN: usize = 127;
/// Key versions Azure issues today: 32 hex characters.
pub(crate) const VERSION_LEN: usize = 32;
const MAX_HOST_LEN: usize = 253;

/// A key URI that does not parse: configuration (A3(c)), labeled `ParseUri`.
fn bad(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::ParseUri, m)
}

/// A value that comes from input rather than configuration (a key identifier, a version):
/// `InvalidArgument`, labeled `Construct`.
fn bad_input(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, Operation::Construct, m)
}

/// A parsed `azure-kv://` key URI: a vault (or Managed HSM) host, a key name and an optional
/// version.
///
/// Parsing checks syntax only; the provider then checks the host against its allowlist before
/// any request (a bearer token is sent to allowlisted hosts only).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AzureKeyRef {
    host: String,
    name: String,
    version: Option<String>,
}

impl fmt::Debug for AzureKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AzureKeyRef({self})")
    }
}

impl fmt::Display for AzureKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}://{}/keys/{}", self.host, self.name)?;
        if let Some(v) = &self.version {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

impl AzureKeyRef {
    /// Parses an `azure-kv://` URI. Errors are `Configuration` (operation `ParseUri`).
    pub fn parse(uri: impl IntoKeyUri) -> Result<Self> {
        let uri = uri.into_key_uri()?;
        if uri.scheme() != SCHEME {
            return Err(bad("not an azure-kv:// URI"));
        }
        let rest = uri
            .rest()
            .strip_prefix("//")
            .ok_or_else(|| bad("azure-kv URI must be azure-kv://<host>/keys/<name>[/<version>]"))?;
        // A pasted key identifier behind the scheme would otherwise fail as an invalid port.
        let lower = rest.get(..8).unwrap_or(rest).to_ascii_lowercase();
        if lower.starts_with("https:") || lower.starts_with("http:") {
            return Err(bad(
                "azure-kv URI must not contain https://: write azure-kv://<host>/keys/<name>\
                 [/<version>] (a key identifier https://<host>/keys/... becomes \
                 azure-kv://<host>/keys/...)",
            ));
        }
        Self::parse_authority_path(rest)
    }

    /// Parses a Key Vault key identifier (`kid`), e.g.
    /// `https://contoso.vault.azure.net/keys/app-kek/0123...`, into the equivalent URI. The host
    /// is not checked against any allowlist here. `https` is never registered as a scheme: this
    /// is a conversion helper only. Errors are `InvalidArgument` (operation `Construct`): a key
    /// identifier usually comes from input (a response, a token).
    pub fn from_key_id(kid: &str) -> Result<Self> {
        let rest = kid
            .strip_prefix("https://")
            .ok_or_else(|| bad_input("key identifier must start with https://"))?;
        Self::parse_authority_path(rest).map_err(|e| bad_input(e.message().to_owned()))
    }

    fn parse_authority_path(rest: &str) -> Result<Self> {
        if rest
            .bytes()
            .any(|b| matches!(b, b'?' | b'#' | b'%' | b'@' | b'\\') || !b.is_ascii_graphic())
        {
            return Err(bad(
                "azure-kv URI must not contain a query, fragment, percent-encoding or userinfo",
            ));
        }
        let (host, path) = rest
            .split_once('/')
            .ok_or_else(|| bad("azure-kv URI has no key path"))?;
        let host = parse_host(host)?;
        let mut segs = path.split('/');
        if segs.next() != Some("keys") {
            return Err(bad("azure-kv URI path must be /keys/<name>[/<version>]"));
        }
        let name = segs
            .next()
            .ok_or_else(|| bad("azure-kv URI has no key name"))?;
        if !name_ok(name) {
            return Err(bad("key name must be 1-127 characters of 0-9 A-Z a-z -"));
        }
        let version = match segs.next() {
            None => None,
            Some(v) => Some(
                parse_version(v)
                    .ok_or_else(|| bad("key version must be 32 hexadecimal characters"))?,
            ),
        };
        if segs.next().is_some() {
            return Err(bad("azure-kv URI path must be /keys/<name>[/<version>]"));
        }
        Ok(Self {
            host,
            name: name.to_owned(),
            version,
        })
    }

    /// The host (lowercase, with `:port` for test hosts).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The key name, as written (Azure compares names case-insensitively).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The pinned version (lowercase), if any.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// The same key without a version.
    pub fn without_version(&self) -> Self {
        Self {
            version: None,
            ..self.clone()
        }
    }

    /// The same key at `version` (32 hex characters, else `InvalidArgument`, operation
    /// `Construct`).
    pub fn with_version(&self, version: &str) -> Result<Self> {
        let v = parse_version(version)
            .ok_or_else(|| bad_input("key version must be 32 hexadecimal characters"))?;
        Ok(Self {
            version: Some(v),
            ..self.clone()
        })
    }

    /// The Key Vault key identifier: `https://<host>/keys/<name>[/<version>]`.
    pub fn to_key_id(&self) -> String {
        let mut s = format!("https://{}/keys/{}", self.host, self.name);
        if let Some(v) = &self.version {
            s.push('/');
            s.push_str(v);
        }
        s
    }

    /// The URI as a [`KeyUri`].
    pub fn to_key_uri(&self) -> KeyUri {
        KeyUri::parse(&self.to_string()).expect("a parsed azure-kv URI is a valid key URI")
    }
}

/// `host[:port]`, lowercased. Labels of `[a-z0-9-]` (no leading or trailing hyphen), at least
/// one dot or a port (`localhost:8443`), port `1..=65535` without leading zeros.
pub(crate) fn parse_host(s: &str) -> Result<String> {
    let (name, port) = match s.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (s, None),
    };
    if name.is_empty() || name.len() > MAX_HOST_LEN {
        return Err(bad("invalid host"));
    }
    let name = name.to_ascii_lowercase();
    let labels_ok = name.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if !labels_ok {
        return Err(bad("invalid host"));
    }
    match port {
        None => {
            if !name.contains('.') {
                return Err(bad("invalid host"));
            }
            Ok(name)
        }
        Some(p) => {
            let ok = !p.is_empty()
                && p.len() <= 5
                && !p.starts_with('0')
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
            if !ok {
                return Err(bad("invalid port"));
            }
            Ok(format!("{name}:{p}"))
        }
    }
}

fn name_ok(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A 32-hex version, lowercased.
pub(crate) fn parse_version(v: &str) -> Option<String> {
    (v.len() == VERSION_LEN && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| v.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "0123456789abcdef0123456789ABCDEF";

    fn p(s: &str) -> Result<AzureKeyRef> {
        AzureKeyRef::parse(s)
    }

    #[test]
    fn parses_and_normalizes() {
        let u = p(&format!(
            "azure-kv://Contoso.Vault.Azure.NET/keys/App-Kek/{V}"
        ))
        .unwrap();
        assert_eq!(u.host(), "contoso.vault.azure.net");
        assert_eq!(u.name(), "App-Kek");
        assert_eq!(u.version(), Some("0123456789abcdef0123456789abcdef"));
        assert_eq!(
            u.to_string(),
            "azure-kv://contoso.vault.azure.net/keys/App-Kek/0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            u.to_key_id(),
            "https://contoso.vault.azure.net/keys/App-Kek/0123456789abcdef0123456789abcdef"
        );
        assert_eq!(AzureKeyRef::from_key_id(&u.to_key_id()).unwrap(), u);
        assert_eq!(u.to_key_uri().to_string(), u.to_string());
        let unpinned = p("azure-kv://hsm1.managedhsm.azure.net/keys/k").unwrap();
        assert_eq!(unpinned.version(), None);
        assert_eq!(u.without_version().version(), None);
        assert!(unpinned.with_version("xyz").is_err());
        let t = p("azure-kv://localhost:8443/keys/k").unwrap();
        assert_eq!(t.host(), "localhost:8443");
        let ip = p("azure-kv://127.0.0.1:8443/keys/k").unwrap();
        assert_eq!(ip.host(), "127.0.0.1:8443");
    }

    /// R-39: a key identifier pasted behind the scheme is explained (it used to fail as an
    /// invalid port).
    #[test]
    fn a_nested_https_url_is_explained() {
        for s in [
            "azure-kv://https://contoso.vault.azure.net/keys/k",
            "azure-kv://HTTPS://contoso.vault.azure.net/keys/k",
            "azure-kv://http://contoso.vault.azure.net/keys/k",
        ] {
            let e = p(s).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{s}");
            assert!(
                e.message()
                    .starts_with("azure-kv URI must not contain https://"),
                "{s}: {e}"
            );
        }
    }

    #[test]
    fn rejects() {
        for bad in [
            "azure-kv:/contoso.vault.azure.net/keys/k",
            "azure-kv://contoso.vault.azure.net/keys/k/",
            "azure-kv://contoso.vault.azure.net/keys/",
            "azure-kv://contoso.vault.azure.net/keys",
            "azure-kv://contoso.vault.azure.net/",
            "azure-kv://contoso.vault.azure.net",
            "azure-kv://contoso.vault.azure.net/secrets/k",
            "azure-kv://contoso.vault.azure.net/deletedkeys/k",
            "azure-kv://contoso.vault.azure.net/keys/k?api-version=1",
            "azure-kv://contoso.vault.azure.net/keys/k#x",
            "azure-kv://contoso.vault.azure.net/keys/k%2F",
            "azure-kv://user@contoso.vault.azure.net/keys/k",
            "azure-kv://contoso.vault.azure.net/keys/../k",
            "azure-kv://contoso.vault.azure.net/keys/./k",
            "azure-kv://contoso.vault.azure.net/keys/k_1",
            "azure-kv://contoso.vault.azure.net/keys/k/123",
            "azure-kv://contoso.vault.azure.net/keys/k/0123456789abcdef0123456789abcdeg",
            "azure-kv://contoso.vault.azure.net/keys/k/0123456789abcdef0123456789abcdef/sign",
            "azure-kv://contoso..vault.azure.net/keys/k",
            "azure-kv://-contoso.vault.azure.net/keys/k",
            "azure-kv://contoso.vault.azure.net:/keys/k",
            "azure-kv://contoso.vault.azure.net:0/keys/k",
            "azure-kv://contoso.vault.azure.net:08443/keys/k",
            "azure-kv://contoso.vault.azure.net:65536/keys/k",
            "azure-kv://localhost/keys/k",
            "azure-kv://[::1]:8443/keys/k",
            "azure-kv:///keys/k",
            "hashivault:///transit/keys/k",
        ] {
            let e = p(bad).unwrap_err();
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::Configuration, Operation::ParseUri),
                "{bad}"
            );
        }
        let long = format!("azure-kv://v.vault.azure.net/keys/{}", "a".repeat(128));
        assert!(p(&long).is_err());
        let ok = format!("azure-kv://v.vault.azure.net/keys/{}", "a".repeat(127));
        assert!(p(&ok).is_ok());
        // Key identifiers and versions are input, not configuration: InvalidArgument, never
        // ParseUri (A3(c)).
        for kid in [
            "http://v.vault.azure.net/keys/k",
            "https://v.vault.azure.net/secrets/k",
            "https://v.vault.azure.net/keys/k/123",
        ] {
            let e = AzureKeyRef::from_key_id(kid).unwrap_err();
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::InvalidArgument, Operation::Construct),
                "{kid}"
            );
        }
        let e = p("azure-kv://v.vault.azure.net/keys/k")
            .unwrap()
            .with_version("123")
            .unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::InvalidArgument, Operation::Construct)
        );
    }
}
