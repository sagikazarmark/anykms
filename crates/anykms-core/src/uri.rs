//! Key URIs: `scheme:rest`, where `rest` is opaque to core and parsed by the provider that owns
//! the scheme.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, ErrorKind, Operation};

const MAX_URI_LEN: usize = 2048;

/// A key URI such as `hashivault:///transit/keys/app-kek` or `local://default/kek`.
///
/// Core only validates the scheme (`[a-z][a-z0-9+.-]*`) and rejects control characters and
/// whitespace. Everything after the first `:` is passed to the provider, which applies its own
/// strict grammar and address policy.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyUri {
    scheme: String,
    rest: String,
}

impl KeyUri {
    /// Parses a key URI. Errors are [`Configuration`](ErrorKind::Configuration) (key URIs come
    /// from configuration), operation [`Operation::ParseUri`]; applications that accept URIs
    /// from users recognize them by that operation.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let err =
            |m: &'static str| Error::new(ErrorKind::Configuration, "core", Operation::ParseUri, m);
        if s.len() > MAX_URI_LEN {
            return Err(err("key URI is too long"));
        }
        let (scheme, rest) = s
            .split_once(':')
            .ok_or_else(|| err("key URI has no scheme"))?;
        let mut chars = scheme.bytes();
        match chars.next() {
            Some(b'a'..=b'z') => {}
            _ => return Err(err("key URI scheme must start with a lowercase letter")),
        }
        if !chars.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'+' | b'.' | b'-')) {
            return Err(err("key URI scheme contains invalid characters"));
        }
        if rest.is_empty() {
            return Err(err("key URI is empty after the scheme"));
        }
        if rest
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b >= 0x80)
        {
            return Err(err(
                "key URI contains whitespace, control or non-ASCII characters",
            ));
        }
        Ok(Self {
            scheme: scheme.to_owned(),
            rest: rest.to_owned(),
        })
    }

    /// The scheme, without the `:`.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Everything after the first `:`.
    pub fn rest(&self) -> &str {
        &self.rest
    }

    /// The URI without its query string (everything from the first `?`), fragment (everything
    /// from the first `#`) or userinfo (an authority's `user:password@` or `token@`), which is how
    /// core names the key in errors ([`Error::resource`](crate::Error::resource)). Backends label
    /// their own errors with it too: a query string may carry options that must not reach logs,
    /// and a credential pasted into the authority of a mistyped URI must not either. No valid key
    /// URI of a built-in backend has userinfo or a fragment, so the label of a valid URI is the
    /// URI without its query. A third-party scheme that puts an `@` in the authority (say
    /// `scheme://name@version`) gets labels without what precedes the `@`: the label cannot
    /// tell a name from a pasted credential, and errs on the side of the credential.
    ///
    /// ```
    /// let uri: anykms_core::KeyUri = "local://default/kek?opt=1".parse().unwrap();
    /// assert_eq!(uri.without_query(), "local://default/kek");
    /// ```
    ///
    /// Core does not normalize URIs: `hashivault:///transit/keys/k` (the provider's default
    /// server) and `hashivault://default/transit/keys/k` (the server named `default`) are
    /// different URIs, and name the same key only when the provider's default server is the one
    /// called `default`.
    pub fn without_query(&self) -> String {
        let end = self.rest.find(['?', '#']).unwrap_or(self.rest.len());
        let rest = &self.rest[..end];
        // Userinfo: the authority (after `//`, up to the next `/`) up to its last `@`. Working on
        // the raw string: `url::Url` cannot parse every key URI (an AWS ARN is not a port).
        if let Some(after) = rest.strip_prefix("//") {
            let auth_end = after.find('/').unwrap_or(after.len());
            if let Some(at) = after[..auth_end].rfind('@') {
                return format!("{}://{}", self.scheme, &after[at + 1..]);
            }
        }
        format!("{}:{rest}", self.scheme)
    }
}

/// Anything a [`Registry`](crate::Registry) accepts as a key URI: a [`KeyUri`] (owned or
/// borrowed) or a string to parse, so callers can write `registry.aead("local://default/kek")`.
/// Implement it for configuration types that hold a URI.
pub trait IntoKeyUri {
    /// Converts to a `KeyUri`, parsing strings with [`KeyUri::parse`].
    fn into_key_uri(self) -> Result<KeyUri, Error>;
}

impl IntoKeyUri for KeyUri {
    fn into_key_uri(self) -> Result<KeyUri, Error> {
        Ok(self)
    }
}

impl IntoKeyUri for &KeyUri {
    fn into_key_uri(self) -> Result<KeyUri, Error> {
        Ok(self.clone())
    }
}

impl IntoKeyUri for &str {
    fn into_key_uri(self) -> Result<KeyUri, Error> {
        KeyUri::parse(self)
    }
}

impl IntoKeyUri for String {
    fn into_key_uri(self) -> Result<KeyUri, Error> {
        KeyUri::parse(&self)
    }
}

impl IntoKeyUri for &String {
    fn into_key_uri(self) -> Result<KeyUri, Error> {
        KeyUri::parse(self)
    }
}

impl FromStr for KeyUri {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::parse(s)
    }
}

impl fmt::Display for KeyUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scheme, self.rest)
    }
}

impl fmt::Debug for KeyUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyUri({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let u: KeyUri = "hashivault:///transit/keys/k".parse().unwrap();
        assert_eq!(u.scheme(), "hashivault");
        assert_eq!(u.rest(), "///transit/keys/k");
        assert_eq!(u.to_string(), "hashivault:///transit/keys/k");
        let a: KeyUri = "aws-kms://arn:aws:kms:us-east-1:1:key/x".parse().unwrap();
        assert_eq!(a.scheme(), "aws-kms");
    }

    #[test]
    fn rejects() {
        for s in [
            "",
            "nocolon",
            "Upper://x",
            "1x://y",
            "a b://c",
            "x:",
            "x://a b",
            "x://\n",
            "x://é",
        ] {
            let e = KeyUri::parse(s).unwrap_err();
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::Configuration, Operation::ParseUri),
                "{s:?}"
            );
            assert!(e.is_config_error(), "{s:?}");
        }
    }
}

#[cfg(test)]
mod review_l21_tests {
    use super::KeyUri;

    /// L21: the label form of a URI never carries userinfo (a password or token pasted before
    /// an `@`) or a fragment, whatever the scheme; ARNs and ordinary URIs are unchanged.
    #[test]
    fn without_query_drops_userinfo_and_fragment() {
        for (uri, label) in [
            ("postgres://app:s3cret@db/app", "postgres://db/app"),
            (
                "hashivault://hvs.TOKEN@vault.internal/transit/keys/app",
                "hashivault://vault.internal/transit/keys/app",
            ),
            ("x://user@host", "x://host"),
            ("x://a@b@host/p?q=1", "x://host/p"),
            ("x://host/p#frag@x", "x://host/p"),
            ("x://host/p?q=a@b", "x://host/p"),
            (
                "aws-kms://arn:aws:kms:us-east-1:111122223333:key/abcd",
                "aws-kms://arn:aws:kms:us-east-1:111122223333:key/abcd",
            ),
            ("local://default/kek?opt=1", "local://default/kek"),
            (
                "hashivault:///transit/keys/k",
                "hashivault:///transit/keys/k",
            ),
            // No authority: an `@` in the path is not userinfo.
            ("x:a@b", "x:a@b"),
            (
                "gcp-kms://projects/p/keys/k@3",
                "gcp-kms://projects/p/keys/k@3",
            ),
        ] {
            let u: KeyUri = uri.parse().unwrap();
            assert_eq!(u.without_query(), label, "{uri}");
        }
    }
}
