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

    /// The URI without its query string (everything from the first `?`), which is how core
    /// names the key in errors ([`Error::resource`](crate::Error::resource)). Backends label
    /// their own errors with it too: a query string may carry options that must not reach logs.
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
        let rest = self.rest.split_once('?').map_or(&*self.rest, |(r, _)| r);
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
