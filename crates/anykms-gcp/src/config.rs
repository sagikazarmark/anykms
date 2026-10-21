//! Endpoints, transport options and environment configuration.

use std::fmt;
use std::net::IpAddr;

use anykms_core::{Error, ErrorKind, Operation, Result};

use crate::BACKEND;

pub(crate) fn config_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

/// Whether `u`'s host is a literal loopback IP (`127.0.0.0/8`, `::1`).
pub(crate) fn is_loopback_ip(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        _ => false,
    }
}

/// The Cloud KMS endpoint. `Debug` prints a custom URL's origin only
/// ([`url_origin`](anykms_http::redact::url_origin)).
#[non_exhaustive]
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Endpoint {
    /// `https://cloudkms.googleapis.com` (default).
    #[default]
    Global,
    /// The regional endpoint of each key's location, `https://cloudkms.<location>.rep.googleapis.com`
    /// (data residency). The location comes from the key URI; a key in `global` is refused at
    /// open with `Configuration`. A location without a regional endpoint fails with
    /// `Unavailable` ("DNS lookup failed"): check Google's list of regional endpoints.
    Regional,
    /// A custom base URL (Private Service Connect, a private or restricted VIP, a test server).
    /// `https://`, or `http://` on a literal loopback IP with
    /// [`allow_loopback_http`](crate::GcpProviderBuilder::allow_loopback_http).
    Custom(String),
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Global => f.write_str("Global"),
            Endpoint::Regional => f.write_str("Regional"),
            // A custom URL may carry userinfo (refused at build, but printed before).
            Endpoint::Custom(u) => write!(f, "Custom({})", anykms_http::redact::url_origin(u)),
        }
    }
}

impl Endpoint {
    /// [`Endpoint::Custom`].
    pub fn custom(url: impl Into<String>) -> Self {
        Endpoint::Custom(url.into())
    }

    /// Parses an `ANYKMS_GCP_ENDPOINT` value: `global`, `regional`, or a URL.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "" | "global" => Ok(Endpoint::Global),
            "regional" => Ok(Endpoint::Regional),
            u if u.starts_with("https://") || u.starts_with("http://") => {
                Ok(Endpoint::Custom(u.to_owned()))
            }
            _ => Err(config_err(
                "the GCP endpoint must be `global`, `regional` or an https:// URL",
            )),
        }
    }

    /// Validates a custom URL: `scheme://host[:port]` with no credentials, query or fragment.
    pub(crate) fn validate_custom(u: &str, allow_loopback_http: bool) -> Result<url::Url> {
        let url =
            url::Url::parse(u).map_err(|_| config_err("the custom endpoint is not a valid URL"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(config_err(
                "the custom endpoint must not contain credentials",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
            return Err(config_err(
                "the custom endpoint must be scheme://host[:port]",
            ));
        }
        match url.scheme() {
            "http" if !is_loopback_ip(&url) => {
                return Err(config_err(
                    "plain http:// is only allowed for literal loopback IPs (127.0.0.0/8, ::1); \
                     use https://",
                ));
            }
            "http" if !allow_loopback_http => {
                return Err(config_err(
                    "plain http:// requires GcpProviderBuilder::allow_loopback_http()",
                ));
            }
            "https" | "http" => {}
            _ => return Err(config_err("the custom endpoint must use https://")),
        }
        Ok(url)
    }

    /// The base URL for a key in `location`.
    pub(crate) fn base_for(&self, location: &str, custom: Option<&url::Url>) -> Result<url::Url> {
        match self {
            Endpoint::Global => {
                Ok(url::Url::parse("https://cloudkms.googleapis.com/").expect("fixed URL"))
            }
            Endpoint::Regional => {
                if location == "global" {
                    return Err(Error::new(
                        ErrorKind::Configuration,
                        BACKEND,
                        Operation::Open,
                        "keys in the `global` location have no regional endpoint; use \
                         Endpoint::Global",
                    ));
                }
                // The location passed the URI grammar ([a-z0-9-]), so it is a valid DNS label.
                url::Url::parse(&format!("https://cloudkms.{location}.rep.googleapis.com/"))
                    .map_err(|_| config_err("invalid regional endpoint"))
            }
            Endpoint::Custom(_) => Ok(custom.expect("validated at build").clone()),
        }
    }
}

/// HTTP protocol version.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.1 (default).
    #[default]
    Http1,
    /// HTTP/2 (multiplexes every request over one connection). Requires the `http2` feature;
    /// negotiated with TLS ALPN, so `https://` endpoints only.
    Http2,
}

/// Proxy configuration. Environment proxies (`HTTPS_PROXY`, ...) are ignored unless configured
/// explicitly.
#[non_exhaustive]
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Proxy {
    /// Connect directly.
    #[default]
    None,
    /// Use this proxy for all requests, including token endpoints (the metadata server is always
    /// reached directly).
    Url(String),
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proxy::None => f.write_str("None"),
            // Proxy URLs may carry credentials; print only scheme, host and port.
            Proxy::Url(u) => write!(f, "Url({})", anykms_http::redact::url_origin(u)),
        }
    }
}

/// A comma-separated list from the environment (`a,b , c`), with empty items dropped.
pub(crate) fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(Endpoint::parse("global").unwrap(), Endpoint::Global);
        assert_eq!(Endpoint::parse("regional").unwrap(), Endpoint::Regional);
        assert_eq!(
            Endpoint::parse("https://kms.p.googleapis.com").unwrap(),
            Endpoint::custom("https://kms.p.googleapis.com")
        );
        assert!(Endpoint::parse("kms.example").is_err());
        let r = Endpoint::Regional.base_for("europe-west1", None).unwrap();
        assert_eq!(
            r.as_str(),
            "https://cloudkms.europe-west1.rep.googleapis.com/"
        );
        assert_eq!(
            Endpoint::Regional
                .base_for("global", None)
                .unwrap_err()
                .kind(),
            ErrorKind::Configuration
        );
        assert!(Endpoint::validate_custom("https://kms.example:8443", false).is_ok());
        assert!(Endpoint::validate_custom("http://127.0.0.1:1234", true).is_ok());
        for bad in [
            ("http://127.0.0.1:1234", false),
            ("http://localhost:1234", true),
            ("http://10.1.2.3", true),
            ("https://u:p@kms.example", false),
            ("https://kms.example/v1", false),
            ("https://kms.example?x", false),
            ("ftp://kms.example", false),
        ] {
            assert!(Endpoint::validate_custom(bad.0, bad.1).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn proxy_debug_hides_credentials() {
        let p = Proxy::Url("http://user:secret@proxy:3128".into());
        assert_eq!(format!("{p:?}"), "Url(http://proxy:3128)");
        let e = Endpoint::custom("https://user:secret@kms.example/x?token=secret");
        assert_eq!(format!("{e:?}"), "Custom(https://kms.example:443)");
    }

    #[test]
    fn lists() {
        assert_eq!(split_list(" a, ,b ,"), vec!["a", "b"]);
    }
}
