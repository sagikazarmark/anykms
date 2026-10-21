//! KMS endpoints: derived from partition and region, or configured.
//!
//! | Partition | Standard | FIPS | Dual-stack | FIPS + dual-stack |
//! |---|---|---|---|---|
//! | `aws` | `kms.<r>.amazonaws.com` | `kms-fips.<r>.amazonaws.com` | `kms.<r>.api.aws` | `kms-fips.<r>.api.aws` |
//! | `aws-us-gov` | `kms.<r>.amazonaws.com` | `kms-fips.<r>.amazonaws.com` | `kms.<r>.api.aws` | `kms-fips.<r>.api.aws` |
//! | `aws-cn` | `kms.<r>.amazonaws.com.cn` | — | `kms.<r>.api.amazonwebservices.com.cn` | — |
//!
//! Other partitions (`aws-iso`, ...) need a configured endpoint.

use std::net::IpAddr;

use anykms_core::{Error, ErrorKind, Operation, Result};

use crate::BACKEND;

fn config_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

/// The derived endpoint of a partition and region.
pub(crate) fn derive(
    partition: &str,
    region: &str,
    fips: bool,
    dual_stack: bool,
) -> Result<String> {
    let host = match (partition, fips, dual_stack) {
        ("aws" | "aws-us-gov", false, false) => format!("kms.{region}.amazonaws.com"),
        ("aws" | "aws-us-gov", true, false) => format!("kms-fips.{region}.amazonaws.com"),
        ("aws" | "aws-us-gov", false, true) => format!("kms.{region}.api.aws"),
        ("aws" | "aws-us-gov", true, true) => format!("kms-fips.{region}.api.aws"),
        ("aws-cn", false, false) => format!("kms.{region}.amazonaws.com.cn"),
        ("aws-cn", false, true) => format!("kms.{region}.api.amazonwebservices.com.cn"),
        ("aws-cn", true, _) => {
            return Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Open,
                "the aws-cn partition has no FIPS KMS endpoints",
            ));
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Open,
                "no built-in KMS endpoint for this partition; configure one with \
                 AwsProviderBuilder::endpoint or AWS_ENDPOINT_URL_KMS",
            ));
        }
    };
    Ok(format!("https://{host}/"))
}

/// Validates a configured endpoint: `https://host[:port][/path]`, or `http://` to a literal
/// loopback IP when `allow_loopback_http`. No credentials, query or fragment.
pub(crate) fn validate_url(
    raw: &str,
    allow_loopback_http: bool,
    what: &str,
) -> Result<anykms_http::url::Url> {
    let url = anykms_http::url::Url::parse(raw)
        .map_err(|_| config_err(format!("{what} is not a valid URL")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(config_err(format!("{what} must not contain credentials")));
    }
    if url.query().is_some() || url.fragment().is_some() || url.host_str().is_none() {
        return Err(config_err(format!(
            "{what} must be scheme://host[:port][/path]"
        )));
    }
    match url.scheme() {
        "https" => {}
        "http" => {
            let loopback = match url.host() {
                Some(anykms_http::url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
                Some(anykms_http::url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
                _ => false,
            };
            if !loopback {
                return Err(config_err(format!(
                    "{what}: plain http:// is only allowed for literal loopback IPs (127.0.0.0/8, ::1); use https://"
                )));
            }
            if !allow_loopback_http {
                return Err(config_err(format!(
                    "{what}: plain http:// requires AwsProviderBuilder::allow_loopback_http()"
                )));
            }
        }
        _ => return Err(config_err(format!("{what} must use https://"))),
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives() {
        let d = |p, r, f, ds| derive(p, r, f, ds).unwrap();
        assert_eq!(
            d("aws", "eu-west-1", false, false),
            "https://kms.eu-west-1.amazonaws.com/"
        );
        assert_eq!(
            d("aws", "eu-west-1", true, false),
            "https://kms-fips.eu-west-1.amazonaws.com/"
        );
        assert_eq!(
            d("aws", "eu-west-1", false, true),
            "https://kms.eu-west-1.api.aws/"
        );
        assert_eq!(
            d("aws", "eu-west-1", true, true),
            "https://kms-fips.eu-west-1.api.aws/"
        );
        assert_eq!(
            d("aws-us-gov", "us-gov-west-1", true, false),
            "https://kms-fips.us-gov-west-1.amazonaws.com/"
        );
        assert_eq!(
            d("aws-cn", "cn-north-1", false, false),
            "https://kms.cn-north-1.amazonaws.com.cn/"
        );
        assert_eq!(
            d("aws-cn", "cn-north-1", false, true),
            "https://kms.cn-north-1.api.amazonwebservices.com.cn/"
        );
        assert!(derive("aws-cn", "cn-north-1", true, false).is_err());
        assert!(derive("aws-iso", "us-iso-east-1", false, false).is_err());
    }

    #[test]
    fn validates() {
        assert!(
            validate_url(
                "https://vpce-1.kms.eu-west-1.vpce.amazonaws.com",
                false,
                "e"
            )
            .is_ok()
        );
        assert!(validate_url("http://127.0.0.1:4566", true, "e").is_ok());
        assert!(validate_url("http://[::1]:4566", true, "e").is_ok());
        for (bad, loopback) in [
            ("http://127.0.0.1:4566", false),
            ("http://localhost:4566", true),
            ("http://10.0.0.1", true),
            ("https://u:p@kms.example", false),
            ("https://kms.example/?x=1", false),
            ("ftp://kms.example", false),
            ("kms.example", false),
        ] {
            assert!(validate_url(bad, loopback, "e").is_err(), "{bad}");
        }
    }
}
