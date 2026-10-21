//! AWS credentials: the [`CredentialSource`] trait, the built-in sources and the default chain.
//!
//! Sources fetch; the provider caches (single flight, refreshed 5 minutes before expiry, a failure
//! returned for 5 s, refetched once after the service rejects the credentials). Nothing is read or
//! fetched before the first operation.
//!
//! | Source | Reads |
//! |---|---|
//! | [`StaticCredentials`] | the values given |
//! | [`EnvCredentials`] | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
//! | [`ProfileCredentials`] | static keys in `~/.aws/credentials` and `~/.aws/config` |
//! | [`WebIdentityCredentials`] | STS `AssumeRoleWithWebIdentity` with a token file (EKS IRSA, GitHub OIDC, ...) |
//! | [`ContainerCredentials`] | the ECS / EKS Pod Identity endpoint |
//! | [`ImdsCredentials`] | the EC2 instance metadata service (IMDSv2 only) |
//! | [`DefaultChain`] | the first of environment, profile, web identity, container, IMDS that is configured |
//! | `SdkCredentials` (feature `sdk-credentials`) | an AWS SDK credentials provider (e.g. from `aws-config`) |
//!
//! Not built in: IAM Identity Center (SSO), role chaining, `credential_process`, MFA. Use the AWS
//! SDK's credentials through the `sdk-credentials` feature (`SdkCredentials`), or a custom
//! [`CredentialSource`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anykms_core::time::system_now;
use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};
use zeroize::Zeroizing;

use crate::BACKEND;

mod chain;
mod container;
mod env;
mod imds;
mod profile;
#[cfg(feature = "sdk-credentials")]
mod sdk;
mod sts;

pub use chain::DefaultChain;
pub use container::ContainerCredentials;
pub use env::{EnvCredentials, StaticCredentials};
pub use imds::ImdsCredentials;
pub use profile::ProfileCredentials;
#[cfg(feature = "sdk-credentials")]
pub use sdk::SdkCredentials;
pub use sts::WebIdentityCredentials;

pub(crate) use profile::parse_ini;
pub(crate) use sts::{parse_sts_success, sts_error};

/// A set of AWS credentials: an access key id, a secret access key and, for temporary
/// credentials, a session token and an expiry. `Debug` shows the access key id only.
#[derive(Clone)]
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    expires_at: Option<SystemTime>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credentials {
    /// Long-term or temporary credentials. Empty values are refused when the credentials are
    /// used (`Configuration`).
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            session_token: session_token.map(Zeroizing::new),
            expires_at: None,
        }
    }

    /// Sets when the credentials expire (`None`: never).
    pub fn with_expiry(mut self, expires_at: Option<SystemTime>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// The access key id (not secret; appears in CloudTrail and in `Debug`).
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The secret access key.
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    /// The session token of temporary credentials.
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref().map(String::as_str)
    }

    /// When the credentials expire.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// Whether `other` holds the same key pair and token (a refetch that returned the same
    /// credentials is no reason to retry a rejected request).
    pub(crate) fn same_as(&self, other: &Credentials) -> bool {
        self.access_key_id == other.access_key_id
            && *self.secret_access_key == *other.secret_access_key
            && self.session_token() == other.session_token()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let ok = |s: &str| !s.is_empty() && !s.bytes().any(|b| b.is_ascii_control() || b == b' ');
        if !ok(&self.access_key_id) || !ok(&self.secret_access_key) {
            return Err(config_err(
                "AWS credentials have an empty or malformed access key id or secret access key",
            ));
        }
        if self.session_token().is_some_and(|t| !ok(t)) {
            return Err(config_err("AWS session token is empty or malformed"));
        }
        Ok(())
    }
}

/// A source of AWS credentials. Implement it for credentials anykms does not fetch itself (SSO,
/// role chaining, a secrets manager).
///
/// [`credentials`](Self::credentials) fetches fresh credentials; the provider caches them, so it
/// is called on the first operation, before the credentials expire and once after AWS rejects
/// them. Errors should be `Configuration` (nothing configured, malformed configuration),
/// `Unavailable` (a credential endpoint is unreachable) or `Unauthenticated` (the identity was
/// refused).
pub trait CredentialSource: Send + Sync + fmt::Debug {
    /// A short, non-secret label for logs: the `credential` field of the `anykms.aws.token` span
    /// and of the credential events. The built-in sources' labels are stable snake_case
    /// (`environment`, `web_identity`, `imds`, `default_chain`, ...); return a snake_case label
    /// too, so one filter matches every source.
    fn kind(&self) -> &'static str;

    /// Fetches credentials. `cx` gives the built-in sources the provider's HTTP clients; custom
    /// sources may ignore it.
    fn credentials<'a>(&'a self, cx: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>>;
}

impl<T: CredentialSource + ?Sized> CredentialSource for Arc<T> {
    fn kind(&self) -> &'static str {
        (**self).kind()
    }

    fn credentials<'a>(&'a self, cx: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        (**self).credentials(cx)
    }
}

/// What a credential source may use: the provider's HTTP clients (TLS settings, proxy) and its
/// clock. Opaque.
pub struct SourceContext {
    pub(crate) http: Arc<crate::client::Http>,
}

impl fmt::Debug for SourceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceContext").finish_non_exhaustive()
    }
}

/// A snapshot of the environment variables the AWS sources read, taken when a source or the
/// provider is configured (so operations never read the process environment).
#[derive(Clone, Default)]
pub(crate) struct Vars(Arc<BTreeMap<&'static str, Zeroizing<String>>>);

impl fmt::Debug for Vars {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

/// Every variable the AWS backend reads.
pub(crate) const VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_STS_REGIONAL_ENDPOINTS",
    "AWS_ENDPOINT_URL_STS",
    "AWS_USE_FIPS_ENDPOINT",
    "AWS_USE_DUALSTACK_ENDPOINT",
    "AWS_ENDPOINT_URL_KMS",
    "AWS_ENDPOINT_URL",
    "AWS_CA_BUNDLE",
    "ANYKMS_AWS_ALLOWED_ACCOUNTS",
    "ANYKMS_AWS_ALLOWED_REGIONS",
    "ANYKMS_AWS_ALLOW_LOOPBACK_HTTP",
    "HOME",
    "USERPROFILE",
];

impl Vars {
    /// The process environment.
    pub(crate) fn from_env() -> Self {
        Self::from_fn(|k| std::env::var(k).ok())
    }

    /// Variables from `lookup` (tests, custom sources). Empty values count as unset, except
    /// for the allowlists, where an empty value is a configuration error at `build()` (P1-10).
    pub(crate) fn from_fn(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        let mut m = BTreeMap::new();
        for &k in VARS {
            let keep_empty = k.starts_with("ANYKMS_AWS_ALLOWED_");
            if let Some(v) = lookup(k).filter(|v| keep_empty || !v.is_empty()) {
                m.insert(k, Zeroizing::new(v));
            }
        }
        Self(Arc::new(m))
    }

    pub(crate) fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(|v| v.as_str())
    }

    /// A boolean variable: `true`/`false` (any case); anything else is `Configuration`.
    pub(crate) fn flag(&self, k: &'static str) -> Result<Option<bool>> {
        match self.get(k) {
            None => Ok(None),
            Some(v) if v.eq_ignore_ascii_case("true") => Ok(Some(true)),
            Some(v) if v.eq_ignore_ascii_case("false") => Ok(Some(false)),
            Some(_) => Err(config_err(format!("{k} must be true or false"))),
        }
    }

    /// The home directory for `~/.aws`.
    pub(crate) fn home(&self) -> Option<std::path::PathBuf> {
        self.get("HOME")
            .or_else(|| self.get("USERPROFILE"))
            .map(std::path::PathBuf::from)
    }
}

pub(crate) fn config_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

/// P1-2: a failure to read a **token file** (web identity, container authorization token):
/// `NotFound` is `Unavailable` (a rotation race), anything else `Configuration`
/// ([`anykms_http::zbuf::token_file_error_kind`]). The message names the file (P1-8).
pub(crate) fn token_file_err(what: &str, path: &std::path::Path, e: &std::io::Error) -> Error {
    Error::new(
        anykms_http::zbuf::token_file_error_kind(e),
        BACKEND,
        Operation::Configure,
        format!("cannot read {what} {}: {}", path.display(), e.kind()),
    )
}

pub(crate) fn unavailable(m: &'static str) -> Error {
    Error::new(ErrorKind::Unavailable, BACKEND, Operation::Configure, m)
}

pub(crate) fn unauthenticated(m: &'static str) -> Error {
    Error::new(ErrorKind::Unauthenticated, BACKEND, Operation::Configure, m)
}

/// The JSON credential shape of IMDS and the container endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct JsonCredentials {
    #[serde(default)]
    pub(crate) code: Option<String>,
    #[serde(default)]
    pub(crate) access_key_id: Option<String>,
    #[serde(default)]
    pub(crate) secret_access_key: Option<String>,
    #[serde(default)]
    pub(crate) token: Option<String>,
    #[serde(default)]
    pub(crate) expiration: Option<String>,
}

impl JsonCredentials {
    /// Parses and converts; `what` names the source in errors. Expired credentials are refused.
    pub(crate) fn parse(body: &[u8], what: &'static str) -> Result<Credentials> {
        let bad = || {
            Error::new(
                ErrorKind::Unavailable,
                BACKEND,
                Operation::Configure,
                format!("{what} returned malformed credentials"),
            )
        };
        let j: JsonCredentials = serde_json::from_slice(body).map_err(|_| bad())?;
        // Secrets move into zeroizing strings at once (moves do not copy the bytes).
        let secret = j.secret_access_key.map(Zeroizing::new);
        let token = j.token.map(Zeroizing::new);
        if j.code.as_deref().is_some_and(|c| c != "Success") {
            return Err(bad());
        }
        let (Some(id), Some(secret)) = (j.access_key_id, secret) else {
            return Err(bad());
        };
        let expires_at = match j.expiration.as_deref() {
            None => None,
            Some(e) => Some(crate::time::parse_rfc3339(e).ok_or_else(bad)?),
        };
        let c = Credentials {
            access_key_id: id,
            secret_access_key: secret,
            session_token: token,
            expires_at,
        };
        c.validate().map_err(|_| bad())?;
        if expires_at.is_some_and(|t| t <= system_now()) {
            return Err(Error::new(
                ErrorKind::Unavailable,
                BACKEND,
                Operation::Configure,
                format!("{what} returned expired credentials"),
            ));
        }
        Ok(c)
    }
}

/// The largest credential response or file read.
pub(crate) const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Fetch timeouts of the link-local endpoints (IMDS, container).
pub(crate) const LOCAL_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let c = Credentials::new("AKIDX", "SECRETX", Some("TOKENX".into()));
        let d = format!("{c:?}");
        assert!(
            d.contains("AKIDX") && !d.contains("SECRETX") && !d.contains("TOKENX"),
            "{d}"
        );
        assert!(c.validate().is_ok());
        assert!(Credentials::new("", "s", None).validate().is_err());
        assert!(Credentials::new("a", "s s", None).validate().is_err());
        assert!(
            Credentials::new("a", "s", Some(String::new()))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn json_credentials() {
        let c = JsonCredentials::parse(
            br#"{"Code":"Success","AccessKeyId":"A","SecretAccessKey":"S","Token":"T","Expiration":"2999-01-01T00:00:00Z"}"#,
            "imds",
        )
        .unwrap();
        assert_eq!(
            (c.access_key_id(), c.secret_access_key(), c.session_token()),
            ("A", "S", Some("T"))
        );
        assert!(c.expires_at().is_some());
        let c =
            JsonCredentials::parse(br#"{"AccessKeyId":"A","SecretAccessKey":"S"}"#, "p").unwrap();
        assert_eq!((c.session_token(), c.expires_at()), (None, None));
        for bad in [
            &br#"{"Code":"Failure","AccessKeyId":"A","SecretAccessKey":"S"}"#[..],
            br#"{"AccessKeyId":"A"}"#,
            br#"{"AccessKeyId":"A","SecretAccessKey":"S","Expiration":"tomorrow"}"#,
            br#"{"AccessKeyId":"A","SecretAccessKey":"S","Expiration":"2000-01-01T00:00:00Z"}"#,
            b"not json",
        ] {
            let e = JsonCredentials::parse(bad, "imds").unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Unavailable);
        }
    }

    #[test]
    fn vars() {
        let v = Vars::from_fn(|k| match k {
            "AWS_EC2_METADATA_DISABLED" => Some("TRUE".into()),
            "AWS_USE_FIPS_ENDPOINT" => Some("maybe".into()),
            "AWS_PROFILE" => Some(String::new()),
            "UNRELATED" => Some("x".into()),
            _ => None,
        });
        assert_eq!(v.flag("AWS_EC2_METADATA_DISABLED").unwrap(), Some(true));
        assert!(v.flag("AWS_USE_FIPS_ENDPOINT").is_err());
        assert_eq!(v.get("AWS_PROFILE"), None);
        assert_eq!(v.get("UNRELATED"), None);
    }
}
