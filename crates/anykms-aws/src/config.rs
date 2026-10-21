//! Provider configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anykms_core::Result;
use rustls::crypto::CryptoProvider;
use zeroize::Zeroizing;

use crate::client::HttpSettings;
use crate::credentials::{CredentialSource, DefaultChain, Vars, config_err};

/// HTTP version for KMS requests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpVersion {
    /// HTTP/1.1 (default).
    #[default]
    Http1,
    /// HTTP/2 (negotiated with TLS ALPN; needs the `http2` feature).
    Http2,
}

/// An outbound proxy for KMS and STS requests (never for the link-local credential endpoints).
#[derive(Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Proxy {
    /// Connect directly; proxy environment variables are ignored.
    #[default]
    None,
    /// Use this proxy URL for every request.
    Url(String),
}

/// `scheme://host:port` of a URL that may carry credentials, a path or a query (P1-1).
pub(crate) fn redacted_url(u: &str) -> String {
    anykms_http::redact::url_origin(u)
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proxy::None => f.write_str("None"),
            // Proxy URLs may carry credentials.
            Proxy::Url(u) => write!(f, "Url({})", redacted_url(u)),
        }
    }
}

/// Builds an [`AwsProvider`](crate::AwsProvider). Building does no network I/O: it builds the
/// KMS HTTP client (reading the trust store), and credentials are resolved on the first
/// operation.
#[derive(Clone)]
pub struct AwsProviderBuilder {
    pub(crate) credentials: Option<Arc<dyn CredentialSource>>,
    pub(crate) allowed_accounts: Option<BTreeSet<String>>,
    pub(crate) allowed_regions: Option<BTreeSet<String>>,
    pub(crate) endpoints: BTreeMap<String, String>,
    pub(crate) endpoint_url: Option<String>,
    pub(crate) fips: bool,
    pub(crate) dual_stack: bool,
    pub(crate) http: HttpSettings,
    pub(crate) http_version: HttpVersion,
    pub(crate) proxy: Proxy,
    pub(crate) allow_loopback_http: bool,
    pub(crate) vars: Option<Vars>,
    pub(crate) request_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl fmt::Debug for AwsProviderBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsProviderBuilder")
            .field(
                "credentials",
                &self
                    .credentials
                    .as_ref()
                    .map(super::credentials::CredentialSource::kind),
            )
            .field("allowed_accounts", &self.allowed_accounts)
            .field("allowed_regions", &self.allowed_regions)
            // Endpoints are only validated by `build`: never print userinfo or queries.
            .field(
                "endpoints",
                &self
                    .endpoints
                    .iter()
                    .map(|(r, u)| (r, redacted_url(u)))
                    .collect::<BTreeMap<_, _>>(),
            )
            .field(
                "endpoint_url",
                &self.endpoint_url.as_deref().map(redacted_url),
            )
            .field("fips", &self.fips)
            .field("dual_stack", &self.dual_stack)
            .field("http_version", &self.http_version)
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl Default for AwsProviderBuilder {
    fn default() -> Self {
        Self {
            credentials: None,
            allowed_accounts: None,
            allowed_regions: None,
            endpoints: BTreeMap::new(),
            endpoint_url: None,
            fips: false,
            dual_stack: false,
            http: HttpSettings::default(),
            http_version: HttpVersion::Http1,
            proxy: Proxy::None,
            allow_loopback_http: false,
            vars: None,
            request_counter: None,
        }
    }
}

impl AwsProviderBuilder {
    /// The defaults: the [`DefaultChain`] credentials, derived endpoints, no allowlists.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configuration from environment variables (a snapshot taken now):
    ///
    /// | Variable | Effect |
    /// |---|---|
    /// | credentials (`AWS_ACCESS_KEY_ID`, `AWS_PROFILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_CONTAINER_CREDENTIALS_*`, `AWS_EC2_METADATA_*`, ...) | the [`DefaultChain`] |
    /// | `AWS_USE_FIPS_ENDPOINT`, `AWS_USE_DUALSTACK_ENDPOINT` | `true`/`false`: [`fips`](Self::fips), [`dual_stack`](Self::dual_stack) |
    /// | `AWS_ENDPOINT_URL_KMS`, else `AWS_ENDPOINT_URL` | [`endpoint_url`](Self::endpoint_url) |
    /// | `AWS_CA_BUNDLE` | a PEM file that replaces the system roots ([`ca_pem`](Self::ca_pem)) |
    /// | `ANYKMS_AWS_ALLOWED_ACCOUNTS`, `ANYKMS_AWS_ALLOWED_REGIONS` | comma-separated allowlists (an empty list is `Configuration` at `build()`) |
    /// | `ANYKMS_AWS_ALLOW_LOOPBACK_HTTP` | `1`/`true`: [`allow_loopback_http`](Self::allow_loopback_http) (emulators) |
    ///
    /// No variable is required (the region comes from each key ARN). A malformed value is
    /// `Configuration`; `AWS_CA_BUNDLE` is read here.
    pub fn from_env() -> Result<Self> {
        Self::from_vars(Vars::from_env())
    }

    /// Like [`from_env`](Self::from_env), reading variables from `lookup` instead of the process
    /// environment. The [`DefaultChain`] takes its variables from the same lookup, so nothing
    /// falls back to the process environment. Like `from_env`, the variables are read once, here
    /// (an empty value counts as unset, except for the allowlists).
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::from_vars(Vars::from_fn(lookup))
    }

    pub(crate) fn from_vars(vars: Vars) -> Result<Self> {
        let mut b = Self::new();
        b.fips = vars.flag("AWS_USE_FIPS_ENDPOINT")?.unwrap_or(false);
        b.dual_stack = vars.flag("AWS_USE_DUALSTACK_ENDPOINT")?.unwrap_or(false);
        b.endpoint_url = vars
            .get("AWS_ENDPOINT_URL_KMS")
            .or_else(|| vars.get("AWS_ENDPOINT_URL"))
            .map(str::to_owned);
        if let Some(path) = vars.get("AWS_CA_BUNDLE") {
            let pem =
                anykms_http::zbuf::read_file(std::path::Path::new(path), 4 << 20).map_err(|e| {
                    config_err(format!("cannot read AWS_CA_BUNDLE {path}: {}", e.kind()))
                })?;
            b.http.ca_pem = Some(Arc::new(pem));
        }
        let list = |k: &str| {
            vars.get(k).map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            })
        };
        b.allowed_accounts = list("ANYKMS_AWS_ALLOWED_ACCOUNTS");
        b.allowed_regions = list("ANYKMS_AWS_ALLOWED_REGIONS");
        b.allow_loopback_http = match vars.get("ANYKMS_AWS_ALLOW_LOOPBACK_HTTP") {
            None | Some("0") => false,
            Some(v) if v.eq_ignore_ascii_case("false") => false,
            Some("1") => true,
            Some(v) if v.eq_ignore_ascii_case("true") => true,
            Some(_) => {
                return Err(config_err(
                    "ANYKMS_AWS_ALLOW_LOOPBACK_HTTP must be 1/true or 0/false",
                ));
            }
        };
        b.credentials = Some(Arc::new(DefaultChain::from_vars(vars.clone())));
        b.vars = Some(vars);
        Ok(b)
    }

    /// The credential source (default: the [`DefaultChain`], from the environment at build time).
    pub fn credentials(mut self, source: impl CredentialSource + 'static) -> Self {
        self.credentials = Some(Arc::new(source));
        self
    }

    /// Like [`credentials`](Self::credentials), with a shared source.
    pub fn credentials_arc(mut self, source: Arc<dyn CredentialSource>) -> Self {
        self.credentials = Some(source);
        self
    }

    /// Only keys of these accounts open (`Configuration` otherwise). Without an allowlist any
    /// account is accepted: a key URI from untrusted input could then point at someone else's
    /// key, which would receive plaintext on `encrypt`. An empty list is `Configuration` at
    /// `build()` (omit it to allow every account).
    pub fn allowed_accounts<I, S>(mut self, accounts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_accounts = Some(accounts.into_iter().map(Into::into).collect());
        self
    }

    /// Only keys in these regions open (`Configuration` otherwise). Entries must be AWS region
    /// names (`eu-west-1`). Set it, with [`allowed_accounts`](Self::allowed_accounts), whenever
    /// key URIs can come from untrusted input: the region chooses the derived endpoint, and the
    /// URI grammar only checks the region's shape.
    pub fn allowed_regions<I, S>(mut self, regions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_regions = Some(regions.into_iter().map(Into::into).collect());
        self
    }

    /// The endpoint for keys in `region` (e.g. a VPC endpoint), over the derived and global ones.
    pub fn endpoint(mut self, region: impl Into<String>, url: impl Into<String>) -> Self {
        self.endpoints.insert(region.into(), url.into());
        self
    }

    /// One endpoint for every region (an emulator, a proxy). Requests are still signed for the
    /// key ARN's region.
    pub fn endpoint_url(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    /// Derives FIPS endpoints (`kms-fips.<region>...`).
    pub fn fips(mut self, fips: bool) -> Self {
        self.fips = fips;
        self
    }

    /// Derives dual-stack (IPv4 and IPv6) endpoints (`kms.<region>.api.aws`).
    pub fn dual_stack(mut self, dual_stack: bool) -> Self {
        self.dual_stack = dual_stack;
        self
    }

    /// Allows `http://` endpoints on literal loopback IPs (emulators, tests).
    pub fn allow_loopback_http(mut self) -> Self {
        self.allow_loopback_http = true;
        self
    }

    /// Connect timeout (default 2 s).
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.http.connect_timeout = d;
        self
    }

    /// Per-request timeout (default 10 s). The overall deadline belongs to `Retry`.
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.http.request_timeout = d;
        self
    }

    /// How long idle pooled connections are kept (default 50 s).
    pub fn pool_idle_timeout(mut self, d: Duration) -> Self {
        self.http.pool_idle_timeout = d;
        self
    }

    /// TCP keepalive interval (default 30 s).
    pub fn tcp_keepalive(mut self, d: Duration) -> Self {
        self.http.tcp_keepalive = d;
        self
    }

    /// HTTP version (default HTTP/1.1).
    pub fn http_version(mut self, v: HttpVersion) -> Self {
        self.http_version = v;
        self
    }

    /// An outbound proxy for KMS and STS (default: none, proxy variables ignored).
    pub fn proxy(mut self, p: Proxy) -> Self {
        self.proxy = p;
        self
    }

    /// PEM CA certificates that replace the system roots.
    pub fn ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.http.ca_pem = Some(Arc::new(Zeroizing::new(pem.into())));
        self
    }

    /// The rustls crypto provider (default: the process default, else aws-lc-rs or ring by
    /// feature).
    pub fn crypto_provider(mut self, p: Arc<CryptoProvider>) -> Self {
        self.http.crypto_provider = Some(p);
        self
    }

    /// The largest response accepted (default 256 KiB; at least 64 KiB, `Configuration` at
    /// `build()` otherwise).
    pub fn max_response_bytes(mut self, n: usize) -> Self {
        self.http.max_response_bytes = n;
        self
    }

    /// Counts every KMS request in `counter` (conformance fixtures). Not part of the public API.
    #[doc(hidden)]
    pub fn __count_requests(mut self, counter: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.request_counter = Some(counter);
        self
    }

    /// Validates the configuration (no I/O).
    pub(crate) fn validate(&mut self) -> Result<()> {
        // P1-10: nobody means "refuse every key".
        if self
            .allowed_accounts
            .as_ref()
            .is_some_and(BTreeSet::is_empty)
        {
            return Err(config_err(
                "allowed_accounts is empty: omit it to allow every account",
            ));
        }
        if self
            .allowed_regions
            .as_ref()
            .is_some_and(BTreeSet::is_empty)
        {
            return Err(config_err(
                "allowed_regions is empty: omit it to allow every region",
            ));
        }
        for a in self.allowed_accounts.iter().flatten() {
            if a.len() != 12 || !a.bytes().all(|b| b.is_ascii_digit()) {
                return Err(config_err("allowed accounts must be 12-digit account ids"));
            }
        }
        for r in self.allowed_regions.iter().flatten() {
            if !crate::uri::region_ok(r) {
                return Err(config_err(
                    "malformed allowed region (expected an AWS region such as eu-west-1)",
                ));
            }
        }
        for (r, u) in &self.endpoints {
            if !crate::uri::region_ok(r) {
                return Err(config_err(
                    "malformed endpoint region (expected an AWS region such as eu-west-1)",
                ));
            }
            crate::endpoint::validate_url(u, self.allow_loopback_http, "the KMS endpoint")?;
        }
        if let Some(u) = &self.endpoint_url {
            crate::endpoint::validate_url(u, self.allow_loopback_http, "the KMS endpoint")?;
        }
        if self.http.connect_timeout.is_zero() || self.http.request_timeout.is_zero() {
            return Err(config_err("timeouts must be greater than zero"));
        }
        if self.http.max_response_bytes < anykms_http::client::MIN_RESPONSE_BYTES {
            return Err(config_err(
                "max_response_bytes must be at least 64 KiB (anykms_http::client::MIN_RESPONSE_BYTES)",
            ));
        }
        if self.http_version == HttpVersion::Http2 && !cfg!(feature = "http2") {
            return Err(config_err("HttpVersion::Http2 needs the `http2` feature"));
        }
        self.http.http2 = self.http_version == HttpVersion::Http2;
        self.http.proxy = match &self.proxy {
            Proxy::None => None,
            Proxy::Url(u) => {
                reqwest::Url::parse(u).map_err(|_| config_err("invalid proxy URL"))?;
                Some(u.clone())
            }
        };
        self.http.loopback_http = self.allow_loopback_http;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_reads_variables() {
        let b = AwsProviderBuilder::from_env_with(|k| match k {
            "AWS_USE_FIPS_ENDPOINT" => Some("true".into()),
            "AWS_ENDPOINT_URL" => Some("https://a.example".into()),
            "AWS_ENDPOINT_URL_KMS" => Some("https://kms.example".into()),
            "ANYKMS_AWS_ALLOWED_ACCOUNTS" => Some("111122223333, 444455556666".into()),
            "ANYKMS_AWS_ALLOW_LOOPBACK_HTTP" => Some("1".into()),
            _ => None,
        })
        .unwrap();
        assert!(b.fips && !b.dual_stack && b.allow_loopback_http);
        assert_eq!(b.endpoint_url.as_deref(), Some("https://kms.example"));
        assert_eq!(b.allowed_accounts.as_ref().unwrap().len(), 2);
        for (k, v) in [
            ("AWS_USE_FIPS_ENDPOINT", "maybe"),
            ("AWS_USE_DUALSTACK_ENDPOINT", "1"),
            ("ANYKMS_AWS_ALLOW_LOOPBACK_HTTP", "yes"),
            ("AWS_CA_BUNDLE", "/nonexistent/anykms-ca.pem"),
        ] {
            let e = AwsProviderBuilder::from_env_with(move |x| (x == k).then(|| v.to_owned()))
                .unwrap_err();
            assert_eq!(e.kind(), anykms_core::ErrorKind::Configuration, "{k}");
        }
    }

    #[test]
    fn proxy_debug_hides_credentials() {
        let p = Proxy::Url("http://user:secret@proxy.example:3128".into());
        assert!(!format!("{p:?}").contains("secret"));
    }

    #[test]
    fn builder_debug_hides_endpoint_credentials() {
        let b = AwsProviderBuilder::new()
            .endpoint("eu-west-1", "https://u:secret1@vpce.example/?q=secret2")
            .endpoint_url("https://u:secret3@kms.example/")
            .proxy(Proxy::Url("http://u:secret4@proxy.example:3128".into()));
        let d = format!("{b:?}");
        assert!(!d.contains("secret"), "{d}");
        assert!(
            d.contains("vpce.example") && d.contains("kms.example"),
            "{d}"
        );
    }

    /// P1-10: an empty allowlist (configured or from the environment) fails at build.
    #[test]
    fn empty_allowlists_are_configuration_errors() {
        let none: [&str; 0] = [];
        for (b, what) in [
            (AwsProviderBuilder::new().allowed_accounts(none), "accounts"),
            (AwsProviderBuilder::new().allowed_regions(none), "regions"),
            (
                AwsProviderBuilder::from_env_with(|k| {
                    (k == "ANYKMS_AWS_ALLOWED_ACCOUNTS").then(String::new)
                })
                .unwrap(),
                "accounts",
            ),
            (
                AwsProviderBuilder::from_env_with(|k| {
                    (k == "ANYKMS_AWS_ALLOWED_REGIONS").then(|| " , ".to_owned())
                })
                .unwrap(),
                "regions",
            ),
        ] {
            let e = b.build().unwrap_err();
            assert_eq!(e.kind(), anykms_core::ErrorKind::Configuration);
            assert!(
                e.to_string()
                    .contains(&format!("allowed_{what} is empty: omit it to allow every")),
                "{e}"
            );
        }
    }

    /// P1-11: limits below 64 KiB break describe and credential responses.
    #[test]
    fn max_response_bytes_has_a_floor() {
        let e = AwsProviderBuilder::new()
            .max_response_bytes(anykms_http::client::MIN_RESPONSE_BYTES - 1)
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), anykms_core::ErrorKind::Configuration);
        AwsProviderBuilder::new()
            .max_response_bytes(anykms_http::client::MIN_RESPONSE_BYTES)
            .build()
            .unwrap();
    }

    #[test]
    fn region_allowlists_and_endpoints_need_region_shapes() {
        for b in [
            AwsProviderBuilder::new().allowed_regions(["s3"]),
            AwsProviderBuilder::new().allowed_regions(["eu-west-1", ""]),
            AwsProviderBuilder::new().endpoint("kms", "https://kms.example"),
        ] {
            let e = b.build().unwrap_err();
            assert_eq!(e.kind(), anykms_core::ErrorKind::Configuration);
        }
        AwsProviderBuilder::new()
            .allowed_regions(["eu-west-1", "us-gov-west-1"])
            .endpoint("eu-west-1", "https://kms.example")
            .build()
            .unwrap();
    }
}
