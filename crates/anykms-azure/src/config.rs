//! Clouds, the host allowlist (the security boundary for bearer tokens), and options.

use std::net::IpAddr;

use anykms_core::{Error, ErrorKind, Operation, Result};

use crate::BACKEND;

pub(crate) fn config_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

/// An Azure cloud: its Key Vault and Managed HSM host suffixes (each with the token scope a host
/// under it gets) and its Entra ID authority host.
///
/// Germany (`vault.microsoftazure.de`) is retired and not listed. Private endpoints keep the
/// public host name, so they need no suffix of their own.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AzureCloud {
    /// Azure public cloud.
    Public,
    /// Azure operated by 21Vianet (China).
    China,
    /// Azure US Government.
    UsGovernment,
}

impl AzureCloud {
    /// Every cloud.
    pub const ALL: &'static [AzureCloud] = &[Self::Public, Self::China, Self::UsGovernment];

    /// The Key Vault host suffix (`vault.azure.net`, ...).
    pub fn vault_suffix(&self) -> &'static str {
        match self {
            Self::Public => "vault.azure.net",
            Self::China => "vault.azure.cn",
            Self::UsGovernment => "vault.usgovcloudapi.net",
        }
    }

    /// The Managed HSM host suffix (`managedhsm.azure.net`, ...). China and US Government are
    /// unverified (to verify with T13).
    pub fn managed_hsm_suffix(&self) -> &'static str {
        match self {
            Self::Public => "managedhsm.azure.net",
            Self::China => "managedhsm.azure.cn",
            Self::UsGovernment => "managedhsm.usgovcloudapi.net",
        }
    }

    /// The Entra ID authority host the built-in credentials use by default.
    pub fn authority_host(&self) -> &'static str {
        match self {
            Self::Public => "https://login.microsoftonline.com",
            // `login.chinacloudapi.cn` is a legacy alias.
            Self::China => "https://login.partner.microsoftonline.cn",
            Self::UsGovernment => "https://login.microsoftonline.us",
        }
    }

    /// The cloud whose authority host is `host` (as in `AZURE_AUTHORITY_HOST`; a trailing slash
    /// is ignored), if it is one of the known ones.
    pub fn from_authority_host(host: &str) -> Option<Self> {
        let h = host.trim_end_matches('/').to_ascii_lowercase();
        match h.as_str() {
            "https://login.microsoftonline.com" => Some(Self::Public),
            "https://login.partner.microsoftonline.cn" | "https://login.chinacloudapi.cn" => {
                Some(Self::China)
            }
            "https://login.microsoftonline.us" => Some(Self::UsGovernment),
            _ => None,
        }
    }
}

/// Whether a host is a key vault or a Managed HSM pool. It decides the token scope and which
/// handle kinds open: `aead` and `mac` need a Managed HSM (Premium-vault `oct-HSM` keys are a
/// preview and are not opened).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VaultKind {
    /// A key vault (`*.vault.azure.net`, standard or Premium).
    Vault,
    /// A Managed HSM pool (`*.managedhsm.azure.net`).
    ManagedHsm,
}

/// A non-Azure host allowed for tests only: Lowkey Vault, a mock server. Matched exactly
/// (`host:port`); its token scope is explicit. Every open of a key on a test host logs a warning
/// (`tracing` feature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestHost {
    pub(crate) host: String,
    pub(crate) scope: String,
    pub(crate) kind: VaultKind,
    pub(crate) plain_http: bool,
}

impl TestHost {
    /// A test host reached over HTTPS (`host:port`, e.g. `localhost:8443`), trusting the
    /// provider's [`ca_pem`](crate::AzureProviderBuilder::ca_pem) (or the system roots), with
    /// tokens for `scope` (e.g. `https://vault.azure.net/.default`).
    pub fn https(host_port: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            host: host_port.into().to_ascii_lowercase(),
            scope: scope.into(),
            kind: VaultKind::Vault,
            plain_http: false,
        }
    }

    /// A test host reached over plain HTTP. Only literal loopback IPs (`127.0.0.0/8`) with a
    /// port are accepted (checked at build): for mock servers.
    pub fn loopback_http(host_port: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            plain_http: true,
            ..Self::https(host_port, scope)
        }
    }

    /// Treats the host as a Managed HSM (default: a key vault).
    pub fn managed_hsm(mut self) -> Self {
        self.kind = VaultKind::ManagedHsm;
        self
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let parsed = crate::uri::parse_host(&self.host)
            .map_err(|_| config_err("test host must be host:port"))?;
        let Some((name, _port)) = parsed.rsplit_once(':') else {
            return Err(config_err("test host must be host:port"));
        };
        if self.plain_http {
            let loopback = name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
            if !loopback {
                return Err(config_err(
                    "plain-HTTP test hosts must be literal loopback IPs (127.0.0.0/8)",
                ));
            }
        }
        if !self.scope.starts_with("https://") || self.scope.bytes().any(|b| !b.is_ascii_graphic())
        {
            return Err(config_err("test host scope must be an https:// scope"));
        }
        Ok(())
    }
}

/// What a host resolved to under the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    /// `host[:port]`, lowercase.
    pub(crate) host: String,
    pub(crate) scope: String,
    pub(crate) kind: VaultKind,
    pub(crate) test: bool,
    pub(crate) plain_http: bool,
}

impl Target {
    /// `https://host/` or `http://host/` (test hosts only).
    pub(crate) fn base_url(&self) -> String {
        let scheme = if self.plain_http { "http" } else { "https" };
        format!("{scheme}://{}/", self.host)
    }
}

/// The host allowlist: a bearer token goes only to a host this policy resolves.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostPolicy {
    /// Clouds whose suffixes are allowed; empty means every cloud.
    pub(crate) clouds: Vec<AzureCloud>,
    /// Exact hosts that narrow the suffix rule (lowercase); `None`: any host under an allowed
    /// suffix.
    pub(crate) allowed_vaults: Option<Vec<String>>,
    pub(crate) test_hosts: Vec<TestHost>,
}

const MIN_VAULT_NAME: usize = 3;
const MAX_VAULT_NAME: usize = 24;

impl HostPolicy {
    /// Resolves `host` (already syntax-checked and lowercased), or `None` if no token may go
    /// there.
    pub(crate) fn resolve(&self, host: &str) -> Option<Target> {
        if let Some(t) = self.test_hosts.iter().find(|t| t.host == host) {
            return Some(Target {
                host: t.host.clone(),
                scope: t.scope.clone(),
                kind: t.kind,
                test: true,
                plain_http: t.plain_http,
            });
        }
        if host.contains(':') {
            return None;
        }
        if let Some(allowed) = &self.allowed_vaults
            && !allowed.iter().any(|a| a == host)
        {
            return None;
        }
        let (label, suffix) = host.split_once('.')?;
        let label_ok = (MIN_VAULT_NAME..=MAX_VAULT_NAME).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !label_ok {
            return None;
        }
        let clouds = if self.clouds.is_empty() {
            AzureCloud::ALL
        } else {
            &self.clouds[..]
        };
        clouds.iter().find_map(|c| {
            let kind = if suffix == c.vault_suffix() {
                VaultKind::Vault
            } else if suffix == c.managed_hsm_suffix() {
                VaultKind::ManagedHsm
            } else {
                return None;
            };
            Some(Target {
                host: host.to_owned(),
                scope: format!("https://{suffix}/.default"),
                kind,
                test: false,
                plain_http: false,
            })
        })
    }
}

/// The HTTP version spoken to vaults.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.1 only (default).
    #[default]
    Http1,
    /// Negotiate HTTP/2 through ALPN (needs the `http2` feature).
    Http2,
}

/// The proxy for vault requests. Environment proxy variables are ignored unless configured
/// explicitly. Managed-identity requests never use a proxy.
///
/// `Debug` prints the proxy URL's origin only (`scheme://host:port`): proxy URLs may carry
/// credentials.
#[non_exhaustive]
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Proxy {
    /// Connect directly (default).
    #[default]
    None,
    /// Send every vault request through this proxy URL.
    Url(String),
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::None => f.write_str("None"),
            Proxy::Url(u) => write!(f, "Url({})", anykms_http::redact::url_origin(u)),
        }
    }
}

/// The pinned Key Vault REST API version. Only one is supported in 0.x; preview versions are
/// never sent.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApiVersion {
    /// `2025-07-01` (latest GA; 7.6 apart from the version string).
    #[default]
    V2025_07_01,
}

impl ApiVersion {
    /// The `api-version` query value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V2025_07_01 => "2025-07-01",
        }
    }
}

/// Azure-specific open options, passed as an [`OpenOptions`](anykms_core::OpenOptions)
/// extension:
///
/// ```
/// use anykms_azure::AzureOptions;
/// let opts = anykms_core::OpenOptions::new().with_extension(AzureOptions::new().local_verify());
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AzureOptions {
    pub(crate) local_verify: bool,
}

impl AzureOptions {
    /// The defaults: server-side verification.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies signatures locally with the key version's public key (`LocalVerifier` from
    /// anykms-recipes) instead of the server's `verify`. Saves the vault's throttling budget.
    /// Each version's public key is trusted for the provider's
    /// [`key_cache_ttl`](crate::AzureProviderBuilder::key_cache_ttl) (±10%) from its fetch, so a
    /// disabled or deleted version keeps verifying for at most that long; when the re-read fails
    /// (vault unreachable, version disabled) verification fails with that error. Versions that
    /// came back unknown are remembered for the same time. Needs `keys/read` instead of
    /// `keys/verify/action`.
    pub fn local_verify(mut self) -> Self {
        self.local_verify = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes_and_scopes() {
        let p = HostPolicy::default();
        let t = p.resolve("contoso.vault.azure.net").unwrap();
        assert_eq!(t.scope, "https://vault.azure.net/.default");
        assert_eq!(t.kind, VaultKind::Vault);
        assert_eq!(t.base_url(), "https://contoso.vault.azure.net/");
        let t = p.resolve("hsm-01.managedhsm.azure.net").unwrap();
        assert_eq!(t.scope, "https://managedhsm.azure.net/.default");
        assert_eq!(t.kind, VaultKind::ManagedHsm);
        assert_eq!(
            p.resolve("kv1.vault.azure.cn").unwrap().scope,
            "https://vault.azure.cn/.default"
        );
        assert_eq!(
            p.resolve("kv1.vault.usgovcloudapi.net").unwrap().scope,
            "https://vault.usgovcloudapi.net/.default"
        );
        for no in [
            "contoso.vault.azure.net.evil.com",
            "evil.com",
            "a.b.vault.azure.net",
            "ab.vault.azure.net",
            "abcdefghijklmnopqrstuvwxy.vault.azure.net",
            "vault.azure.net",
            "contoso.vault.microsoftazure.de",
            "contoso.vault.azure.net:443",
            "localhost:8443",
            "contoso.privatelink.vaultcore.azure.net",
        ] {
            assert!(p.resolve(no).is_none(), "{no}");
        }
    }

    #[test]
    fn narrowing() {
        let p = HostPolicy {
            clouds: vec![AzureCloud::China],
            ..Default::default()
        };
        assert!(p.resolve("contoso.vault.azure.net").is_none());
        assert!(p.resolve("contoso.vault.azure.cn").is_some());
        let p = HostPolicy {
            allowed_vaults: Some(vec!["prod.vault.azure.net".into()]),
            test_hosts: vec![TestHost::https(
                "localhost:8443",
                "https://vault.azure.net/.default",
            )],
            ..Default::default()
        };
        assert!(p.resolve("prod.vault.azure.net").is_some());
        assert!(p.resolve("other.vault.azure.net").is_none());
        let t = p.resolve("localhost:8443").unwrap();
        assert!(t.test && !t.plain_http);
        assert_eq!(t.base_url(), "https://localhost:8443/");
        assert!(p.resolve("localhost:8444").is_none());
    }

    #[test]
    fn test_host_validation() {
        let s = "https://vault.azure.net/.default";
        assert!(TestHost::https("localhost:8443", s).validate().is_ok());
        assert!(
            TestHost::loopback_http("127.0.0.1:1234", s)
                .validate()
                .is_ok()
        );
        assert!(
            TestHost::loopback_http("localhost:1234", s)
                .validate()
                .is_err()
        );
        assert!(
            TestHost::loopback_http("10.0.0.1:1234", s)
                .validate()
                .is_err()
        );
        assert!(TestHost::https("localhost", s).validate().is_err());
        assert!(TestHost::https("localhost:1", "vault").validate().is_err());
    }

    #[test]
    fn clouds() {
        for c in AzureCloud::ALL {
            assert_eq!(
                AzureCloud::from_authority_host(c.authority_host()),
                Some(*c)
            );
        }
        assert_eq!(
            AzureCloud::from_authority_host("https://login.microsoftonline.com/"),
            Some(AzureCloud::Public)
        );
        assert_eq!(AzureCloud::from_authority_host("https://evil"), None);
    }
}
