//! Managed identity: the Azure Instance Metadata Service (VMs, VM scale sets, AKS nodes) and the
//! App Service / Functions identity endpoint.

use std::fmt;
use std::time::Duration;

use anykms_core::{BoxFuture, Result};
use zeroize::Zeroizing;

use crate::credential::{
    AccessToken, AzureCredential, TransportSlot, cred_config_err, resource_of, send_token_request,
};

/// The IMDS token endpoint.
pub const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
const IMDS_API_VERSION: &str = "2018-02-01";
const APP_SERVICE_API_VERSION: &str = "2019-08-01";

/// Which user-assigned identity to use (none: the system-assigned one).
#[derive(Clone, Debug, PartialEq, Eq)]
enum UserAssigned {
    Client(String),
    Object(String),
    Resource(String),
}

#[derive(Clone)]
enum Source {
    Imds {
        endpoint: String,
    },
    AppService {
        endpoint: String,
        header: Zeroizing<String>,
    },
}

/// A managed identity, through IMDS (`169.254.169.254`) or the App Service / Functions identity
/// endpoint (`IDENTITY_ENDPOINT` with `X-IDENTITY-HEADER`).
///
/// Requests go through the provider's transport (the built-in one never proxies link-local hosts)
/// with a per-request timeout of [`IMDS_TIMEOUT`], so that a host off Azure fails as
/// `Unavailable` rather than stalling. On `wasm32-unknown-unknown` (a Cloudflare Worker) IMDS is
/// unreachable and a token request fails with a `Configuration` error before sending anything.
/// Azure Arc and Cloud Shell are not supported (implement [`AzureCredential`] for them).
#[derive(Clone)]
pub struct ManagedIdentity {
    id: Option<UserAssigned>,
    source: Source,
    http: TransportSlot,
}

impl fmt::Debug for ManagedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            Source::Imds { .. } => "imds",
            Source::AppService { .. } => "app-service",
        };
        f.debug_struct("ManagedIdentity")
            .field("source", &source)
            .field("user_assigned", &self.id)
            .finish()
    }
}

/// The per-request timeout of every managed-identity token request (a
/// [`RequestTimeout`](anykms_http::RequestTimeout)).
pub const IMDS_TIMEOUT: Duration = Duration::from_secs(10);

fn id_ok(s: &str) -> Result<()> {
    if (1..=512).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic()) {
        Ok(())
    } else {
        Err(cred_config_err("invalid managed identity id"))
    }
}

fn endpoint_ok(url: &str, imds: bool) -> Result<String> {
    let u = anykms_http::url::Url::parse(url)
        .map_err(|_| cred_config_err("invalid identity endpoint URL"))?;
    if !matches!(u.scheme(), "http" | "https")
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(cred_config_err(
            "the identity endpoint must be an http(s) URL without query or credentials",
        ));
    }
    if imds {
        // Only the real IMDS address or a loopback mock.
        let ok = match u.host() {
            Some(anykms_http::url::Host::Ipv4(ip)) => {
                ip.is_loopback() || ip.octets() == [169, 254, 169, 254]
            }
            _ => false,
        };
        if !ok {
            return Err(cred_config_err(
                "the IMDS endpoint must be 169.254.169.254 or a loopback IP",
            ));
        }
    } else if u.scheme() == "http" && !local_host(u.host().as_ref()) {
        // The header and the token cross the network in clear: only to hosts that cannot be off
        // the machine's own network (Container Apps and Functions use `localhost`, App Service
        // on Linux a private address).
        return Err(cred_config_err(
            "a plain-http identity endpoint must be localhost, a loopback, link-local or \
             private address (use https otherwise)",
        ));
    }
    Ok(u.to_string())
}

/// `localhost` (exactly), or a loopback, link-local or private (RFC 1918, IPv6 unique local)
/// address literal.
fn local_host(host: Option<&anykms_http::url::Host<&str>>) -> bool {
    use anykms_http::url::Host;
    match host {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback() || ip.is_link_local() || ip.is_private(),
        Some(Host::Ipv6(ip)) => {
            let seg0 = ip.segments()[0];
            ip.is_loopback()
                || (seg0 & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (seg0 & 0xfe00) == 0xfc00 // unique local fc00::/7
        }
        None => false,
    }
}

impl ManagedIdentity {
    fn imds(id: Option<UserAssigned>) -> Self {
        Self {
            id,
            source: Source::Imds {
                endpoint: IMDS_ENDPOINT.to_owned(),
            },
            http: TransportSlot::new(),
        }
    }

    /// The system-assigned identity, through IMDS.
    pub fn system() -> Self {
        Self::imds(None)
    }

    /// A user-assigned identity by client id, through IMDS.
    pub fn client_id(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        id_ok(&id)?;
        Ok(Self::imds(Some(UserAssigned::Client(id))))
    }

    /// A user-assigned identity by object (principal) id, through IMDS.
    pub fn object_id(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        id_ok(&id)?;
        Ok(Self::imds(Some(UserAssigned::Object(id))))
    }

    /// A user-assigned identity by ARM resource id, through IMDS.
    pub fn resource_id(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        id_ok(&id)?;
        Ok(Self::imds(Some(UserAssigned::Resource(id))))
    }

    /// From the environment: `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` (App Service, Functions)
    /// if set, else IMDS; `AZURE_CLIENT_ID` selects a user-assigned identity by client id.
    pub fn from_env() -> Result<Self> {
        Self::from_get(&super::process_env)
    }

    pub(crate) fn from_get(get: super::EnvGet<'_>) -> Result<Self> {
        let env = |n: &str| get(n).filter(|v| !v.is_empty());
        let mut me = match env("AZURE_CLIENT_ID") {
            Some(id) => Self::client_id(id)?,
            None => Self::system(),
        };
        if let Some(endpoint) = env("IDENTITY_ENDPOINT") {
            let header = Zeroizing::new(env("IDENTITY_HEADER").ok_or_else(|| {
                cred_config_err("IDENTITY_ENDPOINT is set but IDENTITY_HEADER is not")
            })?);
            me = me.app_service(&endpoint, header.as_str())?;
        }
        Ok(me)
    }

    /// Uses the App Service / Functions identity endpoint (`IDENTITY_ENDPOINT`) with its secret
    /// header value (`IDENTITY_HEADER`). The endpoint must be https, or plain http on `localhost`
    /// or a loopback, link-local or private address literal (`Configuration` otherwise).
    pub fn app_service(mut self, endpoint: &str, identity_header: &str) -> Result<Self> {
        let endpoint = endpoint_ok(endpoint, false)?;
        if identity_header.is_empty() || !identity_header.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(cred_config_err("invalid IDENTITY_HEADER"));
        }
        self.source = Source::AppService {
            endpoint,
            header: Zeroizing::new(identity_header.to_owned()),
        };
        Ok(self)
    }

    /// Overrides the IMDS endpoint (tests): `169.254.169.254` or a loopback IP only.
    pub fn imds_endpoint(mut self, endpoint: &str) -> Result<Self> {
        self.source = Source::Imds {
            endpoint: endpoint_ok(endpoint, true)?,
        };
        Ok(self)
    }

    fn request(&self, scope: &str) -> Result<anykms_http::http::request::Builder> {
        // IMDS is link-local: nothing on a JS host (a Cloudflare Worker) can reach it, and the
        // host's `fetch` need not honour `IMDS_TIMEOUT`. Fail before anything is sent. (The App
        // Service endpoint is a configured URL; it is left to the transport.)
        if cfg!(all(target_arch = "wasm32", target_os = "unknown"))
            && matches!(self.source, Source::Imds { .. })
        {
            return Err(cred_config_err(
                "Azure IMDS is not reachable from this target (wasm32-unknown-unknown): \
                 configure a credential explicitly",
            ));
        }
        let resource = resource_of(scope);
        let (id_param, id_value) = match &self.id {
            None => (None, None),
            Some(UserAssigned::Client(v)) => (Some("client_id"), Some(v.as_str())),
            Some(UserAssigned::Object(v)) => (Some("object_id"), Some(v.as_str())),
            Some(UserAssigned::Resource(v)) => (
                Some(match self.source {
                    Source::Imds { .. } => "msi_res_id",
                    Source::AppService { .. } => "mi_res_id",
                }),
                Some(v.as_str()),
            ),
        };
        let (endpoint, api) = match &self.source {
            Source::Imds { endpoint } => (endpoint.as_str(), IMDS_API_VERSION),
            Source::AppService { endpoint, .. } => (endpoint.as_str(), APP_SERVICE_API_VERSION),
        };
        let mut url = anykms_http::url::Url::parse(endpoint)
            .map_err(|_| cred_config_err("invalid identity endpoint URL"))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("api-version", api);
            q.append_pair("resource", resource);
            if let (Some(p), Some(v)) = (id_param, id_value) {
                q.append_pair(p, v);
            }
        }
        let req = anykms_http::client::request(anykms_http::http::Method::GET, &url)
            .header(anykms_http::http::header::ACCEPT, "application/json")
            .extension(anykms_http::RequestTimeout(IMDS_TIMEOUT));
        Ok(match &self.source {
            Source::Imds { .. } => req.header("Metadata", "true"),
            Source::AppService { header, .. } => {
                let mut v = anykms_http::http::HeaderValue::from_str(header)
                    .map_err(|_| cred_config_err("invalid IDENTITY_HEADER"))?;
                v.set_sensitive(true);
                req.header("X-IDENTITY-HEADER", v)
            }
        })
    }
}

impl AzureCredential for ManagedIdentity {
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, Result<AccessToken>> {
        Box::pin(async move {
            let http = self.http.get()?;
            let req = self.request(scope)?.body(anykms_http::client::empty());
            send_token_request(&*http, req, "managed-identity").await
        })
    }

    fn kind(&self) -> &'static str {
        "managed_identity"
    }

    fn bind_transport(&self, transport: std::sync::Arc<dyn anykms_http::HttpTransport>) {
        self.http.bind(transport);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anykms_core::ErrorKind;

    /// Review L1: plain HTTP to the App Service / Functions identity endpoint only on hosts that
    /// cannot be off the machine's own network: loopback (`localhost` included, as Container
    /// Apps and Functions set it), link-local and private addresses. Anything else needs https.
    #[test]
    fn review_l1_app_service_endpoint_plain_http_only_on_local_hosts() {
        let mi = |u: &str| ManagedIdentity::system().app_service(u, "h");
        for ok in [
            "http://localhost:42356/msi/token",
            "http://127.0.0.1:41000/msi/token",
            "http://[::1]:8081/msi/token",
            "http://172.16.1.4:8081/msi/token",
            "http://10.0.0.5:8081/msi/token",
            "http://192.168.0.2:8081/msi/token",
            "http://169.254.130.1:8081/msi/token",
            "http://[fe80::1]:8081/msi/token",
            "http://[fd00:ec2::23]/msi/token",
            "https://collector.example/msi/token",
        ] {
            assert!(mi(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://collector.example/msi/token",
            "http://8.8.8.8/msi/token",
            "http://172.32.0.1/msi/token",
            "http://localhost./msi/token",
            "http://evil.localhost/msi/token",
            "http://[2001:db8::1]/msi/token",
            "http://[::ffff:8.8.8.8]/msi/token",
        ] {
            let e = mi(bad).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{bad}");
        }
    }
}
