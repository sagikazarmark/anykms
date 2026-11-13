//! EC2 instance metadata service credentials (IMDSv2 only).

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};

use super::{
    CredentialSource, Credentials, JsonCredentials, MAX_CREDENTIAL_BYTES, SourceContext, Vars,
    config_err, unavailable,
};
use crate::BACKEND;

const DEFAULT_V4: &str = "http://169.254.169.254";
const DEFAULT_V6: &str = "http://[fd00:ec2::254]";
/// The session token's lifetime (6 hours, the maximum).
const TOKEN_TTL: &str = "21600";

/// Credentials of the instance profile from the EC2 instance metadata service, IMDSv2 only
/// (a session token is fetched with `PUT /latest/api/token`; there is no IMDSv1 fallback).
/// Timeouts are 1 s to connect and 2 s per request.
///
/// The endpoint comes from `AWS_EC2_METADATA_SERVICE_ENDPOINT`, else
/// `AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE` (`IPv4`, default, or `IPv6`).
///
/// On `wasm32-unknown-unknown` (a Cloudflare Worker) the service is unreachable and this source
/// fails with a `Configuration` error before sending anything; configure credentials explicitly
/// there.
#[derive(Clone)]
pub struct ImdsCredentials {
    endpoint: Option<String>,
    any_http: bool,
    vars: Vars,
}

/// The endpoint as its origin only (P1-1).
impl std::fmt::Debug for ImdsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImdsCredentials")
            .field(
                "endpoint",
                &self.endpoint.as_deref().map(crate::config::redacted_url),
            )
            .field("vars", &self.vars)
            .finish()
    }
}

impl ImdsCredentials {
    /// The endpoint from the environment (a snapshot).
    pub fn new() -> Self {
        Self::from_vars(Vars::from_env())
    }

    /// Uses this endpoint (`http(s)://host[:port]`; see
    /// [`allow_http_to_any_host`](Self::allow_http_to_any_host) for plain HTTP).
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint = Some(url.into());
        self
    }

    /// Allows plain `http://` to any host (a metadata proxy on a private address). Without it,
    /// `http://` is accepted only for loopback, `localhost`, link-local addresses
    /// (169.254.0.0/16, fe80::/10) and the IMDS and container IPv6 addresses (`fd00:ec2::254`,
    /// `fd00:ec2::23`), since the session token and the credentials cross it in clear text.
    pub fn allow_http_to_any_host(mut self) -> Self {
        self.any_http = true;
        self
    }

    /// Like `new`, reading variables from `lookup` instead of the process environment (empty
    /// values count as unset).
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self::from_vars(Vars::from_fn(lookup))
    }

    pub(crate) fn from_vars(vars: Vars) -> Self {
        Self {
            endpoint: None,
            any_http: false,
            vars,
        }
    }

    fn base(&self) -> Result<anykms_http::url::Url> {
        let raw = match &self.endpoint {
            Some(e) => e.clone(),
            None => match self.vars.get("AWS_EC2_METADATA_SERVICE_ENDPOINT") {
                Some(e) => e.to_owned(),
                None => match self.vars.get("AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE") {
                    None => DEFAULT_V4.to_owned(),
                    Some(m) if m.eq_ignore_ascii_case("ipv4") => DEFAULT_V4.to_owned(),
                    Some(m) if m.eq_ignore_ascii_case("ipv6") => DEFAULT_V6.to_owned(),
                    Some(_) => {
                        return Err(config_err(
                            "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE must be IPv4 or IPv6",
                        ));
                    }
                },
            },
        };
        let url = anykms_http::url::Url::parse(&raw)
            .map_err(|_| config_err("the instance metadata endpoint is not a valid URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.query().is_some()
        {
            return Err(config_err(
                "the instance metadata endpoint must be http(s)://host[:port]",
            ));
        }
        if url.scheme() == "http" && !self.any_http && !local_http_ok(&url) {
            return Err(config_err(
                "the instance metadata endpoint: plain http:// is only allowed to loopback, \
                 localhost and link-local addresses; use https:// or \
                 ImdsCredentials::allow_http_to_any_host()",
            ));
        }
        Ok(url)
    }

    pub(crate) async fn fetch(&self, cx: &SourceContext) -> Result<Credentials> {
        use anykms_http::client::empty;
        use anykms_http::http::Method;
        // A link-local service: nothing on a JS host (a Cloudflare Worker) can reach it, and
        // the host's `fetch` need not honour the probe's timeout. Fail before anything is sent,
        // whether this source was chosen explicitly or by the default chain.
        if cfg!(all(target_arch = "wasm32", target_os = "unknown")) {
            return Err(config_err(
                "the EC2 instance metadata service is not reachable from this target \
                 (wasm32-unknown-unknown): configure credentials explicitly",
            ));
        }
        let base = self.base()?;
        let url = |p: &str| {
            let mut u = base.clone();
            u.set_path(p);
            u
        };
        // A link-local request that fails fast (`Http::local`). A TLS or request-building
        // failure against the metadata service is not a configuration the operator can fix
        // here: report it as the service being unreachable.
        let transport = |mut err: Error| {
            if err.kind() == ErrorKind::Configuration {
                err = Error::new(
                    ErrorKind::Unavailable,
                    BACKEND,
                    Operation::Configure,
                    "instance metadata service unreachable",
                );
            }
            err
        };
        let limit = MAX_CREDENTIAL_BYTES;
        let op = Operation::Configure;
        // IMDSv2 session token.
        let resp = cx
            .http
            .send(
                crate::client::Http::local(Method::PUT, &url("/latest/api/token"))
                    .header("x-aws-ec2-metadata-token-ttl-seconds", TOKEN_TTL)
                    .body(empty()),
                4096,
                op,
            )
            .await
            .map_err(transport)?;
        if !resp.status.is_success() {
            return Err(match resp.status.as_u16() {
                403 => {
                    config_err("instance metadata service refused a session token (IMDS disabled?)")
                }
                _ => unavailable("instance metadata service failed to issue a session token"),
            });
        }
        let token = resp.body;
        let token = std::str::from_utf8(&token)
            .ok()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| unavailable("instance metadata service returned a malformed token"))?;
        let mut token_header = anykms_http::http::HeaderValue::from_str(token)
            .map_err(|_| unavailable("instance metadata service returned a malformed token"))?;
        token_header.set_sensitive(true);
        // The instance profile's role.
        let resp = cx
            .http
            .send(
                crate::client::Http::local(
                    Method::GET,
                    &url("/latest/meta-data/iam/security-credentials/"),
                )
                .header("x-aws-ec2-metadata-token", token_header.clone())
                .body(empty()),
                4096,
                op,
            )
            .await
            .map_err(transport)?;
        match resp.status.as_u16() {
            200 => {}
            404 => {
                return Err(config_err(
                    "the EC2 instance has no IAM role (instance profile)",
                ));
            }
            _ => {
                return Err(unavailable(
                    "instance metadata service failed to list the role",
                ));
            }
        }
        let role = resp.body;
        let role = std::str::from_utf8(&role)
            .ok()
            .and_then(|r| r.lines().next())
            .map(str::trim)
            .filter(|r| {
                !r.is_empty()
                    && r.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
            })
            .ok_or_else(|| unavailable("instance metadata service returned a malformed role name"))?
            .to_owned();
        let resp = cx
            .http
            .send(
                crate::client::Http::local(
                    Method::GET,
                    &url(&format!(
                        "/latest/meta-data/iam/security-credentials/{role}"
                    )),
                )
                .header("x-aws-ec2-metadata-token", token_header)
                .body(empty()),
                limit,
                op,
            )
            .await
            .map_err(transport)?;
        if !resp.status.is_success() {
            return Err(unavailable(
                "instance metadata service failed to return credentials",
            ));
        }
        JsonCredentials::parse(&resp.body, "the instance metadata service")
    }
}

impl Default for ImdsCredentials {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialSource for ImdsCredentials {
    fn kind(&self) -> &'static str {
        "imds"
    }

    fn credentials<'a>(&'a self, cx: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(self.fetch(cx))
    }
}

/// Hosts plain HTTP may reach without the opt-in (L1): loopback, `localhost`, link-local
/// (169.254.0.0/16, fe80::/10) and the IMDS and container IPv6 addresses.
fn local_http_ok(url: &anykms_http::url::Url) -> bool {
    use anykms_http::url::Host;
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback() || ip.is_link_local(),
        Some(Host::Ipv6(ip)) => {
            let s = ip.segments();
            ip.is_loopback()
                || (s[0] & 0xffc0) == 0xfe80
                || s == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]
                || s == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23]
        }
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let v = |mode: Option<&str>, ep: Option<&str>| {
            let (mode, ep) = (mode.map(str::to_owned), ep.map(str::to_owned));
            ImdsCredentials::from_vars(Vars::from_fn(move |k| match k {
                "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE" => mode.clone(),
                "AWS_EC2_METADATA_SERVICE_ENDPOINT" => ep.clone(),
                _ => None,
            }))
        };
        assert_eq!(
            v(None, None).base().unwrap().as_str(),
            "http://169.254.169.254/"
        );
        assert_eq!(
            v(Some("IPv6"), None).base().unwrap().as_str(),
            "http://[fd00:ec2::254]/"
        );
        assert_eq!(
            v(Some("IPv6"), Some("http://127.0.0.1:1338"))
                .base()
                .unwrap()
                .as_str(),
            "http://127.0.0.1:1338/"
        );
        assert!(v(Some("ipv5"), None).base().is_err());
        assert!(v(None, Some("ftp://x")).base().is_err());
    }

    /// L1: plain HTTP only to loopback, `localhost`, link-local addresses and the IMDS and
    /// container IPv6 addresses, unless the caller opts in; HTTPS to any host.
    #[test]
    fn plain_http_needs_a_local_host() {
        let ep = |e: &str| {
            let e = e.to_owned();
            ImdsCredentials::from_vars(Vars::from_fn(move |k| {
                (k == "AWS_EC2_METADATA_SERVICE_ENDPOINT").then(|| e.clone())
            }))
        };
        for ok in [
            "http://169.254.169.254",
            "http://169.254.1.2:8080",
            "http://[fd00:ec2::254]",
            "http://[fd00:ec2::23]",
            "http://[fe80::1]",
            "http://127.0.0.1:1338",
            "http://[::1]:1338",
            "http://localhost:1338",
            "https://imds-proxy.internal",
        ] {
            assert!(ep(ok).base().is_ok(), "{ok}");
        }
        for bad in [
            "http://imds-proxy.internal",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://[::ffff:169.254.169.254]",
            "http://metadata.google.internal",
            "http://localhost.evil.example",
        ] {
            let e = ep(bad).base().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{bad}");
        }
        // The explicit opt-in, on the builder only.
        assert!(
            ep("http://10.0.0.1")
                .allow_http_to_any_host()
                .base()
                .is_ok()
        );
        assert!(
            ImdsCredentials::from_vars(Vars::from_fn(|_| None))
                .endpoint("http://imds-proxy.internal")
                .base()
                .is_err()
        );
    }
}
