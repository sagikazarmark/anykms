//! ECS task role and EKS Pod Identity credentials (the container credentials endpoint).

use std::net::IpAddr;
use std::path::PathBuf;

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};
use zeroize::Zeroizing;

use super::{
    CredentialSource, Credentials, JsonCredentials, MAX_CREDENTIAL_BYTES, SourceContext, Vars,
    config_err, token_file_err, unauthenticated, unavailable,
};
use crate::BACKEND;

/// The ECS credentials host for `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
const ECS_HOST: &str = "http://169.254.170.2";

/// Credentials from the container credentials endpoint: ECS task roles
/// (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) and EKS Pod Identity / generic endpoints
/// (`AWS_CONTAINER_CREDENTIALS_FULL_URI`, with the `Authorization` header from
/// `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, re-read on every fetch, or
/// `AWS_CONTAINER_AUTHORIZATION_TOKEN`).
///
/// A full URI must be `https://`, or `http://` to the ECS (`169.254.170.2`) or EKS
/// (`169.254.170.23`, `fd00:ec2::23`) link-local hosts or a loopback address, the same allowlist
/// as the AWS SDKs: credentials never travel in clear text elsewhere.
#[derive(Debug, Clone)]
pub struct ContainerCredentials {
    vars: Vars,
}

impl ContainerCredentials {
    /// The endpoint from the environment (a snapshot).
    pub fn new() -> Self {
        Self::from_vars(Vars::from_env())
    }

    /// Like `new`, reading variables from `lookup` instead of the process environment (empty
    /// values count as unset).
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self::from_vars(Vars::from_fn(lookup))
    }

    pub(crate) fn from_vars(vars: Vars) -> Self {
        Self { vars }
    }

    pub(crate) fn configured(vars: &Vars) -> bool {
        vars.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").is_some()
            || vars.get("AWS_CONTAINER_CREDENTIALS_FULL_URI").is_some()
    }

    pub(crate) fn url(&self) -> Result<reqwest::Url> {
        if let Some(rel) = self.vars.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            if !rel.starts_with('/')
                || rel.starts_with("//")
                || rel.contains("://")
                || rel.contains('@')
            {
                return Err(config_err(
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be a path starting with /",
                ));
            }
            return reqwest::Url::parse(&format!("{ECS_HOST}{rel}")).map_err(|_| {
                config_err("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is not a valid path")
            });
        }
        let full = self
            .vars
            .get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
            .ok_or_else(|| config_err("no container credentials endpoint is configured"))?;
        let url = reqwest::Url::parse(full)
            .map_err(|_| config_err("AWS_CONTAINER_CREDENTIALS_FULL_URI is not a valid URL"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(config_err(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI must not contain credentials",
            ));
        }
        match url.scheme() {
            "https" => {}
            "http" if http_allowed(&url) => {}
            _ => {
                return Err(config_err(
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI must be https://, or http:// to \
                     169.254.170.2, 169.254.170.23, fd00:ec2::23 or a loopback address",
                ));
            }
        }
        Ok(url)
    }

    fn auth_token(&self) -> Result<Option<Zeroizing<String>>> {
        if let Some(path) = self.vars.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            let path = PathBuf::from(path);
            let bytes = anykms_http::zbuf::read_file(&path, MAX_CREDENTIAL_BYTES)
                .map_err(|e| token_file_err("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", &path, &e))?;
            let s = std::str::from_utf8(&bytes).map_err(|_| {
                config_err(format!(
                    "the container authorization token file {} is not UTF-8",
                    path.display()
                ))
            })?;
            return Ok(Some(Zeroizing::new(s.trim().to_owned())));
        }
        Ok(self
            .vars
            .get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
            .map(|t| Zeroizing::new(t.to_owned())))
    }

    pub(crate) async fn fetch(&self, cx: &SourceContext) -> Result<Credentials> {
        let url = self.url()?;
        let client = if url.scheme() == "https" {
            cx.http.main()
        } else {
            cx.http.local().await?
        };
        let mut req = client.get(url);
        if let Some(t) = self.auth_token()? {
            let mut v = reqwest::header::HeaderValue::from_str(&t)
                .map_err(|_| config_err("the container authorization token is malformed"))?;
            v.set_sensitive(true);
            req = req.header(reqwest::header::AUTHORIZATION, v);
        }
        let resp = req.send().await.map_err(|e| {
            let err = anykms_http::client::transport_error(BACKEND, Operation::Configure, e);
            if err.kind() == ErrorKind::Timeout {
                err
            } else {
                Error::new(
                    err.kind().max_unavailable(),
                    BACKEND,
                    Operation::Configure,
                    "container credentials endpoint unreachable",
                )
            }
        })?;
        let status = resp.status().as_u16();
        let body =
            crate::client::read_body(resp, MAX_CREDENTIAL_BYTES, Operation::Configure).await?;
        match status {
            200..=299 => JsonCredentials::parse(&body, "the container credentials endpoint"),
            401 | 403 => Err(unauthenticated(
                "the container credentials endpoint refused the request (authorization token?)",
            )),
            400..=499 => Err(config_err(format!(
                "the container credentials endpoint answered {status}"
            ))),
            _ => Err(unavailable("the container credentials endpoint failed")),
        }
    }
}

/// `Configuration` stays (e.g. a rejected certificate); everything else is `Unavailable`.
trait MaxUnavailable {
    fn max_unavailable(self) -> ErrorKind;
}

impl MaxUnavailable for ErrorKind {
    fn max_unavailable(self) -> ErrorKind {
        if self == ErrorKind::Configuration {
            self
        } else {
            ErrorKind::Unavailable
        }
    }
}

fn http_allowed(url: &reqwest::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => {
            ip.is_loopback()
                || ip.octets() == [169, 254, 170, 2]
                || ip.octets() == [169, 254, 170, 23]
        }
        Some(url::Host::Ipv6(ip)) => {
            IpAddr::V6(ip).is_loopback() || ip.segments() == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23]
        }
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

impl Default for ContainerCredentials {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialSource for ContainerCredentials {
    fn kind(&self) -> &'static str {
        "container"
    }

    fn credentials<'a>(&'a self, cx: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(self.fetch(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(rel: Option<&str>, full: Option<&str>) -> ContainerCredentials {
        let (rel, full) = (rel.map(str::to_owned), full.map(str::to_owned));
        ContainerCredentials::from_vars(Vars::from_fn(move |k| match k {
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => rel.clone(),
            "AWS_CONTAINER_CREDENTIALS_FULL_URI" => full.clone(),
            _ => None,
        }))
    }

    #[test]
    fn host_allowlist() {
        assert_eq!(
            src(Some("/v2/credentials/abc"), None)
                .url()
                .unwrap()
                .as_str(),
            "http://169.254.170.2/v2/credentials/abc"
        );
        for ok in [
            "http://169.254.170.23/v1/credentials",
            "http://[fd00:ec2::23]/v1/credentials",
            "http://127.0.0.1:8080/creds",
            "http://[::1]/creds",
            "http://localhost/creds",
            "https://creds.example.com/x",
        ] {
            assert!(src(None, Some(ok)).url().is_ok(), "{ok}");
        }
        for bad in [
            "http://169.254.169.254/latest",
            "http://example.com/creds",
            "http://10.0.0.1/creds",
            "ftp://127.0.0.1/x",
            "https://user:pw@example.com/x",
            "not a url",
        ] {
            assert!(src(None, Some(bad)).url().is_err(), "{bad}");
        }
        for bad in ["relative", "//evil.example/x", "/x@evil"] {
            assert!(src(Some(bad), None).url().is_err(), "{bad}");
        }
        assert!(src(None, None).url().is_err());
        assert!(!ContainerCredentials::configured(&Vars::default()));
    }
}
