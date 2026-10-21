//! STS `AssumeRoleWithWebIdentity` (EKS IRSA, GitHub Actions OIDC, any OIDC token file).

use std::path::PathBuf;

use anykms_core::{BackendDetail, BoxFuture, Error, ErrorKind, Operation, Result};
use zeroize::Zeroizing;

use super::{
    CredentialSource, Credentials, MAX_CREDENTIAL_BYTES, SourceContext, Vars, config_err,
    token_file_err,
};
use crate::BACKEND;

/// Credentials for `role_arn` from STS `AssumeRoleWithWebIdentity`, presenting the OIDC token in
/// `token_file` (re-read on every fetch, since token files rotate). The request is not signed.
///
/// Configured from `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN` and `AWS_ROLE_SESSION_NAME` by
/// [`from_env`](Self::from_env) (and by the default chain). The STS endpoint is
/// `AWS_ENDPOINT_URL_STS`, else the regional endpoint of [`region`](Self::region) /
/// `AWS_REGION` / `AWS_DEFAULT_REGION`, else the global `https://sts.amazonaws.com`.
#[derive(Clone)]
pub struct WebIdentityCredentials {
    token_file: PathBuf,
    role_arn: String,
    session_name: Option<String>,
    region: Option<String>,
    endpoint: Option<String>,
    vars: Vars,
}

/// The endpoint as its origin only (P1-1); the token file's path, never its content.
impl std::fmt::Debug for WebIdentityCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebIdentityCredentials")
            .field("token_file", &self.token_file)
            .field("role_arn", &self.role_arn)
            .field("session_name", &self.session_name)
            .field("region", &self.region)
            .field(
                "endpoint",
                &self.endpoint.as_deref().map(crate::config::redacted_url),
            )
            .field("vars", &self.vars)
            .finish()
    }
}

impl WebIdentityCredentials {
    /// Assumes `role_arn` with the token in `token_file`.
    pub fn new(token_file: impl Into<PathBuf>, role_arn: impl Into<String>) -> Self {
        Self {
            token_file: token_file.into(),
            role_arn: role_arn.into(),
            session_name: None,
            region: None,
            endpoint: None,
            vars: Vars::from_env(),
        }
    }

    /// From `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN` and `AWS_ROLE_SESSION_NAME`
    /// (`Configuration` if the first two are not both set).
    pub fn from_env() -> Result<Self> {
        Self::from_vars(Vars::from_env())
    }

    pub(crate) fn configured(vars: &Vars) -> bool {
        vars.get("AWS_WEB_IDENTITY_TOKEN_FILE").is_some() || vars.get("AWS_ROLE_ARN").is_some()
    }

    /// Like `new`, reading variables from `lookup` instead of the process environment (empty
    /// values count as unset).
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::from_vars(Vars::from_fn(lookup))
    }

    pub(crate) fn from_vars(vars: Vars) -> Result<Self> {
        let (Some(file), Some(role)) = (
            vars.get("AWS_WEB_IDENTITY_TOKEN_FILE"),
            vars.get("AWS_ROLE_ARN"),
        ) else {
            return Err(config_err(
                "AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN must be set together",
            ));
        };
        let session_name = vars.get("AWS_ROLE_SESSION_NAME").map(str::to_owned);
        let mut s = Self::new(file, role).with_vars(vars);
        s.session_name = session_name;
        Ok(s)
    }

    pub(crate) fn with_vars(mut self, vars: Vars) -> Self {
        self.vars = vars;
        self
    }

    /// The role session name (default `anykms-<unix millis>`), 2 to 64 characters of
    /// `A-Z a-z 0-9 + = , . @ _ -`.
    pub fn session_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = Some(name.into());
        self
    }

    /// The region whose STS endpoint is used.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// An explicit STS endpoint (`https://...`; `http://` only to a loopback address when the
    /// provider allows loopback HTTP).
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint = Some(url.into());
        self
    }

    pub(crate) fn endpoint_url(&self, allow_loopback_http: bool) -> Result<anykms_http::url::Url> {
        let raw = match self
            .endpoint
            .as_deref()
            .or_else(|| self.vars.get("AWS_ENDPOINT_URL_STS"))
        {
            Some(e) => e.to_owned(),
            None => match self
                .region
                .as_deref()
                .or_else(|| self.vars.get("AWS_REGION"))
                .or_else(|| self.vars.get("AWS_DEFAULT_REGION"))
            {
                Some(r) => {
                    if !r
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                        || r.is_empty()
                    {
                        return Err(config_err("malformed STS region"));
                    }
                    let suffix = if r.starts_with("cn-") {
                        "amazonaws.com.cn"
                    } else {
                        "amazonaws.com"
                    };
                    format!("https://sts.{r}.{suffix}")
                }
                None => "https://sts.amazonaws.com".to_owned(),
            },
        };
        crate::endpoint::validate_url(&raw, allow_loopback_http, "the STS endpoint")
    }

    fn session(&self) -> Result<String> {
        let name = match &self.session_name {
            Some(n) => n.clone(),
            None => format!(
                "anykms-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis())
            ),
        };
        if !(2..=64).contains(&name.len())
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
        {
            return Err(config_err("malformed role session name"));
        }
        Ok(name)
    }

    pub(crate) async fn fetch(&self, cx: &SourceContext) -> Result<Credentials> {
        let url = self.endpoint_url(cx.http.loopback_allowed)?;
        if !self.role_arn.starts_with("arn:") || self.role_arn.len() > 2048 {
            return Err(config_err("the web identity role is not an ARN"));
        }
        let session = self.session()?;
        let token = anykms_http::zbuf::read_file(&self.token_file, MAX_CREDENTIAL_BYTES)
            .map_err(|e| token_file_err("the web identity token file", &self.token_file, &e))?;
        let token = std::str::from_utf8(&token)
            .map(str::trim)
            .ok()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                config_err(format!(
                    "the web identity token file {} is empty or not UTF-8",
                    self.token_file.display()
                ))
            })?;
        let enc = |s: &str| crate::sigv4::uri_encode(s, false);
        let mut body = Zeroizing::new(String::with_capacity(token.len() + 256));
        body.push_str("Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=");
        body.push_str(&enc(&self.role_arn));
        body.push_str("&RoleSessionName=");
        body.push_str(&enc(&session));
        body.push_str("&WebIdentityToken=");
        body.push_str(&Zeroizing::new(enc(token)));
        let resp = cx
            .http
            .send(
                anykms_http::client::request(anykms_http::http::Method::POST, &url)
                    .header(
                        anykms_http::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Zeroizing::new(body.as_bytes().to_vec())),
                MAX_CREDENTIAL_BYTES,
                Operation::Configure,
            )
            .await
            .map_err(|err| match err.kind() {
                ErrorKind::Configuration | ErrorKind::Timeout => err,
                _ => Error::new(
                    ErrorKind::Unavailable,
                    BACKEND,
                    Operation::Configure,
                    "STS unreachable",
                ),
            })?;
        let status = resp.status.as_u16();
        let rid = crate::errors::request_id(&resp.headers);
        let body = resp.body;
        let text = std::str::from_utf8(&body).unwrap_or("");
        if (200..300).contains(&status) {
            return parse_sts_success(text);
        }
        Err(sts_error(status, text, rid))
    }
}

/// The raw content of the first `<tag>...</tag>` in `xml`.
fn xml_raw<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let len = xml[start..].find(&close)?;
    Some(&xml[start..start + len])
}

/// The text of the first `<tag>...</tag>` in `xml`, with the five XML entities decoded.
pub(crate) fn xml_text(xml: &str, tag: &str) -> Option<Zeroizing<String>> {
    let raw = xml_raw(xml, tag)?;
    let mut out = Zeroizing::new(String::with_capacity(raw.len()));
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let ent = &rest[i..];
        let (ch, n) = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ]
        .iter()
        .find(|(e, _)| ent.starts_with(e))
        .map(|(e, c)| (*c, e.len()))?;
        out.push(ch);
        rest = &ent[n..];
    }
    out.push_str(rest);
    Some(out)
}

/// Parses an `AssumeRoleWithWebIdentityResponse`.
pub(crate) fn parse_sts_success(xml: &str) -> Result<Credentials> {
    let bad = || {
        Error::new(
            ErrorKind::Unavailable,
            BACKEND,
            Operation::Configure,
            "STS returned a malformed response",
        )
    };
    let creds = xml_raw(xml, "Credentials").ok_or_else(bad)?;
    let id = xml_text(creds, "AccessKeyId").ok_or_else(bad)?;
    let secret = xml_text(creds, "SecretAccessKey").ok_or_else(bad)?;
    let token = xml_text(creds, "SessionToken").ok_or_else(bad)?;
    let exp = xml_text(creds, "Expiration")
        .and_then(|e| crate::time::parse_rfc3339(e.trim()))
        .ok_or_else(bad)?;
    let c = Credentials::new(id.trim(), secret.trim(), Some(token.trim().to_owned()))
        .with_expiry(Some(exp));
    c.validate().map_err(|_| bad())?;
    Ok(c)
}

/// Classifies an STS error response.
pub(crate) fn sts_error(status: u16, xml: &str, request_id: Option<String>) -> Error {
    let code = xml_text(xml, "Code")
        .map(|c| c.trim().to_owned())
        .filter(|c| crate::errors::normalize_code(c) == Some(c.as_str()));
    let (kind, msg) = match code.as_deref() {
        Some(
            "AccessDenied"
            | "InvalidIdentityToken"
            | "ExpiredTokenException"
            | "ExpiredToken"
            | "IDPRejectedClaim",
        ) => (
            ErrorKind::Unauthenticated,
            "STS refused the web identity token or role",
        ),
        Some("IDPCommunicationError" | "ServiceUnavailable" | "InternalFailure") => {
            (ErrorKind::Unavailable, "STS is temporarily unavailable")
        }
        Some("Throttling" | "ThrottlingException") => {
            (ErrorKind::Throttled, "STS throttled the request")
        }
        Some(
            "RegionDisabledException"
            | "MalformedPolicyDocument"
            | "ValidationError"
            | "InvalidParameterValue",
        ) => (
            ErrorKind::Configuration,
            "STS rejected the request parameters",
        ),
        _ if (400..500).contains(&status) => (ErrorKind::Configuration, "STS rejected the request"),
        _ => (ErrorKind::Unavailable, "STS failed"),
    };
    let mut detail = BackendDetail::new().with_http_status(status);
    if let Some(c) = code {
        detail = detail.with_code(c);
    }
    // The body's id goes through the same filter as the header's (`errors::request_id`): it is
    // server-controlled and must not inject into logs.
    let body_id = || {
        xml_text(xml, "RequestId")
            .and_then(|r| anykms_http::redact::request_id(r.trim()).map(str::to_owned))
    };
    if let Some(r) = request_id.or_else(body_id) {
        detail = detail.with_request_id(r);
    }
    if let Some(m) = xml_text(xml, "Message") {
        detail = detail.with_server_message(crate::errors::redact(&m));
    }
    Error::new(kind, BACKEND, Operation::Configure, msg).with_detail(detail)
}

impl CredentialSource for WebIdentityCredentials {
    fn kind(&self) -> &'static str {
        "web_identity"
    }

    fn credentials<'a>(&'a self, cx: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(self.fetch(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "<AssumeRoleWithWebIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIA1</AccessKeyId><SecretAccessKey>s+e/c&amp;r</SecretAccessKey><SessionToken>tok==</SessionToken><Expiration>2999-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>";

    #[test]
    fn parses() {
        let c = parse_sts_success(OK).unwrap();
        assert_eq!(c.access_key_id(), "ASIA1");
        assert_eq!(c.secret_access_key(), "s+e/c&r");
        assert_eq!(c.session_token(), Some("tok=="));
        assert!(parse_sts_success("<x/>").is_err());
        assert!(parse_sts_success(&OK.replace("2999-01-01T00:00:00Z", "soon")).is_err());
        assert_eq!(xml_text("<a>x&bogus;</a>", "a"), None);
    }

    #[test]
    fn errors() {
        let x = "<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>bad SECRETJWT</Message></Error><RequestId>r-1</RequestId></ErrorResponse>";
        let e = sts_error(400, x, None);
        assert_eq!(e.kind(), ErrorKind::Unauthenticated);
        let d = e.detail().unwrap();
        assert_eq!(d.code(), Some("InvalidIdentityToken"));
        assert_eq!(d.request_id(), Some("r-1"));
        assert!(!format!("{e:?}").contains("SECRETJWT"));
        assert_eq!(sts_error(503, "", None).kind(), ErrorKind::Unavailable);
        assert_eq!(sts_error(400, "", None).kind(), ErrorKind::Configuration);
    }

    /// The body's `RequestId` goes through the shared request-id filter.
    #[test]
    fn body_request_ids_are_filtered() {
        let body = |id: &str| {
            format!(
                "<ErrorResponse><Error><Code>AccessDenied</Code></Error><RequestId>{id}</RequestId></ErrorResponse>"
            )
        };
        let rid = |id: &str| {
            sts_error(403, &body(id), None)
                .detail()
                .unwrap()
                .request_id()
                .map(str::to_owned)
        };
        assert_eq!(rid(" r-2\n").as_deref(), Some("r-2"));
        assert_eq!(rid("r-1\ninjected"), None);
        assert_eq!(rid(&"a".repeat(129)), None);
        assert_eq!(rid(&"a".repeat(128)).map(|r| r.len()), Some(128));
        // The header's id wins.
        let e = sts_error(403, &body("r-body"), Some("r-header".into()));
        assert_eq!(e.detail().unwrap().request_id(), Some("r-header"));
    }

    #[test]
    fn endpoints() {
        let s = |region: Option<&str>, ep: Option<&str>| {
            let (region, ep) = (region.map(str::to_owned), ep.map(str::to_owned));
            WebIdentityCredentials::new("/t", "arn:aws:iam::1:role/r").with_vars(Vars::from_fn(
                move |k| match k {
                    "AWS_REGION" => region.clone(),
                    "AWS_ENDPOINT_URL_STS" => ep.clone(),
                    _ => None,
                },
            ))
        };
        assert_eq!(
            s(None, None).endpoint_url(false).unwrap().as_str(),
            "https://sts.amazonaws.com/"
        );
        assert_eq!(
            s(Some("eu-west-1"), None)
                .endpoint_url(false)
                .unwrap()
                .as_str(),
            "https://sts.eu-west-1.amazonaws.com/"
        );
        assert_eq!(
            s(Some("cn-north-1"), None)
                .endpoint_url(false)
                .unwrap()
                .as_str(),
            "https://sts.cn-north-1.amazonaws.com.cn/"
        );
        assert!(
            s(None, Some("http://127.0.0.1:9/"))
                .endpoint_url(false)
                .is_err()
        );
        assert!(
            s(None, Some("http://127.0.0.1:9/"))
                .endpoint_url(true)
                .is_ok()
        );
        assert!(
            s(None, Some("http://sts.example.com/"))
                .endpoint_url(true)
                .is_err()
        );
        assert!(s(Some("EU"), None).endpoint_url(false).is_err());
        assert!(
            WebIdentityCredentials::new("/t", "r")
                .session_name("x")
                .session()
                .is_err()
        );
        assert!(WebIdentityCredentials::new("/t", "r").session().is_ok());
    }
}
