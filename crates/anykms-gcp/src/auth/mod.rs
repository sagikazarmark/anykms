//! Credentials: OAuth 2.0 access tokens for Cloud KMS (see [`Credentials`]).

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};
use anykms_http::HttpTransport;
use anykms_http::credentials::{Credential, CredentialCache, Expiring};
use anykms_http::url::Url;
use zeroize::Zeroizing;

use crate::BACKEND;

mod adc;
mod external_account;
mod file;
#[cfg(feature = "google-cloud-auth")]
mod gca;
mod impersonated;
mod metadata;
mod oauth;
#[cfg(feature = "service-account-key")]
mod service_account;

pub(crate) use adc::AdcSource;
pub(crate) use file::FileSource;
pub(crate) use oauth::bearer as bearer_header;

/// The OAuth scope every token is requested for.
pub(crate) const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The most a credential file or subject-token file may hold.
pub(crate) const MAX_CREDENTIAL_FILE: usize = 64 * 1024;

/// The most a token-endpoint response may hold.
pub(crate) const MAX_TOKEN_RESPONSE: usize = 64 * 1024;

/// How long before expiry a token is refreshed: 4 minutes, not the cache default of 5. The
/// metadata server hands out its cached token until that token has about 5 minutes left, so a
/// 5-minute lead would refetch the same token on every request in that window. §24.4 probe T1
/// confirms the value.
const REFRESH_AHEAD: Duration = Duration::from_mins(4);

/// An OAuth 2.0 access token: zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct Token {
    secret: Arc<Zeroizing<String>>,
    expires_at: Option<SystemTime>,
    /// The cache generation that produced it (0 for tokens from custom sources).
    generation: u64,
}

impl Token {
    /// A token that expires at `expires_at` (`None`: unknown or never).
    pub fn new(secret: impl Into<String>, expires_at: Option<SystemTime>) -> Self {
        Self {
            secret: Arc::new(Zeroizing::new(secret.into())),
            expires_at,
            generation: 0,
        }
    }

    /// The token text. Avoid copying it into buffers that are not zeroized.
    pub fn expose(&self) -> &str {
        &self.secret
    }

    /// When the token expires, if known.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Supplies the access token for each Cloud KMS request. Object-safe; implement it for token
/// sources the built-in [`Credentials`] do not cover, and pass it with [`Credentials::custom`].
///
/// A source passed to [`Credentials::custom`] is cached like the built-in ones: it is asked for
/// a token only when the cached one is within 4 minutes of its
/// [`expires_at`](Token::expires_at) (a token without an expiry is kept until Cloud KMS
/// rejects it), one fetch at a time, inside a token span (`credential = "custom"`); a failed
/// fetch is returned to every caller for 5 s. It need not cache tokens itself.
pub trait CredentialSource: Send + Sync + fmt::Debug {
    /// The token to send as `Authorization: Bearer`, or `None` to send no `Authorization` header
    /// (an emulator or a private proxy that authenticates on its own).
    ///
    /// Errors: `Configuration` when no credentials can be found or a credential file is
    /// unusable, `Unavailable` (retryable) when a token endpoint or the metadata server cannot be
    /// reached or fails, `Unauthenticated` when a token endpoint refuses the credential.
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>>;

    /// Called when Cloud KMS rejected `rejected` with 401. A caching source drops it; if the next
    /// [`token`](Self::token) differs, the request is retried exactly once. For a source passed to
    /// [`Credentials::custom`], the cache drops the token and forwards the call.
    fn invalidate(&self, rejected: &Token) {
        let _ = rejected;
    }

    /// The project to bill and check quota against (`x-goog-user-project`), when the credential
    /// names one (`quota_project_id` in a credential file). A provider's
    /// [`quota_project`](crate::GcpProviderBuilder::quota_project) setting wins over it.
    fn quota_project(&self) -> Option<&str> {
        None
    }
}

pub(crate) fn config_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

pub(crate) fn auth_err(kind: ErrorKind, m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(kind, BACKEND, Operation::Configure, m)
}

/// Where tokens come from: the Google endpoints (the default), or, for tests and emulators, one
/// custom origin that serves every token endpoint and the metadata server.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthEndpoints {
    pub(crate) oauth2_token: Url,
    pub(crate) sts_token: Url,
    pub(crate) iam_credentials: Url,
    /// The metadata server origin (`http://host[:port]`); `None`: `GCE_METADATA_HOST` or
    /// `169.254.169.254`.
    pub(crate) metadata: Option<Url>,
    /// The custom origin, which credential-file URLs may also name.
    pub(crate) custom: Option<Url>,
}

impl Default for AuthEndpoints {
    fn default() -> Self {
        Self::google()
    }
}

impl AuthEndpoints {
    /// Google's endpoints: `https://oauth2.googleapis.com/token`, `https://sts.googleapis.com/v1/token`,
    /// `https://iamcredentials.googleapis.com`, and the metadata server at `GCE_METADATA_HOST`
    /// or `169.254.169.254`.
    pub fn google() -> Self {
        let u = |s: &str| Url::parse(s).expect("fixed URL");
        Self {
            oauth2_token: u("https://oauth2.googleapis.com/token"),
            sts_token: u("https://sts.googleapis.com/v1/token"),
            iam_credentials: u("https://iamcredentials.googleapis.com/"),
            metadata: None,
            custom: None,
        }
    }

    /// Every token endpoint under one origin, **for tests and emulators only**: `<origin>/token`
    /// (OAuth 2.0), `<origin>/v1/token` (STS), `<origin>/v1/projects/-/serviceAccounts/...`
    /// (IAM credentials) and the metadata server at `<origin>/computeMetadata/v1/...`.
    /// Credential-file URLs must then name exactly these endpoints (the Google ones are refused).
    ///
    /// `http://` needs a literal loopback IP **and**
    /// [`GcpProviderBuilder::allow_loopback_http`](crate::GcpProviderBuilder::allow_loopback_http)
    /// (checked by `build`), as for [`Endpoint::Custom`](crate::Endpoint::Custom); other origins
    /// must be `https://`.
    pub fn custom(origin: &str) -> Result<Self> {
        let base = Url::parse(origin)
            .map_err(|_| config_err("the auth endpoint origin is not a valid URL"))?;
        if !matches!(base.path(), "" | "/") || base.query().is_some() || base.fragment().is_some() {
            return Err(config_err(
                "the auth endpoint origin must be scheme://host[:port]",
            ));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(config_err(
                "the auth endpoint origin must not contain credentials",
            ));
        }
        match base.scheme() {
            "https" => {}
            "http" if crate::config::is_loopback_ip(&base) => {}
            _ => {
                return Err(config_err(
                    "the auth endpoint origin must be https://, or http:// on a literal loopback IP",
                ));
            }
        }
        let join = |p: &str| base.join(p).expect("valid path");
        Ok(Self {
            oauth2_token: join("/token"),
            sts_token: join("/v1/token"),
            iam_credentials: join("/"),
            metadata: Some(base.clone()),
            custom: Some(base),
        })
    }

    /// Whether these are custom endpoints served over plain `http://` (which needs
    /// `allow_loopback_http`).
    pub(crate) fn is_plain_http(&self) -> bool {
        self.custom.as_ref().is_some_and(|c| c.scheme() == "http")
    }

    /// The URL to use when a credential file names `u` for `field`, if `u` is one of the fixed
    /// URLs for that field (legacy OAuth token URLs map to the current one):
    ///
    /// - `token_uri`: exactly `https://oauth2.googleapis.com/token` (the legacy
    ///   `https://accounts.google.com/o/oauth2/token` and
    ///   `https://www.googleapis.com/oauth2/v4/token` are sent there instead).
    /// - `token_url`: exactly `https://sts.googleapis.com/v1/token`, or a regional
    ///   `https://sts.<location>.rep.googleapis.com/v1/token`.
    /// - `service_account_impersonation_url`: exactly
    ///   `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>:generateAccessToken`.
    ///
    /// Never a query, a fragment, userinfo or a port. With [`custom`](Self::custom) endpoints,
    /// the same paths on the custom origin, and nothing else.
    fn allowed_url(&self, u: &Url, field: UrlField) -> Option<Url> {
        if u.query().is_some()
            || u.fragment().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return None;
        }
        let google = self.custom.is_none();
        match field {
            UrlField::TokenUri => {
                let legacy = google
                    && matches!(
                        u.as_str(),
                        "https://accounts.google.com/o/oauth2/token"
                            | "https://www.googleapis.com/oauth2/v4/token"
                    );
                (*u == self.oauth2_token || legacy).then(|| self.oauth2_token.clone())
            }
            UrlField::StsTokenUrl => {
                let regional = google
                    && u.scheme() == "https"
                    && u.port().is_none()
                    && u.path() == "/v1/token"
                    && matches!(u.host(), Some(anykms_http::url::Host::Domain(h)) if h
                        .strip_prefix("sts.")
                        .and_then(|h| h.strip_suffix(".rep.googleapis.com"))
                        .is_some_and(crate::uri::location_ok));
                (*u == self.sts_token || regional).then(|| u.clone())
            }
            UrlField::Impersonation => {
                let email = u
                    .path()
                    .strip_prefix("/v1/projects/-/serviceAccounts/")?
                    .strip_suffix(":generateAccessToken")?;
                let expected = impersonated::generate_url(self, email).ok()?;
                (expected == *u).then_some(expected)
            }
        }
    }

    /// Parses a URL a credential file supplies for `field` and checks it against the fixed URLs
    /// for that field (see [`allowed_url`](Self::allowed_url)).
    pub(crate) fn checked_url(&self, s: &str, field: UrlField) -> Result<Url> {
        let name = field.name();
        let u = Url::parse(s).map_err(|_| {
            config_err(format!("credential file field `{name}` is not a valid URL"))
        })?;
        if let Some(u) = self.allowed_url(&u, field) {
            Ok(u)
        } else {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                backend = BACKEND,
                field = name,
                "credential file names a token endpoint other than the fixed one; refused"
            );
            Err(config_err(format!(
                "credential file field `{name}` must be {}",
                field.expected(self.custom.is_some())
            )))
        }
    }
}

/// A credential-file field that names a URL credentials are sent to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UrlField {
    /// `token_uri` (`authorized_user`).
    TokenUri,
    /// `token_url` (`external_account`).
    StsTokenUrl,
    /// `service_account_impersonation_url`.
    Impersonation,
}

impl UrlField {
    fn name(self) -> &'static str {
        match self {
            UrlField::TokenUri => "token_uri",
            UrlField::StsTokenUrl => "token_url",
            UrlField::Impersonation => "service_account_impersonation_url",
        }
    }

    fn expected(self, custom: bool) -> &'static str {
        match (self, custom) {
            (_, true) => "the matching endpoint of the custom auth origin, with no query",
            (UrlField::TokenUri, false) => "https://oauth2.googleapis.com/token",
            (UrlField::StsTokenUrl, false) => {
                "https://sts.googleapis.com/v1/token or \
                 https://sts.<location>.rep.googleapis.com/v1/token"
            }
            (UrlField::Impersonation, false) => {
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/\
                 <email>:generateAccessToken"
            }
        }
    }
}

/// What every credential source needs: the HTTP transport, the endpoints and where environment
/// variables come from.
#[derive(Clone)]
pub(crate) struct AuthCtx {
    pub(crate) http: Arc<dyn HttpTransport>,
    pub(crate) endpoints: AuthEndpoints,
    /// The variables ADC and the metadata server read on first use.
    pub(crate) env: EnvVars,
}

/// An environment-variable lookup ([`GcpProviderBuilder::from_env_with`]).
///
/// [`GcpProviderBuilder::from_env_with`]: crate::GcpProviderBuilder::from_env_with
pub(crate) type EnvLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Where the lazily read variables (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`,
/// `HOME`/`APPDATA`, `GCE_METADATA_HOST`) come from: the process environment, or the lookup the
/// builder was configured from.
#[derive(Clone, Default)]
pub(crate) struct EnvVars(Option<EnvLookup>);

impl fmt::Debug for EnvVars {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            None => "EnvVars(process)",
            Some(_) => "EnvVars(lookup)",
        })
    }
}

impl EnvVars {
    pub(crate) fn lookup(lookup: EnvLookup) -> Self {
        Self(Some(lookup))
    }

    /// The variable `name`, `None` when unset or empty.
    pub(crate) fn get(&self, name: &str) -> Option<std::ffi::OsString> {
        match &self.0 {
            None => std::env::var_os(name),
            Some(lookup) => lookup(name).map(Into::into),
        }
        .filter(|v| !v.is_empty())
    }
}

/// How a provider gets its tokens: OAuth 2.0 access tokens from Application Default Credentials
/// (ADC) or an explicit source. Cheap to clone; resolved (lazily) when the provider is built.
///
/// (ADC) or an explicit source.
///
/// Every source is lazy: nothing is read, probed or fetched before the first operation needs a
/// token. Fetched tokens are cached per source, custom sources included, and refreshed 4
/// minutes before they expire, one fetch at a time
/// ([`anykms_http::credentials::CredentialCache`]): concurrent callers share one fetch and its
/// result, an early refresh does not hold up callers with a valid token, and a failed fetch with
/// no usable token is returned to every caller for 5 s before the next fetch.
/// After a 401 the client [invalidates](CredentialSource::invalidate) the token and retries the
/// request exactly once if a different token comes back.
///
/// # Application Default Credentials
///
/// [`Credentials::adc`] (the default) takes the first of:
///
/// 1. the JSON file named by `GOOGLE_APPLICATION_CREDENTIALS`;
/// 2. the gcloud ADC file (`$CLOUDSDK_CONFIG/application_default_credentials.json`, by default
///    `~/.config/gcloud/…`, or `%APPDATA%\gcloud\…` on Windows), written by
///    `gcloud auth application-default login`;
/// 3. the metadata server (GCE, GKE Workload Identity, Cloud Run, Cloud Functions), at
///    `GCE_METADATA_HOST` or `169.254.169.254`, probed with a 1 s connect timeout.
///
/// With none of them, every operation fails with `Configuration`. The source chosen is logged at
/// INFO (`tracing` feature), never a value.
///
/// # Credential files
///
/// The JSON `type`s supported are `service_account` (a self-signed RS256 JWT, no token-endpoint
/// round trip; feature `service-account-key`), `authorized_user` (refresh token),
/// `external_account` with a `file` or `url` subject token (workload identity federation: STS
/// token exchange, then optional service-account impersonation) and
/// `impersonated_service_account`. Other types (`external_account` with an `aws` or
/// `executable` source, `external_account_authorized_user`, `gdch_service_account`) are refused
/// with `Configuration` naming the type.
///
/// Token endpoints are fixed per field. A URL a credential file supplies must be exactly the
/// fixed URL for its field, with no query or fragment: `token_uri` is
/// `https://oauth2.googleapis.com/token`; `token_url` is `https://sts.googleapis.com/v1/token`
/// or `https://sts.<location>.rep.googleapis.com/v1/token`;
/// `service_account_impersonation_url` is
/// `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>:generateAccessToken`
/// (with [`AuthEndpoints::custom`], the same paths on the custom origin instead). Anything else
/// is `Configuration`: a planted credential file cannot send subject tokens or refresh tokens
/// anywhere else, not even to another Google API that stores request bodies. A file's
/// `credential_source.url` (the local subject-token endpoint, e.g. a sidecar or an instance
/// metadata service) is not restricted: what it returns is only ever sent to the STS endpoint.
/// Treat credential files as trusted configuration all the same.
/// Credential files are read with a 64 KiB bound, and errors name the path, never the contents.
#[derive(Clone)]
pub struct Credentials(pub(crate) Spec);

#[derive(Clone)]
pub(crate) enum Spec {
    Adc,
    Metadata,
    File {
        path: PathBuf,
        expected: Option<&'static str>,
    },
    Json(Arc<Zeroizing<Vec<u8>>>),
    Static(Token),
    None,
    Impersonated {
        source: Box<Credentials>,
        target: String,
        delegates: Vec<String>,
        lifetime: Duration,
    },
    Custom(Arc<dyn CredentialSource>),
    #[cfg(feature = "google-cloud-auth")]
    GoogleCloudAuth(::google_cloud_auth::credentials::AccessTokenCredentials),
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Spec::Adc => f.write_str("Credentials::Adc"),
            Spec::Metadata => f.write_str("Credentials::MetadataServer"),
            Spec::File { path, expected } => f
                .debug_struct("Credentials::File")
                .field("path", path)
                .field("type", expected)
                .finish(),
            Spec::Json(_) => f.write_str("Credentials::Json(<redacted>)"),
            Spec::Static(_) => f.write_str("Credentials::StaticToken(<redacted>)"),
            Spec::None => f.write_str("Credentials::None"),
            Spec::Impersonated { source, target, .. } => f
                .debug_struct("Credentials::Impersonated")
                .field("source", source)
                .field("target", target)
                .finish(),
            Spec::Custom(c) => f.debug_tuple("Credentials::Custom").field(c).finish(),
            #[cfg(feature = "google-cloud-auth")]
            Spec::GoogleCloudAuth(c) => f
                .debug_tuple("Credentials::GoogleCloudAuth")
                .field(c)
                .finish(),
        }
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Self::adc()
    }
}

impl Credentials {
    /// Application Default Credentials (see [`Credentials`]). The default.
    pub fn adc() -> Self {
        Self(Spec::Adc)
    }

    /// The metadata server only (GCE, GKE Workload Identity, Cloud Run), at `GCE_METADATA_HOST`
    /// or `169.254.169.254`, over plain HTTP with `Metadata-Flavor: Google`.
    pub fn metadata_server() -> Self {
        Self(Spec::Metadata)
    }

    /// A credential JSON file of any supported `type`, read (bounded) on first use.
    pub fn from_file(path: impl Into<PathBuf>) -> Self {
        Self(Spec::File {
            path: path.into(),
            expected: None,
        })
    }

    /// A `service_account` key file (feature `service-account-key`). Google recommends against
    /// service-account keys: prefer the metadata server or workload identity federation.
    pub fn service_account_file(path: impl Into<PathBuf>) -> Self {
        Self(Spec::File {
            path: path.into(),
            expected: Some("service_account"),
        })
    }

    /// An `external_account` (workload identity federation) configuration file, as written by
    /// `gcloud iam workload-identity-pools create-cred-config` or `google-github-actions/auth`.
    pub fn external_account_file(path: impl Into<PathBuf>) -> Self {
        Self(Spec::File {
            path: path.into(),
            expected: Some("external_account"),
        })
    }

    /// An `authorized_user` file (a gcloud user login; development use).
    pub fn authorized_user_file(path: impl Into<PathBuf>) -> Self {
        Self(Spec::File {
            path: path.into(),
            expected: Some("authorized_user"),
        })
    }

    /// A credential JSON document of any supported `type`, held in zeroizing memory and parsed on
    /// first use.
    pub fn from_json(json: impl Into<Vec<u8>>) -> Self {
        Self(Spec::Json(Arc::new(Zeroizing::new(json.into()))))
    }

    /// Impersonates `target_service_account` (an email) with tokens from `source`
    /// (`iamcredentials.generateAccessToken`, 1 h tokens). `source` needs
    /// `roles/iam.serviceAccountTokenCreator` on the target.
    pub fn impersonated(source: Credentials, target_service_account: impl Into<String>) -> Self {
        Self(Spec::Impersonated {
            source: Box::new(source),
            target: target_service_account.into(),
            delegates: Vec::new(),
            lifetime: Duration::from_secs(3600),
        })
    }

    /// A fixed access token. It is never refreshed: once it expires every request fails with
    /// `Unauthenticated`.
    pub fn static_token(token: impl Into<String>) -> Self {
        Self(Spec::Static(Token::new(token, None)))
    }

    /// No `Authorization` header (an emulator, or a proxy that authenticates requests itself).
    pub fn none() -> Self {
        Self(Spec::None)
    }

    /// A custom source, cached and traced like the built-in ones (see [`CredentialSource`]).
    pub fn custom(source: Arc<dyn CredentialSource>) -> Self {
        Self(Spec::Custom(source))
    }

    /// Access tokens from Google's official auth library (feature `google-cloud-auth`), for
    /// credential types not built in: AWS- and executable-sourced workload identity federation,
    /// `external_account_authorized_user` and whatever else the library supports.
    ///
    /// ```no_run
    /// # use anykms_gcp::{Credentials, GcpProvider};
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// let creds = google_cloud_auth::credentials::Builder::default()
    ///     .build_access_token_credentials()?;
    /// let provider = GcpProvider::builder()
    ///     .credentials(Credentials::google_cloud_auth(creds))
    ///     .build()?;
    /// # Ok(()) }
    /// ```
    ///
    /// Only tokens come from the library: Cloud KMS calls stay on this crate's client. The
    /// library caches and refreshes tokens itself, so this provider asks it on every request
    /// rather than caching them. It fetches with its own HTTP client: with its default features
    /// off (as this crate depends on it), it needs a process-wide rustls provider
    /// (`rustls::crypto::CryptoProvider::install_default`), or enable its
    /// `default-rustls-provider` feature in your `Cargo.toml`. Building the library's credentials
    /// spawns its refresh task, so do it inside a tokio runtime. Errors carry the library's error
    /// as their source.
    #[cfg(feature = "google-cloud-auth")]
    pub fn google_cloud_auth(
        credentials: ::google_cloud_auth::credentials::AccessTokenCredentials,
    ) -> Self {
        Self(Spec::GoogleCloudAuth(credentials))
    }

    /// The source, given the provider's HTTP clients. No I/O.
    pub(crate) fn into_source(self, ctx: &AuthCtx) -> Result<Arc<dyn CredentialSource>> {
        Ok(match self.0 {
            Spec::Adc => Arc::new(AdcSource::new(ctx.clone())),
            Spec::Metadata => Arc::new(metadata::source(ctx)?),
            Spec::File { path, expected } => Arc::new(FileSource::new(
                file::Origin::Path(path),
                expected,
                ctx.clone(),
            )),
            Spec::Json(json) => {
                Arc::new(FileSource::new(file::Origin::Json(json), None, ctx.clone()))
            }
            Spec::Static(t) => Arc::new(StaticSource(Some(t))),
            Spec::None => Arc::new(StaticSource(None)),
            Spec::Impersonated {
                source,
                target,
                delegates,
                lifetime,
            } => {
                let source = source.into_source(ctx)?;
                let url = impersonated::generate_url(&ctx.endpoints, &target)?;
                Arc::new(Cached::new(impersonated::Impersonate {
                    http: ctx.http.clone(),
                    source,
                    url,
                    delegates,
                    lifetime,
                    quota_project: None,
                }))
            }
            Spec::Custom(c) => Arc::new(Cached::new(CustomFetch {
                source: c,
                last: Mutex::new(None),
            })),
            #[cfg(feature = "google-cloud-auth")]
            Spec::GoogleCloudAuth(c) => Arc::new(gca::GoogleCloudAuth(c)),
        })
    }
}

/// A custom [`CredentialSource`] behind [`Cached`] (P1-7): the cache, the token span and the
/// refresh-once trigger apply to it as to every built-in source.
struct CustomFetch {
    source: Arc<dyn CredentialSource>,
    /// The token the source last handed out, for forwarding [`CredentialSource::invalidate`].
    last: Mutex<Option<Token>>,
}

impl Fetch for CustomFetch {
    fn kind(&self) -> &'static str {
        "custom"
    }

    fn endpoint_host(&self) -> Option<String> {
        None
    }

    fn fetch(&self) -> BoxFuture<'_, Result<Expiring<Fetched>>> {
        Box::pin(async move {
            let t = self.source.token().await?;
            self.last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone_from(&t);
            Ok(match t {
                None => Expiring::new(Fetched::none(), None),
                Some(t) => {
                    let secret = Zeroizing::new(t.expose().to_owned());
                    match t.expires_at() {
                        Some(at) => Fetched::valid_until(secret, at),
                        None => Expiring::new(
                            Fetched {
                                secret: Some(Arc::new(secret)),
                                expires_at: None,
                            },
                            None,
                        ),
                    }
                }
            })
        })
    }

    fn rejected(&self) {
        let last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(t) = last {
            self.source.invalidate(&t);
        }
    }

    fn quota_project(&self) -> Option<&str> {
        self.source.quota_project()
    }

    fn describe(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CustomCredentials")
            .field(&self.source)
            .finish()
    }
}

/// A fixed token, or none.
struct StaticSource(Option<Token>);

impl fmt::Debug for StaticSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(_) => f.write_str("StaticToken(<redacted>)"),
            None => f.write_str("NoToken"),
        }
    }
}

impl CredentialSource for StaticSource {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        let t = self.0.clone();
        Box::pin(async move { Ok(t) })
    }
}

/// The value a fetch produces.
#[derive(Clone)]
pub(crate) struct Fetched {
    /// `None`: send no `Authorization` header (a custom source that returned no token).
    secret: Option<Arc<Zeroizing<String>>>,
    expires_at: Option<SystemTime>,
}

impl Fetched {
    /// A token valid for `lifetime` from now.
    pub(crate) fn valid_for(secret: Zeroizing<String>, lifetime: Duration) -> Expiring<Self> {
        Expiring::valid_for(
            Self {
                secret: Some(Arc::new(secret)),
                expires_at: anykms_core::time::system_now().checked_add(lifetime),
            },
            lifetime,
        )
    }

    /// A token valid until `at`.
    pub(crate) fn valid_until(secret: Zeroizing<String>, at: SystemTime) -> Expiring<Self> {
        Expiring::valid_until(
            Self {
                secret: Some(Arc::new(secret)),
                expires_at: Some(at),
            },
            at,
        )
    }

    /// The token text (empty for no token).
    pub(crate) fn secret(&self) -> &str {
        self.secret.as_deref().map_or("", |s| s.as_str())
    }

    /// No token.
    fn none() -> Self {
        Self {
            secret: None,
            expires_at: None,
        }
    }
}

/// A token fetcher behind [`Cached`].
pub(crate) trait Fetch: Send + Sync + 'static {
    /// The credential type, for logs (`metadata`, `service_account`, ...): the token span's
    /// `credential`, a stable snake_case label.
    fn kind(&self) -> &'static str;
    /// The token endpoint's host, for logs (`None` for self-signed tokens).
    fn endpoint_host(&self) -> Option<String>;
    /// Fetches a new token.
    fn fetch(&self) -> BoxFuture<'_, Result<Expiring<Fetched>>>;
    /// The quota project from the credential file.
    fn quota_project(&self) -> Option<&str> {
        None
    }
    /// Cloud KMS rejected the token this fetcher produced last (a custom source drops its own
    /// cache).
    fn rejected(&self) {}
    /// `Debug` of the cached source.
    fn describe(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedToken")
            .field("type", &self.kind())
            .field("endpoint", &self.endpoint_host())
            .finish_non_exhaustive()
    }
}

/// A fetcher with a single-flight cache: the shape of every built-in source.
pub(crate) struct Cached<F> {
    fetcher: F,
    cache: CredentialCache<Fetched>,
    /// The credential last handed out, for [`CredentialSource::invalidate`].
    last: Mutex<Option<Credential<Fetched>>>,
}

impl<F: Fetch> fmt::Debug for Cached<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fetcher.describe(f)
    }
}

impl<F: Fetch> Cached<F> {
    pub(crate) fn new(fetcher: F) -> Self {
        Self {
            fetcher,
            cache: CredentialCache::new().refresh_ahead(REFRESH_AHEAD),
            last: Mutex::new(None),
        }
    }

    /// Fetches inside a token span (`anykms.gcp.token`, the shared schema of
    /// [`anykms_http::span`]), with a `debug` event on success and a `warn` event on failure
    /// carrying the error kind and the error (which names a failed file's path).
    async fn fetch_logged(&self) -> Result<Expiring<Fetched>> {
        let span = anykms_http::token_span!(
            "anykms.gcp.token",
            backend = BACKEND,
            credential = self.fetcher.kind(),
        );
        let started = anykms_core::time::Instant::now();
        let r = anykms_http::span::instrument(self.fetcher.fetch(), &span).await;
        let expires_in = r.as_ref().ok().and_then(|t| {
            t.value()
                .expires_at
                .and_then(|at| at.duration_since(anykms_core::time::system_now()).ok())
        });
        anykms_http::span::finish_token(&span, started, expires_in, &r);
        #[cfg(feature = "tracing")]
        match &r {
            Ok(_) => tracing::debug!(
                parent: &span,
                backend = BACKEND,
                credential = self.fetcher.kind(),
                "access token refreshed"
            ),
            Err(e) => tracing::warn!(
                parent: &span,
                backend = BACKEND,
                credential = self.fetcher.kind(),
                error_kind = e.kind().as_str(),
                error = %e,
                "access token refresh failed"
            ),
        }
        r
    }
}

impl<F: Fetch> CredentialSource for Cached<F> {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async move {
            let c = self.cache.get(|| self.fetch_logged()).await?;
            let t = c.value().secret.clone().map(|secret| Token {
                secret,
                expires_at: c.value().expires_at,
                generation: c.generation(),
            });
            *self
                .last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(c);
            Ok(t)
        })
    }

    fn invalidate(&self, rejected: &Token) {
        let last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(c) = last.as_ref()
            && c.generation() == rejected.generation
            && rejected.generation != 0
        {
            self.cache.invalidate(c);
            self.fetcher.rejected();
        }
    }

    fn quota_project(&self) -> Option<&str> {
        self.fetcher.quota_project()
    }
}

/// Parses an RFC 3339 UTC timestamp (`2024-01-02T03:04:05.123Z`, also with a `+00:00` offset)
/// into seconds since the Unix epoch (fractions dropped). Used for token expiry and
/// `createTime`.
pub(crate) fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    // At most four ASCII digits each, so `i64` holds them losslessly.
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let p = s.get(r)?;
        p.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| p.parse().ok())
            .flatten()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = s.get(19..)?;
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
    }
    let offset: i64 = match rest {
        "Z" | "z" => 0,
        o if o.len() == 6
            && (o.starts_with('+') || o.starts_with('-'))
            && o.get(3..4) == Some(":") =>
        {
            let hh: i64 = o.get(1..3)?.parse().ok()?;
            let mm: i64 = o.get(4..6)?.parse().ok()?;
            let v = hh * 3600 + mm * 60;
            if o.starts_with('+') { v } else { -v }
        }
        _ => return None,
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let t = days * 86_400 + h * 3600 + mi * 60 + sec - offset;
    u64::try_from(t).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339("2024-02-29T12:34:56.789123Z"),
            Some(1_709_210_096)
        );
        assert_eq!(
            parse_rfc3339("2024-02-29T13:34:56+01:00"),
            Some(1_709_210_096)
        );
        assert_eq!(parse_rfc3339("2000-03-01T00:00:00Z"), Some(951_868_800));
        for bad in [
            "",
            "2024-02-29",
            "2024-02-29T12:34:56",
            "2024-13-01T00:00:00Z",
            "2024-02-29T12:34:56.Z",
            "2024-02-29 12:34:56Z",
            "1969-12-31T23:59:59Z",
            "2024-02-29T12:34:56+0100",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    const SA: &str = "a@b.iam.gserviceaccount.com";

    #[test]
    fn credential_file_urls_are_exact_per_field() {
        use UrlField::*;
        let g = AuthEndpoints::google();
        let check = |s: &str, f: UrlField| g.checked_url(s, f).map(|u| u.to_string());
        // The fixed URLs.
        let ok = [
            ("https://oauth2.googleapis.com/token", TokenUri),
            ("https://sts.googleapis.com/v1/token", StsTokenUrl),
            (
                "https://sts.europe-west1.rep.googleapis.com/v1/token",
                StsTokenUrl,
            ),
            (
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a@b.iam.gserviceaccount.com:generateAccessToken",
                Impersonation,
            ),
        ];
        for (u, f) in ok {
            assert_eq!(check(u, f).unwrap(), u, "{u}");
        }
        // Legacy OAuth token URLs go to the current endpoint.
        for u in [
            "https://accounts.google.com/o/oauth2/token",
            "https://www.googleapis.com/oauth2/v4/token",
        ] {
            assert_eq!(
                check(u, TokenUri).unwrap(),
                "https://oauth2.googleapis.com/token"
            );
        }
        let bad = [
            // The exfiltration example (review M1): Google hosts that store request bodies.
            (
                "https://firebasestorage.googleapis.com/v0/b/attacker-bucket/o?name=leak",
                StsTokenUrl,
            ),
            (
                "https://storage.googleapis.com/upload/storage/v1/b/bucket/o?uploadType=media&name=leak",
                StsTokenUrl,
            ),
            (
                "https://storage.googleapis.com/upload/storage/v1/b/bucket/o",
                TokenUri,
            ),
            (
                "https://firebasestorage.googleapis.com/v0/b/attacker-bucket/o",
                Impersonation,
            ),
            // Another field's URL.
            ("https://sts.googleapis.com/v1/token", TokenUri),
            ("https://oauth2.googleapis.com/token", StsTokenUrl),
            // Queries, fragments, ports, userinfo, http, other paths.
            ("https://sts.googleapis.com/v1/token?x=1", StsTokenUrl),
            ("https://sts.googleapis.com/v1/token#x", StsTokenUrl),
            ("https://oauth2.googleapis.com/token?name=leak", TokenUri),
            ("http://sts.googleapis.com/v1/token", StsTokenUrl),
            ("https://sts.googleapis.com:8443/v1/token", StsTokenUrl),
            ("https://user@sts.googleapis.com/v1/token", StsTokenUrl),
            ("https://sts.googleapis.com/v1/token/x", StsTokenUrl),
            ("https://sts.googleapis.com/v1/oauthtoken", StsTokenUrl),
            ("https://evil.example/v1/token", StsTokenUrl),
            ("https://googleapis.com.evil.example/v1/token", StsTokenUrl),
            ("https://sts..rep.googleapis.com/v1/token", StsTokenUrl),
            ("https://sts.a.b.rep.googleapis.com/v1/token", StsTokenUrl),
            (
                "https://iamcredentials.googleapis.com/v1/x:generateAccessToken",
                Impersonation,
            ),
            (
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a@b.iam.gserviceaccount.com:generateAccessToken?x=1",
                Impersonation,
            ),
            (
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/not-an-email:generateAccessToken",
                Impersonation,
            ),
            (
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a@b/c:generateAccessToken",
                Impersonation,
            ),
            (
                "https://storage.googleapis.com/v1/projects/-/serviceAccounts/a@b.iam.gserviceaccount.com:generateAccessToken",
                Impersonation,
            ),
            ("not a url", TokenUri),
        ];
        for (u, f) in bad {
            let e = g.checked_url(u, f).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{u}");
            assert!(e.to_string().contains(f.name()), "{e}");
        }

        // Custom endpoints: the same paths on that origin, and nothing else.
        let c = AuthEndpoints::custom("http://127.0.0.1:8080").unwrap();
        assert!(c.is_plain_http());
        assert!(
            !AuthEndpoints::custom("https://auth.test")
                .unwrap()
                .is_plain_http()
        );
        assert_eq!(c.sts_token.as_str(), "http://127.0.0.1:8080/v1/token");
        let imp =
            format!("http://127.0.0.1:8080/v1/projects/-/serviceAccounts/{SA}:generateAccessToken");
        for (u, f) in [
            ("http://127.0.0.1:8080/token", TokenUri),
            ("http://127.0.0.1:8080/v1/token", StsTokenUrl),
            (imp.as_str(), Impersonation),
        ] {
            assert!(c.checked_url(u, f).is_ok(), "{u}");
        }
        for (u, f) in [
            ("http://127.0.0.1:8080/x", TokenUri),
            ("http://127.0.0.1:8081/token", TokenUri),
            ("http://127.0.0.1:8080/v1/token?x", StsTokenUrl),
            ("https://oauth2.googleapis.com/token", TokenUri),
            ("https://sts.googleapis.com/v1/token", StsTokenUrl),
            ("https://sts.us.rep.googleapis.com/v1/token", StsTokenUrl),
            ("https://accounts.google.com/o/oauth2/token", TokenUri),
        ] {
            assert!(c.checked_url(u, f).is_err(), "{u}");
        }
        for bad in [
            "http://localhost:8080",
            "http://10.0.0.1",
            "ftp://127.0.0.1",
            "http://127.0.0.1/path",
            "https://u:p@example.com",
        ] {
            assert!(AuthEndpoints::custom(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_redacts() {
        let t = Token::new("ya29.SECRET", None);
        assert!(!format!("{t:?}").contains("SECRET"));
        let c = Credentials::static_token("ya29.SECRET");
        assert!(!format!("{c:?}").contains("SECRET"));
        let c = Credentials::from_json(b"{\"private_key\":\"SECRET\"}".to_vec());
        assert!(!format!("{c:?}").contains("SECRET"));
    }
}
