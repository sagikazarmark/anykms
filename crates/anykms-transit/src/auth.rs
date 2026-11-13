//! Built-in login: the Kubernetes and JWT auth methods, with token renewal.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anykms_core::time::Instant;

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};
use anykms_http::HttpTransport;
use anykms_http::http::header::{CONTENT_TYPE, HeaderValue};
use anykms_http::url::Url;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::token::{Token, TokenSource};

/// The service-account token path Kubernetes mounts into pods.
pub const KUBERNETES_SERVICE_ACCOUNT_TOKEN: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Upper bound for a JWT file.
const MAX_JWT_FILE: usize = 64 * 1024;
/// Upper bound for a login or renewal response.
const MAX_AUTH_RESPONSE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Kubernetes,
    Jwt,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Kubernetes => "kubernetes",
            Method::Jwt => "jwt",
        }
    }
}

/// Logs in to Vault/OpenBao with an auth method and keeps the token fresh. Set it with
/// [`ServerConfig::login`](crate::ServerConfig::login) (or `ANYKMS_TRANSIT_AUTH`, see
/// [`EnvConfig`](crate::EnvConfig)).
///
/// Both methods post a JWT read from a file to `auth/<mount>/login` with a role:
///
/// - [`kubernetes`](Self::kubernetes): the pod's service-account token
///   ([`KUBERNETES_SERVICE_ACCOUNT_TOKEN`]), mount `kubernetes`;
/// - [`jwt`](Self::jwt): any JWT file (e.g. a projected token with a Vault audience, or a CI
///   identity token), mount `jwt`.
///
/// **Lifecycle.** The first request logs in; the token is then reused until two thirds of its
/// lease have passed. A renewable token is then renewed (`auth/token/renew-self`); a token that
/// is not renewable, whose renewal fails, or whose renewal comes back with less than half of
/// its previous lease (its max TTL is near) is replaced by a fresh login. If that login fails
/// while the current token has not expired yet, the current token is still used, and the next
/// refresh is attempted 5 s later, so a brief server outage near a refresh does not fail
/// requests or stall them behind repeated logins. When the server rejects the token with 403,
/// the request is retried once with a fresh login, at most once per 30 s: Vault and OpenBao
/// also answer policy denials with 403, which must not mint a token per request. The current
/// token is kept until a new login succeeds. Leases are capped at 10 years. Tokens without a lease
/// (`lease_duration` 0) are never refreshed. Concurrent requests share one login or renewal; when
/// a login fails with no usable token, requests get that error for the next 5 s instead of each
/// logging in again. A 403-triggered login the caller cancels is retried by the next request.
/// A request waits for another's login or renewal at most the transport's
/// [`follower_wait`](anykms_http::HttpTransport::follower_wait) bound (twice the connect plus
/// request timeout with the built-in transport), then runs its own: a caller that keeps a
/// request future alive without polling it cannot stall the others. A login or renewal that
/// finishes after a newer token was stored that way does not replace it.
///
/// The JWT file is re-read (a small blocking read) at every login, so a rotated token is picked
/// up. Unlike [`FileToken`](crate::FileToken), its permissions are not checked: Kubernetes
/// mounts service-account tokens group- and world-readable by default, and these tokens are
/// short-lived and audience-bound.
///
/// **Errors.** A login the server refuses (400, 401, 403: wrong role, bad audience, unknown
/// mount, expired JWT) fails requests with `PermissionDenied`; a missing JWT file (a rotation
/// race) with `Unavailable`; any other unusable JWT file (unreadable, empty, over 64 KiB, not
/// UTF-8, whitespace or control characters) with `Configuration`; server-side failures keep
/// their usual classification. Messages never contain the JWT or the token. Warnings in login
/// responses are ignored: they concern the token's TTL, not ignored request parameters.
///
/// **Tracing.** With the `tracing` feature, every login and renewal runs in a token span
/// (`anykms.transit.token`, `credential` = the method name), with a `debug` event on success and
/// a `warn` event on failure (naming the JWT file when reading it failed).
#[derive(Clone)]
pub struct Login {
    method: Method,
    mount: String,
    role: String,
    jwt_file: PathBuf,
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("method", &self.method.as_str())
            .field("mount", &self.mount)
            .field("role", &self.role)
            .field("jwt_file", &self.jwt_file)
            .finish()
    }
}

impl Login {
    /// Kubernetes auth with `role`: mount `kubernetes`, JWT from
    /// [`KUBERNETES_SERVICE_ACCOUNT_TOKEN`].
    pub fn kubernetes(role: impl Into<String>) -> Self {
        Self {
            method: Method::Kubernetes,
            mount: "kubernetes".into(),
            role: role.into(),
            jwt_file: KUBERNETES_SERVICE_ACCOUNT_TOKEN.into(),
        }
    }

    /// JWT auth with `role`, reading the JWT from `jwt_file`: mount `jwt`.
    pub fn jwt(role: impl Into<String>, jwt_file: impl Into<PathBuf>) -> Self {
        Self {
            method: Method::Jwt,
            mount: "jwt".into(),
            role: role.into(),
            jwt_file: jwt_file.into(),
        }
    }

    /// The auth mount path (default `kubernetes` or `jwt`), e.g. `k8s-prod` for
    /// `auth/k8s-prod/login`.
    pub fn mount(mut self, mount: impl Into<String>) -> Self {
        mount.into().trim_matches('/').clone_into(&mut self.mount);
        self
    }

    /// The file the JWT is read from at every login.
    pub fn jwt_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.jwt_file = path.into();
        self
    }

    /// The method name (`kubernetes` or `jwt`).
    pub fn method(&self) -> &'static str {
        self.method.as_str()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let bad = |m: &'static str| {
            Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Configure,
                m,
            ))
        };
        if self.role.is_empty() {
            return bad("login role is empty");
        }
        if !crate::uri::namespace_ok(&self.mount) {
            return bad("invalid login auth mount");
        }
        Ok(())
    }
}

/// A token from a login or renewal.
struct Lease {
    token: Token,
    duration: Duration,
    renewable: bool,
    obtained: Instant,
}

impl Lease {
    fn refresh_due(&self, now: Instant) -> bool {
        !self.duration.is_zero() && now >= self.obtained + self.duration * 2 / 3
    }

    fn expired(&self, now: Instant) -> bool {
        !self.duration.is_zero() && now >= self.obtained + self.duration
    }
}

/// The [`TokenSource`] a server uses when [`Login`] is configured. It shares the server's HTTP
/// client (TLS, proxy, timeouts).
pub(crate) struct LoginSource {
    login: Login,
    http: Arc<dyn HttpTransport>,
    base: Url,
    namespace: Option<String>,
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    alias: String,
    /// Locked only between awaits: decisions and their outcomes.
    state: std::sync::Mutex<State>,
    /// Held across a login or renewal, so concurrent requests share one.
    flight: tokio::sync::Mutex<()>,
    /// How long a request waits for `flight` before running its own login or renewal: the
    /// transport's [`follower_wait`](HttpTransport::follower_wait). A holder that is alive but
    /// not polled would otherwise block every later request (its own request timeout cannot fire
    /// while it is not polled). `None`: as long as the holder lives.
    max_wait: Option<(Duration, anykms_core::SleepFn)>,
    /// The token a 403 rejected, set by [`TokenSource::invalidate`] and acted on by the next
    /// `token()`.
    rejected: std::sync::Mutex<Option<Token>>,
}

/// Leases longer than this are clamped, so lease arithmetic cannot overflow on a hostile or
/// misconfigured server's `lease_duration`.
const MAX_LEASE: Duration = Duration::from_hours(10 * 365 * 24);
/// After a failed refresh while the current token is still valid, requests keep using that token
/// for this long before the next attempt, instead of each retrying the login in turn.
const REFRESH_BACKOFF: Duration = Duration::from_secs(5);
/// At most one login per this interval is triggered by a 403. Vault and OpenBao also answer a
/// policy denial with 403, so without a limit every denied request would mint a new token.
const FORCED_LOGIN_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Default)]
struct State {
    lease: Option<Lease>,
    /// No refresh before this instant (set after a failed refresh).
    retry_at: Option<Instant>,
    /// When a 403 last triggered a login.
    last_forced: Option<Instant>,
    /// The error of the last failed login when no usable token was left, returned to requests
    /// until `retry_at` instead of each logging in again in turn.
    last_error: Option<Error>,
    /// Bumped whenever `lease` is replaced. A login or renewal stores its outcome only if this
    /// has not moved since it was decided: one that stalled while a request that stopped
    /// waiting for it stored a newer token must not replace that token when it resumes.
    generation: u64,
}

impl State {
    fn store(&mut self, lease: Lease) {
        self.lease = Some(lease);
        self.generation = self.generation.wrapping_add(1);
    }

    /// What `token()` does next, given a 403 report (`rejected`).
    fn plan(&self, now: Instant, rejected: Option<&Token>) -> Step {
        let forced = rejected.is_some_and(|r| {
            self.lease
                .as_ref()
                .is_some_and(|l| l.token.expose() == r.expose())
        }) && self
            .last_forced
            .is_none_or(|t| now.duration_since(t) >= FORCED_LOGIN_INTERVAL);
        if !forced && self.lease.as_ref().is_none_or(|l| l.expired(now)) {
            // No usable token and a login just failed: share that failure for the backoff.
            if let (Some(t), Some(e)) = (self.retry_at, self.last_error.as_ref())
                && now < t
            {
                return Step::Done(Err(e.clone()));
            }
        }
        let mut renew = None;
        if let Some(l) = self.lease.as_ref().filter(|_| !forced) {
            if !l.refresh_due(now) {
                return Step::Done(Ok(Some(l.token.clone())));
            }
            let backing_off = self.retry_at.is_some_and(|t| now < t);
            if backing_off && !l.expired(now) {
                return Step::Done(Ok(Some(l.token.clone())));
            }
            if l.renewable && !l.expired(now) {
                renew = Some((l.token.clone(), l.duration));
            }
        }
        Step::Refresh {
            renew,
            forced,
            generation: self.generation,
        }
    }
}

/// What a `token()` call does next, decided under the state lock.
enum Step {
    /// Answer without a request.
    Done(Result<Option<Token>>),
    /// Renew the token (with the lease it had) if given, else (or if that fails) log in;
    /// `forced` by a 403. `generation` is the state's when this was decided.
    Refresh {
        renew: Option<(Token, Duration)>,
        forced: bool,
        generation: u64,
    },
}

/// Puts a 403 report back if the login it triggered does not finish (the caller dropped the
/// future), so the next request retries that login instead of reusing the rejected token.
struct PendingRejection<'a> {
    slot: &'a std::sync::Mutex<Option<Token>>,
    token: Option<Token>,
}

impl Drop for PendingRejection<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.token.take() {
            let mut slot = self
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.is_none() {
                *slot = Some(t);
            }
        }
    }
}

impl fmt::Debug for LoginSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSource")
            .field("login", &self.login)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct LoginReq<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Deserialize)]
struct AuthResp {
    auth: Option<AuthData>,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

const OP: Operation = Operation::Configure;

impl LoginSource {
    pub(crate) fn new(
        login: Login,
        http: Arc<dyn HttpTransport>,
        base: Url,
        namespace: Option<String>,
        alias: String,
    ) -> Self {
        Self {
            login,
            max_wait: http.follower_wait(),
            http,
            base,
            namespace,
            alias,
            state: std::sync::Mutex::new(State::default()),
            flight: tokio::sync::Mutex::new(()),
            rejected: std::sync::Mutex::new(None),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn take_rejected(&self) -> Option<Token> {
        self.rejected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Waits for the login or renewal another request is running, at most
    /// [`max_wait`](Self::max_wait). `None` once that passes: the caller then runs its own,
    /// outside `flight`.
    async fn enter(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        if let Ok(g) = self.flight.try_lock() {
            return Some(g);
        }
        let Some((max, sleep)) = &self.max_wait else {
            return Some(self.flight.lock().await);
        };
        let mut lock = std::pin::pin!(self.flight.lock());
        let mut timer = sleep(*max);
        let entered = std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(g) = lock.as_mut().poll(cx) {
                return std::task::Poll::Ready(Some(g));
            }
            if timer.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(None);
            }
            std::task::Poll::Pending
        })
        .await;
        #[cfg(feature = "tracing")]
        if entered.is_none() {
            tracing::debug!(
                backend = BACKEND,
                server_alias = %self.alias,
                waited_secs = max.as_secs(),
                "the running login or renewal is not progressing; running another"
            );
        }
        entered
    }

    /// Reads the JWT file. A missing file is `Unavailable`, every other failure
    /// `Configuration` ([`token_file_error_kind`](anykms_http::zbuf::token_file_error_kind)).
    fn jwt(&self) -> Result<Zeroizing<String>> {
        let path = &self.login.jwt_file;
        let err = |kind: ErrorKind, what: String| {
            Error::new(
                kind,
                BACKEND,
                OP,
                format!("login JWT file {} {what}", path.display()),
            )
        };
        let invalid = |what: &str| err(ErrorKind::Configuration, what.to_owned());
        let raw = anykms_http::zbuf::read_file(path, MAX_JWT_FILE).map_err(|e| {
            err(
                anykms_http::zbuf::token_file_error_kind(&e),
                format!("cannot be read: {}", crate::config::io_reason(&e)),
            )
            .with_source(e)
        })?;
        let s = std::str::from_utf8(&raw).map_err(|_| invalid("is not UTF-8"))?;
        let s = s.trim();
        if s.is_empty() {
            return Err(invalid("is empty"));
        }
        if s.bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(invalid("contains whitespace or control characters"));
        }
        Ok(Zeroizing::new(s.to_owned()))
    }

    /// Runs a login or renewal inside a token span and logs its outcome (P1-8). `fetch` returns
    /// whether a failure came from the JWT file, so the event names the file.
    async fn traced(
        &self,
        what: &'static str,
        fetch: impl Future<Output = std::result::Result<Lease, (Error, bool)>>,
    ) -> Result<Lease> {
        let span = anykms_http::token_span!(
            "anykms.transit.token",
            backend = BACKEND,
            credential = self.login.method.as_str(),
        );
        let started = Instant::now();
        let r = anykms_http::span::instrument(fetch, &span).await;
        #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
        let (r, file_failed) = match r {
            Ok(l) => (Ok(l), false),
            Err((e, file)) => (Err(e), file),
        };
        let expires = r.as_ref().ok().map(|l| l.duration).filter(|d| !d.is_zero());
        anykms_http::span::finish_token(&span, started, expires, &r);
        #[cfg(feature = "tracing")]
        span.in_scope(|| match &r {
            Ok(l) => tracing::debug!(
                backend = BACKEND,
                server_alias = %self.alias,
                method = self.login.method.as_str(),
                mount = %self.login.mount,
                lease_secs = l.duration.as_secs(),
                renewable = l.renewable,
                "{what} succeeded"
            ),
            Err(e) if file_failed => tracing::warn!(
                backend = BACKEND,
                server_alias = %self.alias,
                method = self.login.method.as_str(),
                path = %self.login.jwt_file.display(),
                error_kind = e.kind().as_str(),
                error = %e,
                "{what} failed: cannot use the JWT file"
            ),
            Err(e) => tracing::warn!(
                backend = BACKEND,
                server_alias = %self.alias,
                method = self.login.method.as_str(),
                mount = %self.login.mount,
                error_kind = e.kind().as_str(),
                error = %e,
                "{what} failed"
            ),
        });
        #[cfg(not(feature = "tracing"))]
        let _ = what;
        r
    }

    async fn login(&self) -> Result<Lease> {
        self.traced("login", async {
            let jwt = self.jwt().map_err(|e| (e, true))?;
            self.login_with(jwt).await.map_err(|e| (e, false))
        })
        .await
    }

    async fn login_with(&self, jwt: Zeroizing<String>) -> Result<Lease> {
        let mut body = anykms_http::zbuf::Writer(Zeroizing::new(Vec::with_capacity(
            jwt.len() + self.login.role.len() + 32,
        )));
        serde_json::to_writer(
            &mut body,
            &LoginReq {
                role: &self.login.role,
                jwt: &jwt,
            },
        )
        .map_err(|_| Error::new(ErrorKind::Backend, BACKEND, OP, "cannot encode the login"))?;
        drop(jwt);
        let mut segments = vec!["auth"];
        segments.extend(self.login.mount.split('/'));
        segments.push("login");
        self.post(&segments, None, Some(body.0)).await
    }

    async fn renew(&self, token: &Token) -> Result<Lease> {
        self.traced("token renewal", async {
            self.post(&["auth", "token", "renew-self"], Some(token), None)
                .await
                .map_err(|e| (e, false))
        })
        .await
    }

    async fn post(
        &self,
        segments: &[&str],
        token: Option<&Token>,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Lease> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| Error::new(ErrorKind::Configuration, BACKEND, OP, "invalid login path"))?
            .pop_if_empty()
            .push("v1")
            .extend(segments);
        let mut req = anykms_http::client::request(anykms_http::http::Method::POST, &url)
            .header("X-Vault-Request", "true")
            .header(CONTENT_TYPE, "application/json");
        // The body stays in a zeroizing buffer up to the transport (which may copy it; see the
        // crate docs).
        let body = body.unwrap_or_else(|| Zeroizing::new(b"{}".to_vec()));
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        if let Some(t) = token {
            let mut v = HeaderValue::from_str(t.expose()).map_err(|_| {
                Error::new(
                    ErrorKind::Backend,
                    BACKEND,
                    OP,
                    "token contains invalid characters",
                )
            })?;
            v.set_sensitive(true);
            req = req.header("X-Vault-Token", v);
        }
        let resp = crate::client::send(
            &*self.http,
            req.body(body),
            MAX_AUTH_RESPONSE,
            OP,
            &self.alias,
            "login response exceeds the maximum size",
        )
        .await?;
        let (status, buf) = (resp.status, resp.body);
        if !status.is_success() {
            let messages = crate::errors::ErrorBody::messages(&buf);
            let e = crate::errors::classify(&crate::errors::Failure {
                status: status.as_u16(),
                messages: &messages,
                retry_after: None,
                op: OP,
                alias: &self.alias,
                key_read: false,
            });
            if matches!(status.as_u16(), 400 | 401 | 403) {
                let mut denied = Error::new(
                    ErrorKind::PermissionDenied,
                    BACKEND,
                    OP,
                    format!(
                        "{} login to auth/{} was refused (check the role, the JWT and the mount)",
                        self.login.method.as_str(),
                        self.login.mount
                    ),
                );
                if let Some(d) = e.detail() {
                    denied = denied.with_detail(d.clone());
                }
                return Err(denied);
            }
            return Err(e);
        }
        let auth = serde_json::from_slice::<AuthResp>(&buf)
            .ok()
            .and_then(|r| r.auth)
            .filter(|a| !a.client_token.is_empty())
            .ok_or_else(|| {
                crate::errors::unusable_response(
                    OP,
                    &self.alias,
                    Some(status.as_u16()),
                    "login response carries no token",
                )
            })?;
        Ok(Lease {
            token: Token::new(auth.client_token),
            duration: Duration::from_secs(auth.lease_duration).min(MAX_LEASE),
            renewable: auth.renewable,
            obtained: Instant::now(),
        })
    }
}

impl TokenSource for LoginSource {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        Box::pin(async move {
            let rejected = self.take_rejected();
            let step = self.state().plan(Instant::now(), rejected.as_ref());
            let forced = match step {
                Step::Done(r) => return r,
                Step::Refresh { forced, .. } => forced,
            };
            // The limit and the report are only used up once the login finishes.
            let mut pending = PendingRejection {
                slot: &self.rejected,
                token: rejected.filter(|_| forced),
            };
            // One login or renewal at a time: wait for the one running (bounded), whose outcome
            // may answer this request too, so decide again after.
            let _flight = self.enter().await;
            let now = Instant::now();
            let rejected = pending.token.take().or_else(|| self.take_rejected());
            let step = self.state().plan(now, rejected.as_ref());
            let (renew, forced, generation) = match step {
                Step::Done(r) => return r,
                Step::Refresh {
                    renew,
                    forced,
                    generation,
                } => (renew, forced, generation),
            };
            pending.token = rejected.filter(|_| forced);
            if let Some((token, previous)) = renew {
                match self.renew(&token).await {
                    // Renewal near the max TTL returns only the remaining time: once that is
                    // under half the previous lease, log in again below instead of renewing
                    // into ever shorter leases.
                    Ok(new) if new.duration >= previous / 2 => {
                        let token = new.token.clone();
                        let mut state = self.state();
                        // Unless a newer token was stored meanwhile (see `State::generation`).
                        if state.generation == generation {
                            state.store(new);
                            state.retry_at = None;
                        }
                        return Ok(Some(token));
                    }
                    // A failed renewal was logged in its token span; log in again below.
                    Ok(_) | Err(_) => {}
                }
            }
            let result = self.login().await;
            pending.token = None;
            let mut state = self.state();
            if forced {
                state.last_forced = Some(now);
            }
            let now = Instant::now();
            if state.generation != generation {
                // This login stalled while a request that stopped waiting for it stored a newer
                // token: keep that one, and this login's outcome out of the state.
                return match (result, state.lease.as_ref()) {
                    (Ok(new), _) => Ok(Some(new.token)),
                    (Err(_), Some(l)) if !l.expired(now) => Ok(Some(l.token.clone())),
                    (Err(e), _) => Err(e),
                };
            }
            match result {
                Ok(new) => {
                    let token = new.token.clone();
                    state.store(new);
                    state.retry_at = None;
                    state.last_error = None;
                    Ok(Some(token))
                }
                Err(e) => {
                    match state.lease.as_ref() {
                        // Still valid: keep using it (and stop retrying for a while) rather
                        // than fail the request. A token a 403 rejected is kept too: the
                        // caller sees it unchanged and reports the 403.
                        Some(l) if !l.expired(now) => {
                            // The failure itself was logged (warn) in the login's token span.
                            #[cfg(feature = "tracing")]
                            tracing::debug!(
                                backend = BACKEND,
                                server_alias = %self.alias,
                                error_kind = e.kind().as_str(),
                                "login failed; using the current token until it expires"
                            );
                            let token = l.token.clone();
                            state.retry_at = Some(now + REFRESH_BACKOFF);
                            Ok(Some(token))
                        }
                        _ => {
                            state.retry_at = Some(now + REFRESH_BACKOFF);
                            state.last_error = Some(e.clone());
                            Err(e)
                        }
                    }
                }
            }
        })
    }

    fn invalidate(&self, rejected: &Token) {
        *self
            .rejected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(rejected.clone());
    }
}
