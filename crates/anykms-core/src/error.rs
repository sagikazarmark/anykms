//! One error taxonomy for every backend.
//!
//! Errors never carry plaintext, AAD, tokens, data keys, request bodies or URL query strings.
//! Backends construct them from fixed messages and from [`BackendDetail`], whose server message is
//! either a known, pinned message or a redacted fingerprint.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Result alias used throughout anykms.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What went wrong, independent of the backend.
///
/// Every kind falls in exactly one of three classes, so callers can decide what to do without
/// matching on kinds:
///
/// | Kind | Class | Typical cause |
/// |---|---|---|
/// | [`NotFound`](Self::NotFound) | [config](Self::is_config_error) | wrong key name or mount in the configuration |
/// | [`PermissionDenied`](Self::PermissionDenied) | [config](Self::is_config_error) | policy does not grant the operation |
/// | [`Unauthenticated`](Self::Unauthenticated) | [config](Self::is_config_error) | credentials missing, expired or revoked |
/// | [`KeyStateInvalid`](Self::KeyStateInvalid) | [config](Self::is_config_error) | key disabled or scheduled for deletion |
/// | [`KeyMismatch`](Self::KeyMismatch) | [config](Self::is_config_error) | key type or algorithm cannot do the operation |
/// | [`Unsupported`](Self::Unsupported) | [config](Self::is_config_error) | backend, flavor or key lacks the capability |
/// | [`Configuration`](Self::Configuration) | [config](Self::is_config_error) | client configuration is wrong |
/// | [`InvalidArgument`](Self::InvalidArgument) | [caller](Self::is_caller_error) | malformed input (wrong digest length, payload too large) |
/// | [`DecryptFailed`](Self::DecryptFailed) | [caller](Self::is_caller_error) | wrong AAD, tampered or foreign ciphertext |
/// | [`VerificationFailed`](Self::VerificationFailed) | [caller](Self::is_caller_error) | signature or tag does not match |
/// | [`KeyVersionUnusable`](Self::KeyVersionUnusable) | [caller](Self::is_caller_error) | the input's key version is below the minimum decryption version, disabled or destroyed |
/// | [`UnknownKeyVersion`](Self::UnknownKeyVersion) | [caller](Self::is_caller_error) | the input names a key version this key does not have (an untrusted `kid`, a stale reference) |
/// | [`Throttled`](Self::Throttled) | [retryable](Self::is_retryable) | rate limit |
/// | [`Unavailable`](Self::Unavailable) | [retryable](Self::is_retryable) | sealed, standby, network failure |
/// | [`Timeout`](Self::Timeout) | [retryable](Self::is_retryable) | client-side timeout |
/// | [`Backend`](Self::Backend) | [config](Self::is_config_error) | unclassified server error, unusable response, internal failure |
///
/// Config errors need an operator (fix the configuration, policy or key, or investigate the
/// backend); retrying or changing the input does not help. Caller errors depend on the input of
/// one request: report them to whoever supplied it, do not page anyone.
///
/// The class depends on the kind alone, never on the operation: [`Error::is_config_error`] and
/// [`Error::is_caller_error`] equal these methods for the error's kind. Backends keep the
/// classes apart by choosing the kind. A key version the handle chose itself (its URI pin, or the
/// current or primary version) that cannot be used is
/// [`KeyStateInvalid`](Self::KeyStateInvalid) (config) for every operation; a version taken from
/// the input is [`KeyVersionUnusable`](Self::KeyVersionUnusable) or
/// [`UnknownKeyVersion`](Self::UnknownKeyVersion) (caller), or
/// [`VerificationFailed`](Self::VerificationFailed) when verifying. [`Error::class`] adds the
/// [retry hint](Error::retry_hint) to the picture.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The key (or mount) does not exist.
    NotFound,
    /// The credentials are not allowed to perform the operation.
    PermissionDenied,
    /// The backend did not accept the credentials at all: missing, malformed, expired or revoked
    /// (HTTP 401, AWS `UnrecognizedClientException`/`ExpiredTokenException`, gRPC
    /// `UNAUTHENTICATED`). Unlike [`PermissionDenied`](Self::PermissionDenied), the identity is
    /// unknown, not the policy wrong.
    ///
    /// A config error, not retryable: client libraries refresh credentials before a request, so
    /// a rejected credential that reaches the caller needs an operator (renew the token, fix the
    /// credential source, check Agent or workload-identity health). Transit reports this kind for 401 and for 403
    /// responses that name the token as invalid (Vault adds `invalid token`); OpenBao answers a bad
    /// token with a plain 403 `permission denied`, indistinguishable from a policy denial, which
    /// stays [`PermissionDenied`](Self::PermissionDenied).
    Unauthenticated,
    /// The key exists but cannot be used (disabled, pending deletion), or the key version the
    /// handle chose (its URI pin, or the current or primary version) cannot be used, for every
    /// operation, [`public_key`](crate::PublicKeys::public_key) included.
    ///
    /// A config error: the deployment uses that key or version. When the key is fine but a
    /// version taken from the *input* is unusable, the kind is
    /// [`KeyVersionUnusable`](Self::KeyVersionUnusable) instead.
    KeyStateInvalid,
    /// Decryption failed: wrong key, wrong AAD, tampered or truncated ciphertext. These causes are
    /// deliberately indistinguishable.
    DecryptFailed,
    /// A signature or MAC did not verify.
    VerificationFailed,
    /// The request was malformed: payload too large, digest of the wrong length or algorithm,
    /// unparsable signature, and similar.
    InvalidArgument,
    /// The key's type or algorithm does not support the operation or algorithm asked for (e.g. an
    /// AEAD key opened as a MAC key, or an ECDSA P-256 key opened for P-384 signatures). A
    /// deployment problem, unlike [`InvalidArgument`](Self::InvalidArgument).
    KeyMismatch,
    /// The backend, key or flavor does not support the capability or parameter.
    Unsupported,
    /// The client configuration is wrong: unknown server alias, namespace not found, disallowed
    /// mount, insecure transport.
    Configuration,
    /// The backend rate-limited the request.
    Throttled,
    /// The backend is temporarily unavailable (sealed, standby, network failure).
    Unavailable,
    /// The request timed out on the client side.
    Timeout,
    /// An unclassified backend error: a server error no mapping recognizes, a response that
    /// cannot be used (undecodable or oversized), or an internal failure.
    ///
    /// A config error: an operator has to look at the backend (server logs, versions) or report
    /// the unrecognized error; nothing suggests that retrying helps (known transient server
    /// errors are [`Unavailable`](Self::Unavailable)), and it does not depend on the input.
    Backend,
    /// The key is usable, but a key version taken from the input (the version that produced a
    /// ciphertext, signature or tag, or one the caller names) is not: below the minimum decryption
    /// version, or disabled or destroyed on its own.
    ///
    /// Always a caller error, unlike [`KeyStateInvalid`](Self::KeyStateInvalid): it depends on
    /// the input (old data), not on the deployment, and other requests with the same key keep
    /// working. The usual fix is to rewrap or re-sign data before raising the minimum version.
    /// A version the handle chose itself (a pinned version that was disabled) is
    /// `KeyStateInvalid`, never this kind.
    KeyVersionUnusable,
    /// The input names a key version this key does not have, or another key's version (an
    /// untrusted `kid`, a stale reference), e.g. in
    /// [`public_key_version`](crate::PublicKeys::public_key_version). A malformed version is
    /// [`InvalidArgument`](Self::InvalidArgument), and verifying with an unknown version is
    /// [`VerificationFailed`](Self::VerificationFailed).
    ///
    /// A caller error. It may carry a [retry hint](Error::retry_hint) when the version may not
    /// have replicated yet; [`Error::class`] is still [`Caller`](ErrorClass::Caller). Backends
    /// never drop cached key metadata because of it.
    UnknownKeyVersion,
}

impl ErrorKind {
    /// A short, stable, lowercase name, suitable for logs and metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::NotFound => "not_found",
            ErrorKind::PermissionDenied => "permission_denied",
            ErrorKind::Unauthenticated => "unauthenticated",
            ErrorKind::KeyStateInvalid => "key_state_invalid",
            ErrorKind::DecryptFailed => "decrypt_failed",
            ErrorKind::VerificationFailed => "verification_failed",
            ErrorKind::InvalidArgument => "invalid_argument",
            ErrorKind::KeyMismatch => "key_mismatch",
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::Configuration => "configuration",
            ErrorKind::Throttled => "throttled",
            ErrorKind::Unavailable => "unavailable",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Backend => "backend",
            ErrorKind::KeyVersionUnusable => "key_version_unusable",
            ErrorKind::UnknownKeyVersion => "unknown_key_version",
        }
    }

    /// Whether an operation that failed with this kind may succeed when retried.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ErrorKind::Throttled | ErrorKind::Unavailable | ErrorKind::Timeout
        )
    }

    /// Whether this kind points at the deployment (configuration, policy, key setup) rather than
    /// the request; see the [table](Self).
    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            ErrorKind::NotFound
                | ErrorKind::PermissionDenied
                | ErrorKind::Unauthenticated
                | ErrorKind::KeyStateInvalid
                | ErrorKind::KeyMismatch
                | ErrorKind::Unsupported
                | ErrorKind::Configuration
                | ErrorKind::Backend
        )
    }

    /// Whether this kind is caused by the input of the failed request (malformed arguments,
    /// ciphertexts that do not decrypt, signatures that do not verify, data on an unusable or
    /// unknown key version); see the [table](Self).
    pub fn is_caller_error(&self) -> bool {
        matches!(
            self,
            ErrorKind::InvalidArgument
                | ErrorKind::DecryptFailed
                | ErrorKind::VerificationFailed
                | ErrorKind::KeyVersionUnusable
                | ErrorKind::UnknownKeyVersion
        )
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The operation that failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    Encrypt,
    Decrypt,
    Rewrap,
    GenerateDataKey,
    Sign,
    Verify,
    Mac,
    VerifyMac,
    PublicKey,
    Describe,
    /// Opening a key handle.
    Open,
    /// Building a provider or registry.
    Configure,
    /// Building a value type (e.g. [`Digest`](crate::Digest)) from caller-supplied parts, outside
    /// any key operation.
    Construct,
    /// Application code reporting its own failure with an anykms error (see [`Error::app`]).
    App,
    /// Parsing a key URI ([`KeyUri::parse`](crate::KeyUri::parse), or a provider's own grammar).
    /// Key URIs come from configuration, so these errors are
    /// [`Configuration`](ErrorKind::Configuration); applications that accept URIs from users
    /// recognize them by this operation.
    ParseUri,
    /// Wrapping key material under a key-wrapping key ([`KeyWrap::wrap_key`](crate::KeyWrap::wrap_key)).
    WrapKey,
    /// Unwrapping key material ([`KeyWrap::unwrap_key`](crate::KeyWrap::unwrap_key)).
    UnwrapKey,
}

impl Operation {
    /// A short, stable, lowercase name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Encrypt => "encrypt",
            Operation::Decrypt => "decrypt",
            Operation::Rewrap => "rewrap",
            Operation::GenerateDataKey => "generate_data_key",
            Operation::Sign => "sign",
            Operation::Verify => "verify",
            Operation::Mac => "mac",
            Operation::VerifyMac => "verify_mac",
            Operation::PublicKey => "public_key",
            Operation::Describe => "describe",
            Operation::Open => "open",
            Operation::Configure => "configure",
            Operation::Construct => "construct",
            Operation::App => "app",
            Operation::ParseUri => "parse_uri",
            Operation::WrapKey => "wrap_key",
            Operation::UnwrapKey => "unwrap_key",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A server-provided error message, as far as it is safe to keep.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMessage {
    /// A message the backend recognizes (pinned by tests); kept verbatim.
    Known(Cow<'static, str>),
    /// Any other message, reduced to its length and a short hash fingerprint so that it can be
    /// correlated with server logs without leaking content. Build it with
    /// [`ServerMessage::redacted`]; fields may be added.
    #[non_exhaustive]
    Redacted {
        /// Length of the original message in bytes.
        len: usize,
        /// Hex-encoded prefix of a cryptographic hash of the message.
        fingerprint: String,
    },
}

impl ServerMessage {
    /// A [`Redacted`](Self::Redacted) message: the original message's length in bytes and a
    /// hex-encoded fingerprint (a prefix of a keyed or cryptographic hash, never content).
    pub fn redacted(len: usize, fingerprint: impl Into<String>) -> Self {
        ServerMessage::Redacted {
            len,
            fingerprint: fingerprint.into(),
        }
    }
}

impl fmt::Display for ServerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerMessage::Known(m) => write!(f, "{m:?}"),
            ServerMessage::Redacted { len, fingerprint } => {
                write!(f, "<redacted {len} bytes, fp {fingerprint}>")
            }
        }
    }
}

/// Backend-specific context attached to an error. Never contains input data.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackendDetail {
    /// HTTP status, for HTTP-based backends.
    pub http_status: Option<u16>,
    /// The server's message, verbatim if known, redacted otherwise.
    pub server_message: Option<ServerMessage>,
    /// The server's request ID (AWS `x-amzn-RequestId`, Vault's `request_id`, ...), to correlate
    /// with server logs and support cases. Shown in `Display`.
    pub request_id: Option<String>,
    /// A backend-native error code: an AWS exception name (`"KMSInvalidStateException"`), a gRPC
    /// status code (`"FAILED_PRECONDITION"`), an Azure error code. Stable identifiers only, never
    /// free-form messages (those go in [`server_message`](Self::server_message)).
    pub code: Option<Cow<'static, str>>,
}

impl BackendDetail {
    /// An empty detail.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the HTTP status.
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    /// Sets the server message.
    pub fn with_server_message(mut self, message: ServerMessage) -> Self {
        self.server_message = Some(message);
        self
    }

    /// Sets the server's request ID.
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Sets the backend-native error code.
    pub fn with_code(mut self, code: impl Into<Cow<'static, str>>) -> Self {
        self.code = Some(code.into());
        self
    }

    /// The server's request ID, if known.
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// The backend-native error code, if any.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The anykms error.
///
/// Construct with [`Error::new`] and the `with_*` builders. The message must be a fixed, non-secret
/// description. Cheap to clone: the source error is shared.
#[non_exhaustive]
#[derive(Clone)]
pub struct Error {
    kind: ErrorKind,
    backend: &'static str,
    op: Operation,
    message: Cow<'static, str>,
    resource: Option<Box<str>>,
    detail: Option<Box<BackendDetail>>,
    retry_after: Option<Duration>,
    retry_hint: Option<Duration>,
    source: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// Creates an error; the constructor for backends and recipes. Application code usually wants
    /// [`app`](Self::app) or a shorthand such as [`invalid_argument`](Self::invalid_argument).
    /// `message` must not contain secrets.
    pub fn new(
        kind: ErrorKind,
        backend: &'static str,
        op: Operation,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            kind,
            backend,
            op,
            message: message.into(),
            resource: None,
            detail: None,
            retry_after: None,
            retry_hint: None,
            source: None,
        }
    }

    /// An error raised by application code (backend `"app"`, operation [`Operation::App`]), e.g.
    /// to report a domain failure through the same type as KMS errors. Re-label the operation
    /// with [`with_operation`](Self::with_operation) where useful. `message` must not contain
    /// secrets.
    pub fn app(kind: ErrorKind, message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(kind, "app", Operation::App, message)
    }

    /// [`app`](Self::app) error of kind [`ErrorKind::InvalidArgument`]: the caller's input is
    /// malformed. Backends use [`new`](Self::new) with their backend name and operation instead.
    pub fn invalid_argument(message: impl Into<Cow<'static, str>>) -> Self {
        Self::app(ErrorKind::InvalidArgument, message)
    }

    /// [`app`](Self::app) error of kind [`ErrorKind::Unsupported`].
    pub fn unsupported(message: impl Into<Cow<'static, str>>) -> Self {
        Self::app(ErrorKind::Unsupported, message)
    }

    /// [`app`](Self::app) error of kind [`ErrorKind::KeyMismatch`].
    pub fn key_mismatch(message: impl Into<Cow<'static, str>>) -> Self {
        Self::app(ErrorKind::KeyMismatch, message)
    }

    /// Attaches backend detail.
    pub fn with_detail(mut self, detail: BackendDetail) -> Self {
        self.detail = Some(Box::new(detail));
        self
    }

    /// Attaches a server-requested minimum retry delay.
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Marks an error whose kind is not retryable as worth one retry after at least `delay`: the
    /// backend knows the condition is often transient (a key or version not yet replicated to the
    /// node that answered, a key version still being generated) but cannot tell it from the
    /// permanent one. [`Retry`](crate::Retry) acts on it only with
    /// [`RetryPolicy::retry_on_hint`](crate::RetryPolicy::retry_on_hint), see
    /// [`retry_hint`](Self::retry_hint).
    pub fn with_retry_hint(mut self, delay: Duration) -> Self {
        self.retry_hint = Some(delay);
        self
    }

    /// Attaches a source error. The caller must make sure its `Display`/`Debug` output (and its
    /// own sources) cannot contain secrets.
    pub fn with_source(mut self, source: impl Into<BoxError>) -> Self {
        self.source = Some(Arc::from(source.into()));
        self
    }

    /// Names the resource the failed operation was about, typically the key URI. `Display` shows
    /// it after the operation: `transit encrypt [hashivault:///transit/keys/app]: not_found: ...`.
    /// Replaces an earlier resource.
    ///
    /// **Must never contain secrets.** Pass identifiers that are safe to log (key URIs without
    /// query strings, key names, ARNs), never tokens, credentials, request bodies or anything
    /// derived from plaintext or AAD.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into().into_boxed_str());
        self
    }

    /// Replaces the operation (used by wrappers that re-label errors).
    pub fn with_operation(mut self, op: Operation) -> Self {
        self.op = op;
        self
    }

    /// The error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The backend that produced the error (e.g. `"transit"`, `"local"`, `"envelope"`).
    pub fn backend(&self) -> &'static str {
        self.backend
    }

    /// The failed operation.
    pub fn operation(&self) -> Operation {
        self.op
    }

    /// The fixed, non-secret message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The resource (e.g. key URI) the failed operation was about, if known; see
    /// [`with_resource`](Self::with_resource).
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    /// Backend detail, if any.
    pub fn detail(&self) -> Option<&BackendDetail> {
        self.detail.as_deref()
    }

    /// Whether the operation may succeed when retried ([`ErrorKind::is_retryable`]).
    pub fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }

    /// Whether the deployment is at fault: [`ErrorKind::is_config_error`] of the error's kind,
    /// whatever the operation (see the [error table](ErrorKind)).
    pub fn is_config_error(&self) -> bool {
        self.kind.is_config_error()
    }

    /// Whether the request's input is at fault: [`ErrorKind::is_caller_error`] of the error's
    /// kind, whatever the operation and whether or not it carries a
    /// [retry hint](Self::retry_hint).
    pub fn is_caller_error(&self) -> bool {
        self.kind.is_caller_error()
    }

    /// Server-requested minimum delay before retrying, if any.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// The backend's hint that this error, although its kind is not retryable, may go away when
    /// the request is repeated once after at least this delay (see
    /// [`with_retry_hint`](Self::with_retry_hint)). Errors of a retryable kind follow the normal
    /// backoff and [`retry_after`](Self::retry_after) instead; [`Retry`](crate::Retry) ignores
    /// their hint.
    pub fn retry_hint(&self) -> Option<Duration> {
        self.retry_hint
    }

    /// What the caller should do with this error, in one value: the classification of the
    /// [error table](ErrorKind), with the [retry hint](Self::retry_hint) checked before the
    /// retryable and config classes.
    ///
    /// A caller-class error is always [`Caller`](ErrorClass::Caller), even with a hint: the
    /// input may name a version that has not replicated yet, but it may as well be forged (a
    /// `kid` such as `vault:v999999:`), so it must not turn into a 503. It keeps its hint in
    /// [`retry_hint`](Self::retry_hint), and [`Retry`](crate::Retry) still honors it. Other
    /// hinted errors have kinds that are not retryable, so matching on
    /// [`is_retryable`](Self::is_retryable) and friends alone misses them; `class` encodes the
    /// order. A service answering HTTP requests can map the classes like this (the
    /// `docs/operations.md` table):
    ///
    /// ```
    /// use anykms_core::{Error, ErrorClass};
    ///
    /// /// The status code and `Retry-After` seconds for an error out of the retry layer.
    /// fn http_status(e: &Error, verifying_caller_token: bool) -> (u16, Option<u64>) {
    ///     let secs = |d: std::time::Duration| d.as_secs() + u64::from(d.subsec_nanos() > 0);
    ///     match e.class() {
    ///         ErrorClass::Hinted(d) => (503, Some(secs(d))),
    ///         ErrorClass::Retryable(d) => (503, d.map(secs)),
    ///         ErrorClass::Config => (500, None),
    ///         ErrorClass::Caller if verifying_caller_token => (401, None),
    ///         ErrorClass::Caller => (400, None),
    ///         _ => (500, None),
    ///     }
    /// }
    /// # let e = Error::invalid_argument("bad");
    /// # assert_eq!(http_status(&e, false), (400, None));
    /// ```
    pub fn class(&self) -> ErrorClass {
        if self.is_caller_error() {
            ErrorClass::Caller
        } else if let Some(h) = self.retry_hint {
            ErrorClass::Hinted(h)
        } else if self.is_retryable() {
            ErrorClass::Retryable(self.retry_after)
        } else {
            ErrorClass::Config
        }
    }
}

/// The class of an [`Error`], from [`Error::class`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// The backend hinted that the condition is usually transient although its kind is not
    /// retryable (a key not yet replicated to the node that answered, a key version still being
    /// generated); retry after at least this delay. A hinted error that keeps coming back is the
    /// permanent condition. Never a caller-class error, whose hint stays in
    /// [`Error::retry_hint`] only. See [`Error::retry_hint`].
    Hinted(Duration),
    /// Transient: retry with backoff, after at least the server-requested delay if any
    /// ([`Error::retry_after`]).
    Retryable(Option<Duration>),
    /// The deployment is at fault (configuration, policy, key, credentials, backend): an operator
    /// must act. See [`Error::is_config_error`].
    Config,
    /// The request's input is at fault: report it to whoever sent it, also when it carries a
    /// retry hint. See [`Error::is_caller_error`].
    Caller,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.backend)?;
        // `Operation::App` adds nothing to the backend (normally `"app"` too): print it once.
        if self.op != Operation::App {
            write!(f, " {}", self.op)?;
        }
        if let Some(r) = &self.resource {
            write!(f, " [{r}]")?;
        }
        write!(f, ": {}: {}", self.kind, self.message)?;
        if let Some(d) = &self.detail {
            if let Some(s) = d.http_status {
                write!(f, " (http {s})")?;
            }
            if let Some(m) = &d.server_message {
                write!(f, " (server: {m})")?;
            }
            if let Some(id) = &d.request_id {
                write!(f, " (request id {id})")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Error");
        d.field("kind", &self.kind)
            .field("backend", &self.backend)
            .field("op", &self.op)
            .field("message", &self.message);
        if let Some(r) = &self.resource {
            d.field("resource", r);
        }
        if let Some(detail) = &self.detail {
            d.field("detail", detail);
        }
        if let Some(r) = &self.retry_after {
            d.field("retry_after", r);
        }
        if let Some(h) = &self.retry_hint {
            d.field("retry_hint", h);
        }
        if let Some(s) = &self.source {
            d.field("source", s);
        }
        d.finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| &**s as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_retryable() {
        let e = Error::new(
            ErrorKind::Throttled,
            "transit",
            Operation::Encrypt,
            "rate limited",
        )
        .with_detail(BackendDetail::new().with_http_status(429))
        .with_retry_after(Duration::from_secs(1));
        assert!(e.is_retryable());
        assert_eq!(
            e.to_string(),
            "transit encrypt: throttled: rate limited (http 429)"
        );
        assert!(!Error::new(ErrorKind::DecryptFailed, "x", Operation::Decrypt, "m").is_retryable());
    }

    #[test]
    fn classes_are_disjoint() {
        let all = [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::Unauthenticated,
            ErrorKind::KeyStateInvalid,
            ErrorKind::DecryptFailed,
            ErrorKind::VerificationFailed,
            ErrorKind::InvalidArgument,
            ErrorKind::KeyMismatch,
            ErrorKind::Unsupported,
            ErrorKind::Configuration,
            ErrorKind::Throttled,
            ErrorKind::Unavailable,
            ErrorKind::Timeout,
            ErrorKind::Backend,
            ErrorKind::KeyVersionUnusable,
            ErrorKind::UnknownKeyVersion,
        ];
        let ops = [
            Operation::Encrypt,
            Operation::Decrypt,
            Operation::Rewrap,
            Operation::GenerateDataKey,
            Operation::Sign,
            Operation::Verify,
            Operation::Mac,
            Operation::VerifyMac,
            Operation::PublicKey,
            Operation::Describe,
            Operation::Open,
            Operation::Configure,
            Operation::Construct,
            Operation::App,
            Operation::ParseUri,
            Operation::WrapKey,
            Operation::UnwrapKey,
        ];
        for k in all {
            let n = [k.is_retryable(), k.is_config_error(), k.is_caller_error()]
                .iter()
                .filter(|b| **b)
                .count();
            assert_eq!(n, 1, "{k}");
            // An error's class is its kind's, whatever its operation.
            for op in ops {
                let e = Error::new(k, "t", op, "m");
                assert_eq!(
                    [e.is_retryable(), e.is_config_error(), e.is_caller_error()],
                    [k.is_retryable(), k.is_config_error(), k.is_caller_error()],
                    "{k} {op}"
                );
            }
        }
        assert!(ErrorKind::Backend.is_config_error());
        assert!(Error::new(ErrorKind::Backend, "t", Operation::Decrypt, "m").is_config_error());
        // An unusable or unknown version is the caller's for every operation: a version the
        // handle chose is KeyStateInvalid instead.
        for op in ops {
            for k in [ErrorKind::KeyVersionUnusable, ErrorKind::UnknownKeyVersion] {
                let e = Error::new(k, "t", op, "m");
                assert!(e.is_caller_error() && !e.is_config_error(), "{k} {op}");
            }
            let e = Error::new(ErrorKind::KeyStateInvalid, "t", op, "m");
            assert!(e.is_config_error() && !e.is_caller_error(), "{op}");
        }
        assert!(ErrorKind::KeyMismatch.is_config_error());
        assert!(ErrorKind::InvalidArgument.is_caller_error());
        assert!(ErrorKind::KeyVersionUnusable.is_caller_error());
        assert!(ErrorKind::KeyStateInvalid.is_config_error());
        assert!(ErrorKind::UnknownKeyVersion.is_caller_error());
        assert_eq!(
            ErrorKind::KeyVersionUnusable.as_str(),
            "key_version_unusable"
        );
        assert_eq!(ErrorKind::UnknownKeyVersion.as_str(), "unknown_key_version");
        assert_eq!(Operation::WrapKey.as_str(), "wrap_key");
        assert_eq!(Operation::UnwrapKey.as_str(), "unwrap_key");
    }

    #[test]
    fn resource_request_id_and_code() {
        let e = Error::new(
            ErrorKind::NotFound,
            "transit",
            Operation::Encrypt,
            "key not found",
        )
        .with_resource("hashivault://default/transit/keys/app")
        .with_detail(
            BackendDetail::new()
                .with_http_status(404)
                .with_request_id("req-1")
                .with_code("NotFoundException"),
        );
        assert_eq!(e.resource(), Some("hashivault://default/transit/keys/app"));
        assert_eq!(
            e.to_string(),
            "transit encrypt [hashivault://default/transit/keys/app]: not_found: key not found \
             (http 404) (request id req-1)"
        );
        let d = e.detail().unwrap();
        assert_eq!(
            (d.request_id(), d.code()),
            (Some("req-1"), Some("NotFoundException"))
        );
        let dbg = format!("{e:?}");
        assert!(
            dbg.contains("resource") && dbg.contains("NotFoundException"),
            "{dbg}"
        );
        let e = Error::app(ErrorKind::NotFound, "no user").with_resource("users/42");
        assert_eq!(e.to_string(), "app [users/42]: not_found: no user");
        assert_eq!(
            ServerMessage::redacted(3, "abcd").to_string(),
            "<redacted 3 bytes, fp abcd>"
        );
    }

    #[test]
    fn class_checks_the_hint_first() {
        let d = Duration::from_millis(500);
        let e = Error::new(ErrorKind::NotFound, "t", Operation::Decrypt, "m");
        assert_eq!(e.class(), ErrorClass::Config);
        assert_eq!(e.clone().with_retry_hint(d).class(), ErrorClass::Hinted(d));
        let e = Error::new(ErrorKind::Throttled, "t", Operation::Sign, "m");
        assert_eq!(e.class(), ErrorClass::Retryable(None));
        assert_eq!(
            e.with_retry_after(d).class(),
            ErrorClass::Retryable(Some(d))
        );
        assert_eq!(Error::invalid_argument("m").class(), ErrorClass::Caller);
        // KeyVersionUnusable is Caller whatever the operation.
        for op in [Operation::Encrypt, Operation::Decrypt, Operation::Sign] {
            let e = Error::new(ErrorKind::KeyVersionUnusable, "t", op, "m");
            assert_eq!(e.class(), ErrorClass::Caller, "{op}");
        }
        let e = Error::new(ErrorKind::KeyStateInvalid, "t", Operation::Encrypt, "m");
        assert_eq!(e.class(), ErrorClass::Config);
        let e = Error::new(ErrorKind::Unauthenticated, "t", Operation::Sign, "m");
        assert_eq!(e.class(), ErrorClass::Config);
        assert!(!e.is_retryable());
    }

    /// A hint never lifts a caller-class error out of `Caller` (a forged `kid` must not become a
    /// 503), but the hint stays readable for `Retry`.
    #[test]
    fn caller_class_errors_ignore_the_hint_in_class() {
        let d = Duration::from_secs(1);
        for k in [
            ErrorKind::UnknownKeyVersion,
            ErrorKind::KeyVersionUnusable,
            ErrorKind::InvalidArgument,
            ErrorKind::VerificationFailed,
            ErrorKind::DecryptFailed,
        ] {
            let e = Error::new(k, "t", Operation::PublicKey, "m").with_retry_hint(d);
            assert_eq!(e.class(), ErrorClass::Caller, "{k}");
            assert!(e.is_caller_error(), "{k}");
            assert_eq!(e.retry_hint(), Some(d), "{k}");
        }
        // Every other class with a hint is Hinted.
        for k in [
            ErrorKind::NotFound,
            ErrorKind::KeyStateInvalid,
            ErrorKind::Backend,
            ErrorKind::Unavailable,
        ] {
            let e = Error::new(k, "t", Operation::Encrypt, "m").with_retry_hint(d);
            assert_eq!(e.class(), ErrorClass::Hinted(d), "{k}");
        }
    }

    #[test]
    fn app_shorthands() {
        let e = Error::invalid_argument("malformed token");
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        assert_eq!(e.backend(), "app");
        assert_eq!(e.to_string(), "app: invalid_argument: malformed token");
        assert_eq!(Error::unsupported("x").kind(), ErrorKind::Unsupported);
        assert_eq!(Error::key_mismatch("x").kind(), ErrorKind::KeyMismatch);
    }

    #[test]
    fn clone_keeps_source_and_app_errors() {
        let inner = Error::new(ErrorKind::Unavailable, "t", Operation::Sign, "down");
        let e = Error::app(ErrorKind::Backend, "wrapped").with_source(inner);
        let c = e.clone();
        assert_eq!(c.backend(), "app");
        assert_eq!(c.operation(), Operation::App);
        let src = std::error::Error::source(&c)
            .and_then(|s| s.downcast_ref::<Error>())
            .unwrap();
        assert_eq!(src.kind(), ErrorKind::Unavailable);
    }

    #[test]
    fn app_errors_display_without_repeating_app() {
        let e = Error::app(ErrorKind::InvalidArgument, "malformed token");
        assert_eq!(e.to_string(), "app: invalid_argument: malformed token");
        let e = e.with_operation(Operation::Verify);
        assert_eq!(
            e.to_string(),
            "app verify: invalid_argument: malformed token"
        );
    }
}
