//! Mapping of Cloud KMS REST errors (`google.rpc.Status` as JSON) to [`ErrorKind`]s (the plan's
//! §7 table, `docs/cloud/gcp.md`).
//!
//! Error bodies look like `{"error": {"code": 400, "message": "...", "status":
//! "FAILED_PRECONDITION", "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
//! "reason": "..."}, ...]}}`. The canonical `status` decides when present, the HTTP status
//! otherwise. Messages are matched case-insensitively as substrings, and only where the status
//! alone is ambiguous (decrypt failures, checksum mismatches, version states, purpose
//! mismatches). Each pinned message is listed in [`KNOWN`] and covered by the mock tests; the
//! live texts are recorded by the probe (`scripts/probe-gcp.sh`, baseline in
//! `scripts/probe-baseline/gcp/`). Unknown
//! messages are never echoed: they are reduced to a keyed fingerprint ([`redact`]), and
//! unclassified errors fall back to [`ErrorKind::Backend`] (less specific, never misclassified).

use std::time::Duration;

use anykms_core::{BackendDetail, Error, ErrorKind, Operation, ServerMessage};
use anykms_http::redact::{Pinned, contains_ci};
use serde::Deserialize;

use crate::BACKEND;
use crate::handles::Origin;

/// The retry hint for a version that is still being generated or imported.
pub(crate) const PENDING_VERSION_HINT: Duration = Duration::from_secs(2);

/// Messages (or message prefixes) that are safe to keep verbatim: they never echo request input.
/// The fragment is kept, not the whole message (which may name resources).
pub(crate) const KNOWN: &[&str] = &[
    // "Decryption failed.", "Decryption failed: the ciphertext is invalid." (§24.4 probe T1) and
    // "Decryption failed: verify that 'name' refers to the correct CryptoKey." ([S17]).
    "Decryption failed",
    "is not enabled, current state is: ",
    "checksum",
    "incorrect key purpose",
    "denied on resource",
    "(or it may not exist)",
    "Request is prohibited by organization's policy",
    "Request had invalid authentication credentials",
    "Quota exceeded",
];

/// Version states named by `FAILED_PRECONDITION` "… is not enabled, current state is: <STATE>".
const UNUSABLE_STATES: &[&str] = &["DISABLED", "DESTROYED", "DESTROY_SCHEDULED"];
const PENDING_STATES: &[&str] = &["PENDING_GENERATION", "PENDING_IMPORT"];

/// A key version that is not `ENABLED` (from a `FAILED_PRECONDITION` "… current state is:
/// <STATE>" or from the version-state lookup before `getPublicKey`), by where the version came
/// from (A3): the version the handle chose (its URI pin, or the primary version encrypt uses) is
/// [`ErrorKind::KeyStateInvalid`] (config: the deployment uses it); a version taken from the
/// input (a ciphertext, signature or tag, `public_key_version`) is
/// [`ErrorKind::KeyVersionUnusable`] (caller). A version still being generated or imported
/// adds [`PENDING_VERSION_HINT`].
fn unusable_version(origin: Origin, pending: bool) -> (ErrorKind, &'static str, Option<Duration>) {
    let kind = match origin {
        Origin::Handle => ErrorKind::KeyStateInvalid,
        Origin::Ciphertext | Origin::Input => ErrorKind::KeyVersionUnusable,
    };
    match (origin, pending) {
        (_, true) => (
            kind,
            "the key version is still being generated or imported",
            Some(PENDING_VERSION_HINT),
        ),
        (Origin::Handle, false) => (
            kind,
            "the key version this handle uses is not enabled (disabled, destroyed or scheduled \
             for destruction)",
            None,
        ),
        (_, false) => (
            kind,
            "the key version is not enabled (disabled, destroyed or scheduled for destruction)",
            None,
        ),
    }
}

/// The error for a version whose `cryptoKeyVersions.get` reports `state` (anything but
/// `ENABLED`), see [`unusable_version`]. The state itself is not echoed.
pub(crate) fn version_not_enabled(op: Operation, state: &str, origin: Origin) -> Error {
    let (kind, msg, hint) = unusable_version(origin, PENDING_STATES.contains(&state));
    let e = Error::new(kind, BACKEND, op, msg);
    match hint {
        Some(h) => e.with_retry_hint(h),
        None => e,
    }
}

/// A server message as it may appear in errors and logs: a pinned fragment verbatim, or the
/// message's length and a keyed fingerprint ([`anykms_http::redact`]).
pub(crate) fn redact(message: &str) -> ServerMessage {
    anykms_http::redact::redact(message, KNOWN, Pinned::ContainsIgnoreCase)
}

/// A response that arrived but cannot be used (undecodable or oversized success body, a response
/// for another key): [`ErrorKind::Backend`] with a fixed message and a warn event. Success bodies
/// are never logged nor fingerprinted (they carry plaintext and key material).
pub(crate) fn unusable_response(
    op: Operation,
    http_status: Option<u16>,
    message: &'static str,
) -> Error {
    #[cfg(feature = "tracing")]
    tracing::warn!(
        op = op.as_str(),
        backend = BACKEND,
        http_status,
        reason = message,
        "unusable Cloud KMS response; reporting Backend"
    );
    let e = Error::new(ErrorKind::Backend, BACKEND, op, message);
    match http_status {
        Some(s) => e.with_detail(BackendDetail::new().with_http_status(s)),
        None => e,
    }
}

/// A failed integrity check (a CRC32C mismatch, a `verified*` flag that is not true, a
/// `verifiedSuccessIntegrity` contradiction): the response is discarded and the request may be
/// retried ([`ErrorKind::Unavailable`], Google's data-integrity guidance). `field` names the
/// field, never its value.
pub(crate) fn integrity_failure(op: Operation, field: &'static str) -> Error {
    #[cfg(feature = "tracing")]
    tracing::warn!(
        op = op.as_str(),
        backend = BACKEND,
        field,
        "Cloud KMS integrity check failed; response discarded"
    );
    let _ = field;
    Error::new(
        ErrorKind::Unavailable,
        BACKEND,
        op,
        "integrity check (CRC32C) failed; the response was discarded",
    )
}

#[derive(Deserialize)]
struct Envelope {
    error: Option<StatusBody>,
}

#[derive(Deserialize)]
struct StatusBody {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    details: Vec<serde_json::Value>,
}

/// The parts of an error body the mapping uses.
#[derive(Debug, Default)]
pub(crate) struct Status {
    /// The canonical code name (`"FAILED_PRECONDITION"`), when the body had one.
    pub(crate) code: Option<String>,
    pub(crate) message: Option<String>,
    /// `google.rpc.ErrorInfo.reason` values.
    pub(crate) reasons: Vec<String>,
    /// `google.rpc.RetryInfo.retryDelay`.
    pub(crate) retry_delay: Option<Duration>,
    /// `google.rpc.RequestInfo.requestId`.
    pub(crate) request_id: Option<String>,
    /// The body was a `google.rpc.Status` JSON envelope.
    pub(crate) json: bool,
}

/// A protobuf `Duration` in JSON (`"1.5s"`).
fn parse_proto_duration(s: &str) -> Option<Duration> {
    let secs = s.strip_suffix('s')?;
    let (whole, frac) = match secs.split_once('.') {
        Some((w, f)) => (w, f),
        None => (secs, ""),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if frac.len() > 9 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    let nanos: u32 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<9}").parse().ok()?
    };
    Some(Duration::new(whole, nanos))
}

impl Status {
    pub(crate) fn parse(body: &[u8]) -> Self {
        let Ok(Envelope { error: Some(e) }) = serde_json::from_slice::<Envelope>(body) else {
            return Self::default();
        };
        let mut s = Status {
            code: e.status,
            message: e.message,
            json: true,
            ..Self::default()
        };
        for d in &e.details {
            let t = d.get("@type").and_then(|t| t.as_str()).unwrap_or("");
            if t.ends_with("google.rpc.ErrorInfo") {
                if let Some(r) = d.get("reason").and_then(|r| r.as_str()) {
                    s.reasons.push(r.to_owned());
                }
            } else if t.ends_with("google.rpc.RetryInfo") {
                s.retry_delay = d
                    .get("retryDelay")
                    .and_then(|r| r.as_str())
                    .and_then(parse_proto_duration);
            } else if t.ends_with("google.rpc.RequestInfo") {
                // Request IDs are opaque server tokens; keep only sane ones (1-128 visible
                // ASCII characters).
                if let Some(id) = d
                    .get("requestId")
                    .and_then(|r| r.as_str())
                    .and_then(anykms_http::redact::request_id)
                {
                    s.request_id = Some(id.to_owned());
                }
            }
        }
        s
    }

    fn has(&self, needle: &str) -> bool {
        self.message
            .as_deref()
            .is_some_and(|m| contains_ci(m, needle))
    }

    /// A `NOT_FOUND` message about the key ("CryptoKey projects/… not found"), not one of its
    /// versions ("CryptoKeyVersion projects/… not found").
    fn names_missing_key(&self) -> bool {
        self.has("cryptokey ") && !self.has("cryptokeyversion")
    }

    /// The state named by "… is not enabled, current state is: <STATE>".
    fn version_state(&self) -> Option<&str> {
        let m = self.message.as_deref()?;
        let lower = m.to_ascii_lowercase();
        let at = lower.find("current state is: ")? + "current state is: ".len();
        let rest = &m[at..];
        let end = rest
            .find(|c: char| !(c.is_ascii_uppercase() || c == '_'))
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

/// The canonical code for an HTTP status, when the body names none.
fn status_for_http(http: u16) -> &'static str {
    match http {
        400 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        409 => "ABORTED",
        429 => "RESOURCE_EXHAUSTED",
        499 => "CANCELLED",
        501 => "UNIMPLEMENTED",
        502 | 503 => "UNAVAILABLE",
        504 => "DEADLINE_EXCEEDED",
        _ => "UNKNOWN",
    }
}

/// Context of a failed request.
#[derive(Clone, Copy)]
pub(crate) struct Failure<'a> {
    pub(crate) http: u16,
    pub(crate) body: &'a [u8],
    /// The `Retry-After` header.
    pub(crate) retry_after: Option<Duration>,
    pub(crate) op: Operation,
    /// Where the request's key version came from: it decides between `KeyStateInvalid` and
    /// `KeyVersionUnusable` for a version that is not enabled, and makes a `NOT_FOUND` on an
    /// input version [`ErrorKind::UnknownKeyVersion`].
    pub(crate) origin: Origin,
}

/// Classifies a non-success response.
pub(crate) fn classify(f: Failure<'_>) -> Error {
    use ErrorKind as K;
    let s = Status::parse(f.body);
    let code: &str = match &s.code {
        Some(c) if !c.is_empty() => c.as_str(),
        _ => status_for_http(f.http),
    };
    let decrypt = matches!(f.op, Operation::Decrypt | Operation::UnwrapKey);
    let (kind, msg, hint): (ErrorKind, &'static str, Option<Duration>) = match (f.http, code) {
        (300..=399, _) => (
            K::Configuration,
            "the server answered with a redirect (redirects are never followed); check the \
             endpoint and any proxy",
            None,
        ),
        // Any status: a checksum mismatch detected by the server is retried by the caller.
        (_, "INVALID_ARGUMENT") if s.has("checksum") => (
            K::Unavailable,
            "the server reported a CRC32C checksum mismatch; the request may be retried",
            None,
        ),
        (_, "INVALID_ARGUMENT" | "OUT_OF_RANGE") if s.has("incorrect key purpose") => (
            K::KeyMismatch,
            "the key's purpose does not support this operation",
            None,
        ),
        (_, "INVALID_ARGUMENT") if decrypt => (K::DecryptFailed, "decryption failed", None),
        (_, "INVALID_ARGUMENT" | "OUT_OF_RANGE") => (
            K::InvalidArgument,
            "the server rejected the request as invalid",
            None,
        ),
        (_, "FAILED_PRECONDITION") => match s.version_state() {
            Some(st) if UNUSABLE_STATES.contains(&st) => unusable_version(f.origin, false),
            Some(st) if PENDING_STATES.contains(&st) => unusable_version(f.origin, true),
            _ if s.has("incorrect key purpose") => (
                K::KeyMismatch,
                "the key's purpose does not support this operation",
                None,
            ),
            _ => (
                K::Backend,
                "the server refused the request (FAILED_PRECONDITION)",
                None,
            ),
        },
        (_, "UNAUTHENTICATED") => (
            K::Unauthenticated,
            "the server did not accept the credentials",
            None,
        ),
        (_, "PERMISSION_DENIED")
            if s.reasons.iter().any(|r| {
                matches!(
                    r.as_str(),
                    "SERVICE_DISABLED" | "BILLING_DISABLED" | "ACCESS_TOKEN_SCOPE_INSUFFICIENT"
                )
            }) =>
        {
            (
                K::Configuration,
                "the Cloud KMS API is not usable by this project or token (API or billing \
                 disabled, or insufficient OAuth scopes)",
                None,
            )
        }
        (_, "PERMISSION_DENIED") => (
            K::PermissionDenied,
            "permission denied (or the key does not exist and the caller cannot see its key ring)",
            None,
        ),
        // A version taken from input that does not exist (a forged or stale `kid`): the
        // caller's (A3). Verification turns it into `VerificationFailed`. When the message
        // says the key itself is missing ("CryptoKey <name> not found", as opposed to
        // "CryptoKeyVersion <name> not found"), it stays `NotFound`, as for every other request
        // on a missing key. A version's own GET says "CryptoKeyVersion" even when the key is
        // missing (§24.4 probe T1): the public-key lookup asks for the key then.
        (_, "NOT_FOUND") if f.origin == Origin::Input && !s.names_missing_key() => (
            K::UnknownKeyVersion,
            "the key version named by the input does not exist",
            None,
        ),
        (_, "NOT_FOUND") => (K::NotFound, "key or key version not found", None),
        (_, "RESOURCE_EXHAUSTED") => (K::Throttled, "quota exceeded (rate limited)", None),
        (_, "ABORTED" | "UNAVAILABLE") => (K::Unavailable, "service unavailable", None),
        (_, "DEADLINE_EXCEEDED") => (K::Timeout, "the server timed out", None),
        (_, "UNIMPLEMENTED") => (
            K::Unsupported,
            "the operation is not implemented for this key",
            None,
        ),
        // A front end answering 5xx without a google.rpc.Status body.
        (500..=599, _) if !s.json => (K::Unavailable, "service unavailable", None),
        (502 | 503, _) => (K::Unavailable, "service unavailable", None),
        (504, _) => (K::Timeout, "the server timed out", None),
        _ => (K::Backend, "unexpected server response", None),
    };
    let server_message = s.message.as_deref().map(redact);
    #[cfg(feature = "tracing")]
    if kind == K::Backend {
        tracing::warn!(
            op = f.op.as_str(),
            backend = BACKEND,
            http_status = f.http,
            code,
            server_message = %server_message
                .as_ref()
                .map_or_else(|| "<none>".to_owned(), ToString::to_string),
            "unclassified Cloud KMS error; reporting Backend"
        );
    }
    let mut detail = BackendDetail::new().with_http_status(f.http);
    if s.json {
        detail = detail.with_code(code.to_owned());
    }
    if let Some(sm) = server_message {
        detail = detail.with_server_message(sm);
    }
    if let Some(id) = s.request_id.clone() {
        detail = detail.with_request_id(id);
    }
    let mut e = Error::new(kind, BACKEND, f.op, msg).with_detail(detail);
    if let Some(h) = hint {
        e = e.with_retry_hint(h);
    }
    // Attached whatever the kind (`Retry` reads it only for retryable kinds): Google's front
    // ends send `Retry-After` with 503s too.
    if let Some(r) = f.retry_after.or(s.retry_delay) {
        e = e.with_retry_after(r);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use anykms_core::ErrorClass;
    use serde_json::json;

    fn body(code: u16, status: &str, message: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"error": {"code": code, "status": status, "message": message}}))
            .unwrap()
    }

    /// Classifies with the origin each operation has in the handles: decrypt takes its version
    /// from the ciphertext, verification from the tag; the rest use the handle's version.
    fn k(http: u16, b: &[u8], op: Operation) -> Error {
        let origin = match op {
            Operation::Decrypt => Origin::Ciphertext,
            Operation::VerifyMac | Operation::Verify => Origin::Input,
            _ => Origin::Handle,
        };
        ko(http, b, op, origin)
    }

    fn ko(http: u16, b: &[u8], op: Operation, origin: Origin) -> Error {
        classify(Failure {
            http,
            body: b,
            retry_after: None,
            op,
            origin,
        })
    }

    #[test]
    fn table() {
        use ErrorKind as K;
        use Operation as O;
        let cases: Vec<(u16, Vec<u8>, O, K)> = vec![
            (
                400,
                body(
                    400,
                    "INVALID_ARGUMENT",
                    "Decryption failed: verify that 'name' refers to the correct CryptoKey.",
                ),
                O::Decrypt,
                K::DecryptFailed,
            ),
            (
                400,
                body(400, "INVALID_ARGUMENT", "anything"),
                O::Decrypt,
                K::DecryptFailed,
            ),
            (
                400,
                body(
                    400,
                    "INVALID_ARGUMENT",
                    "The checksum in field ciphertext_crc32c did not match the data in field ciphertext.",
                ),
                O::Decrypt,
                K::Unavailable,
            ),
            (
                400,
                body(400, "INVALID_ARGUMENT", "Digest type mismatch"),
                O::Sign,
                K::InvalidArgument,
            ),
            (
                400,
                body(400, "OUT_OF_RANGE", "too big"),
                O::Encrypt,
                K::InvalidArgument,
            ),
            (
                400,
                body(
                    400,
                    "FAILED_PRECONDITION",
                    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1 is not enabled, current state is: DISABLED.",
                ),
                O::Sign,
                K::KeyStateInvalid,
            ),
            (
                400,
                body(
                    400,
                    "FAILED_PRECONDITION",
                    "x is not enabled, current state is: DISABLED.",
                ),
                O::VerifyMac,
                K::KeyVersionUnusable,
            ),
            (
                400,
                body(
                    400,
                    "FAILED_PRECONDITION",
                    "x is not enabled, current state is: DESTROY_SCHEDULED.",
                ),
                O::Decrypt,
                K::KeyVersionUnusable,
            ),
            (
                400,
                body(
                    400,
                    "INVALID_ARGUMENT",
                    "Decryption failed: the ciphertext is invalid.",
                ),
                O::UnwrapKey,
                K::DecryptFailed,
            ),
            (
                404,
                body(404, "NOT_FOUND", "x"),
                O::VerifyMac,
                K::UnknownKeyVersion,
            ),
            (404, body(404, "NOT_FOUND", "x"), O::Decrypt, K::NotFound),
            (
                400,
                body(
                    400,
                    "FAILED_PRECONDITION",
                    "Operation requested for Key x has incorrect key purpose: ENCRYPT_DECRYPT",
                ),
                O::Sign,
                K::KeyMismatch,
            ),
            (
                400,
                body(400, "FAILED_PRECONDITION", "EKM unreachable"),
                O::Encrypt,
                K::Backend,
            ),
            (
                401,
                body(401, "UNAUTHENTICATED", "x"),
                O::Encrypt,
                K::Unauthenticated,
            ),
            (
                403,
                body(
                    403,
                    "PERMISSION_DENIED",
                    "Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied on resource 'x' (or it may not exist).",
                ),
                O::Encrypt,
                K::PermissionDenied,
            ),
            (404, body(404, "NOT_FOUND", "x"), O::Encrypt, K::NotFound),
            (
                429,
                body(429, "RESOURCE_EXHAUSTED", "Quota exceeded"),
                O::Encrypt,
                K::Throttled,
            ),
            (409, body(409, "ABORTED", "x"), O::Encrypt, K::Unavailable),
            (
                503,
                body(503, "UNAVAILABLE", "x"),
                O::Encrypt,
                K::Unavailable,
            ),
            (
                502,
                b"<html>bad gateway</html>".to_vec(),
                O::Encrypt,
                K::Unavailable,
            ),
            (500, b"oops".to_vec(), O::Encrypt, K::Unavailable),
            (
                504,
                body(504, "DEADLINE_EXCEEDED", "x"),
                O::Encrypt,
                K::Timeout,
            ),
            (
                501,
                body(501, "UNIMPLEMENTED", "x"),
                O::Encrypt,
                K::Unsupported,
            ),
            (500, body(500, "INTERNAL", "x"), O::Encrypt, K::Backend),
            (500, body(500, "UNKNOWN", "x"), O::Encrypt, K::Backend),
            (302, Vec::new(), O::Encrypt, K::Configuration),
            (418, Vec::new(), O::Encrypt, K::Backend),
        ];
        for (http, b, op, want) in cases {
            let e = k(http, &b, op);
            assert_eq!(
                e.kind(),
                want,
                "{http} {} -> {e}",
                String::from_utf8_lossy(&b)
            );
        }
    }

    #[test]
    fn pending_versions_get_a_retry_hint() {
        let e = k(
            400,
            &body(
                400,
                "FAILED_PRECONDITION",
                "v is not enabled, current state is: PENDING_GENERATION.",
            ),
            Operation::Sign,
        );
        // The handle's own version: KeyStateInvalid, a config error, hinted.
        assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
        assert_eq!(e.retry_hint(), Some(PENDING_VERSION_HINT));
        assert!(
            e.is_config_error(),
            "sign with a pending version is a config error"
        );
        assert_eq!(e.class(), ErrorClass::Hinted(PENDING_VERSION_HINT));
        // An input version: KeyVersionUnusable, a caller error that keeps its hint.
        let e = ko(
            400,
            &body(
                400,
                "FAILED_PRECONDITION",
                "v is not enabled, current state is: PENDING_IMPORT.",
            ),
            Operation::PublicKey,
            Origin::Input,
        );
        assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable);
        assert_eq!(e.retry_hint(), Some(PENDING_VERSION_HINT));
        assert_eq!(e.class(), ErrorClass::Caller);
    }

    /// A3: the same "not enabled" answer is `KeyStateInvalid` for the version the handle chose
    /// (every operation, `public_key()` included) and `KeyVersionUnusable` for one taken from
    /// input; a missing input version is `UnknownKeyVersion`, a missing handle version
    /// `NotFound`. The version-state lookup maps the same way.
    #[test]
    fn version_errors_depend_on_the_version_origin() {
        let disabled = body(
            400,
            "FAILED_PRECONDITION",
            "v is not enabled, current state is: DISABLED.",
        );
        let missing = body(404, "NOT_FOUND", "CryptoKeyVersion v not found.");
        for op in [
            Operation::Encrypt,
            Operation::Sign,
            Operation::Mac,
            Operation::PublicKey,
            Operation::WrapKey,
            Operation::UnwrapKey,
        ] {
            let e = ko(400, &disabled, op, Origin::Handle);
            assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{op}");
            assert!(e.is_config_error(), "{op}");
            assert_eq!(
                ko(404, &missing, op, Origin::Handle).kind(),
                ErrorKind::NotFound,
                "{op}"
            );
            let e = version_not_enabled(op, "DESTROYED", Origin::Handle);
            assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{op}");
        }
        for (op, origin) in [
            (Operation::Decrypt, Origin::Ciphertext),
            (Operation::VerifyMac, Origin::Input),
            (Operation::Verify, Origin::Input),
            (Operation::PublicKey, Origin::Input),
        ] {
            let e = ko(400, &disabled, op, origin);
            assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{op}");
            assert!(e.is_caller_error(), "{op}");
            let e = version_not_enabled(op, "DISABLED", origin);
            assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{op}");
        }
        let e = ko(404, &missing, Operation::PublicKey, Origin::Input);
        assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion);
        assert_eq!(e.class(), ErrorClass::Caller);
        // Unless the key itself is missing.
        let key_missing = body(404, "NOT_FOUND", "CryptoKey projects/p/k not found.");
        assert_eq!(
            ko(404, &key_missing, Operation::Verify, Origin::Input).kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            ko(
                404,
                &body(404, "NOT_FOUND", "x"),
                Operation::Verify,
                Origin::Input
            )
            .kind(),
            ErrorKind::UnknownKeyVersion
        );
        // The ciphertext's version is opaque: a 404 on decrypt is the key's.
        assert_eq!(
            ko(404, &missing, Operation::Decrypt, Origin::Ciphertext).kind(),
            ErrorKind::NotFound
        );
        let e = version_not_enabled(Operation::Sign, "PENDING_GENERATION", Origin::Handle);
        assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
        assert_eq!(e.retry_hint(), Some(PENDING_VERSION_HINT));
        assert!(!e.message().contains("PENDING"), "{e}");
    }

    #[test]
    fn details_are_parsed() {
        let b = serde_json::to_vec(&json!({"error": {
            "code": 429, "status": "RESOURCE_EXHAUSTED", "message": "secret-ish input",
            "details": [
                {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "1.500s"},
                {"@type": "type.googleapis.com/google.rpc.RequestInfo", "requestId": "abc-123"},
            ]
        }}))
        .unwrap();
        let e = k(429, &b, Operation::Encrypt);
        assert_eq!(e.kind(), ErrorKind::Throttled);
        assert_eq!(e.retry_after(), Some(Duration::from_millis(1500)));
        let d = e.detail().unwrap();
        assert_eq!(d.request_id(), Some("abc-123"));
        assert_eq!(d.code(), Some("RESOURCE_EXHAUSTED"));
        assert!(!e.to_string().contains("secret-ish"), "{e}");
        assert!(!format!("{e:?}").contains("secret-ish"));

        let b = serde_json::to_vec(&json!({"error": {
            "code": 403, "status": "PERMISSION_DENIED", "message": "API not enabled",
            "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED"}]
        }}))
        .unwrap();
        assert_eq!(
            k(403, &b, Operation::Encrypt).kind(),
            ErrorKind::Configuration
        );
    }

    /// P1-3: `Retry-After` is attached whatever the kind; P1-9: request ids go through the
    /// shared filter (an empty one is dropped).
    #[test]
    fn retry_after_and_request_ids() {
        let b = serde_json::to_vec(&json!({"error": {
            "code": 503, "status": "UNAVAILABLE", "message": "x",
            "details": [{"@type": "type.googleapis.com/google.rpc.RequestInfo", "requestId": ""}]
        }}))
        .unwrap();
        let e = classify(Failure {
            http: 503,
            body: &b,
            retry_after: Some(Duration::from_secs(3)),
            op: Operation::Encrypt,
            origin: Origin::Handle,
        });
        assert_eq!(e.kind(), ErrorKind::Unavailable);
        assert_eq!(e.retry_after(), Some(Duration::from_secs(3)));
        assert_eq!(e.detail().unwrap().request_id(), None);
        let e = classify(Failure {
            http: 404,
            body: &body(404, "NOT_FOUND", "x"),
            retry_after: Some(Duration::from_secs(1)),
            op: Operation::Encrypt,
            origin: Origin::Handle,
        });
        assert_eq!(e.retry_after(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn proto_durations() {
        assert_eq!(parse_proto_duration("2s"), Some(Duration::from_secs(2)));
        assert_eq!(
            parse_proto_duration("0.000000001s"),
            Some(Duration::from_nanos(1))
        );
        assert_eq!(parse_proto_duration("1.5"), None);
        assert_eq!(parse_proto_duration("-1s"), None);
        assert_eq!(parse_proto_duration("s"), None);
        assert_eq!(parse_proto_duration("1.0000000001s"), None);
    }

    #[test]
    fn redaction_keeps_only_pinned_fragments() {
        assert_eq!(
            redact("x is not enabled, current state is: DISABLED."),
            ServerMessage::Known("is not enabled, current state is: ".into())
        );
        assert!(matches!(
            redact("echo of user input"),
            ServerMessage::Redacted { .. }
        ));
    }
}
