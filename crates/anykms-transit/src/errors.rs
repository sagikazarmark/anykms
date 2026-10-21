//! Mapping of transit HTTP responses to [`ErrorKind`]s.
//!
//! The table is pinned by conformance and mock-server tests on every CI server version (the
//! messages were observed on Vault 1.20/2.1 and OpenBao 2.4/2.7; `scripts/probe-transit.sh`
//! records them in `scripts/probe-baseline/`).
//! Messages are matched case-insensitively as substrings. Unknown messages fall back to
//! [`ErrorKind::Backend`] (less specific, never misclassified) with the server message redacted
//! to a keyed fingerprint (see [`redact`]).

use std::time::Duration;

use anykms_core::{BackendDetail, Error, ErrorKind, Operation, ServerMessage};
use anykms_http::redact::{Pinned, contains_ci};

use crate::BACKEND;

/// The [`retry_hint`](Error::retry_hint) on errors that replica lag can cause ("not found" for a
/// just-created key, "version is too new" after a rotation): long enough for a performance or
/// raft standby to catch up in the common case, short against the default 5 s backoff cap.
pub(crate) const REPLICA_LAG_HINT: Duration = Duration::from_millis(500);

/// Messages that are safe to keep verbatim (they never echo request input).
const KNOWN: &[&str] = &[
    "encryption key not found",
    "signing key not found",
    "signature verification key not found",
    "supplied signature is invalid",
    "invalid base64 signature value",
    "invalid signature: no prefix",
    "invalid signature: version is too new",
    "invalid HMAC to verify: no prefix",
    "invalid HMAC: version is too new",
    "cannot verify HMAC: version is too old (disallowed by policy)",
    "unable to decode verification HMAC as base64",
    "cipher: message authentication failed",
    "invalid ciphertext: no prefix",
    "invalid ciphertext: version is too new",
    "invalid ciphertext: could not decode base64",
    "invalid ciphertext: unable to parse version",
    "ciphertext or signature version is disallowed by policy (too old)",
    "refusing to use soft-deleted key",
    "JSON string value exceeds allowed length",
    "namespace not found",
    "permission denied",
    "invalid token",
    "Vault is sealed",
    "context deadline exceeded",
    "active cluster node not found",
    "local node not active but active cluster node not found",
    "provided for non-AEAD cipher suite",
];

/// Transient 500 messages (failover, storage), mapped to `Unavailable`. Matched as substrings, so
/// each entry is a specific phrase. "local node not active but active cluster node not found" is
/// the only 500 that `scripts/probe-failover.sh` observed for data-plane requests during
/// step-downs and killed leaders on every CI server version (baselines in
/// `scripts/failover-baseline/`). The `hashicorp/raft` errors (`ErrNotLeader`, `ErrLeadershipLost`,
/// `ErrLeadershipTransferInProgress`, `ErrRaftShutdown`, `ErrEnqueueTimeout`) were never observed
/// there, since data-plane requests only read storage; they are kept because each is transient by
/// definition, so retrying one can only repeat an idempotent request.
const TRANSIENT_500: &[&str] = &[
    "context deadline exceeded",
    "active cluster node not found",
    "local node not active",
    "node is not the leader",
    "leadership lost while committing log",
    "leadership transfer in progress",
    "raft is already shutdown",
    "timed out enqueuing operation",
];

/// 500 messages meaning the request was too large (InvalidArgument). Vault's JSON parser limit;
/// the HTTP-level `max_request_size` limit answers 413 instead.
const TOO_LARGE_500: &[&str] = &["JSON string value exceeds allowed length"];

/// Messages meaning the key does not exist (400 on data-plane endpoints). "encryption key not
/// found" is also what the HMAC and datakey endpoints answer.
const KEY_NOT_FOUND: &[&str] = &[
    "encryption key not found",
    "signing key not found",
    "signature verification key not found",
];

/// A server message as it may appear in errors and logs: a pinned known message verbatim, or its
/// length and a keyed fingerprint ([`anykms_http::redact`]). Unknown messages may echo request
/// input, so they are never kept.
pub(crate) fn redact(message: &str) -> ServerMessage {
    anykms_http::redact::redact(message, KNOWN, Pinned::ContainsIgnoreCase)
}

/// A response that arrived but cannot be used (undecodable success body, oversized response):
/// reported as [`ErrorKind::Backend`] with a fixed message and a warn event. Response bodies are
/// never logged nor fingerprinted, since success bodies carry plaintext and key material.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
pub(crate) fn unusable_response(
    op: Operation,
    alias: &str,
    http_status: Option<u16>,
    message: &'static str,
) -> Error {
    #[cfg(feature = "tracing")]
    tracing::warn!(
        op = op.as_str(),
        backend = BACKEND,
        server_alias = alias,
        http_status,
        reason = message,
        "unusable transit response; reporting Backend"
    );
    let e = Error::new(ErrorKind::Backend, BACKEND, op, message);
    match http_status {
        Some(s) => e.with_detail(BackendDetail::new().with_http_status(s)),
        None => e,
    }
}

/// Context of a failed request.
pub(crate) struct Failure<'a> {
    pub(crate) status: u16,
    pub(crate) messages: &'a [String],
    pub(crate) retry_after: Option<Duration>,
    pub(crate) op: Operation,
    /// For tracing only: errors name the server through their resource.
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    pub(crate) alias: &'a str,
    /// The request was a `GET keys/:name` (404 means the key is missing).
    pub(crate) key_read: bool,
}

fn any(messages: &[String], needles: &[&str]) -> bool {
    messages
        .iter()
        .any(|m| needles.iter().any(|n| contains_ci(m, n)))
}

/// Classifies a non-success response.
pub(crate) fn classify(f: &Failure<'_>) -> Error {
    let m = f.messages;
    let has = |needles: &[&str]| any(m, needles);
    let (kind, msg, lag): (ErrorKind, &'static str, bool) = match f.status {
        _ if has(KEY_NOT_FOUND) => (ErrorKind::NotFound, "key not found", true),
        400 if has(&["cipher: message authentication failed"]) => {
            (ErrorKind::DecryptFailed, "decryption failed", false)
        }
        400 if has(&["version is too new"]) => {
            (ErrorKind::DecryptFailed, "decryption failed", true)
        }
        // Structurally malformed ciphertexts, signatures and HMACs. Verify operations turn
        // DecryptFailed into VerificationFailed (see `Server::call`).
        400 if has(&[
            "invalid ciphertext",
            "illegal base64",
            "invalid signature",
            "supplied signature is invalid",
            "invalid base64 signature value",
            "invalid hmac",
        ]) =>
        {
            (ErrorKind::DecryptFailed, "decryption failed", false)
        }
        400 if has(&[
            "disallowed by policy (too old)",
            "version is too old (disallowed by policy)",
        ]) =>
        {
            (
                ErrorKind::KeyVersionUnusable,
                "key version is below the minimum decryption version",
                false,
            )
        }
        400 if has(&["refusing to use soft-deleted key"]) => {
            (ErrorKind::KeyStateInvalid, "key cannot be used", false)
        }
        // The key's type cannot do this (an Ed25519 key asked to encrypt, AAD for a non-AEAD
        // key): the key is not what the handle expects, which may mean it was recreated with
        // another type (P1-4).
        400 if has(&[
            "does not support",
            "not supported for key type",
            "provided for non-AEAD cipher suite",
        ]) =>
        {
            (
                ErrorKind::KeyMismatch,
                "key type does not support this operation",
                false,
            )
        }
        400 if has(&["missing 'context'"]) => (
            ErrorKind::Unsupported,
            "derived keys are not supported",
            false,
        ),
        413 => (ErrorKind::InvalidArgument, "request too large", false),
        500 if has(TOO_LARGE_500) => (ErrorKind::InvalidArgument, "request too large", false),
        // OpenBao answers sign/verify on a soft-deleted key with 500 (encrypt gets 400).
        500 if has(&["refusing to use soft-deleted key"]) => (
            ErrorKind::KeyStateInvalid,
            "key or key version cannot be used",
            false,
        ),
        404 if has(&["namespace not found"]) => {
            (ErrorKind::Configuration, "namespace not found", false)
        }
        404 if has(&["no handler for route", "unsupported path"]) => {
            (ErrorKind::Configuration, "no such mount or path", false)
        }
        404 if f.key_read => (ErrorKind::NotFound, "key not found", true),
        // Vault answers a bad token with 403 "permission denied" plus "invalid token"
        // (Unauthenticated). OpenBao answers a plain 403 "permission denied", which stays
        // PermissionDenied: it cannot be told from a policy denial.
        401 => (ErrorKind::Unauthenticated, "authentication required", false),
        403 if has(&["invalid token", "token expired", "bad token"]) => {
            (ErrorKind::Unauthenticated, "token not accepted", false)
        }
        403 => (ErrorKind::PermissionDenied, "permission denied", false),
        429 => (ErrorKind::Throttled, "rate limited", false),
        412 => (ErrorKind::Unavailable, "server not yet consistent", false),
        502..=504 => (ErrorKind::Unavailable, "server unavailable", false),
        // A standby that cannot forward answers 307 to the active node: transient (forwarding
        // may resume, or the standby may become active).
        307 => (
            ErrorKind::Unavailable,
            "server answered with a temporary redirect (redirects are never followed; check \
             standby request forwarding)",
            false,
        ),
        301 | 308 => (
            ErrorKind::Configuration,
            "server answered with a permanent redirect (redirects are never followed); \
             configure the final address",
            false,
        ),
        // 302/303 come from proxies and login pages in front of the server, not from Vault or
        // OpenBao: retrying does not help.
        300..=399 => (
            ErrorKind::Configuration,
            "server answered with a redirect (redirects are never followed); check the address \
             and any proxy in front of the server",
            false,
        ),
        500 if has(TRANSIENT_500) => (ErrorKind::Unavailable, "server unavailable", false),
        _ => (ErrorKind::Backend, "unexpected server response", false),
    };
    let server_message = m.first().map(|first| redact(first));
    #[cfg(feature = "tracing")]
    if kind == ErrorKind::Backend {
        // Only the redacted form (a pinned known message, or length + hash fingerprint) is logged.
        tracing::warn!(
            op = f.op.as_str(),
            backend = BACKEND,
            server_alias = f.alias,
            http_status = f.status,
            server_message = %server_message
                .as_ref()
                .map_or_else(|| "<none>".to_owned(), ToString::to_string),
            "unclassified transit error; reporting Backend"
        );
    }
    let mut detail = BackendDetail::new().with_http_status(f.status);
    if let Some(sm) = server_message {
        detail = detail.with_server_message(sm);
    }
    let mut e = Error::new(kind, BACKEND, f.op, msg).with_detail(detail);
    if lag {
        e = e.with_retry_hint(REPLICA_LAG_HINT);
    }
    if let Some(r) = f.retry_after {
        e = e.with_retry_after(r);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(status: u16, msg: &str) -> ErrorKind {
        let m = vec![msg.to_owned()];
        classify(&Failure {
            status,
            messages: &m,
            retry_after: None,
            op: Operation::Decrypt,
            alias: "a",
            key_read: false,
        })
        .kind()
    }

    #[test]
    fn table() {
        assert_eq!(k(400, "encryption key not found"), ErrorKind::NotFound);
        assert_eq!(
            k(400, "cipher: message authentication failed"),
            ErrorKind::DecryptFailed
        );
        assert_eq!(
            k(400, "invalid ciphertext: version is too new"),
            ErrorKind::DecryptFailed
        );
        assert_eq!(
            k(
                400,
                "ciphertext or signature version is disallowed by policy (too old)"
            ),
            ErrorKind::KeyVersionUnusable
        );
        assert_eq!(
            k(400, "refusing to use soft-deleted key"),
            ErrorKind::KeyStateInvalid
        );
        assert_eq!(
            k(
                500,
                "1 error occurred:\n\t* refusing to use soft-deleted key\n\n"
            ),
            ErrorKind::KeyStateInvalid
        );
        assert_eq!(
            k(400, "message encryption not supported for key type ed25519"),
            ErrorKind::KeyMismatch
        );
        assert_eq!(
            k(400, "key type aes256-gcm96 does not support signing"),
            ErrorKind::KeyMismatch
        );
        assert_eq!(
            k(500, "JSON string value exceeds allowed length"),
            ErrorKind::InvalidArgument
        );
        assert_eq!(k(404, "namespace not found"), ErrorKind::Configuration);
        assert_eq!(k(403, "permission denied"), ErrorKind::PermissionDenied);
        assert_eq!(k(403, "invalid token"), ErrorKind::Unauthenticated);
        assert_eq!(k(401, "missing client token"), ErrorKind::Unauthenticated);
        assert_eq!(k(429, "rate limit quota exceeded"), ErrorKind::Throttled);
        assert_eq!(k(503, "Vault is sealed"), ErrorKind::Unavailable);
        // Every status/message pair in scripts/failover-baseline/ is transient.
        assert_eq!(
            k(
                500,
                "local node not active but active cluster node not found"
            ),
            ErrorKind::Unavailable
        );
        assert_eq!(k(307, ""), ErrorKind::Unavailable);
        for permanent in [301, 308, 302, 303] {
            assert_eq!(k(permanent, ""), ErrorKind::Configuration, "{permanent}");
        }
        assert_eq!(k(500, "context deadline exceeded"), ErrorKind::Unavailable);
        assert_eq!(k(500, "something odd"), ErrorKind::Backend);
        // Only the pinned size message is InvalidArgument; other "exceeds" 500s are not.
        assert_eq!(
            k(
                500,
                "1 error occurred:\n\t* JSON string value exceeds allowed length"
            ),
            ErrorKind::InvalidArgument
        );
        assert_eq!(k(500, "storage quota exceeds limit"), ErrorKind::Backend);
        // Transient phrases are specific; incidental words are not.
        assert_eq!(k(500, "node is not the leader"), ErrorKind::Unavailable);
        assert_eq!(
            k(500, "leadership lost while committing log"),
            ErrorKind::Unavailable
        );
        assert_eq!(k(500, "raft is already shutdown"), ErrorKind::Unavailable);
        assert_eq!(k(500, "failed to read raft config"), ErrorKind::Backend);
        assert_eq!(k(500, "leadership of the team"), ErrorKind::Backend);
    }

    /// Messages observed on Vault 1.20.4/2.1.1 and OpenBao 2.4.4/2.7.1 (identical on all four).
    #[test]
    fn observed_sign_verify_hmac_messages() {
        let kd = |status: u16, msg: &str| {
            let m = vec![msg.to_owned()];
            let e = classify(&Failure {
                status,
                messages: &m,
                retry_after: None,
                op: Operation::Verify,
                alias: "a",
                key_read: false,
            });
            let lag = e.retry_hint().is_some();
            (e.kind(), lag)
        };
        // Missing keys: sign, verify, and (shared message) hmac/datakey/decrypt.
        for msg in [
            "signing key not found",
            "signature verification key not found",
            "encryption key not found",
        ] {
            assert_eq!(kd(400, msg), (ErrorKind::NotFound, true), "{msg}");
            assert!(matches!(redact(msg), ServerMessage::Known(_)), "{msg}");
        }
        // Malformed signatures and HMACs (mapped to VerificationFailed for verify operations).
        for msg in [
            "supplied signature is invalid",
            "invalid base64 signature value",
            "invalid signature: no prefix",
            "invalid HMAC to verify: no prefix",
            "unable to decode verification HMAC as base64: illegal base64 data at input byte 0",
        ] {
            assert_eq!(kd(400, msg), (ErrorKind::DecryptFailed, false), "{msg}");
            assert!(matches!(redact(msg), ServerMessage::Known(_)), "{msg}");
        }
        for msg in [
            "invalid signature: version is too new",
            "invalid HMAC: version is too new",
        ] {
            assert_eq!(kd(400, msg), (ErrorKind::DecryptFailed, true), "{msg}");
        }
        for msg in [
            "cannot verify HMAC: version is too old (disallowed by policy)",
            "ciphertext or signature version is disallowed by policy (too old)",
        ] {
            assert_eq!(
                kd(400, msg),
                (ErrorKind::KeyVersionUnusable, false),
                "{msg}"
            );
        }
        // Case-insensitive.
        assert_eq!(kd(400, "INVALID hmac: X").0, ErrorKind::DecryptFailed);
    }

    #[test]
    fn redaction() {
        assert_eq!(
            redact("Vault is sealed"),
            ServerMessage::Known("Vault is sealed".into())
        );
        match redact("1 error occurred: secret-ish input echo") {
            ServerMessage::Redacted {
                len, fingerprint, ..
            } => {
                assert_eq!(len, 39);
                assert_eq!(fingerprint.len(), 12);
            }
            other => panic!("{other:?}"),
        }
    }
}
