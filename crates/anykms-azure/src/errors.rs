//! Mapping of Key Vault HTTP responses to [`ErrorKind`]s (`docs/cloud/azure.md` §8).
//!
//! Classification uses the status, the error `code` and the inner error codes only. A 403
//! `Forbidden` is told apart by its inner code (`KeyDisabled`, `KeyNotYetValid`, `KeyExpired`,
//! `KeyOperationForbidden`, `ForbiddenByFirewall`; the live probe `scripts/probe-azure.sh`, task
//! T3, pinned them); without one it is `PermissionDenied`. Key-size and algorithm errors are 400
//! `BadParameter` with no inner code and stay `InvalidArgument`: under-classified, never
//! misclassified (PLAN §12).
//! Server messages are never kept verbatim (they can carry client IPs and object ids): they are
//! reduced to a length and a keyed fingerprint.

use std::time::Duration;

use anykms_core::{BackendDetail, Error, ErrorKind, Operation, ServerMessage};
use serde::Deserialize;

use crate::BACKEND;

/// What a request's version came from, which decides what a 400 or 404 means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReqClass {
    /// `GET` of a key, its versions or a version.
    Read,
    /// `sign`, `wrapkey`, `encrypt`: the URI's version or the current one.
    Write,
    /// `verify`, `unwrapkey`, `decrypt`: the version came from the caller's input (a signature
    /// or a ciphertext frame).
    InputVersion,
}

/// A server message as it may appear in errors and logs: its length and a keyed fingerprint
/// ([`anykms_http::redact`]); no Azure message is pinned.
pub(crate) fn redact(message: &str) -> ServerMessage {
    anykms_http::redact::fingerprint(message)
}

/// A response that arrived but cannot be used (undecodable success body, mismatched `kid`,
/// wrong signature or IV size): `Backend` with a fixed message and a warn event. Success bodies
/// are never logged nor fingerprinted.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
pub(crate) fn unusable_response(
    op: Operation,
    host: &str,
    http_status: Option<u16>,
    message: &'static str,
) -> Error {
    #[cfg(feature = "tracing")]
    tracing::warn!(
        op = op.as_str(),
        backend = BACKEND,
        host,
        http_status,
        reason = message,
        "unusable Azure Key Vault response; reporting Backend"
    );
    let e = Error::new(ErrorKind::Backend, BACKEND, op, message);
    match http_status {
        Some(s) => e.with_detail(BackendDetail::new().with_http_status(s)),
        None => e,
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: Option<ErrorObject>,
}

#[derive(Deserialize)]
struct ErrorObject {
    code: Option<String>,
    message: Option<String>,
    #[serde(rename = "innererror", alias = "innerError")]
    inner: Option<Box<ErrorObject>>,
}

/// The parts of an error body that classification uses.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ErrorBody {
    /// `code`, then the inner codes, outermost first (sanitized, at most 4).
    pub(crate) codes: Vec<String>,
    pub(crate) message: Option<String>,
}

fn code_ok(c: &str) -> bool {
    (1..=128).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl ErrorBody {
    pub(crate) fn parse(body: &[u8]) -> Self {
        let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(body) else {
            return Self::default();
        };
        let Some(mut obj) = env.error else {
            return Self::default();
        };
        let message = obj.message.take();
        let mut codes = Vec::new();
        let mut cur = Some(Box::new(obj));
        while let Some(o) = cur {
            if codes.len() == 4 {
                break;
            }
            match o.code.as_deref() {
                Some(c) if code_ok(c) => codes.push(c.to_owned()),
                Some(_) => codes.push("<invalid>".to_owned()),
                None => {}
            }
            cur = o.inner;
        }
        Self { codes, message }
    }

    fn has(&self, code: &str) -> bool {
        self.codes.iter().any(|c| c.eq_ignore_ascii_case(code))
    }
}

/// The error code Lowkey Vault gives undecryptable ciphertexts and wrapped keys (with a 500).
const LOWKEY_CRYPTO_EXCEPTION: &str =
    "com.github.nagyesta.lowkeyvault.service.exception.CryptoException";

/// Context of a failed request.
pub(crate) struct Failure<'a> {
    pub(crate) status: u16,
    pub(crate) body: &'a ErrorBody,
    pub(crate) retry_after: Option<Duration>,
    pub(crate) request_id: Option<&'a str>,
    pub(crate) op: Operation,
    pub(crate) class: ReqClass,
    /// The key-type check read the key (so a 404 on an input version means that version).
    pub(crate) key_seen: bool,
    /// For a 401: the tenant the vault's challenge names, when it differs from the credential's.
    pub(crate) tenant_hint: Option<&'a str>,
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    pub(crate) host: &'a str,
}

fn input_failure(op: Operation) -> (ErrorKind, &'static str) {
    match op {
        Operation::Verify | Operation::VerifyMac => {
            (ErrorKind::VerificationFailed, "verification failed")
        }
        _ => (ErrorKind::DecryptFailed, "decryption failed"),
    }
}

/// Classifies a non-success response.
pub(crate) fn classify(f: &Failure<'_>) -> Error {
    let b = f.body;
    let (kind, msg): (ErrorKind, std::borrow::Cow<'static, str>) = match f.status {
        401 => match f.tenant_hint {
            Some(t) => (
                ErrorKind::Unauthenticated,
                format!(
                    "the vault rejected the access token; the vault belongs to tenant {t}: \
                     configure AZURE_TENANT_ID"
                )
                .into(),
            ),
            None => (
                ErrorKind::Unauthenticated,
                "the vault rejected the access token".into(),
            ),
        },
        403 if b.has("ForbiddenByFirewall") => (
            ErrorKind::PermissionDenied,
            "denied by a vault network rule (firewall or private endpoint), not by RBAC".into(),
        ),
        // The key's state, by the inner code (§24.4 probe T3, 2026-10-12: `KeyDisabled`,
        // `KeyNotYetValid`, `KeyExpired` under a 403 `Forbidden`): the handle's version is
        // `KeyStateInvalid`, a version from input `KeyVersionUnusable` (A3).
        403 if b.has("KeyDisabled") || b.has("KeyNotYetValid") || b.has("KeyExpired") => {
            let what = if b.has("KeyDisabled") {
                "the key or key version is disabled"
            } else if b.has("KeyNotYetValid") {
                "the key is not valid yet (nbf)"
            } else {
                "the key has expired (exp)"
            };
            match f.class {
                ReqClass::InputVersion => (ErrorKind::KeyVersionUnusable, what.into()),
                _ => (ErrorKind::KeyStateInvalid, what.into()),
            }
        }
        // The key's `key_ops` exclude the operation.
        403 if b.has("KeyOperationForbidden") => (
            ErrorKind::KeyMismatch,
            "the key's permitted operations (key_ops) exclude this operation".into(),
        ),
        403 => (ErrorKind::PermissionDenied, "permission denied".into()),
        404 => match f.class {
            ReqClass::InputVersion if f.key_seen => {
                let (k, m) = input_failure(f.op);
                (k, m.into())
            }
            _ => (ErrorKind::NotFound, "key or key version not found".into()),
        },
        400 => match f.class {
            // Tag mismatch, padding, wrong key, malformed signature: indistinguishable on purpose.
            ReqClass::InputVersion => {
                let (k, m) = input_failure(f.op);
                (k, m.into())
            }
            _ => (
                ErrorKind::InvalidArgument,
                "the vault rejected the request".into(),
            ),
        },
        413 => (ErrorKind::InvalidArgument, "request too large".into()),
        409 => (
            ErrorKind::KeyStateInvalid,
            "key is being deleted or recovered".into(),
        ),
        429 => (ErrorKind::Throttled, "throttled by the vault".into()),
        // Lowkey Vault (the emulator) answers undecryptable input with a 500 and this code; Azure
        // answers 400 (above).
        500 if f.class == ReqClass::InputVersion && b.has(LOWKEY_CRYPTO_EXCEPTION) => {
            let (k, m) = input_failure(f.op);
            (k, m.into())
        }
        500 | 502 | 503 | 504 => (ErrorKind::Unavailable, "vault unavailable".into()),
        300..=399 => (
            ErrorKind::Configuration,
            "the vault answered with a redirect (redirects are never followed); check the host \
             and any proxy in front of it"
                .into(),
        ),
        _ => (ErrorKind::Backend, "unexpected vault response".into()),
    };
    let server_message = b.message.as_deref().map(redact);
    // A 405 on a versionless write is expected on some servers and handled by the fallback
    // (`post_write`): no warning.
    #[cfg(feature = "tracing")]
    if kind == ErrorKind::Backend && f.status != 405 {
        tracing::warn!(
            op = f.op.as_str(),
            backend = BACKEND,
            host = f.host,
            http_status = f.status,
            code = b.codes.last().map(String::as_str),
            codes = b.codes.join("/"),
            request_id = f.request_id,
            server_message = %server_message
                .as_ref()
                .map_or_else(|| "<none>".to_owned(), ToString::to_string),
            "unclassified Azure Key Vault error; reporting Backend"
        );
    }
    let mut detail = BackendDetail::new().with_http_status(f.status);
    // The innermost (most specific) code: `ForbiddenByRbac`, not `Forbidden/ForbiddenByRbac`.
    if let Some(code) = b.codes.last() {
        detail = detail.with_code(code.clone());
    }
    if let Some(id) = f.request_id {
        detail = detail.with_request_id(id);
    }
    if let Some(sm) = server_message {
        detail = detail.with_server_message(sm);
    }
    let mut e = Error::new(kind, BACKEND, f.op, msg).with_detail(detail);
    if let Some(r) = f.retry_after {
        e = e.with_retry_after(r);
    }
    e
}

/// Entra ID authority hosts a challenge may name.
const LOGIN_HOSTS: &[&str] = &[
    "login.microsoftonline.com",
    "login.windows.net",
    "login.partner.microsoftonline.cn",
    "login.chinacloudapi.cn",
    "login.microsoftonline.us",
];

/// The tenant named by a `WWW-Authenticate: Bearer authorization="https://login.../<tenant>"`
/// challenge (diagnostics only: it never chooses what token is minted or where it goes). Only
/// Entra ID authority hosts count (Lowkey Vault names itself).
pub(crate) fn challenge_tenant(header: &str) -> Option<&str> {
    let rest = header.trim_start();
    let rest = rest
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("bearer "))
        .map(|_| &rest[7..])?;
    for part in rest.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        let key = k.trim();
        if key.eq_ignore_ascii_case("authorization")
            || key.eq_ignore_ascii_case("authorization_uri")
        {
            let v = v.trim().trim_matches('"');
            let after = v.strip_prefix("https://")?;
            let (host, path) = after.split_once('/')?;
            if !LOGIN_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h)) {
                return None;
            }
            let tenant = path.trim_end_matches('/');
            let ok = (1..=64).contains(&tenant.len())
                && tenant
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'));
            return ok.then_some(tenant);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(status: u16, body: &str, op: Operation, class: ReqClass, seen: bool) -> Error {
        let b = ErrorBody::parse(body.as_bytes());
        classify(&Failure {
            status,
            body: &b,
            retry_after: None,
            request_id: Some("rid-1"),
            op,
            class,
            key_seen: seen,
            tenant_hint: None,
            host: "h",
        })
    }

    fn kind(status: u16, body: &str, op: Operation, class: ReqClass) -> ErrorKind {
        k(status, body, op, class, true).kind()
    }

    #[test]
    fn table() {
        use ErrorKind::*;
        use Operation as O;
        use ReqClass::*;
        let forbidden = r#"{"error":{"code":"Forbidden","message":"Caller is not authorized","innererror":{"code":"ForbiddenByRbac"}}}"#;
        assert_eq!(kind(401, "", O::Sign, Write), Unauthenticated);
        assert_eq!(kind(403, forbidden, O::Sign, Write), PermissionDenied);
        let fw = r#"{"error":{"code":"Forbidden","message":"Client address 1.2.3.4 is not authorized","innererror":{"code":"ForbiddenByFirewall"}}}"#;
        let e = k(403, fw, O::Sign, Write, true);
        assert_eq!(e.kind(), PermissionDenied);
        assert!(e.to_string().contains("network rule"), "{e}");
        assert!(!format!("{e:?}").contains("1.2.3.4"));
        // Key states (the live bodies of §24.4 probe T3).
        let state = |inner: &str, msg: &str| {
            format!(
                r#"{{"error":{{"code":"Forbidden","message":"{msg}","innererror":{{"code":"{inner}"}}}}}}"#
            )
        };
        let disabled = state(
            "KeyDisabled",
            "Operation sign is not allowed on a disabled key.",
        );
        let nbf = state(
            "KeyNotYetValid",
            "Operation sign is not allowed because the 'not before' constraint on this key is not met.",
        );
        let exp = state(
            "KeyExpired",
            "Operation sign is not allowed on an expired key.",
        );
        for b in [&disabled, &nbf, &exp] {
            assert_eq!(kind(403, b, O::Sign, Write), KeyStateInvalid, "{b}");
            assert_eq!(kind(403, b, O::WrapKey, Write), KeyStateInvalid, "{b}");
            assert_eq!(kind(403, b, O::Describe, Read), KeyStateInvalid, "{b}");
            assert_eq!(
                kind(403, b, O::Verify, InputVersion),
                KeyVersionUnusable,
                "{b}"
            );
            assert_eq!(
                kind(403, b, O::UnwrapKey, InputVersion),
                KeyVersionUnusable,
                "{b}"
            );
        }
        let ops = state(
            "KeyOperationForbidden",
            "Operation sign is not permitted on this key.",
        );
        assert_eq!(kind(403, &ops, O::Sign, Write), KeyMismatch);
        let nf = r#"{"error":{"code":"KeyNotFound","message":"A key with (name/id) k was not found in this key vault."}}"#;
        assert_eq!(kind(404, nf, O::Describe, Read), NotFound);
        assert_eq!(kind(404, nf, O::Sign, Write), NotFound);
        assert_eq!(kind(404, nf, O::Decrypt, InputVersion), DecryptFailed);
        assert_eq!(kind(404, nf, O::Verify, InputVersion), VerificationFailed);
        assert_eq!(
            k(404, nf, O::Decrypt, InputVersion, false).kind(),
            NotFound,
            "TrustCaller"
        );
        let bp = r#"{"error":{"code":"BadParameter","message":"..."}}"#;
        assert_eq!(kind(400, bp, O::Decrypt, InputVersion), DecryptFailed);
        assert_eq!(kind(400, bp, O::Verify, InputVersion), VerificationFailed);
        assert_eq!(
            kind(400, bp, O::VerifyMac, InputVersion),
            VerificationFailed
        );
        assert_eq!(kind(400, bp, O::Sign, Write), InvalidArgument);
        assert_eq!(kind(413, "", O::Encrypt, Write), InvalidArgument);
        assert_eq!(kind(409, "", O::Sign, Write), KeyStateInvalid);
        assert_eq!(kind(429, "", O::Sign, Write), Throttled);
        for s in [500, 502, 503, 504] {
            assert_eq!(kind(s, "", O::Sign, Write), Unavailable, "{s}");
        }
        for s in [301, 302, 307, 308] {
            assert_eq!(kind(s, "", O::Sign, Write), Configuration, "{s}");
        }
        assert_eq!(kind(418, "", O::Sign, Write), Backend);
        let lowkey = r#"{"error":{"code":"com.github.nagyesta.lowkeyvault.service.exception.CryptoException","message":"Cannot decrypt message."}}"#;
        assert_eq!(kind(500, lowkey, O::Decrypt, InputVersion), DecryptFailed);
        assert_eq!(kind(500, lowkey, O::Sign, Write), Unavailable);
        assert_eq!(kind(501, "", O::Sign, Write), Backend);
    }

    #[test]
    fn detail() {
        let e = k(
            403,
            r#"{"error":{"code":"Forbidden","message":"oid 1234 secret","innererror":{"code":"ForbiddenByRbac"}}}"#,
            Operation::Sign,
            ReqClass::Write,
            true,
        );
        let d = e.detail().unwrap();
        assert_eq!(d.code(), Some("ForbiddenByRbac"));
        assert_eq!(d.request_id(), Some("rid-1"));
        assert!(!format!("{e:?} {e}").contains("1234"));
        // Codes are sanitized and bounded.
        let b = ErrorBody::parse(
            br#"{"error":{"code":"A b","innererror":{"code":"B","innererror":{"code":"C","innererror":{"code":"D","innererror":{"code":"E"}}}}}}"#,
        );
        assert_eq!(b.codes, ["<invalid>", "B", "C", "D"]);
        let long = format!(r#"{{"error":{{"code":"{}"}}}}"#, "a".repeat(129));
        assert_eq!(ErrorBody::parse(long.as_bytes()).codes, ["<invalid>"]);
        assert_eq!(ErrorBody::parse(b"not json"), ErrorBody::default());
        assert_eq!(ErrorBody::parse(b"{}"), ErrorBody::default());
    }

    #[test]
    fn challenge() {
        let h = r#"Bearer authorization="https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47", resource="https://vault.azure.net""#;
        assert_eq!(
            challenge_tenant(h),
            Some("72f988bf-86f1-41af-91ab-2d7cd011db47")
        );
        let h2 = r#"Bearer authorization_uri="https://login.windows.net/contoso.onmicrosoft.com/", resource_id="x""#;
        assert_eq!(challenge_tenant(h2), Some("contoso.onmicrosoft.com"));
        assert_eq!(challenge_tenant("Basic realm=x"), None);
        assert_eq!(
            challenge_tenant(r#"Bearer authorization="https://x/te nant""#),
            None
        );
        assert_eq!(challenge_tenant("Bearer"), None);
        // Lowkey Vault's challenge names itself, not a tenant.
        assert_eq!(
            challenge_tenant(
                r#"Bearer resource="https://localhost:8443", authorization_uri="https://localhost:8443/keys/k""#
            ),
            None
        );
    }
}
