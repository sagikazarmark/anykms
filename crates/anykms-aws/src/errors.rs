//! AWS JSON 1.1 error responses → [`ErrorKind`].
//!
//! The exception name comes from the `x-amzn-ErrorType` header or the body's `__type` (any
//! `namespace#` prefix and `:...` suffix removed); the message from `message` / `Message`.
//! Every error carries [`BackendDetail`] with the HTTP status, the exception name as `code`, the
//! `x-amzn-RequestId` as `request_id` and the server message, verbatim only when it is a pinned
//! message that never echoes input, otherwise redacted to its length and a keyed fingerprint.
//! Unknown exceptions fall back to [`ErrorKind::Backend`] (less specific, never misclassified).

use std::time::Duration;

use anykms_core::{BackendDetail, Error, ErrorKind, Operation, ServerMessage};
use anykms_http::redact::Pinned;
use reqwest::header::HeaderMap;

use crate::BACKEND;

/// Messages kept verbatim: fixed AWS texts that never contain request input. Most were recorded
/// from real AWS by the A0 probe (2026-10-07, `docs/research/aws-kms.md`); real AWS sends no
/// message at all with `InvalidCiphertextException`, `KMSInvalidSignatureException` and
/// `KMSInvalidMacException` (the two texts below are kept for compatible servers).
const KNOWN: &[&str] = &[
    "The security token included in the request is expired",
    "The security token included in the request is invalid.",
    // The first paragraph of AWS's `InvalidSignatureException`; the rest (the canonical request
    // and string to sign) is dropped by `redact`.
    "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.",
    "The key ID in the request does not identify a CMK that can perform this operation.",
    "Invalid EncryptionContext",
    "EncryptionContext is not supported when encrypting/decrypting with asymmetric CMKs.",
    "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length greater than or equal to 1",
    "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length less than or equal to 4096",
    "1 validation error detected: Value at 'message' failed to satisfy constraint: Member must have length greater than or equal to 1",
    "1 validation error detected: Value at 'message' failed to satisfy constraint: Member must have length less than or equal to 4096",
    "The ciphertext is invalid.",
    "The MAC is not valid.",
    "Rate exceeded",
];

/// The hint of `IncorrectKeyException` (PLAN Appendix A).
pub(crate) const INCORRECT_KEY_HINT: &str = "decryption failed: the ciphertext is under another key \
     (alias repointed? route old ciphertexts with EnvelopeKeyring)";

/// A server message as it may appear in errors and logs: pinned messages verbatim, anything else
/// as its length and a keyed fingerprint ([`anykms_http::redact`]). A message whose first
/// paragraph is pinned keeps that paragraph only: real AWS appends the expected canonical request
/// to the pinned `InvalidSignatureException` text (A0, `invalid-signature.json`).
pub(crate) fn redact(message: &str) -> ServerMessage {
    let first = message
        .split_once("\n\n")
        .map_or(message, |(first, _)| first);
    match KNOWN.iter().find(|k| **k == first) {
        Some(k) if first.len() < message.len() => ServerMessage::Known((*k).into()),
        _ => anykms_http::redact::redact(message, KNOWN, Pinned::Exact),
    }
}

/// An exception name without a `namespace#` prefix or a `:...` suffix; `None` unless it looks
/// like an identifier.
pub(crate) fn normalize_code(raw: &str) -> Option<&str> {
    let s = raw.rsplit('#').next().unwrap_or(raw);
    let s = s.split(':').next().unwrap_or(s).trim();
    (!s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_'))
    .then_some(s)
}

#[derive(serde::Deserialize)]
struct ErrorBody<'a> {
    #[serde(rename = "__type", default, borrow)]
    kind: Option<std::borrow::Cow<'a, str>>,
    #[serde(default, borrow)]
    message: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "Message", default, borrow)]
    message_upper: Option<std::borrow::Cow<'a, str>>,
}

/// The exception name and message of an error response.
pub(crate) fn parse_error(headers: &HeaderMap, body: &[u8]) -> (Option<String>, Option<String>) {
    let parsed = serde_json::from_slice::<ErrorBody<'_>>(body).ok();
    let from_header = headers
        .get("x-amzn-errortype")
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_code)
        .map(str::to_owned);
    let (body_code, message) = match parsed {
        Some(b) => (
            b.kind
                .as_deref()
                .and_then(normalize_code)
                .map(str::to_owned),
            b.message.or(b.message_upper).map(|m| m.into_owned()),
        ),
        None => (None, None),
    };
    (from_header.or(body_code), message)
}

/// The response's request id, through the shared filter (P1-9:
/// [`anykms_http::redact::request_id`]).
pub(crate) fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-amzn-requestid")
        .or_else(|| headers.get("x-amz-request-id"))
        .and_then(|v| v.to_str().ok())
        .and_then(anykms_http::redact::request_id)
        .map(str::to_owned)
}

/// Authentication failures after which the credentials are refetched once.
pub(crate) const REFRESH_CODES: &[&str] = &[
    "ExpiredTokenException",
    "ExpiredToken",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
];

/// Whether a rejection is caused by clock skew (the signing time is off).
pub(crate) fn is_skew(code: Option<&str>, message: Option<&str>) -> bool {
    match code {
        Some("RequestTimeTooSkewed" | "RequestExpired") => true,
        Some("InvalidSignatureException") => message.is_some_and(|m| {
            m.contains("Signature expired") || m.contains("Signature not yet current")
        }),
        _ => false,
    }
}

/// Whether a `NotFoundException` is AWS's answer to a malformed key ARN: real AWS answers
/// "Invalid arn <arn>" with `NotFoundException`, not the documented `InvalidArnException`
/// (A0, `invalid-arn.json`). Local URI parsing catches malformed ARNs first.
pub(crate) fn is_invalid_arn(code: Option<&str>, message: Option<&str>) -> bool {
    code == Some("NotFoundException") && message.is_some_and(|m| m.starts_with("Invalid arn "))
}

/// Classifies an error response: kind and fixed message.
pub(crate) fn kind_of(status: u16, code: Option<&str>) -> (ErrorKind, &'static str) {
    use ErrorKind as K;
    if let Some(c) = code {
        let k = match c {
            "NotFoundException" => (K::NotFound, "key not found"),
            "InvalidCiphertextException" => (K::DecryptFailed, "decryption failed"),
            "IncorrectKeyException" => (K::DecryptFailed, INCORRECT_KEY_HINT),
            "KMSInvalidSignatureException" => (K::VerificationFailed, "signature is invalid"),
            "KMSInvalidMacException" => (K::VerificationFailed, "MAC is invalid"),
            "DisabledException" => (K::KeyStateInvalid, "key is disabled"),
            "KMSInvalidStateException" => (
                K::KeyStateInvalid,
                "key is not in a usable state (pending deletion or import, or its custom key store failed)",
            ),
            "KeyUnavailableException"
            | "CustomKeyStoreInvalidStateException"
            | "CloudHsmClusterNotActiveException"
            | "XksProxyUriUnreachableException"
            | "XksProxyInvalidResponseException" => (
                K::Unavailable,
                "key material is temporarily unavailable (custom key store or HSM unreachable)",
            ),
            "InvalidKeyUsageException" => (
                K::KeyMismatch,
                "the key's usage or algorithms do not allow this operation",
            ),
            "ValidationException" | "ValidationError" | "RequestEntityTooLargeException" => {
                (K::InvalidArgument, "AWS rejected the request parameters")
            }
            "UnsupportedOperationException" => (
                K::Unsupported,
                "AWS does not support this operation on this key",
            ),
            "InvalidGrantTokenException" => (K::Configuration, "a grant token is invalid"),
            "InvalidArnException" | "UnknownOperationException" | "OptInRequired" => (
                K::Configuration,
                "the endpoint or partition does not serve this key or operation",
            ),
            "AccessDeniedException" | "AccessDenied" => {
                (K::PermissionDenied, "access denied by AWS")
            }
            "UnrecognizedClientException"
            | "InvalidClientTokenId"
            | "ExpiredTokenException"
            | "ExpiredToken"
            | "InvalidSignatureException"
            | "SignatureDoesNotMatch"
            | "IncompleteSignature"
            | "MissingAuthenticationToken"
            | "MissingAuthenticationTokenException"
            | "NotAuthorized" => (K::Unauthenticated, "AWS rejected the credentials"),
            "ThrottlingException" | "Throttling" => (K::Throttled, "request rate exceeded"),
            "LimitExceededException" => (K::Backend, "an AWS resource quota is exceeded"),
            "KMSInternalException"
            | "DependencyTimeoutException"
            | "InternalFailure"
            | "InternalError"
            | "InternalServerError"
            | "ServiceUnavailable"
            | "ServiceUnavailableException"
            | "RequestTimeoutException" => (K::Unavailable, "AWS KMS is temporarily unavailable"),
            "RequestTimeTooSkewed" | "RequestExpired" => (
                K::Unavailable,
                "request time too skewed; the clock offset was recorded, retry",
            ),
            _ => (K::Backend, ""),
        };
        if !k.1.is_empty() {
            return k;
        }
    }
    match status {
        300..=399 => (
            K::Configuration,
            "unexpected redirect (not followed): check the endpoint",
        ),
        401 => (K::Unauthenticated, "AWS rejected the credentials"),
        403 => (K::PermissionDenied, "access denied by AWS"),
        404 => (K::NotFound, "key not found"),
        408 | 500 | 502 | 503 | 504 => (K::Unavailable, "AWS KMS is temporarily unavailable"),
        413 => (K::InvalidArgument, "request too large"),
        429 => (K::Throttled, "request rate exceeded"),
        _ => (K::Backend, "unexpected AWS error"),
    }
}

/// A failed response.
pub(crate) struct Failure<'a> {
    pub(crate) status: u16,
    pub(crate) code: Option<&'a str>,
    pub(crate) message: Option<&'a str>,
    pub(crate) request_id: Option<String>,
    pub(crate) retry_after: Option<Duration>,
    pub(crate) op: Operation,
}

/// Classifies a non-success response.
pub(crate) fn classify(f: Failure<'_>) -> Error {
    let skew = is_skew(f.code, f.message);
    let (kind, msg) = if skew {
        (
            ErrorKind::Unavailable,
            "request time too skewed; the clock offset was recorded, retry",
        )
    } else if is_invalid_arn(f.code, f.message) {
        (
            ErrorKind::Configuration,
            "AWS refused the key ARN as malformed; check the key URI",
        )
    } else {
        kind_of(f.status, f.code)
    };
    let mut detail = BackendDetail::new().with_http_status(f.status);
    if let Some(c) = f.code {
        detail = detail.with_code(c.to_owned());
    }
    if let Some(r) = f.request_id {
        detail = detail.with_request_id(r);
    }
    if let Some(m) = f.message {
        detail = detail.with_server_message(redact(m));
    }
    #[cfg(feature = "tracing")]
    {
        if kind == ErrorKind::Backend {
            tracing::warn!(
                backend = BACKEND,
                op = f.op.as_str(),
                http_status = f.status,
                code = f.code,
                "unclassified AWS error; reporting Backend"
            );
        }
        if kind == ErrorKind::InvalidArgument {
            tracing::warn!(
                backend = BACKEND,
                op = f.op.as_str(),
                code = f.code,
                "AWS rejected an input that local checks should have caught"
            );
        }
    }
    let mut e = Error::new(kind, BACKEND, f.op, msg).with_detail(detail);
    if let Some(d) = f.retry_after {
        e = e.with_retry_after(d);
    }
    e
}

/// A response that arrived but cannot be used (undecodable success body, oversized response).
/// Bodies are never logged nor fingerprinted.
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
        "unusable AWS response; reporting Backend"
    );
    let e = Error::new(ErrorKind::Backend, BACKEND, op, message);
    match http_status {
        Some(s) => e.with_detail(BackendDetail::new().with_http_status(s)),
        None => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_normalized() {
        assert_eq!(
            normalize_code("NotFoundException"),
            Some("NotFoundException")
        );
        assert_eq!(
            normalize_code("com.amazonaws.kms#NotFoundException"),
            Some("NotFoundException")
        );
        assert_eq!(
            normalize_code("NotFoundException:http://internal.amazon.com/coral/com.amazonaws.kms/"),
            Some("NotFoundException")
        );
        assert_eq!(normalize_code(""), None);
        assert_eq!(normalize_code("has space"), None);
    }

    #[test]
    fn parses_bodies_and_headers() {
        let mut h = HeaderMap::new();
        let (c, m) = parse_error(&h, br#"{"__type":"x#DisabledException","Message":"m"}"#);
        assert_eq!(
            (c.as_deref(), m.as_deref()),
            (Some("DisabledException"), Some("m"))
        );
        h.insert(
            "x-amzn-ErrorType",
            "ThrottlingException:http://x/".parse().unwrap(),
        );
        h.insert("x-amzn-RequestId", "req-1".parse().unwrap());
        let (c, m) = parse_error(&h, b"not json");
        assert_eq!((c.as_deref(), m), (Some("ThrottlingException"), None));
        assert_eq!(request_id(&h).as_deref(), Some("req-1"));
        // P1-9: an empty id carries nothing.
        h.insert("x-amzn-RequestId", "".parse().unwrap());
        assert_eq!(request_id(&h), None);
    }

    #[test]
    fn skew() {
        assert!(is_skew(
            Some("InvalidSignatureException"),
            Some("Signature expired: 20150830T123600Z is now earlier than ...")
        ));
        assert!(!is_skew(
            Some("InvalidSignatureException"),
            Some("The request signature we calculated does not match")
        ));
        assert!(is_skew(Some("RequestTimeTooSkewed"), None));
        let e = classify(Failure {
            status: 400,
            code: Some("InvalidSignatureException"),
            message: Some("Signature expired: x"),
            request_id: None,
            retry_after: None,
            op: Operation::Encrypt,
        });
        assert_eq!(e.kind(), ErrorKind::Unavailable);
    }

    #[test]
    fn invalid_arn() {
        let e = classify(Failure {
            status: 400,
            code: Some("NotFoundException"),
            message: Some("Invalid arn arn:aws:kms:nowhere"),
            request_id: None,
            retry_after: None,
            op: Operation::Encrypt,
        });
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert!(!format!("{e} {e:?}").contains("nowhere"));
        assert!(!is_invalid_arn(
            Some("NotFoundException"),
            Some("Key 'arn:aws:kms:us-east-1:111122223333:key/x' does not exist")
        ));
    }

    #[test]
    fn redaction() {
        assert_eq!(
            redact("The ciphertext is invalid."),
            ServerMessage::Known("The ciphertext is invalid.".into())
        );
        let r = redact("Key 'arn:SECRET' not found");
        assert!(!format!("{r}").contains("SECRET"));
        let sig = format!(
            "{}\n\nThe Canonical String for this request should have been\n'SECRET'",
            KNOWN[2]
        );
        assert_eq!(redact(&sig), ServerMessage::Known(KNOWN[2].into()));
        let r = redact("not pinned\n\nSECRET");
        assert!(!format!("{r}").contains("SECRET"));
    }
}
