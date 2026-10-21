//! proto3 JSON helpers: base64 bytes, `Int64Value` CRC32C fields as strings, zeroizing bodies.

use anykms_core::{Operation, Result};
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crc32c::crc32c;
use crate::errors::{integrity_failure, unusable_response};

pub(crate) const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Room for field names and punctuation on top of a body's variable-length fields.
const BODY_OVERHEAD: usize = 256;

/// Base64-encodes into a zeroizing, pre-sized string.
pub(crate) fn b64(data: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(data.len().div_ceil(3) * 4 + 4));
    B64.encode_string(data, &mut s);
    s
}

/// The CRC32C of `data` as a proto3 JSON `Int64Value` (a decimal string).
pub(crate) fn crc(data: &[u8]) -> String {
    crc32c(data).to_string()
}

/// Serializes a request body into a zeroizing buffer pre-sized for `hint` bytes of field values.
pub(crate) fn body<T: Serialize>(value: &T, hint: usize) -> Zeroizing<Vec<u8>> {
    anykms_http::zbuf::json_body(value, hint.saturating_add(BODY_OVERHEAD))
        .expect("request serializes")
}

/// An `Int64Value` field: a JSON string (proto3) or number; anything else, including a value
/// outside `u32` (a CRC32C never is), fails to decode.
pub(crate) fn int64<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum N {
        S(String),
        U(u64),
    }
    let n = match Option::<N>::deserialize(d)? {
        None => return Ok(None),
        Some(N::U(u)) => u,
        Some(N::S(s)) => s
            .parse()
            .map_err(|_| serde::de::Error::custom("bad int64"))?,
    };
    if n > u64::from(u32::MAX) {
        return Err(serde::de::Error::custom("CRC32C out of range"));
    }
    Ok(Some(n))
}

/// Decodes base64 response bytes into a zeroizing buffer, wiping an owned source string.
pub(crate) fn decode_secret(
    mut s: std::borrow::Cow<'_, str>,
    op: Operation,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 4 * 3 + 3));
    let r = B64.decode_vec(s.as_bytes(), &mut out);
    if let std::borrow::Cow::Owned(o) = &mut s {
        o.zeroize();
    }
    r.map_err(|_| bad_response(op))?;
    Ok(out)
}

/// Decodes base64 response bytes that are not secret.
pub(crate) fn decode(s: &str, op: Operation) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|_| bad_response(op))
}

/// An undecodable success body.
pub(crate) fn bad_response(op: Operation) -> anykms_core::Error {
    unusable_response(op, Some(200), "unexpected response format")
}

/// Checks a response CRC32C against the data; a missing CRC counts as zero (proto3 omits
/// defaults), which only matches empty data.
pub(crate) fn check_crc(
    data: &[u8],
    got: Option<u64>,
    op: Operation,
    field: &'static str,
) -> Result<()> {
    if u64::from(crc32c(data)) == got.unwrap_or(0) {
        Ok(())
    } else {
        Err(integrity_failure(op, field))
    }
}

/// Checks a `verified*Crc32c` flag that must be true (a CRC was sent).
pub(crate) fn check_verified(flag: bool, op: Operation, field: &'static str) -> Result<()> {
    if flag {
        Ok(())
    } else {
        Err(integrity_failure(op, field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct T {
        #[serde(default, deserialize_with = "int64")]
        c: Option<u64>,
    }

    #[test]
    fn int64_fields() {
        let p = |s: &str| serde_json::from_str::<T>(s).map(|t| t.c);
        assert_eq!(p(r#"{"c":"123"}"#).unwrap(), Some(123));
        assert_eq!(p(r#"{"c":123}"#).unwrap(), Some(123));
        assert_eq!(p(r#"{"c":"4294967295"}"#).unwrap(), Some(4_294_967_295));
        assert_eq!(p(r"{}").unwrap(), None);
        assert_eq!(p(r#"{"c":null}"#).unwrap(), None);
        assert!(p(r#"{"c":"4294967296"}"#).is_err());
        assert!(p(r#"{"c":"-1"}"#).is_err());
        assert!(p(r#"{"c":"x"}"#).is_err());
        assert!(p(r#"{"c":1.5}"#).is_err());
        assert!(p(r#"{"c":"10"}"#).is_ok());
    }

    #[test]
    fn crc_checks() {
        assert!(check_crc(b"", None, Operation::Decrypt, "f").is_ok());
        assert!(check_crc(b"123456789", Some(0xE306_9283), Operation::Decrypt, "f").is_ok());
        let e = check_crc(b"123456789", None, Operation::Decrypt, "f").unwrap_err();
        assert_eq!(e.kind(), anykms_core::ErrorKind::Unavailable);
        assert_eq!(crc(b"123456789"), "3808858755");
    }
}
