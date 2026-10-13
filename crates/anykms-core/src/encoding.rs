//! Canonical, versioned storage encoding for [`Signature`] and [`Tag`].
//!
//! Stored signatures and tags must keep their algorithm and key version so they can be verified
//! after a key rotation. The format is binary:
//!
//! ```text
//! magic ("AKS" for signatures, "AKT" for tags) | format version 0x01 | algorithm code u8 |
//! u8 key_version_len | key_version (UTF-8, 0..=255 bytes; 0 = no version) | value bytes (rest)
//! ```
//!
//! Algorithm codes are stable and never reused. [`Signature::to_base64`] and [`Tag::to_base64`]
//! (and their `_url` variants) wrap this encoding in base64 for text columns, JSON and URLs.
//!
//! Encoding fails only for a key version longer than 255 bytes, which the length byte cannot
//! express. No backend issues such versions (transit, GCP: decimal numbers; Azure: 32 hex
//! characters; AWS: none), but [`KeyVersion`] is an open string and [`Signature::from_parts`] /
//! [`Tag::from_parts`] accept any, so the encoders stay fallible rather than panic or truncate.
//!
//! Decoding failures (wrong magic, unknown format version or algorithm code, truncation) are
//! `VerificationFailed`, as for a forged or malformed signature from a backend: a corrupt stored
//! value is handled like one that does not verify.

use crate::error::{Error, ErrorKind, Operation, Result};
use crate::types::{KeyVersion, MacAlgorithm, Signature, SignatureAlgorithm, Tag};

const SIG_MAGIC: &[u8; 3] = b"AKS";
const TAG_MAGIC: &[u8; 3] = b"AKT";
const FORMAT_V1: u8 = 1;

fn err(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::VerificationFailed, "encoding", op, m)
}

fn encode_parts(
    magic: &[u8; 3],
    op: Operation,
    code: u8,
    version: Option<&KeyVersion>,
    value: &[u8],
) -> Result<Vec<u8>> {
    let v = version.map(|v| v.as_str().as_bytes()).unwrap_or_default();
    if v.len() > 255 {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            "encoding",
            op,
            "key version is longer than 255 bytes",
        ));
    }
    let mut out = Vec::with_capacity(6 + v.len() + value.len());
    out.extend_from_slice(magic);
    out.push(FORMAT_V1);
    out.push(code);
    out.push(v.len() as u8);
    out.extend_from_slice(v);
    out.extend_from_slice(value);
    Ok(out)
}

fn decode_parts<'a>(
    magic: &[u8; 3],
    op: Operation,
    bytes: &'a [u8],
) -> Result<(u8, Option<KeyVersion>, &'a [u8])> {
    if bytes.len() < 6 || &bytes[..3] != magic {
        return Err(err(op, "not an anykms-encoded value"));
    }
    if bytes[3] != FORMAT_V1 {
        return Err(err(op, "unsupported encoding version"));
    }
    let code = bytes[4];
    let vlen = bytes[5] as usize;
    let rest = &bytes[6..];
    if rest.len() < vlen {
        return Err(err(op, "truncated encoding"));
    }
    let (v, value) = rest.split_at(vlen);
    let version = if vlen == 0 {
        None
    } else {
        Some(KeyVersion::new(
            std::str::from_utf8(v).map_err(|_| err(op, "key version is not UTF-8"))?,
        ))
    };
    if value.is_empty() {
        return Err(err(op, "empty value"));
    }
    Ok((code, version, value))
}

/// Encodes a signature for storage. Fails with `InvalidArgument` only for a key version longer
/// than 255 bytes (see the [module docs](self)).
pub fn encode_signature(sig: &Signature) -> Result<Vec<u8>> {
    encode_parts(
        SIG_MAGIC,
        Operation::Sign,
        sig.algorithm().code(),
        sig.key_version(),
        sig.as_bytes(),
    )
}

/// Decodes a signature produced by [`encode_signature`]; anything else is `VerificationFailed`.
pub fn decode_signature(bytes: &[u8]) -> Result<Signature> {
    let (code, version, value) = decode_parts(SIG_MAGIC, Operation::Verify, bytes)?;
    let alg = SignatureAlgorithm::from_code(code)
        .ok_or_else(|| err(Operation::Verify, "unknown algorithm code"))?;
    Ok(Signature::from_parts(alg, version, value.to_vec()))
}

/// Encodes a MAC tag for storage. Fails with `InvalidArgument` only for a key version longer
/// than 255 bytes (see the [module docs](self)).
pub fn encode_tag(tag: &Tag) -> Result<Vec<u8>> {
    encode_parts(
        TAG_MAGIC,
        Operation::Mac,
        tag.algorithm().code(),
        tag.key_version(),
        tag.as_bytes(),
    )
}

/// Decodes a tag produced by [`encode_tag`]; anything else is `VerificationFailed`.
pub fn decode_tag(bytes: &[u8]) -> Result<Tag> {
    let (code, version, value) = decode_parts(TAG_MAGIC, Operation::VerifyMac, bytes)?;
    let alg = MacAlgorithm::from_code(code)
        .ok_or_else(|| err(Operation::VerifyMac, "unknown algorithm code"))?;
    Ok(Tag::from_parts(alg, version, value.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = Signature::from_parts(
            SignatureAlgorithm::EcdsaP384Sha384,
            Some(KeyVersion::from(3)),
            vec![1, 2, 3],
        );
        assert_eq!(decode_signature(&encode_signature(&s).unwrap()).unwrap(), s);
        let t = Tag::from_parts(MacAlgorithm::HmacSha512, None, vec![9; 64]);
        assert_eq!(decode_tag(&encode_tag(&t).unwrap()).unwrap(), t);
        // Pinned encoding.
        assert_eq!(
            encode_signature(&s).unwrap(),
            b"AKS\x01\x02\x013\x01\x02\x03"
        );
    }

    #[test]
    fn rejects_garbage() {
        for b in [
            &b""[..],
            b"AKS",
            b"AKT\x01\x01\x00\x01",
            b"AKS\x02\x01\x00\x01",
            b"AKS\x01\xff\x00\x01",
            b"AKS\x01\x01\x05ab",
        ] {
            let e = decode_signature(b).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{b:?}");
            assert!(e.is_caller_error());
        }
        assert_eq!(
            decode_tag(b"AKS\x01\x01\x00\x01").unwrap_err().operation(),
            Operation::VerifyMac
        );
    }

    #[test]
    fn only_overlong_versions_fail_to_encode() {
        let long = Some(KeyVersion::new("v".repeat(256)));
        let e = encode_tag(&Tag::from_parts(
            MacAlgorithm::HmacSha256,
            long.clone(),
            [1],
        ))
        .unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::InvalidArgument, Operation::Mac)
        );
        let e = encode_signature(&Signature::from_parts(
            SignatureAlgorithm::Ed25519,
            long,
            [1],
        ))
        .unwrap_err();
        assert_eq!(e.operation(), Operation::Sign);
        let max = Some(KeyVersion::new("v".repeat(255)));
        let t = Tag::from_parts(MacAlgorithm::HmacSha256, max, [1]);
        assert_eq!(decode_tag(&encode_tag(&t).unwrap()).unwrap(), t);
    }
}
