//! Helpers shared by cases.

use anykms_core::Ciphertext;

/// Flips one byte in the middle of the ciphertext, keeping it in the base64 alphabet so that
/// text-framed ciphertexts (`vault:v1:...`) stay syntactically valid.
pub(crate) fn tamper(ct: &Ciphertext) -> Ciphertext {
    let mut b = ct.as_bytes().to_vec();
    let i = b.len() / 2 + 2;
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    Ciphertext::from_bytes(b)
}

/// Flips the first byte of the ciphertext (in the base64 alphabet, as [`tamper`]): the prefix,
/// where framed formats keep a magic, a version or a key identifier.
pub(crate) fn tamper_prefix(ct: &Ciphertext) -> Ciphertext {
    let mut b = ct.as_bytes().to_vec();
    b[0] = if b[0] == b'A' { b'B' } else { b'A' };
    Ciphertext::from_bytes(b)
}

/// Drops the last bytes.
pub(crate) fn truncate(ct: &Ciphertext) -> Ciphertext {
    let b = ct.as_bytes();
    Ciphertext::from_bytes(b[..b.len().saturating_sub(4)].to_vec())
}

/// The two keys of [`Ctx::keys(kind, 2)`](crate::ctx::Ctx::keys).
pub(crate) fn two<T>(v: Vec<T>) -> [T; 2] {
    match <[T; 2]>::try_from(v) {
        Ok(a) => a,
        Err(v) => panic!("expected two keys, got {}", v.len()),
    }
}

/// A per-run unique marker.
pub(crate) fn marker(label: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("MARKER{label}{n:x}")
}

/// A per-run unique 32-byte key to wrap: [`marker`] padded with `_`. 32 bytes is what every
/// key-wrapping key accepts (an AES-KW key takes a multiple of 8 bytes of at least 16, an RSA-OAEP
/// key anything up to its modulus bound, an AEAD key anything), and the length every recipe wraps.
pub(crate) fn marker_key(label: &str) -> [u8; 32] {
    let m = marker(label);
    let mut out = [b'_'; 32];
    let n = m.len().min(out.len());
    out[..n].copy_from_slice(&m.as_bytes()[..n]);
    out
}
