//! The AAD wire encoding, native encryption contexts and grant tokens.
//!
//! **AAD encoding (a wire format; it never changes).** The portable `aad: &[u8]` of `Aead`,
//! `Rewrap` and `DataKeys` maps to an AWS encryption context: empty AAD sends no
//! `EncryptionContext` at all; non-empty AAD sends `{"associatedData": lowercase_hex(aad)}`.
//! This is Tink's mapping (`AwsKmsAead` in Java, Python and C++, and Go's default), so AWS
//! ciphertexts with AAD interoperate with Tink under the same key. The same mapping applies to
//! `Encrypt`, `Decrypt`, `ReEncrypt` (source and destination) and `GenerateDataKey`.
//!
//! **Size caps** (checked before any request, `InvalidArgument`): AAD at most
//! [`MAX_AAD_BYTES`] (its encoding is then at most 6144 characters); a native context at most
//! [`MAX_CONTEXT_BYTES`] of keys and values. AWS documents no limit; these are deliberately
//! conservative and may only ever rise. The AAD cap binds only the operations that produce a
//! ciphertext (`Encrypt`, `GenerateDataKey*` and `ReEncrypt`, whose destination context is the
//! AAD's), never `Decrypt`, so ciphertexts written under a raised cap still decrypt with an
//! older release. Real AWS accepted a one-entry context of 8150 bytes of key and value and
//! refused 8151 (measured on 2026-10-07): under the 14-byte `associatedData` key that is 8136 hex
//! characters (4068 AAD bytes), about 1.3 times the AAD cap and twice the native one.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use anykms_core::{Error, ErrorKind, Operation, Result};
use zeroize::Zeroizing;

use crate::BACKEND;

/// The reserved encryption-context key that carries the portable AAD (Tink's key).
pub const AAD_CONTEXT_KEY: &str = "associatedData";

/// The largest AAD (bytes) that operations producing a ciphertext accept (6144 hex characters
/// on the wire); `Decrypt` takes any length. This is anykms's limit: AWS documents none. It may
/// be raised in a minor release, never lowered. Measured on 2026-10-07 (us-east-1): AWS accepted
/// a one-entry context of 8150 bytes of key and value and refused 8151 with
/// `ValidationException` "Invalid EncryptionContext". Under [`AAD_CONTEXT_KEY`] that leaves 8136
/// hex characters (4068 AAD bytes), so the cap's 6158 bytes use about three quarters of the
/// real limit.
pub const MAX_AAD_BYTES: usize = 3072;

/// The largest native encryption context (sum of key and value lengths, bytes). This is
/// anykms's limit: AWS documents none. It may be raised in a minor release, never lowered.
/// Measured on 2026-10-07: a one-entry context of 8150 bytes (key and value) was accepted, 8151
/// refused; contexts with more entries were not measured.
pub const MAX_CONTEXT_BYTES: usize = 4096;

/// The wire map of a portable AAD.
pub(crate) type AadContext = BTreeMap<&'static str, Zeroizing<String>>;

/// The AAD's context map for an operation that produces a ciphertext (`Encrypt`,
/// `GenerateDataKey*`, `ReEncrypt`), `None` for empty AAD. `InvalidArgument` above
/// [`MAX_AAD_BYTES`].
pub(crate) fn aad_context(aad: &[u8], op: Operation) -> Result<Option<AadContext>> {
    if aad.len() > MAX_AAD_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            BACKEND,
            op,
            "AAD is too long for an AWS encryption context (at most 3072 bytes)",
        ));
    }
    Ok(decrypt_aad_context(aad))
}

/// The AAD's context map for `Decrypt`, `None` for empty AAD. Not capped, so raising
/// [`MAX_AAD_BYTES`] never strands a ciphertext; AWS refuses a context it cannot take.
pub(crate) fn decrypt_aad_context(aad: &[u8]) -> Option<AadContext> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if aad.is_empty() {
        return None;
    }
    // Pre-sized, so the zeroizing string never reallocates (no unwiped copy is left behind).
    let mut v = Zeroizing::new(String::with_capacity(aad.len() * 2));
    for &b in aad {
        v.push(char::from(HEX[usize::from(b >> 4)]));
        v.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    let mut m = BTreeMap::new();
    m.insert(AAD_CONTEXT_KEY, v);
    Some(m)
}

/// An AWS encryption context: a map of non-secret strings, authenticated with the ciphertext and
/// logged in CloudTrail. For ciphertexts shared with other AWS tools (the AWS Encryption SDK, S3,
/// ...), through [`EncryptionContextAead`](crate::EncryptionContextAead).
///
/// May not use the reserved key [`AAD_CONTEXT_KEY`] (the portable API's), so the two modes never
/// mix. Keys and values must be non-empty; the total size is capped at [`MAX_CONTEXT_BYTES`].
/// `Debug` shows the keys only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EncryptionContext(BTreeMap<String, String>);

impl fmt::Debug for EncryptionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionContext")
            .field("keys", &self.0.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl EncryptionContext {
    /// An empty context (sends no `EncryptionContext`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a pair (replacing an earlier value of `key`).
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Adds a pair.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    /// The pairs, ordered by key.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// The number of pairs.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the context is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks the rules above (`InvalidArgument` before any request).
    pub(crate) fn check(&self, op: Operation) -> Result<()> {
        let bad = |m| Error::new(ErrorKind::InvalidArgument, BACKEND, op, m);
        if self.0.contains_key(AAD_CONTEXT_KEY) {
            return Err(bad(
                "the encryption context key associatedData is reserved for the portable AAD",
            ));
        }
        if self.0.iter().any(|(k, v)| k.is_empty() || v.is_empty()) {
            return Err(bad("encryption context keys and values must be non-empty"));
        }
        let size: usize = self.0.iter().map(|(k, v)| k.len() + v.len()).sum();
        if size > MAX_CONTEXT_BYTES {
            return Err(bad(
                "the encryption context is too large (at most 4096 bytes of keys and values)",
            ));
        }
        Ok(())
    }

    /// The wire map, `None` when empty.
    pub(crate) fn wire(&self) -> Option<&BTreeMap<String, String>> {
        (!self.0.is_empty()).then_some(&self.0)
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for EncryptionContext {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

/// Grant tokens sent with every request of a handle, for grants that are not yet eventually
/// consistent. Attach them at open:
/// `OpenOptions::new().with_extension(GrantTokens::new([token])?)`.
///
/// At most 10 tokens of 1 to 8192 characters. Never logged; `Debug` shows the count only.
#[derive(Clone)]
pub struct GrantTokens(Arc<[Zeroizing<String>]>);

impl fmt::Debug for GrantTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantTokens({} tokens)", self.0.len())
    }
}

impl GrantTokens {
    /// Validates and stores `tokens` (`InvalidArgument` if there are more than 10, or one is
    /// empty, longer than 8192 characters or not printable ASCII).
    pub fn new<I, S>(tokens: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let t: Vec<Zeroizing<String>> = tokens
            .into_iter()
            .map(|s| Zeroizing::new(s.into()))
            .collect();
        let bad = |m| Error::new(ErrorKind::InvalidArgument, BACKEND, Operation::Open, m);
        if t.is_empty() || t.len() > 10 {
            return Err(bad("between 1 and 10 grant tokens"));
        }
        if t.iter()
            .any(|s| s.is_empty() || s.len() > 8192 || !s.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Err(bad(
                "grant tokens must be 1 to 8192 printable ASCII characters",
            ));
        }
        Ok(Self(t.into()))
    }

    pub(crate) fn tokens(&self) -> Vec<&str> {
        self.0.iter().map(|s| s.as_str()).collect()
    }

    /// Tells this set from another without copying a token: clones share it; sets built
    /// separately (whatever their tokens) never do while both are alive. Never 0.
    pub(crate) fn identity(&self) -> usize {
        Arc::as_ptr(&self.0).cast::<()>().addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The context as JSON, as it goes on the wire.
    fn wire_json(m: &AadContext) -> String {
        serde_json::to_string(
            &m.iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap()
    }

    /// The wire format, pinned byte for byte: Tink's key, lowercase hex, no context for empty
    /// AAD. Both encoders agree.
    #[test]
    fn aad_wire_vectors() {
        assert!(aad_context(b"", Operation::Encrypt).unwrap().is_none());
        assert!(decrypt_aad_context(b"").is_none());
        let every_byte: Vec<u8> = (0..=255).collect();
        let every_hex = format!(
            r#"{{"associatedData":"{}"}}"#,
            every_byte
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert!(
            every_hex.contains("00010203")
                && every_hex.contains("9a9b9c9d9e9fa0")
                && every_hex.ends_with("fcfdfeff\"}")
        );
        for (aad, want) in [
            (&b"users/42"[..], r#"{"associatedData":"75736572732f3432"}"#),
            (&[0x00], r#"{"associatedData":"00"}"#),
            (
                &[0xfb, 0xff, 0xfe, 0x0a],
                r#"{"associatedData":"fbfffe0a"}"#,
            ),
            (
                &[0x00, 0x7f, 0x80, 0xab, 0xcd, 0xef, 0x10, 0xff],
                r#"{"associatedData":"007f80abcdef10ff"}"#,
            ),
            (&every_byte, &every_hex),
        ] {
            let m = aad_context(aad, Operation::Encrypt).unwrap().unwrap();
            assert_eq!(wire_json(&m), want);
            assert_eq!(wire_json(&decrypt_aad_context(aad).unwrap()), want);
        }
    }

    /// The cap is inclusive and binds the producing operations only (R-50): `Decrypt` encodes
    /// any length, so a ciphertext written under a raised cap still decrypts.
    #[test]
    fn aad_cap() {
        // The largest AAD encodes to 6144 characters, within the measured 8150 bytes.
        let m = aad_context(&[7; MAX_AAD_BYTES], Operation::Encrypt)
            .unwrap()
            .unwrap();
        assert_eq!(m[AAD_CONTEXT_KEY].len(), 6144);
        assert!(AAD_CONTEXT_KEY.len() + 6144 <= 8150);
        for op in [
            Operation::Encrypt,
            Operation::Rewrap,
            Operation::GenerateDataKey,
        ] {
            let e = aad_context(&[0; MAX_AAD_BYTES + 1], op).unwrap_err();
            assert_eq!((e.kind(), e.operation()), (ErrorKind::InvalidArgument, op));
        }
        let m = decrypt_aad_context(&[0xab; MAX_AAD_BYTES + 1]).unwrap();
        assert_eq!(m[AAD_CONTEXT_KEY].len(), 2 * (MAX_AAD_BYTES + 1));
    }

    #[test]
    fn contexts() {
        let c = EncryptionContext::new().with("tenant", "SECRETVALUE");
        assert!(c.check(Operation::Encrypt).is_ok());
        assert!(!format!("{c:?}").contains("SECRETVALUE"));
        assert_eq!(c.get("tenant"), Some("SECRETVALUE"));
        assert!(EncryptionContext::new().wire().is_none());
        for bad in [
            EncryptionContext::new().with(AAD_CONTEXT_KEY, "x"),
            EncryptionContext::new().with("", "x"),
            EncryptionContext::new().with("k", ""),
            EncryptionContext::new().with("k", "v".repeat(MAX_CONTEXT_BYTES)),
        ] {
            assert_eq!(
                bad.check(Operation::Encrypt).unwrap_err().kind(),
                ErrorKind::InvalidArgument
            );
        }
        let c: EncryptionContext = [("a", "1"), ("b", "2")].into_iter().collect();
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn grant_tokens() {
        let g = GrantTokens::new(["SECRETGRANT"]).unwrap();
        assert!(!format!("{g:?}").contains("SECRETGRANT"));
        assert_eq!(g.tokens(), vec!["SECRETGRANT"]);
        assert!(GrantTokens::new(Vec::<String>::new()).is_err());
        assert!(GrantTokens::new(vec!["t"; 11]).is_err());
        assert!(GrantTokens::new(["a b"]).is_err());
        assert!(GrantTokens::new(["x".repeat(8193)]).is_err());
    }
}
