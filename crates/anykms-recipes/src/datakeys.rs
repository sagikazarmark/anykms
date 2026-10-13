//! Data keys generated locally and wrapped by a KMS key.
//!
//! - [`EmulatedDataKeys`] wraps with any [`Aead`] key and binds the wrapped key to the AAD.
//! - [`KeyWrapDataKeys`] wraps with any [`KeyWrap`] key (e.g. an RSA-OAEP or AES-KW KEK), which
//!   has no AAD slot, so it accepts only empty AAD.

use anykms_core::{
    Aead, DataKey, DataKeySpec, DataKeys, Error, ErrorKind, KeyWrap, Operation, Result,
};
use zeroize::Zeroizing;

/// Generates `spec`'s key material from the OS RNG (`Backend` on RNG failure), or `Unsupported`
/// for a spec this crate does not know.
fn random_data_key(spec: DataKeySpec, backend: &'static str) -> Result<Zeroizing<Vec<u8>>> {
    let n = match spec {
        DataKeySpec::Aes256 => 32,
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                backend,
                Operation::GenerateDataKey,
                "data key spec",
            ));
        }
    };
    let mut dek = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut dek[..]).map_err(|e| {
        Error::new(
            ErrorKind::Backend,
            backend,
            Operation::GenerateDataKey,
            format!("operating system RNG failed: {e}"),
        )
    })?;
    Ok(dek)
}

/// [`DataKeys`] over any [`Aead`] key.
///
/// **Emulates:** backend-generated data keys (`GenerateDataKey`). **Enforced by:** the data key is
/// generated **locally** from the OS RNG; the KMS only wraps it, binding the wrapped key to the
/// AAD. Use it for portable AAD binding, e.g. on Vault, where native `DataKeys` with AAD is
/// `Unsupported`. The [`DataKey`]'s ciphertext decrypts with [`Aead::decrypt`] and the same AAD.
#[derive(Clone, Debug)]
pub struct EmulatedDataKeys<K>(K);

impl<K> EmulatedDataKeys<K> {
    /// Data keys wrapped by `aead`.
    pub fn new(aead: K) -> Self {
        Self(aead)
    }

    /// The AEAD key.
    pub fn inner(&self) -> &K {
        &self.0
    }

    /// Returns the AEAD key.
    pub fn into_inner(self) -> K {
        self.0
    }
}

impl<K: Aead> DataKeys for EmulatedDataKeys<K> {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        let dek = random_data_key(spec, "emulated-data-keys")?;
        let ct = self
            .0
            .encrypt(&dek, aad)
            .await
            .map_err(|e| e.with_operation(Operation::GenerateDataKey))?;
        DataKey::new(spec, dek, ct)
    }
}

const KEYWRAP_DATA_KEYS: &str = "keywrap-data-keys";

/// [`DataKeys`] over any [`KeyWrap`] key: a key-wrapping key without an AAD slot, such as an
/// Azure Key Vault RSA key that only does `wrapKey`/`unwrapKey`.
///
/// **Emulates:** backend-generated data keys (`GenerateDataKey`). **Enforced by:** the data key is
/// generated **locally** from the OS RNG; the KMS only wraps it with [`KeyWrap::wrap_key`].
/// **No AAD binding:** key wrapping has no AAD slot, so a non-empty `aad` fails with
/// `Unsupported` before the RNG runs and before any I/O. Bind context to the payload instead
/// (e.g. envelope encryption with the AAD, over the same KEK).
///
/// The [`DataKey`]'s ciphertext is a **wrapped key**: unwrap it with [`KeyWrap::unwrap_key`] on
/// the same KEK, not with [`Aead::decrypt`]. This is a separate type from [`EmulatedDataKeys`],
/// whose point is the AAD binding.
///
/// ```
/// # use anykms_core::{DataKeys, DataKeySpec, KeyWrap};
/// # use anykms_recipes::KeyWrapDataKeys;
/// # async fn demo(kek: impl KeyWrap) -> anykms_core::Result<()> {
/// let data_keys = KeyWrapDataKeys::new(kek);
/// let dk = data_keys.generate_data_key(DataKeySpec::Aes256, b"").await?;
/// let again = data_keys.inner().unwrap_key(dk.ciphertext()).await?;
/// assert_eq!(&again[..], dk.plaintext());
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct KeyWrapDataKeys<K>(K);

impl<K> KeyWrapDataKeys<K> {
    /// Data keys wrapped by `kek`.
    pub fn new(kek: K) -> Self {
        Self(kek)
    }

    /// The key-wrapping key.
    pub fn inner(&self) -> &K {
        &self.0
    }

    /// Returns the key-wrapping key.
    pub fn into_inner(self) -> K {
        self.0
    }
}

impl<K: KeyWrap> DataKeys for KeyWrapDataKeys<K> {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        if !aad.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                KEYWRAP_DATA_KEYS,
                Operation::GenerateDataKey,
                "KeyWrap has no AAD slot: data keys wrapped by a KeyWrap key take empty AAD; \
                 bind context to the payload with EnvelopeAead",
            ));
        }
        let dek = random_data_key(spec, KEYWRAP_DATA_KEYS)?;
        let ct = self
            .0
            .wrap_key(&dek)
            .await
            .map_err(|e| e.with_operation(Operation::GenerateDataKey))?;
        DataKey::new(spec, dek, ct)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anykms_core::Ciphertext;

    use super::*;

    // The tests over real keys (anykms-local) are in tests/emulated.rs: anykms-local is a
    // path-only dev-dependency, so unit tests here must not use it (the packaged crate builds
    // them).

    /// Counts wrap calls so the AAD refusal can be shown to happen before any I/O.
    #[derive(Default)]
    struct Counting(AtomicUsize);

    impl KeyWrap for Counting {
        async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Ciphertext::from_bytes(key.to_vec()))
        }
        async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(wrapped.as_bytes().to_vec()))
        }
    }

    #[tokio::test]
    async fn aad_is_unsupported_before_any_call() {
        let dk = KeyWrapDataKeys::new(Counting::default());
        let err = dk
            .generate_data_key(DataKeySpec::Aes256, b"ctx")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.operation(), Operation::GenerateDataKey);
        assert_eq!(dk.inner().0.load(Ordering::SeqCst), 0);
        dk.generate_data_key(DataKeySpec::Aes256, b"")
            .await
            .unwrap();
        assert_eq!(dk.inner().0.load(Ordering::SeqCst), 1);
    }
}
