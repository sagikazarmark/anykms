//! Rewrap in the client: decrypt, then encrypt under the key's current version.
//!
//! **Emulates:** server-side rewrap ([`Rewrap`]). **Enforced by:** none; **the plaintext passes
//! through this process** (held in zeroizing memory between the two calls). The KMS still
//! enforces the AAD on decrypt and binds it again on encrypt. Use it only where the backend has
//! no rewrap (e.g. GCP Cloud KMS) and plaintext in the client is acceptable; it is never used
//! implicitly. For envelopes, prefer `EnvelopeAead::rewrap_local`, which touches only the data
//! key and checks its commitment.

use anykms_core::{Aead, Ciphertext, Operation, Result, Rewrap};

/// [`Rewrap`] over any [`Aead`] key, as [`Aead::decrypt`] then [`Aead::encrypt`] with the same
/// AAD in this process.
///
/// **Emulates:** server-side rewrap. **Enforced by:** none; the plaintext passes through the
/// client. Decrypt failures keep their kind (e.g. `DecryptFailed` for a wrong AAD); every error
/// reports [`Operation::Rewrap`]. Opt-in: wrap a key in it explicitly.
///
/// ```
/// # use anykms_core::{Aead, Ciphertext, Rewrap};
/// # use anykms_recipes::ClientRewrap;
/// # async fn demo(key: impl Aead, ct: Ciphertext) -> anykms_core::Result<()> {
/// let rewrapper = ClientRewrap::new(key);
/// let fresh = rewrapper.rewrap(&ct, b"context").await?;
/// # let _ = fresh; Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct ClientRewrap<K>(K);

impl<K> ClientRewrap<K> {
    /// Client-side rewrap with `key`.
    pub fn new(key: K) -> Self {
        Self(key)
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

impl<K: Aead> Rewrap for ClientRewrap<K> {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        let pt = self
            .0
            .decrypt(ct, aad)
            .await
            .map_err(|e| e.with_operation(Operation::Rewrap))?;
        self.0
            .encrypt(&pt, aad)
            .await
            .map_err(|e| e.with_operation(Operation::Rewrap))
    }
}

// Tests: tests/emulated.rs (they need anykms-local, a path-only dev-dependency).
