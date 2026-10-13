//! In-process software backend for anykms. **For tests and development only.**
//!
//! **When to use this crate.** Most applications depend on the [`anykms`] facade with its `local`
//! feature (typically only for development and tests) and reach this crate as `anykms::local`.
//! Depend on `anykms-local` directly, usually as a dev-dependency, to test code written against
//! `anykms-core` or a single backend crate without the facade.
//!
//! [`anykms`]: https://docs.rs/anykms
//!
//! Keys live in process memory with no persistence and vanish when the process exits; data
//! encrypted under them is then unrecoverable. Opening keys through a [`Provider`] therefore
//! requires the explicit runtime opt-in [`LocalProvider::allow_ephemeral_local_keys`], and every
//! open logs a warning.
//!
//! ```
//! use anykms_core::prelude::*;
//! use anykms_local::{Fault, LocalKeyset};
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let ks = LocalKeyset::builder().aead("kek").hmac("tok").ecdsa_p256("sig").ed25519("ed").build();
//! let kek = ks.aead_key("kek");
//! let ct = kek.encrypt(b"secret", b"aad").await.unwrap();
//! assert_eq!(&*kek.decrypt(&ct, b"aad").await.unwrap(), b"secret");
//!
//! ks.rotate("kek").unwrap();
//! ks.inject(Fault::throttled(1));
//! assert!(kek.encrypt(b"x", b"").await.unwrap_err().is_retryable());
//! # });
//! ```
//!
//! Supported: AES-256-GCM (`Aead`, `Rewrap` including with AAD, `DataKeys` with AAD), HMAC-SHA2,
//! ECDSA P-256/P-384/P-521 and Ed25519. There are no RSA keys. Ciphertexts are framed as
//! `local:v<N>:` followed by the nonce, ciphertext and tag.
//!
//! [`Provider`]: anykms_core::Provider

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod handles;
mod keyset;
mod provider;

pub use handles::{
    LocalAeadKey, LocalDigestKey, LocalEd25519Key, LocalMacKey, MAX_PLAINTEXT,
    parse_local_ciphertext,
};
pub use keyset::{Fault, LocalKeyKind, LocalKeyset, LocalKeysetBuilder};
pub use provider::{LocalProvider, SCHEME, parse_local_uri};

/// Internal functions exposed for the fuzz targets. Not part of the public API.
#[doc(hidden)]
pub mod __fuzz {
    /// Formats `local:v<N>:` + nonce + ciphertext + tag, as encryption does.
    pub fn frame(version: u64, nonce: &[u8], ct: &[u8]) -> Vec<u8> {
        crate::handles::frame(version, nonce, ct)
    }
}
