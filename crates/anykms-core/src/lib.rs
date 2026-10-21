//! Core traits and types for anykms.
//!
//! **When to use this crate.** Most applications depend on the [`anykms`] facade, which re-exports
//! this crate at its root. Depend on `anykms-core` directly when you implement a backend (a
//! [`Provider`] and its key handles; the [`Provider`] docs state the contract, errors included),
//! or when a library or [`Layer`] needs only the traits, types and errors, without the facade's
//! backends and defaults.
//!
//! [`anykms`]: https://docs.rs/anykms
//!
//! anykms gives applications one way to use key-management services for data-plane operations
//! (encrypt, rewrap, sign, MAC, describe) without hiding how the services differ:
//!
//! - **Capability traits** ([`Aead`], [`Rewrap`], [`DataKeys`], [`DigestSigner`],
//!   [`MessageSigner`], [`DigestVerifier`], [`MessageVerifier`], [`Mac`], [`PublicKeys`],
//!   [`Describe`], [`WrappedDataKeys`]) are implemented by key handles for exactly the operations the key supports.
//!   [`KeyWrap`] is what envelope encryption needs from a KEK; an [`Aead`] key becomes one
//!   explicitly ([`Aead::into_key_wrap`]). With a backend known at compile time, a missing
//!   capability is a compile error.
//! - **Config-driven use** goes through the [`Registry`], which routes [`KeyUri`]s to
//!   [`Provider`]s and returns opaque handles ([`AeadKey`], [`KeyWrapKey`], [`DataKeysKey`],
//!   [`MacKey`], ...)
//!   that implement the same static traits. The capability traits are not object-safe
//!   (`dyn Aead` is E0038); `Arc<dyn DynAead>` and the handles are the trait-object path.
//!   [`Layer`]s such as [`RetryLayer`] decorate every part of a handle without changing its
//!   type, and `downcast_ref` reaches the backend's typed handle behind it; backend-specific
//!   operations on it run through the layers with `call_extension`
//!   (e.g. [`AeadKey::call_extension`]).
//! - **One error taxonomy** ([`ErrorKind`]) with [`Error::is_retryable`],
//!   [`Error::is_config_error`] and [`Error::is_caller_error`], or all at once as an
//!   [`ErrorClass`] ([`Error::class`]).
//! - **Declared differences.** Where backends legitimately differ (version model, limits,
//!   data-key AAD, local verification), a handle states what it does as [`KeySemantics`],
//!   read through [`Semantics`] without I/O.
//!
//! Core exposes only what a backend natively does. Portable emulations (envelope encryption,
//! emulated data keys, local verification) live in `anykms-recipes`.
//!
//! The [glossary] defines the terms these docs use: typed and opaque handles, parts, layers,
//! providers, KEKs (key-wrapping keys), data keys and more.
//!
//! [glossary]: https://github.com/sagikazarmark/anykms/blob/main/docs/glossary.md
//!
//! # Public dependencies
//!
//! [`Zeroizing`] is re-exported from `zeroize` 1, so `zeroize`'s major version is part of this
//! crate's semver contract. The bounds of the opaque handles' `full` constructors are frozen at
//! the original part set: a newer part is not set by `full`; set it with its `with_*` method, so
//! adding one does not break backends that call `full`.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod around;
mod dynamic;
pub mod encoding;
mod error;
pub mod observe;
mod provider;
pub mod retry;
mod semantics;
#[cfg(feature = "serde")]
mod serde_impls;
pub mod time;
mod traits;
mod types;
mod uri;

pub use around::{Around, Call, CallCx, CallOutput};
pub use dynamic::{
    AeadKey, BoxFuture, DataKeysKey, DescribeKey, DigestSignerKey, DigestVerifierKey, DynAead,
    DynDataKeys, DynDescribe, DynDigestSigner, DynDigestVerifier, DynExtensionCalls, DynKeyWrap,
    DynMac, DynMessageSigner, DynMessageVerifier, DynPreflight, DynPublicKeys, DynRewrap,
    DynWrappedDataKeys, KeyWrapKey, Layer, LayerCx, MacKey, MessageSignerKey, MessageVerifierKey,
    OpaqueHandle, Part, PartKind, PublicKeysKey,
};
pub use error::{BackendDetail, Error, ErrorClass, ErrorKind, Operation, Result, ServerMessage};
pub use observe::{ObserveLayer, Observed, OpEvent};
pub use provider::{KeyTypeCheck, OpenOptions, Provider, Registry, RegistryBuilder};
pub use retry::{
    ClockFn, Retry, RetryBudget, RetryLayer, RetryPolicy, SleepFn, instant_sleep, std_clock,
};
pub use semantics::{
    DataKeyAad, DataKeySource, KeySemantics, PinnedVerify, Semantics, StateScope,
    UnversionedVerify, Verification, VersionModel, VersionShape,
};
pub use traits::{
    Aead, AeadKeyWrap, DataKeys, Describe, DigestSigner, DigestVerifier, ExtensionCalls, KeyWrap,
    Mac, MessageSigner, MessageVerifier, PinnedVerifier, Preflight, PublicKeys, Rewrap,
    WrappedDataKeys,
};
pub use types::{
    AsymmetricKeyType, Capabilities, Ciphertext, DataKey, DataKeySpec, Decrypted, Digest,
    HashAlgorithm, KeyInfo, KeyState, KeyVersion, KeyVersionInfo, MacAlgorithm, PublicKey,
    Signature, SignatureAlgorithm, SigningShape, Tag,
};
pub use uri::{IntoKeyUri, KeyUri};

/// Re-exported so users do not need a direct `zeroize` dependency for plaintext outputs.
pub use zeroize::Zeroizing;

/// Glob-importable traits (static method names only).
pub mod prelude {
    pub use crate::{
        Aead, DataKeys, Describe, DigestSigner, DigestVerifier, KeyWrap, Mac, MessageSigner,
        MessageVerifier, PinnedVerifier, Preflight, PublicKeys, Rewrap, WrappedDataKeys,
    };
}
