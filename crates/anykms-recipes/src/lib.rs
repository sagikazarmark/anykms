//! Portable recipes over anykms key handles.
//!
//! **When to use this crate.** Most applications depend on the [`anykms`] facade and reach the
//! recipes as `anykms::recipes` (facade feature `recipes`, on by default, which enables every
//! recipe). Depend on `anykms-recipes` directly to compile only some recipes
//! (`default-features = false` plus `jose`, `envelope` and an RSA backend), or from a library or
//! backend that uses them without the facade (the cloud backends verify signatures locally with
//! [`LocalVerifier`]).
//!
//! [`anykms`]: https://docs.rs/anykms
//!
//! Core (`anykms-core`) exposes only what a backend natively does. The recipes here give uniform
//! behavior across backends. Each one documents what it **emulates** and what is **enforced by**
//! the KMS versus by this process, so emulated behavior is never mistaken for KMS-enforced
//! behavior.
//!
//! | Recipe | Emulates | Enforced by the KMS | Done locally | Feature |
//! |---|---|---|---|---|
//! | [`EnvelopeAead`] | AEAD of any size | wrapping the 32-byte data key (with an RSA KEK, only unwrapping: every holder of the public key can write envelopes) | payload AES-256-GCM, key commitment, optional length-hiding padding | `envelope` |
//! | [`EnvelopeKeyring`] | multi-KEK decrypt | wrapping the data key | routing by `kek_id` | `envelope` |
//! | [`CachingKeyWrap`] | — (saves KMS calls) | unwrapping each data key once per TTL | reusing unwrapped data keys | always |
//! | [`EmulatedDataKeys`] | `GenerateDataKey` | wrapping (with AAD) | key generation | always |
//! | [`KeyWrapDataKeys`] | `GenerateDataKey` (empty AAD only) | wrapping | key generation | always |
//! | [`ClientRewrap`] | `Rewrap` | decrypt, encrypt (with AAD) | **plaintext passes through the client** | always |
//! | [`rsa_oaep_sha256_encrypt`] | public-key encrypt (RSA-OAEP-SHA-256) | the private-key decrypt | the public-key encrypt | `rsa-aws-lc-rs` or `rsa-rustcrypto` |
//! | [`LocalVerifier`], [`CachedVerifier`] | verify | nothing (public keys only) | verification | always |
//! | [`sign_message_hashed`], [`verify_message_hashed`] | message signing for ECDSA/RSA | signing the digest | hashing | always |
//! | [`jose`] | — | signing | JWS/JWT signing, JWK/JWKS publishing | `jose` |
//!
//! # Cargo features
//!
//! | Feature | Default | Gates | Pulls in |
//! |---|---|---|---|
//! | `jose` | yes | [`jose`], the [`serde_json`] re-export | serde, serde_json |
//! | `envelope` | yes | [`envelope`], [`Envelope`], [`EnvelopeAead`], [`EnvelopeKeyring`], [`IntoKek`], `envelope::Padding` | aes-gcm, hkdf, sha2, subtle |
//! | `rsa-aws-lc-rs` | yes | RSA verification and [`rsa_oaep_sha256_encrypt`] with AWS-LC (see below) | aws-lc-rs |
//! | `rsa-rustcrypto` | | RSA verification and [`rsa_oaep_sha256_encrypt`] with RustCrypto (see below) | rsa, sha2 |
//!
//! Local verification ([`LocalVerifier`], [`CachedVerifier`], the hashed helpers, [`ecdsa_der`],
//! every curve), [`EmulatedDataKeys`], [`KeyWrapDataKeys`] and [`ClientRewrap`] are always
//! compiled: a backend that only verifies locally depends on this crate with
//! `default-features = false` (plus an RSA backend if it has RSA keys).
//!
//! # RSA backends
//!
//! Verifying RSA signatures and RSA-OAEP encryption ([`rsa_oaep_sha256_encrypt`]) need an RSA
//! backend, chosen with crate features named as in the facade and the cloud backends:
//! `rsa-aws-lc-rs` (AWS-LC, the default; needs a C toolchain) or `rsa-rustcrypto` (RustCrypto's
//! `rsa` crate, pure Rust). The `rsa` crate's only release on the digest-0.11/signature-3 stack is
//! a 0.10 release candidate, so it is opt-in: a later RC may change its API. With both enabled,
//! `rsa-aws-lc-rs` is used, so a dependency that enables `rsa-rustcrypto` never swaps the backend;
//! for `rsa-rustcrypto` alone, disable default features. With neither, RSA keys fail with
//! `Unsupported` in the verifiers and in RSA-OAEP encryption; ECDSA, Ed25519, RSA key parsing and
//! JWKs need no backend. ring is not offered: it cannot verify a precomputed digest, which
//! [`DigestVerifier`](anykms_core::DigestVerifier) requires.
//!
//! The RSA backend is chosen independently of the other features: with `default-features = false`
//! and neither `rsa-rustcrypto` nor `rsa-aws-lc-rs`, the crate compiles, and verifying an RSA
//! signature fails **at run time** with `Unsupported`. Enable one of them whenever RSA keys may be
//! verified.
//!
// The feature-gated items are linked only when they exist, so docs build warning-free with any
// feature set; otherwise the links point at the crate on docs.rs.
#![cfg_attr(feature = "envelope", doc = "[`envelope`]: crate::envelope")]
#![cfg_attr(feature = "envelope", doc = "[`Envelope`]: crate::Envelope")]
#![cfg_attr(feature = "envelope", doc = "[`EnvelopeAead`]: crate::EnvelopeAead")]
#![cfg_attr(
    feature = "envelope",
    doc = "[`EnvelopeKeyring`]: crate::EnvelopeKeyring"
)]
#![cfg_attr(feature = "envelope", doc = "[`IntoKek`]: crate::IntoKek")]
#![cfg_attr(
    not(feature = "envelope"),
    doc = "[`envelope`]: <https://docs.rs/anykms-recipes>"
)]
#![cfg_attr(
    not(feature = "envelope"),
    doc = "[`Envelope`]: <https://docs.rs/anykms-recipes>"
)]
#![cfg_attr(
    not(feature = "envelope"),
    doc = "[`EnvelopeAead`]: <https://docs.rs/anykms-recipes>"
)]
#![cfg_attr(
    not(feature = "envelope"),
    doc = "[`EnvelopeKeyring`]: <https://docs.rs/anykms-recipes>"
)]
#![cfg_attr(
    not(feature = "envelope"),
    doc = "[`IntoKek`]: <https://docs.rs/anykms-recipes>"
)]
#![cfg_attr(feature = "jose", doc = "[`jose`]: crate::jose")]
#![cfg_attr(feature = "jose", doc = "[`serde_json`]: crate::serde_json")]
#![cfg_attr(
    not(feature = "jose"),
    doc = "[`jose`]: <https://docs.rs/anykms-recipes>"
)]
#![cfg_attr(
    not(feature = "jose"),
    doc = "[`serde_json`]: <https://docs.rs/serde_json>"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod cached;
mod datakeys;
mod dek_cache;
pub mod ecdsa_der;
#[cfg(feature = "envelope")]
pub mod envelope;
mod hashed;
#[cfg(feature = "jose")]
pub mod jose;
mod rewrap;
mod rsa_backend;
mod verify;

pub use cached::CachedVerifier;
pub use datakeys::{EmulatedDataKeys, KeyWrapDataKeys};
pub use dek_cache::CachingKeyWrap;
#[cfg(feature = "envelope")]
pub use envelope::{Envelope, EnvelopeAead, EnvelopeKeyring, IntoKek};
pub use hashed::{
    PinnedVerifier, sign_message_hashed, verify_message_hashed, verify_message_hashed_as,
};
pub use rewrap::ClientRewrap;
pub use rsa_backend::rsa_oaep_sha256_encrypt;
/// Re-exported for the JSON values of [`jose`] (JWKs, JWKS documents, headers).
#[cfg(feature = "jose")]
#[doc(no_inline)]
pub use serde_json;
pub use verify::{
    LocalVerifier, MIN_RSA_BITS, pem_to_der, public_key_from_pem, public_key_from_spki_der,
    spki_key_type,
};
