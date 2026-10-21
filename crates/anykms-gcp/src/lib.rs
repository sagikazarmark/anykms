//! Google Cloud KMS backend for anykms.
//!
//! **When to use this crate.** Most applications depend on the [`anykms`] facade with its `gcp`
//! feature (and `gcp-google-cloud-auth` for `google-cloud-auth` credentials), and reach this crate
//! as `anykms::gcp` or open `gcp-kms://` keys through `anykms::with_default_providers()`. Depend on
//! `anykms-gcp` directly to use only this backend with `anykms-core`, without the facade.
//!
//! [`anykms`]: https://docs.rs/anykms
//!
//! ```no_run
//! use anykms_core::prelude::*;
//! use anykms_core::{Digest, SignatureAlgorithm};
//! use anykms_gcp::GcpProvider;
//!
//! # async fn demo() -> anykms_core::Result<()> {
//! // Application Default Credentials, global endpoint; ANYKMS_GCP_* variables refine it.
//! let gcp = GcpProvider::builder()
//!     .allowed_projects(["prod-kms"])
//!     .build()?;
//! let kek = gcp.aead_key("gcp-kms://projects/prod-kms/locations/global/keyRings/app/cryptoKeys/kek")?;
//! let ct = kek.encrypt(b"secret", b"users/42").await?;
//! let pt = kek.decrypt(&ct, b"users/42").await?;
//!
//! let signer = gcp.digest_signing_key(
//!     "gcp-kms://projects/prod-kms/locations/global/keyRings/app/cryptoKeys/release/cryptoKeyVersions/1",
//!     SignatureAlgorithm::EcdsaP256Sha256,
//! )?;
//! let sig = signer.sign_digest(&Digest::sha256(b"release.tar.gz")).await?;
//! signer.verify_digest(&Digest::sha256(b"release.tar.gz"), &sig).await?; // local
//! # Ok(()) }
//! ```
//!
//! # Behavior worth knowing
//!
//! - **URIs** are Cloud KMS resource names under `gcp-kms://` (Tink's spelling):
//!   `gcp-kms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>[/cryptoKeyVersions/<n>]`.
//!   AEAD keys are opened **without** a version (encrypt uses the primary, decrypt finds the
//!   version); signing, MAC and RSA key-wrapping keys **with** one (Cloud KMS asymmetric and MAC
//!   keys have no primary). The other way round fails to open with `KeyMismatch`. Rotating a
//!   signing key is therefore a configuration change (publish the new version's public key,
//!   switch the URI, keep the old version enabled until its signatures expire); an opt-in
//!   "newest enabled version" mode is planned.
//! - **Allowlists.** [`GcpProviderBuilder::allowed_projects`] and `allowed_locations` refuse
//!   keys elsewhere. Set them: a key URI from configuration could otherwise name an
//!   attacker-owned key that grants everyone encrypt rights.
//! - **Not native:** `Rewrap` and `DataKeys`. Handles from [`Provider::aead`] report
//!   `Unsupported` for both before any I/O, and [`Provider::data_keys`] is `Unsupported`. The
//!   recipes are explicit: `EnvelopeAead::rewrap_local` for envelope KEK rotation,
//!   `ClientRewrap` (the plaintext passes through the client) and `EmulatedDataKeys`.
//! - **Verification is local.** Signatures are verified in this process with the public key of
//!   the signature's version of the handle's key (`getPublicKey`, cached for
//!   [`public_key_ttl`](GcpProviderBuilder::public_key_ttl), default 60 s) through
//!   `LocalVerifier`. MAC tags are verified by Cloud KMS (`macVerify`). A signature or tag
//!   naming a version this key does not have is `VerificationFailed`.
//! - **Public keys of disabled versions are refused.** Before each `getPublicKey` (a cache
//!   miss), `cryptoKeyVersions.get` checks that the version is `ENABLED`, so local verification
//!   and `CachedVerifier` stop trusting a disabled version (Cloud KMS may serve its public key).
//!   This needs `cloudkms.cryptoKeyVersions.get` wherever public keys are read (signing,
//!   verification, RSA key wrapping, `PublicKeys`); without it they fail with
//!   `PermissionDenied` (fail closed).
//! - **Staleness.** Ciphertexts are opaque ([`ciphertext_version`](anykms_core::Aead::ciphertext_version)
//!   is `None`); [`decrypt_with_info`](anykms_core::Aead::decrypt_with_info) reports
//!   `used_primary` (Cloud KMS's `usedPrimary`), the only signal that data is on an old version.
//! - **Integrity.** Every request carries CRC32C checksums of its inputs and every response's
//!   checksums and `verified*` flags are checked (Google's data-integrity guidelines); a failure
//!   discards the response and is `Unavailable`, so a `Retry` layer retries it. A response for
//!   another key is `Backend`.
//! - **Key-type check.** Before a handle's first operation (cached per provider for about 10
//!   minutes): AEAD keys read `cryptoKeys.get` (`purpose` must be `ENCRYPT_DECRYPT`), signing
//!   keys `getPublicKey` on the pinned version (the algorithm must match, which also catches PSS
//!   vs PKCS#1; Cloud EKM keys are refused), MAC keys `cryptoKeyVersions.get`. Mismatches are
//!   `KeyMismatch`. [`KeyTypeCheck::TrustCaller`](anykms_core::KeyTypeCheck::TrustCaller) skips
//!   it (needed when the identity lacks the metadata permissions).
//! - **Versions.** A disabled, destroyed or scheduled-for-destruction version that the handle
//!   chose (its URI pin, or the primary version encrypt uses) is `KeyStateInvalid` for every
//!   operation, `public_key()` included (config class); one taken from the input (a ciphertext,
//!   signature or tag, `public_key_version`) is `KeyVersionUnusable` (caller class). A pending
//!   version adds a 2 s retry hint. A version from the input that does not exist is
//!   `UnknownKeyVersion` in `public_key_version`. Disabling takes about a minute to propagate in
//!   Cloud KMS.
//! - **403 vs 404.** A missing key is `NotFound` only when the caller may see the key ring;
//!   otherwise Cloud KMS answers 403 "(or it may not exist)", `PermissionDenied`.
//! - **Limits.** Plaintext and AAD up to 64 KiB each, MAC input and Ed25519 messages up to 64 KiB
//!   (`InvalidArgument` before any I/O); HSM keys have lower limits the server enforces. Use
//!   `EnvelopeAead` for bulk data.
//! - **No retries, no redirects.** The backend never retries (that is `Retry`'s job), except
//!   once after a 401 when the credential source yields a new token. Redirects are never
//!   followed.
//! - **Transport.** Every request (Cloud KMS, the token endpoints, the metadata server) goes
//!   through one [`HttpTransport`](anykms_http::HttpTransport): [`GcpProviderBuilder::http_transport`],
//!   or a default [`ReqwestTransport`](anykms_http::ReqwestTransport) (feature `reqwest`). TLS
//!   trust, the crypto provider, proxying, timeouts and the HTTP version are the transport's
//!   settings ([`ReqwestTransportBuilder`](anykms_http::ReqwestTransportBuilder)). The built-in
//!   transport never proxies the link-local metadata server, whose requests carry a 3 s
//!   per-request timeout.
//! - **Errors name the key.** Every handle error carries `gcp-kms://projects/...` as its
//!   [`resource`](anykms_core::Error::resource). Server messages are kept only when pinned;
//!   others are reduced to a keyed fingerprint.
//! - **Runtime.** The built-in transport requires a tokio runtime; called outside one, an
//!   operation fails with `Configuration` instead of panicking, before the credential source is
//!   asked.
//!
//! # Credentials
//!
//! [`Credentials::adc`] (the default) follows Application Default Credentials:
//! `GOOGLE_APPLICATION_CREDENTIALS`, the gcloud ADC file, then the metadata server. Supported
//! credential files: `service_account` (self-signed JWTs, feature `service-account-key`),
//! `authorized_user`, `external_account` with a file or URL subject token (workload identity
//! federation, e.g. GitHub Actions through `google-github-actions/auth`) and
//! `impersonated_service_account`. Nothing is resolved before the first operation; call
//! `preflight()` on each handle at startup to fail fast. See
//! [`Credentials`]; custom sources implement [`CredentialSource`]. Other credential types (AWS- or
//! executable-sourced federation, `external_account_authorized_user`, ...) come from Google's
//! auth library through the `google-cloud-auth` feature (`Credentials::google_cloud_auth`).
//!
//! # TLS crypto provider
//!
//! rustls needs a crypto provider. The built-in transport takes the first of:
//! [`ReqwestTransportBuilder::crypto_provider`](anykms_http::ReqwestTransportBuilder::crypto_provider);
//! the process default ([`CryptoProvider::install_default`]); aws-lc-rs with the `rustls-aws-lc-rs`
//! feature (default); ring with the `rustls-ring` feature. Nothing is installed process-wide. The
//! system roots are used unless
//! [`ReqwestTransportBuilder::ca_pem`](anykms_http::ReqwestTransportBuilder::ca_pem) replaces
//! them; there is no way to skip verification.
//!
//! # Cargo features
//!
//! | Feature | Default | Effect |
//! |---|---|---|
//! | `reqwest` | yes | the built-in transport ([`ReqwestTransport`](anykms_http::ReqwestTransport)); without it, [`GcpProviderBuilder::http_transport`] is required |
//! | `rustls-aws-lc-rs` | yes | aws-lc-rs as the fallback TLS crypto provider of the built-in transport (wins over ring) |
//! | `rustls-ring` | | ring as the fallback provider (opt-in, with `default-features = false`) |
//! | `rsa-aws-lc-rs` | yes | RSA verification and RSA-OAEP wrapping with aws-lc-rs |
//! | `rsa-rustcrypto` | | the same with RustCrypto's `rsa` (a release candidate) |
//! | `service-account-key` | yes | `service_account` key files (RS256 with aws-lc-rs) |
//! | `tracing` | | spans and events (field allowlist; never data or tokens) |
//! | `http2` | | allow HTTP/2 in the built-in transport ([`ReqwestTransportBuilder::http2`](anykms_http::ReqwestTransportBuilder::http2)) |
//!
//! Without an `rsa-*` feature, RSA signing, verifying and public-key handles and RSA KEKs fail
//! to open with `Configuration` (ECDSA and Ed25519 are unaffected).
//!
//! # Observability
//!
//! With `tracing`: one `anykms.gcp` span per request with the fields shared by every HTTP
//! backend (`backend`, `op`, `resource` = the key URI, `key_version`, `attempt`, `http_status`,
//! `code` = the `google.rpc.Status` name, `request_id`, `latency_ms`, `error_kind`, `outcome`),
//! one `anykms.gcp.token` span per token fetch (`backend`, `credential`, `outcome`,
//! `error_kind`, `latency_ms`, `expires_in_s`), and events for the credential source chosen,
//! token refreshes and their failures, the 401 retry, integrity failures (field name only),
//! unusable responses, unclassified errors and allowlist refusals. Never plaintext, AAD, tokens,
//! keys or bodies.
//! Cap `reqwest` and `hyper` at INFO.
//!
//! # Zeroization limits
//!
//! Request and response bodies, decoded plaintexts, tokens, refresh tokens, subject tokens and
//! service-account keys are held in zeroizing buffers. Not wiped: with the built-in transport, the
//! body copy reqwest sends, the `Authorization` header value and hyper/rustls buffers;
//! serde_json's scratch buffers for
//! escaped strings, the process environment and kernel socket buffers.
//!
//! [`CryptoProvider::install_default`]: anykms_http::rustls::crypto::CryptoProvider::install_default
//! [`Provider::aead`]: anykms_core::Provider::aead
//! [`Provider::data_keys`]: anykms_core::Provider::data_keys

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod auth;
mod client;
mod config;
mod crc32c;
mod errors;
mod handles;
mod keyinfo;
mod provider;
mod semantics;
mod uri;
mod wire;

pub(crate) const BACKEND: &str = "gcp";

/// The HTTP plumbing: the [`HttpTransport`](anykms_http::HttpTransport) seam and the built-in
/// [`ReqwestTransport`](anykms_http::ReqwestTransport) for [`GcpProviderBuilder::http_transport`].
pub use anykms_http;
pub use auth::{AuthEndpoints, CredentialSource, Credentials, Token};
pub use config::Endpoint;
pub use handles::{
    GcpAeadKey, GcpDescribeKey, GcpDigestKey, GcpEd25519Key, GcpKeyWrapKey, GcpMacKey,
};
pub use keyinfo::{GcpKeyInfo, GcpVersionInfo};
pub use provider::{GcpProvider, GcpProviderBuilder};
pub use uri::{GcpKeyRef, SCHEME, SCHEMES};

/// Internal parsers exposed for the fuzz targets. Not part of the public API.
#[doc(hidden)]
pub mod __fuzz {
    /// URI parsing (the part after `gcp-kms:`); on success, the canonical form round-trips.
    pub fn parse_uri(rest: &str) -> bool {
        match crate::uri::GcpKeyRef::parse_rest(rest) {
            Ok(r) => {
                let again = crate::uri::GcpKeyRef::parse_rest(&format!("//{}", r.resource_name()))
                    .expect("canonical form parses");
                assert_eq!(again, r);
                true
            }
            Err(_) => false,
        }
    }

    /// Error-response classification (status, body). Never panics.
    pub fn classify(status: u16, body: &[u8], op_selector: u8) -> anykms_core::ErrorKind {
        use anykms_core::Operation as O;
        let ops = [
            O::Encrypt,
            O::Decrypt,
            O::Sign,
            O::Mac,
            O::VerifyMac,
            O::PublicKey,
            O::WrapKey,
            O::UnwrapKey,
        ];
        use crate::handles::Origin;
        let origins = [Origin::Handle, Origin::Ciphertext, Origin::Input];
        let i = usize::from(op_selector);
        crate::errors::classify(crate::errors::Failure {
            http: status,
            body,
            retry_after: None,
            op: ops[i % ops.len()],
            origin: origins[(i / ops.len()) % origins.len()],
        })
        .kind()
    }

    /// Success-response decoding of encrypt, decrypt, sign, macSign, macVerify, key metadata and
    /// asymmetricDecrypt (`which % 7`). Returns whether the body was accepted.
    pub fn decode_success(which: u8, body: &[u8]) -> bool {
        crate::handles::fuzz_decode_success(which, body)
    }

    /// The CRC32C used for the integrity fields.
    pub fn crc32c(data: &[u8]) -> u32 {
        crate::crc32c::crc32c(data)
    }
}
