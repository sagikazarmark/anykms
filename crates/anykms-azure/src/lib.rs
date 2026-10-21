//! Azure Key Vault and Managed HSM backend for anykms.
//!
//! **When to use this crate.** Most applications depend on the [`anykms`] facade with its `azure`
//! feature (and `azure-identity` for Azure SDK credentials), and reach this crate as
//! `anykms::azure` or open `azure-kv://` keys through `anykms::with_default_providers()`. Depend on
//! `anykms-azure` directly to use only this backend with `anykms-core`, without the facade, or to
//! enable the experimental `mhsm-hmac` feature, which the facade does not forward.
//!
//! [`anykms`]: https://docs.rs/anykms
//!
//! ```no_run
//! use anykms_core::prelude::*;
//! use anykms_azure::{AzureProvider, WorkloadIdentity};
//!
//! # async fn demo() -> anykms_core::Result<()> {
//! let azure = AzureProvider::builder()
//!     .credential(WorkloadIdentity::from_env()?)
//!     .allowed_vaults(["contoso-prod.vault.azure.net"])
//!     .build()?;
//! let kek = azure.key_wrap_key("azure-kv://contoso-prod.vault.azure.net/keys/app-kek")?;
//! let wrapped = kek.wrap_key(&[7u8; 32]).await?;
//! let dek = kek.unwrap_key(&wrapped).await?;
//! # Ok(()) }
//! ```
//!
//! # What opens
//!
//! | Key | Handles |
//! |---|---|
//! | `RSA`, `RSA-HSM` (2048+) | signer/verifier/public keys (`PS*`, `RS*`); `KeyWrap` (`RSA-OAEP-256`); data keys (`KeyWrapDataKeys`, no AAD) |
//! | `EC`, `EC-HSM` P-256/384/521 | signer/verifier/public keys (`ES256/384/512`) |
//! | Managed HSM `oct-HSM` (AES-256) | `Aead` (`A256GCM`, framed) with `EmulatedDataKeys`; `KeyWrap` (`A256KW`) |
//! | Managed HSM `oct-HSM` (HMAC) | `Mac` (`HS*`), feature `mhsm-hmac`, experimental |
//!
//! Not opened: P-256K keys and RSA keys under 2048 bits (`KeyMismatch`), `oct-HSM` keys on
//! Premium vaults (a preview; `Unsupported`), Ed25519 (Azure has none), `RSA-OAEP` with SHA-1
//! and `RSA1_5`, server-side rewrap (Azure has none: envelopes rewrap locally).
//!
//! # Behavior worth knowing
//!
//! - **Host allowlist.** A bearer token is only ever sent to an allowlisted host: a vault or
//!   Managed HSM name under the Key Vault and Managed HSM suffixes of the public, China and US
//!   Government clouds ([`AzureCloud`]), narrowed with
//!   [`allowed_vaults`](AzureProviderBuilder::allowed_vaults) (recommended when key URIs come
//!   from shared configuration). Another host is `Configuration` at open, with no I/O. The
//!   token scope comes from the host suffix (`https://vault.azure.net/.default`), **never** from
//!   a 401 challenge; a challenge naming another tenant only adds a hint to the
//!   `Unauthenticated` error.
//! - **Key URIs.** `azure-kv://<vault>.vault.azure.net/keys/<name>[/<version>]` (see
//!   [`AzureKeyRef`], with [`AzureKeyRef::from_key_id`] for Key Vault key identifiers). With a
//!   version, every operation uses it: inputs naming another version fail, and
//!   `public_key_version` serves only that version (`UnknownKeyVersion` otherwise, before any I/O).
//!   Without one, writes use the current version (read back from the response `kid`, which must
//!   name this key on this host, else `Backend`) and reads of old data use the version in the
//!   input. A host that refuses versionless writes with 405 (Lowkey Vault) is remembered, and
//!   writes on its unversioned URIs name the current version from the key-type cache. `describe`
//!   reports the current version as primary, also for a pinned URI.
//! - **Key-type check.** Each handle reads the key bundle (`GET /keys/<name>`, cached per
//!   provider for [`key_cache_ttl`](AzureProviderBuilder::key_cache_ttl), ~10 minutes; concurrent
//!   first operations on a key share one read) before its first operation and refuses a key
//!   whose type, curve, size or `key_ops` does not fit (`KeyMismatch`). This needs `keys/read`;
//!   `KeyTypeCheck::TrustCaller` opts out (Managed HSM wrapping and data keys still read it, to
//!   pick the algorithm).
//! - **Verification** is server-side (`verify`, which honours disabled keys and the audit log)
//!   unless a handle is opened with [`AzureOptions::local_verify`]
//!   ([`AzureProvider::digest_signing_key_with`]; RSA needs the `rsa-aws-lc-rs` or
//!   `rsa-rustcrypto` feature). For high volumes (JWKS consumers) prefer `CachedVerifier` over
//!   the handle's `PublicKeys`: `verify` counts against the vault's throttling budget.
//!   Signatures carry the key version from the response `kid`; verification needs it.
//! - **Framed ciphertexts.** Wrapped keys and AES-GCM ciphertexts are framed with the key version
//!   and algorithm (`docs/azure-ciphertext.md`; [`framing`]), so they are **not** readable by
//!   other Azure tools without stripping the frame ([`framing::parse`]).
//! - **Data keys** on a vault come from `KeyWrapDataKeys`: a local random key wrapped with
//!   RSA-OAEP-256; non-empty AAD is `Unsupported` before any I/O (bind context with
//!   `EnvelopeAead` instead). Unwrap them with the `KeyWrap` handle of the same key.
//! - **Errors** are classified on HTTP status and error codes (`BackendDetail::code` = the
//!   innermost Azure code, e.g. `ForbiddenByRbac`; `request_id` = `x-ms-request-id`). Until the
//!   live probe pins Azure's codes, a disabled key and an RBAC denial are both
//!   `PermissionDenied` (403) and a key-size error is `InvalidArgument`: under-classified, never
//!   misclassified. A 404 on a
//!   version taken from a signature or ciphertext is `VerificationFailed`/`DecryptFailed` once
//!   the key-type check has seen the key. Server messages are redacted to a fingerprint.
//! - **Credentials** are lazy: nothing is read or fetched before the first operation. Tokens are
//!   cached per scope (single flight: concurrent requests share one fetch and its result, a
//!   failure for 5 s; refreshed 5 minutes before expiry by one request while the others keep
//!   using the current token). A 401 refreshes the
//!   token and retries the request **once** if the token changed; there are no other retries
//!   (use `RetryLayer`). `429 Throttled` carries `Retry-After` when Azure sends it.
//! - **Transport.** Every request (vaults, the Entra ID token endpoint, IMDS) goes through one
//!   [`HttpTransport`](anykms_http::HttpTransport): [`AzureProviderBuilder::http_transport`], or
//!   a default [`ReqwestTransport`](anykms_http::ReqwestTransport) (feature `reqwest`); the
//!   built-in credentials receive it from the provider ([`AzureCredential::bind_transport`]).
//!   TLS trust (a test host's CA included), the crypto provider, proxying, timeouts and the HTTP
//!   version are the transport's settings ([`ReqwestTransportBuilder`](anykms_http::ReqwestTransportBuilder)).
//!   The built-in transport follows no redirects (a 3xx is `Configuration`, no token or body is
//!   sent on), uses rustls with the system roots (see [TLS crypto provider](#tls-crypto-provider))
//!   with no way to skip verification, and never proxies IMDS. Plain HTTP exists only for
//!   loopback test hosts.
//! - **Runtime.** The built-in transport requires a tokio runtime; called outside one, an
//!   operation fails with `Configuration` instead of panicking, before the credential is asked.
//!
//! # Credentials
//!
//! [`WorkloadIdentity`] (AKS), [`ManagedIdentity`] (IMDS, App Service), [`ClientSecret`],
//! [`StaticToken`] (tests), or any [`AzureCredential`], such as the Azure SDK's credentials through
//! the `azure-identity` feature (Azure CLI, certificates and the rest of `azure_identity`).
//! [`AzureProvider::from_env`] picks one by environment ([`credential_from_env`]), never by
//! probing the network. With none configured it still builds, and the first operation is
//! `Configuration` naming the variables (as on AWS and GCP).
//!
//! # Features
//!
//! `reqwest` (default): the built-in transport; without it [`AzureProviderBuilder::http_transport`]
//! is required. `rustls-aws-lc-rs` (default) or `rustls-ring`: its TLS crypto provider. `rsa-aws-lc-rs`
//! (default) or `rsa-rustcrypto`: local RSA verification. `tracing`: spans and events (see
//! `docs/operations-azure.md`, "Tracing"). `http2`, `azure-identity`, and the experimental
//! `mhsm-hmac`.
//!
//! # TLS crypto provider
//!
//! As anykms-transit, for the built-in transport:
//! [`ReqwestTransportBuilder::crypto_provider`](anykms_http::ReqwestTransportBuilder::crypto_provider),
//! else the process default
//! ([`CryptoProvider::install_default`]), else aws-lc-rs (`rustls-aws-lc-rs`, default), else
//! ring (`rustls-ring`). Never installed process-wide.
//!
//! # Zeroization limits
//!
//! Request and response bodies, decoded plaintexts, data keys, tokens and secrets are held in
//! zeroizing buffers. Copies outside anykms' control are not wiped: with the built-in transport,
//! the body reqwest sends, the `Authorization` header value and hyper and rustls buffers; the
//! process environment (`AZURE_CLIENT_SECRET`), kernel socket buffers.
//!
//! [`CryptoProvider::install_default`]: anykms_http::rustls::crypto::CryptoProvider::install_default

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod client;
mod config;
mod cred;
mod credential;
mod errors;
pub mod framing;
mod handles;
mod keyinfo;
mod provider;
mod semantics;
mod uri;

pub(crate) const BACKEND: &str = "azure";

/// The HTTP plumbing: the [`HttpTransport`](anykms_http::HttpTransport) seam and the built-in
/// [`ReqwestTransport`](anykms_http::ReqwestTransport) for [`AzureProviderBuilder::http_transport`].
pub use anykms_http;
pub use config::{ApiVersion, AzureCloud, AzureOptions, TestHost, VaultKind};
#[cfg(feature = "azure-identity")]
pub use cred::AzureIdentity;
pub use cred::{
    ClientSecret, EnvCredentialKind, IMDS_ENDPOINT, IMDS_TIMEOUT, ManagedIdentity,
    TOKEN_REQUEST_TIMEOUT, WorkloadIdentity, credential_from_env, credential_from_env_with,
    env_credential_kind, env_credential_kind_with,
};
pub use credential::{AccessToken, AzureCredential, StaticToken};
#[cfg(feature = "mhsm-hmac")]
pub use handles::AzureMacKey;
pub use handles::{AzureAeadKey, AzureDigestKey, AzureKeyWrapKey};
pub use keyinfo::{AzureKeyInfo, AzureKeyType, AzureVersionInfo};
pub use provider::{AzureProvider, AzureProviderBuilder};
pub use uri::{AzureKeyRef, SCHEME, SCHEMES};

/// Internal parsers exposed for the fuzz targets. Not part of the public API.
#[doc(hidden)]
pub mod __fuzz {
    /// URI parsing and the host policy (default suffixes).
    pub fn parse_uri(s: &str) -> bool {
        match crate::uri::AzureKeyRef::parse(s) {
            Ok(u) => {
                let p = crate::config::HostPolicy::default();
                let _ = p.resolve(u.host());
                let again = crate::uri::AzureKeyRef::parse(u.to_string().as_str())
                    .expect("a parsed URI reparses");
                assert_eq!(again, u);
                true
            }
            Err(_) => false,
        }
    }

    /// Error-body parsing and classification.
    pub fn classify(status: u16, body: &[u8]) -> anykms_core::ErrorKind {
        let b = crate::errors::ErrorBody::parse(body);
        crate::errors::classify(&crate::errors::Failure {
            status,
            body: &b,
            retry_after: None,
            request_id: None,
            op: anykms_core::Operation::Decrypt,
            class: crate::errors::ReqClass::InputVersion,
            key_seen: status.is_multiple_of(2),
            tenant_hint: None,
            host: "fuzz",
        })
        .kind()
    }

    /// Success-body decoding (sign/wrap/encrypt, verify, key bundles), by `which`.
    pub fn decode_success(which: u8, body: &[u8]) -> bool {
        crate::handles::fuzz_decode_success(which, body)
    }

    /// Key bundle parsing and the portable view.
    pub fn parse_key_bundle(body: &[u8]) -> bool {
        match crate::keyinfo::KeyBundle::parse(body, crate::config::VaultKind::ManagedHsm) {
            Ok(b) => {
                let _ = b.info.to_key_info();
                true
            }
            Err(_) => false,
        }
    }

    /// JWK → SPKI for RSA (`n`, `e`) and EC (`crv`, `x`, `y`).
    pub fn jwk_spki(n_or_crv: &str, e_or_x: &str, y: Option<&str>) -> bool {
        match y {
            None => crate::keyinfo::rsa_spki(n_or_crv, e_or_x).is_some(),
            Some(y) => crate::keyinfo::ec_spki(n_or_crv, e_or_x, y).is_some(),
        }
    }

    /// Token-endpoint responses and errors.
    pub fn token_response(status: u16, body: &[u8]) -> bool {
        if (200..300).contains(&status) {
            crate::credential::parse_token_response(body, "fuzz").is_ok()
        } else {
            let _ = crate::credential::token_error("fuzz", status, body, None);
            false
        }
    }
}
