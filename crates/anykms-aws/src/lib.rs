//! AWS KMS backend for anykms.
//!
//! **When to use this crate.** Most applications depend on the [`anykms`] facade with its `aws`
//! feature (and `aws-sdk-credentials` for AWS SDK credentials), and reach this crate as
//! `anykms::aws` or open `aws-kms://` keys through `anykms::with_default_providers()`. Depend on
//! `anykms-aws` directly to use only this backend with `anykms-core`, without the facade.
//!
//! [`anykms`]: https://docs.rs/anykms
//!
//! ```no_run
//! use anykms_core::prelude::*;
//! use anykms_aws::AwsProvider;
//!
//! # async fn demo() -> anykms_core::Result<()> {
//! // Credentials from the default chain (environment, profile, web identity, container, IMDS),
//! // resolved on the first operation.
//! let aws = AwsProvider::from_env()?;
//! let kek = aws.aead_key("aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/app-kek")?;
//! let ct = kek.encrypt(b"secret", b"users/42").await?;
//! let pt = kek.decrypt(&ct, b"users/42").await?;
//! # Ok(()) }
//! ```
//!
//! # Behavior worth knowing
//!
//! - **Key URIs** are full ARNs: `aws-kms://arn:<partition>:kms:<region>:<account>:key/<id>` or
//!   `...:alias/<name>` (Tink's format). The URI chooses partition, region and account, never a
//!   host; the endpoint is derived (standard, FIPS, dual-stack) or configured. The region must
//!   have the AWS region shape and belong to the partition, so a derived host is always a KMS
//!   endpoint. Optional account and region allowlists
//!   ([`AwsProviderBuilder::allowed_accounts`], [`AwsProviderBuilder::allowed_regions`]):
//!   without them, a key URI from untrusted input could name someone else's key.
//! - **AAD is an encryption context.** Non-empty AAD is sent as
//!   `{"associatedData": lowercase_hex(aad)}` ([`AAD_CONTEXT_KEY`]), empty AAD as no context:
//!   Tink's mapping, so ciphertexts with AAD interoperate with Tink's `AwsKmsAead`. This is a
//!   wire format. **CloudTrail logs the encryption context in clear**, so AAD must not be secret
//!   (hex is an encoding, not protection). AAD is capped at [`MAX_AAD_BYTES`] when producing a
//!   ciphertext (`Decrypt` takes any length). For native context maps (ciphertexts shared with
//!   other AWS tools) use [`EncryptionContextAead`].
//! - **Limits.** `Encrypt`, `Sign` (Ed25519, raw) and `GenerateMac` take 1 to 4096 bytes: AWS
//!   rejects empty input, and bulk data belongs in `EnvelopeAead`. These are checked before any
//!   request (`InvalidArgument`).
//! - **`Decrypt` and `ReEncrypt` always name the handle's key**, so a ciphertext under another key
//!   never decrypts through this handle. After an alias is repointed, old ciphertexts fail with
//!   `DecryptFailed` and a hint (`IncorrectKeyException`): route them with `EnvelopeKeyring` to
//!   the old key's own URI.
//! - **Versions.** Symmetric keys expose none (`ciphertext_version` is `None`). Signatures, tags
//!   and public keys of asymmetric and HMAC keys carry the **key ARN** (for an alias, the key it
//!   resolves to) as their version, so repointing an alias gives a new JWKS `kid`. A handle
//!   accepts only its own key's ARN: another ARN is `VerificationFailed` before any request when
//!   verifying and `UnknownKeyVersion` from `public_key_version`, a malformed version
//!   `InvalidArgument`, and a missing version verifies with this handle's key (an AWS key has
//!   exactly one version, so absence selects nothing).
//! - **Key-type check.** Each handle reads `DescribeKey` once (cached per provider, ~10 minutes;
//!   concurrent first operations on a key share one request) before its first operation and
//!   refuses mismatched keys with `KeyMismatch` (needs
//!   `kms:DescribeKey`; [`KeyTypeCheck::TrustCaller`](anykms_core::KeyTypeCheck) opts out, and
//!   AWS still rejects wrong usages server-side).
//! - **Public keys of disabled keys are refused.** AWS serves them, so `public_key` and
//!   `public_key_version` send an uncached `DescribeKey` of the same key first (always, so
//!   `kms:DescribeKey` is required) and fail with `KeyStateInvalid` unless the key is enabled.
//! - **Credentials** ([`credentials`]): resolved lazily, cached, refreshed 5 minutes before they
//!   expire by one request while the others keep using them. Concurrent requests without usable
//!   credentials share one fetch and its result; a failure is returned for 5 s before the next
//!   fetch. When AWS rejects them as expired or unknown they are refetched
//!   and the request is sent **once** more if they changed; no other retry happens in this crate
//!   (use `anykms_core::Retry`). A clock-skew rejection records the server's clock offset (later
//!   requests are signed with it) and is a retryable `Unavailable`. SSO, role chaining and
//!   `credential_process` come from the AWS SDK through the `sdk-credentials` feature.
//! - **Envelope KEKs** ([`AwsKeyWrapKey`]): symmetric keys wrap with `Encrypt`; RSA
//!   `ENCRYPT_DECRYPT` keys wrap locally with RSAES-OAEP-SHA-256 over the pinned public key and
//!   unwrap with `Decrypt` (needs the `rsa-aws-lc-rs` or `rsa-rustcrypto` feature).
//! - **Transport.** Every request (KMS, STS, IMDS, the container endpoint) goes through one
//!   [`HttpTransport`](anykms_http::HttpTransport): [`AwsProviderBuilder::http_transport`], or a
//!   default [`ReqwestTransport`](anykms_http::ReqwestTransport) (feature `reqwest`). TLS trust,
//!   the crypto provider, proxying, timeouts and the HTTP version are the transport's settings
//!   ([`ReqwestTransportBuilder`](anykms_http::ReqwestTransportBuilder)); `AWS_CA_BUNDLE` builds
//!   one. The built-in transport follows no redirects (a 3xx is `Configuration`), times out after
//!   2 s connecting and 10 s per request (the link-local credential endpoints after 2 s), never
//!   proxies link-local hosts, and offers no way to skip TLS verification. Plain `http://` only
//!   for literal loopback IPs with [`AwsProviderBuilder::allow_loopback_http`] (emulators).
//! - **Tracing** (`tracing` feature): each request is a `debug` span `anykms.aws` with `backend`,
//!   `op`, `resource`, `key_version`, `attempt`, `http_status`, `code`, `request_id`,
//!   `latency_ms`, `error_kind` and `outcome`; credential fetches are `anykms.aws.token` spans.
//!   Never data, contexts, grant tokens or credentials.
//! - **Errors** (backend name `aws`) name the key (`resource` = the key URI) and carry the AWS
//!   exception name (`BackendDetail::code`), the request id and the HTTP status; server
//!   messages are kept verbatim only when they are pinned, fixed texts.
//! - **Runtime.** The built-in transport requires a tokio runtime; called outside one, an
//!   operation fails with `Configuration` instead of panicking, before the credential chain runs.
//!
//! # TLS crypto provider
//!
//! The built-in transport takes the first of:
//! [`ReqwestTransportBuilder::crypto_provider`](anykms_http::ReqwestTransportBuilder::crypto_provider); the process default
//! ([`CryptoProvider::install_default`]); aws-lc-rs with the `rustls-aws-lc-rs` feature
//! (default; it builds C, so a C compiler is needed); ring with the `rustls-ring` feature (opt-in,
//! with `default-features = false`). The provider is never installed process-wide.
//!
//! # Zeroization limits
//!
//! Request and response bodies, decoded plaintexts, data keys, secret access keys, session
//! tokens and derived SigV4 signing keys live in zeroizing buffers. Copies outside anykms'
//! control are not wiped: with the built-in transport, the body reqwest sends, header values (the
//! session token) and hyper/rustls buffers; the process environment and the page cache of
//! credential files.
//!
//! [`CryptoProvider::install_default`]: anykms_http::rustls::crypto::CryptoProvider::install_default

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

// The hidden `__test-fixtures` feature (key administration for the test fixtures) must never
// reach a production build. `debug_assertions` is a profile setting, so this is defense in depth
// only; the CI `features` job also fails when the facade enables the feature. A consequence:
// `cargo test --release -p anykms-aws` (whose dev-dependency enables it) is unsupported.
#[cfg(all(feature = "__test-fixtures", not(debug_assertions)))]
compile_error!(
    "the `__test-fixtures` feature of anykms-aws is for its own tests only and is refused in \
     builds without debug assertions (release builds)"
);

#[cfg(feature = "__test-fixtures")]
mod admin;
mod client;
mod config;
mod context;
pub mod credentials;
mod endpoint;
mod errors;
mod extension;
mod handles;
mod keyinfo;
mod provider;
mod semantics;
mod sigv4;
mod time;
mod uri;

/// The backend name of errors and of [`Provider::name`](anykms_core::Provider::name).
pub(crate) const BACKEND: &str = "aws";

/// The HTTP plumbing: the [`HttpTransport`](anykms_http::HttpTransport) seam and the built-in
/// [`ReqwestTransport`](anykms_http::ReqwestTransport) for [`AwsProviderBuilder::http_transport`].
pub use anykms_http;
pub use config::AwsProviderBuilder;
pub use context::{
    AAD_CONTEXT_KEY, EncryptionContext, GrantTokens, MAX_AAD_BYTES, MAX_CONTEXT_BYTES,
};
pub use credentials::{CredentialSource, Credentials};
pub use extension::EncryptionContextAead;
pub use handles::{AwsAeadKey, AwsDigestKey, AwsEd25519Key, AwsKeyWrapKey, AwsMacKey};
pub use keyinfo::AwsKeyInfo;
pub use provider::AwsProvider;
pub use uri::{AwsKeyRef, SCHEME, SCHEMES};

/// Key administration for the test fixtures and the A0 probe (hidden `__test-fixtures` feature).
/// Not part of the public API.
#[cfg(feature = "__test-fixtures")]
#[doc(hidden)]
pub mod __test {
    pub use crate::admin::Admin;
}

/// Internal parsers exposed for the fuzz targets. Not part of the public API.
#[doc(hidden)]
pub mod __fuzz {
    /// ARN / URI parsing.
    pub fn parse_uri(s: &str) -> bool {
        s.parse::<anykms_core::KeyUri>()
            .ok()
            .and_then(|u| crate::uri::AwsKeyRef::parse(&u).ok())
            .is_some()
    }

    /// Error-response classification (`x-amzn-ErrorType` from `header`, body JSON).
    pub fn classify(status: u16, header: Option<&str>, body: &[u8]) -> anykms_core::ErrorKind {
        let mut h = anykms_http::http::HeaderMap::new();
        if let Some(v) = header.and_then(|v| anykms_http::http::HeaderValue::from_str(v).ok()) {
            h.insert("x-amzn-errortype", v);
        }
        let (code, message) = crate::errors::parse_error(&h, body);
        crate::errors::classify(crate::errors::Failure {
            status,
            code: code.as_deref(),
            message: message.as_deref(),
            request_id: crate::errors::request_id(&h),
            retry_after: None,
            op: anykms_core::Operation::Decrypt,
        })
        .kind()
    }

    /// Success-body decoding of every operation (`which % 9`).
    pub fn decode_success(which: u8, body: &[u8]) -> bool {
        crate::handles::fuzz_decode_success(which, body)
    }

    /// The shared-file INI parser.
    pub fn parse_profile(text: &str) -> bool {
        crate::credentials::parse_ini(text).is_ok()
    }

    /// IMDS / container JSON credentials.
    pub fn parse_credentials_json(body: &[u8]) -> bool {
        crate::credentials::JsonCredentials::parse(body, "fuzz").is_ok()
    }

    /// STS `AssumeRoleWithWebIdentity` responses, success and error.
    pub fn parse_sts(status: u16, body: &str) -> bool {
        if (200..300).contains(&status) {
            crate::credentials::parse_sts_success(body).is_ok()
        } else {
            let _ = crate::credentials::sts_error(status, body, None);
            true
        }
    }

    /// The AAD encoding of the producing operations: returns the encoded context value, `None`
    /// for empty or oversized AAD.
    pub fn encode_aad(aad: &[u8]) -> Option<String> {
        crate::context::aad_context(aad, anykms_core::Operation::Encrypt)
            .ok()
            .flatten()
            .map(|m| m[crate::context::AAD_CONTEXT_KEY].to_string())
    }

    /// RFC 3339 timestamps of credential expirations.
    pub fn parse_time(s: &str) -> bool {
        crate::time::parse_rfc3339(s).is_some()
    }
}
