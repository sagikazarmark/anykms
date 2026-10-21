//! HashiCorp Vault and OpenBao transit backend for anykms.
//!
//! **When to use this crate.** Most applications depend on the [`anykms`] facade with its
//! `transit` feature, and reach this crate as `anykms::transit` or open `hashivault://` and
//! `openbao://` keys through `anykms::with_default_providers()`. Depend on `anykms-transit`
//! directly to use only this backend with `anykms-core`, without the facade.
//!
//! [`anykms`]: https://docs.rs/anykms
//!
//! ```no_run
//! use anykms_core::prelude::*;
//! use anykms_transit::TransitProvider;
//!
//! # async fn demo() -> anykms_core::Result<()> {
//! // VAULT_ADDR, VAULT_TOKEN / VAULT_TOKEN_FILE / ~/.vault-token, VAULT_NAMESPACE, VAULT_CACERT, ...
//! let transit = TransitProvider::from_env()?;
//! let kek = transit.aead_key("hashivault:///transit/keys/app-kek")?;
//! let ct = kek.encrypt(b"secret", b"users/42").await?;
//! let pt = kek.decrypt(&ct, b"users/42").await?;
//! # Ok(()) }
//! ```
//!
//! # Behavior worth knowing
//!
//! - **Native ciphertexts.** Ciphertexts are transit's own `vault:vN:...` strings and stay
//!   readable by other Vault/OpenBao clients. An empty AAD equals an omitted `associated_data`.
//! - **Key-type check.** Transit does not reject a mismatched key type (a P-384 key signs a
//!   "P-256" request; an RSA key "encrypts" without AEAD). Every handle therefore reads
//!   `transit/keys/<name>` once (cached per provider) before its first operation and refuses
//!   mismatches. This needs `read` on that path; [`KeyTypeCheck::TrustCaller`] opts out.
//! - **Fail closed.** Any response `warnings` (e.g. "Endpoint ignored these unrecognized
//!   parameters") turn into `Unsupported`, and each request sends only the parameters its
//!   operation needs.
//! - **Flavor differences.** Vault cannot bind AAD to data keys (`Unsupported` before any I/O;
//!   use `EmulatedDataKeys`); OpenBao ≥ 2.5 can. Transit's `rewrap` ignores AAD, so rewrap with
//!   non-empty AAD is `Unsupported`. Ed25519 is message signing only.
//! - **Upsert.** Encrypting to a missing key creates it unless the mount sets
//!   `transit/config/keys disable_upsert=true`. Set it, and never grant `create`.
//! - **Mount paths.** Mounts with a reserved segment (`sys`, `auth`, `identity`, `cubbyhole`) are
//!   refused. Multi-segment mounts (`team-a/transit`) open only when listed in
//!   [`ServerConfig::allowed_mounts`]: Vault Enterprise resolves leading path segments as
//!   namespaces, which would bypass `allowed_namespaces`. A single-segment mount can still name
//!   a child namespace on Vault Enterprise and OpenBao (`hashivault:///ns1/keys/k` may resolve
//!   as namespace `ns1`, mount `keys`), so deployments that use namespaces should set
//!   `allowed_mounts` too.
//! - **Login and renewal.** [`Login`] (Kubernetes or JWT auth, via [`ServerConfig::login`] or
//!   `ANYKMS_TRANSIT_AUTH`) logs in, renews the token before it expires and logs in again when
//!   renewal ends. Fixed tokens (a variable, a file, a static token) are never renewed: a service token
//!   with a TTL then fails with `PermissionDenied` once it expires. For those, use a Vault/Bao
//!   Agent (token sink via [`FileToken`], or its API proxy with [`NoToken`]), a batch or
//!   periodic token that outlives the process, or a custom [`TokenSource`]. Token files must not be
//!   group- or world-accessible: set `mode = 0600` on an Agent file sink (default `0640`) and
//!   `defaultMode: 0400` on a Kubernetes secret volume (default `0644`; `fsGroup` adds group
//!   read, see [`FileToken`] for non-root containers), or opt out with
//!   [`FileToken::allow_insecure_permissions`], [`EnvConfig::allow_insecure_token_file`] or
//!   `ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE=1` (see [`FileToken`]).
//! - **Key strength.** `aes128-gcm96` keys work as KEKs and for data keys but wrap 256-bit data
//!   keys at 128-bit strength; prefer `aes256-gcm96` (see [`TransitAeadKey`]).
//! - **Transport.** Every request goes through one [`HttpTransport`](anykms_http::HttpTransport):
//!   [`ServerConfig::http_transport`], or a default [`ReqwestTransport`](anykms_http::ReqwestTransport)
//!   (feature `reqwest`). TLS trust, client certificates (mTLS), the crypto provider, proxying,
//!   timeouts and the HTTP version are the transport's settings
//!   ([`ReqwestTransportBuilder`](anykms_http::ReqwestTransportBuilder)); `EnvConfig` builds one
//!   from `VAULT_CACERT`, `VAULT_CAPATH`, `VAULT_CLIENT_CERT` and `VAULT_CLIENT_KEY`. The built-in
//!   transport follows no redirects (a standby's 307 would otherwise receive the token and body),
//!   uses rustls (see [TLS crypto provider](#tls-crypto-provider)), and `ca_pem` replaces the
//!   system roots with no way to skip verification. Plain `http://` is allowed only for literal
//!   loopback IPs. A rejected server certificate (unknown issuer, name
//!   mismatch, expired) or client certificate is `Configuration`, not retryable; DNS failures
//!   ("DNS lookup failed") and refused or reset connections are `Unavailable`.
//! - **RSA-PSS salt length.** Signing and verification always send `salt_length=hash` (RFC 7518
//!   `PS256`/`PS384`/`PS512`). Signatures made by other Vault/OpenBao clients with transit's
//!   default `auto` (maximum salt) do **not** verify through anykms (see [`TransitDigestKey`]).
//! - **Environment.** [`EnvConfig`] reads every setting from the prefix that supplied the
//!   address (`BAO_*` or `VAULT_*`, never mixed), supports `*_CACERT` and `*_CAPATH`, and fails
//!   when no token source is found unless told there is none ([`EnvConfig::no_token`],
//!   `ANYKMS_TRANSIT_NO_TOKEN=1`, for an Agent API proxy). The anykms variables are prefixed
//!   `ANYKMS_TRANSIT_*`; the unprefixed names of earlier development builds (`ANYKMS_AUTH`,
//!   `ANYKMS_NO_TOKEN`, ...) are refused with `Configuration` naming the new one.
//!   [`TransitProvider::from_env_with`] (and [`EnvConfig::load_with`]) read the variables
//!   from a lookup instead of the process environment.
//! - **Errors name the key.** Every error from a handle carries the key as its
//!   [`resource`](anykms_core::Error::resource):
//!   `<scheme>://<server alias>/<mount>/keys/<name>`, plus ` (namespace <ns>)` when a namespace
//!   applies (the alias is the resolved one, so `hashivault:///...` shows the default server's
//!   name). It never holds a query string or token. File errors from [`EnvConfig`] and
//!   [`FileToken`] name the path and the I/O reason, never the contents. Vault and OpenBao send
//!   no request id with error responses (only success bodies carry `request_id`), so
//!   [`BackendDetail::request_id`](anykms_core::BackendDetail) is never set by this crate.
//! - **Runtime.** The built-in transport requires a tokio runtime; called outside one, an
//!   operation fails with `Configuration` instead of panicking, before the token source is asked.
//!
//! # TLS crypto provider
//!
//! rustls needs a crypto provider. The built-in transport takes the first of:
//!
//! 1. [`ReqwestTransportBuilder::crypto_provider`](anykms_http::ReqwestTransportBuilder::crypto_provider);
//! 2. the process default, installed by the application with
//!    [`CryptoProvider::install_default`] (e.g. a FIPS build of aws-lc-rs);
//! 3. aws-lc-rs, with the `rustls-aws-lc-rs` feature (default; also when `rustls-ring` is
//!    enabled too: features unify, so this is not an error);
//! 4. ring, with the `rustls-ring` feature.
//!
//! With none of these, building the transport fails with `Configuration`. An installed process
//! default therefore always wins over a feature, including one enabled by default somewhere in
//! the dependency graph. With the `tracing` feature a debug event names the provider chosen.
//! The provider is chosen per transport and never installed process-wide. reqwest is
//! built with `rustls-no-provider`, so only the selected provider is linked: by default ring is
//! not in the dependency tree. aws-lc-rs builds C and assembly (aws-lc-sys), so the default build
//! needs a C compiler (and, on Windows, uses prebuilt NASM objects; CMake only for FIPS). For ring
//! instead, use `default-features = false, features = ["reqwest", "rustls-ring"]`: aws-lc-sys is
//! then not in the dependency tree. Without the `reqwest` feature there is no built-in transport:
//! every server needs [`ServerConfig::http_transport`], and reqwest, hyper and rustls leave the
//! dependency tree. Through the `anykms` facade the same feature names apply
//! (`rustls-aws-lc-rs` is one of its default features).
//!
//! # Zeroization limits
//!
//! Request and response bodies, decoded plaintexts, data keys, tokens and the mTLS key PEM are
//! held in zeroizing buffers that grow without leaving unwiped copies. Copies outside anykms'
//! control are not wiped: with the built-in transport, the body reqwest sends and the token in its
//! `X-Vault-Token` header value (another transport decides for itself);
//! the process environment (`VAULT_TOKEN`), hyper/rustls buffers, kernel socket buffers, and the
//! parsed mTLS signing key inside the crypto provider (aws-lc clears it when freed; ring does
//! not).
//!
//! # Public dependencies
//!
//! [`anykms_http`] is re-exported: its [`HttpTransport`](anykms_http::HttpTransport) appears in
//! [`ServerConfig::http_transport`], and its `rustls` 0.23 re-export in
//! `ReqwestTransportBuilder::crypto_provider`, so a caller-built `CryptoProvider` matches the
//! rustls the built-in transport links. Their major versions are part of this crate's semver
//! contract: moving to a new rustls major version is a breaking anykms-transit release.
//!
//! [`CryptoProvider::install_default`]: anykms_http::rustls::crypto::CryptoProvider::install_default
//! [`KeyTypeCheck::TrustCaller`]: anykms_core::KeyTypeCheck::TrustCaller

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod auth;
mod client;
mod config;
mod errors;
mod handles;
mod keyinfo;
mod provider;
mod semantics;
mod token;
mod uri;

pub(crate) const BACKEND: &str = "transit";

/// The HTTP plumbing: the [`HttpTransport`](anykms_http::HttpTransport) seam and the built-in
/// [`ReqwestTransport`](anykms_http::ReqwestTransport) for [`ServerConfig::http_transport`].
pub use anykms_http;
pub use auth::{KUBERNETES_SERVICE_ACCOUNT_TOKEN, Login};
pub use config::{EnvConfig, Flavor, ServerConfig};
pub use handles::{TransitAeadKey, TransitDigestKey, TransitEd25519Key, TransitMacKey};
pub use keyinfo::{TransitKeyInfo, TransitKeyType};
pub use provider::{TransitProvider, TransitProviderBuilder};
pub use token::{EnvToken, FileToken, NoToken, StaticToken, Token, TokenSource};
pub use uri::{SCHEMES, TransitKeyRef};

/// Internal parsers exposed for the fuzz targets. Not part of the public API.
#[doc(hidden)]
pub mod __fuzz {
    /// `vault:v<N>:<payload>` prefix parsing.
    pub fn parse_versioned(s: &str) -> Option<(u64, &str)> {
        crate::handles::parse_versioned(s)
    }

    /// `GET keys/<name>` response decoding and conversion to the portable view.
    pub fn parse_key_info(body: &[u8]) -> bool {
        crate::keyinfo::TransitKeyInfo::parse(body)
            .map(|i| drop(i.to_key_info()))
            .is_ok()
    }

    /// Error-response classification.
    pub fn classify(status: u16, body: &[u8]) -> anykms_core::ErrorKind {
        #[derive(serde::Deserialize)]
        struct E {
            #[serde(default)]
            errors: Vec<String>,
        }
        let messages = serde_json::from_slice::<E>(body)
            .map(|e| e.errors)
            .unwrap_or_default();
        crate::errors::classify(&crate::errors::Failure {
            status,
            messages: &messages,
            retry_after: None,
            op: anykms_core::Operation::Decrypt,
            alias: "fuzz",
            key_read: status.is_multiple_of(2),
        })
        .kind()
    }

    /// Success-response decoding of encrypt/rewrap, decrypt, datakey, sign, verify and hmac
    /// (`which % 6`; `which / 6` picks the algorithm). Returns whether the body was accepted.
    pub fn decode_success(which: u8, body: &[u8]) -> bool {
        crate::handles::fuzz_decode_success(which, body)
    }
}
