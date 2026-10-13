# Crates and Cargo features

## Crates

Most applications depend on the `anykms` facade and choose backends with its features. The
member crates can also be used directly.

| Crate | What |
|---|---|
| [`anykms`](../crates/anykms) | facade: re-exports, `with_default_providers()`, tokio retries (`retry_layer()`) |
| [`anykms-core`](../crates/anykms-core) | traits, types, errors, `KeyUri`, `Provider`/`Registry`, `Retry` (no HTTP, no runtime) |
| [`anykms-recipes`](../crates/anykms-recipes) | `EnvelopeAead`, `EnvelopeKeyring`, `EmulatedDataKeys`, `LocalVerifier`, `CachedVerifier`, JOSE signing and JWKS (verify JWTs with `jsonwebtoken`) |
| [`anykms-transit`](../crates/anykms-transit) | Vault and OpenBao transit (in-house client on `reqwest` + rustls with ring or aws-lc-rs) |
| [`anykms-aws`](../crates/anykms-aws) | AWS KMS (in-house SigV4 client and workload credential chain on `reqwest` + rustls, AWS SDK credentials as an option; facade feature `aws`) |
| [`anykms-gcp`](../crates/anykms-gcp) | Google Cloud KMS (in-house REST client and Application Default Credentials, `google-cloud-auth` as an option; CRC32C integrity checks; local signature verification; facade feature `gcp`) |
| [`anykms-azure`](../crates/anykms-azure) | Azure Key Vault and Managed HSM (in-house REST client and Entra ID workload credentials, Azure SDK credentials as an option; vault host allowlist; framed ciphertexts; facade feature `azure`) |
| [`anykms-http`](../crates/anykms-http) | HTTP plumbing shared by the backends (TLS, no-redirect client, zeroizing buffers); for anykms backends only |
| [`anykms-local`](../crates/anykms-local) | in-memory software keys, **tests and development only** |
| [`anykms-conformance`](../crates/anykms-conformance) | the shared conformance suite for backends, including third-party ones (published; its fixture API may change in minor releases, and new `Feature`s and cases come only in minor releases) |

## Cargo features

Features choose backends and crypto implementations, with sensible defaults. Cargo unifies
features across a build, so enabling both alternatives is not an error: a fixed priority picks
one.

| Feature | Default | What |
|---|---|---|
| `recipes` | yes | envelope encryption, emulated data keys, local verification, JOSE (every recipe; see below) |
| `tokio` | yes | `retry_layer()`, `tokio_sleep()`, `tokio_clock()` (tokio's timer only) |
| `transit` | | Vault and OpenBao transit |
| `aws` | | AWS KMS (`aws-kms://arn:...`; see [docs/operations-aws.md](operations-aws.md)) |
| `aws-sdk-credentials` | | credentials from the AWS SDK for `aws` (`anykms_aws::credentials::SdkCredentials` over an `aws-config` provider: SSO, role chaining, `credential_process`) |
| `gcp` | | Google Cloud KMS (`gcp-kms://projects/...`; see [docs/operations-gcp.md](operations-gcp.md)) |
| `gcp-service-account-key` | yes | service-account key files for `gcp` (they sign with aws-lc-rs, so a C toolchain is needed even with `rustls-ring` and `rsa-rustcrypto`); without it a service-account credential is a `Configuration` error naming the feature |
| `gcp-google-cloud-auth` | | access tokens from Google's `google-cloud-auth` for `gcp` (`Credentials::google_cloud_auth`: AWS- and executable-sourced workload identity federation and the other credential types not built in) |
| `azure` | | Azure Key Vault and Managed HSM (`azure-kv://<host>/keys/...`; see [docs/operations-azure.md](operations-azure.md)); for Managed HSM HMAC (experimental `mhsm-hmac`), depend on `anykms-azure` directly |
| `azure-identity` | | credentials from the Azure SDK for `azure` (`anykms_azure::AzureIdentity` over an `azure_identity` credential: the Azure CLI, certificates, ...) |
| `http2` | | allow HTTP/2 on every enabled HTTP backend |
| `local` | | in-memory keys, development and tests only |
| `tracing` | | spans and events (no secrets) |
| `serde` | | `Serialize`/`Deserialize` for `Ciphertext`, `Signature` and `Tag`: their base64 storage encoding in JSON and other text formats, bytes in binary ones |
| `rustls-aws-lc-rs` | yes | TLS for every HTTP backend (transit, aws, gcp, azure) with aws-lc-rs (needs a C toolchain); wins over `rustls-ring` when both are on |
| `rustls-ring` | | TLS for every HTTP backend with ring |
| `rsa-aws-lc-rs` | yes | local RSA verification and local RSA-OAEP wrapping (AWS, GCP and Azure) with AWS-LC (needs a C toolchain) |
| `rsa-rustcrypto` | | the same with RustCrypto's pure-Rust `rsa` (a 0.10 release candidate); `rsa-aws-lc-rs` wins when both are on |

- Each HTTP backend picks its TLS provider the same way (transit per server): the configured
  provider (e.g. transit's `ServerConfig::crypto_provider`) if set, else the
  process-wide provider installed with rustls' `CryptoProvider::install_default` (e.g. a FIPS
  provider for TLS; see [FIPS scope](guarantees.md)), else the `rustls-*` feature's
  provider; with none of these it fails with
  `Configuration`. An installed default always wins over the default `rustls-aws-lc-rs`
  feature.
- **Build requirements.** The defaults use AWS-LC for TLS and RSA (one crypto library; ring is
  not linked). aws-lc-sys compiles C and assembly, so even a transit-only default build needs a
  C compiler; on Windows it uses prebuilt NASM objects, and CMake is needed only for FIPS
  builds. Without a C toolchain, use ring and RustCrypto (below).
- With neither `rsa-*` feature, RSA keys fail with `Unsupported` in the local verifiers; ECDSA
  and Ed25519 need no backend. ring is not an RSA option: it cannot verify a precomputed digest,
  which `DigestVerifier` requires.
- `recipes` enables every recipe. To compile only some, depend on `anykms-recipes` directly
  with `default-features = false` and pick its features: `jose` (JWS/JWT/JWK/JWKS; serde,
  serde_json), `envelope` (`EnvelopeAead`, `EnvelopeKeyring`; AES-GCM, HKDF), and
  `rsa-aws-lc-rs` (the default) or `rsa-rustcrypto`, the RSA verification backend under the same
  names as on anykms. Local verification (`LocalVerifier`, `CachedVerifier`) and
  `EmulatedDataKeys` are always there. Without an RSA backend feature the crate still builds, and
  RSA verification fails at run time with `Unsupported`.
- For a build without AWS-LC (no C toolchain): ring for TLS and RSA verification with
  RustCrypto's `rsa` 0.10 release candidate (a later RC may break its API; `Cargo.lock` pins
  it). Leave out `gcp-service-account-key`, which always signs with aws-lc-rs:

  ```toml
  anykms = { version = "0.1", default-features = false, features = ["transit", "rustls-ring", "recipes", "rsa-rustcrypto", "tokio"] }
  ```

- **For library authors.** A library depends on anykms (or on `anykms-core`, `anykms-recipes`
  and the backend crates) with `default-features = false` and only the features its own code
  needs, and lets the application choose the TLS (`rustls-*`) and RSA (`rsa-*`) backends.
  Features unify across the build, so a library's defaults (AWS-LC for TLS and RSA, `recipes`,
  `tokio`) would be forced on every application that uses it, with no way to turn them off.

## Public dependencies

These crates appear in anykms' public API, so their major versions are part of anykms' semver
contract: a major bump of any of them is a breaking anykms release (while on 0.x, a minor bump).
The SDK bridge crates count only with their feature on.

| Dependency | Where | Why |
|---|---|---|
| `rustls` 0.23 | `anykms_transit::rustls`, `anykms_aws::rustls`, `anykms_gcp::rustls`, `anykms_azure::rustls`, `anykms_http::rustls` (re-exports); each builder's `crypto_provider` | pass a `CryptoProvider` built with the same rustls version anykms uses |
| `zeroize` 1 | `anykms::Zeroizing` (re-export) | plaintexts and data keys are returned in `Zeroizing` |
| `serde_json` 1 | `anykms_recipes::serde_json` (re-export) | JOSE: `jwks()` returns a `serde_json::Value` |
| `serde` 1 | `Serialize`/`Deserialize` impls (core feature `serde`) | `Ciphertext`, `Signature` and `Tag` in your own serde types |
| `aws-credential-types` 1 | `anykms_aws::credentials::SdkCredentials::new` (feature `aws-sdk-credentials`) | wrap an AWS SDK `ProvideCredentials` provider |
| `google-cloud-auth` 1 (≥ 1.3) | `anykms_gcp::Credentials::google_cloud_auth` (feature `gcp-google-cloud-auth`) | wrap Google's `AccessTokenCredentials` |
| `azure_core` 1 | `anykms_azure::AzureIdentity::new` (feature `azure-identity`) | wrap an `Arc<dyn azure_core::credentials::TokenCredential>` |
| `reqwest` 0.13 | `anykms_http::reqwest` (re-export) | for anykms backend authors only (`anykms-http`) |
| `http` 1 | `anykms_http::client::Response` (`StatusCode`, `HeaderMap`), `retry_after` | for anykms backend authors only |
| `rustls-pki-types` 1 | `anykms_http::tls::private_key_from_pem` (`PrivateKeyDer`) | for anykms backend authors only |
| `tracing` 0.1 | `anykms_http::span::Span` (feature `tracing`) | for anykms backend authors only |

The bounds of the opaque handles' `full` constructors are frozen at the original part set: a
newer optional part is not set by `full` (backends set it with its `with_*` method), so adding one
does not break backends that call `full`.
