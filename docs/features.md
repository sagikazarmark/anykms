# Crates and Cargo features

## Crates

Most applications depend on the `anykms` facade and choose backends with its features. The
member crates can also be used directly.

| Crate | What |
|---|---|
| [`anykms`](../crates/anykms) | facade: re-exports, `with_default_providers()`, tokio retries (`retry_layer()`) |
| [`anykms-core`](../crates/anykms-core) | traits, types, errors, `KeyUri`, `Provider`/`Registry`, `Retry` (no HTTP, no runtime) |
| [`anykms-recipes`](../crates/anykms-recipes) | `EnvelopeAead`, `EnvelopeKeyring`, `EmulatedDataKeys`, `LocalVerifier`, `CachedVerifier`, JOSE signing and JWKS (verify JWTs with `jsonwebtoken`) |
| [`anykms-transit`](../crates/anykms-transit) | Vault and OpenBao transit (in-house client over the `HttpTransport` seam; the built-in transport is reqwest + rustls with ring or aws-lc-rs) |
| [`anykms-aws`](../crates/anykms-aws) | AWS KMS (in-house SigV4 client and workload credential chain over the `HttpTransport` seam, AWS SDK credentials as an option; facade feature `aws`) |
| [`anykms-gcp`](../crates/anykms-gcp) | Google Cloud KMS (in-house REST client and Application Default Credentials, `google-cloud-auth` as an option; CRC32C integrity checks; local signature verification; facade feature `gcp`) |
| [`anykms-azure`](../crates/anykms-azure) | Azure Key Vault and Managed HSM (in-house REST client and Entra ID workload credentials, Azure SDK credentials as an option; vault host allowlist; framed ciphertexts; facade feature `azure`) |
| [`anykms-http`](../crates/anykms-http) | HTTP plumbing shared by the backends: the `HttpTransport` seam and the built-in `ReqwestTransport` (TLS, no redirects, zeroizing bodies); an application touches it only to build or bring a transport |
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
| `reqwest` | yes | the built-in HTTP transport of the HTTP backends (`anykms_http::ReqwestTransport`: reqwest over rustls). Without it, each HTTP backend needs a transport through its builder's `.http_transport(..)`, and `with_default_providers` skips the HTTP backends; the dependency tree then holds no reqwest, hyper or rustls |
| `http2` | | allow HTTP/2 in the built-in transport (`ReqwestTransportBuilder::http2`) |
| `local` | | in-memory keys, development and tests only |
| `tracing` | | spans and events (no secrets) |
| `serde` | | `Serialize`/`Deserialize` for `Ciphertext`, `Signature` and `Tag`: their base64 storage encoding in JSON and other text formats, bytes in binary ones |
| `rustls-aws-lc-rs` | yes | TLS crypto provider of the built-in transport (`reqwest`) with aws-lc-rs (needs a C toolchain); wins over `rustls-ring` when both are on |
| `rustls-ring` | | the same with ring |
| `rsa-aws-lc-rs` | yes | local RSA verification and local RSA-OAEP wrapping (AWS, GCP and Azure) with AWS-LC (needs a C toolchain) |
| `rsa-rustcrypto` | | the same with RustCrypto's pure-Rust `rsa` (a 0.10 release candidate); `rsa-aws-lc-rs` wins when both are on |

- **The HTTP transport.** The HTTP backends (transit, aws, gcp, azure) send every request,
  token and credential fetches included, through one `anykms_http::HttpTransport`. TLS trust,
  client certificates, the crypto provider, proxying, timeouts and the HTTP version are the
  transport's settings, not the backends': with the built-in one, configure them on
  `ReqwestTransportBuilder` and pass the result to the backend builder's `.http_transport(..)`
  (one transport may serve several providers); without, each backend builds a default
  `ReqwestTransport`. The `rustls-*`, `http2` features apply to the built-in transport only.
- The built-in transport picks its TLS provider the same way everywhere: the configured provider
  (`ReqwestTransportBuilder::crypto_provider`) if set, else the process-wide provider installed
  with rustls' `CryptoProvider::install_default` (e.g. a FIPS provider for TLS; see
  [FIPS scope](guarantees.md)), else the `rustls-*` feature's provider; with none of these it
  fails with `Configuration`. An installed default always wins over the default
  `rustls-aws-lc-rs` feature.
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
  anykms = { version = "0.1", default-features = false, features = ["transit", "reqwest", "rustls-ring", "recipes", "rsa-rustcrypto", "tokio"] }
  ```

- **For library authors.** A library depends on anykms (or on `anykms-core`, `anykms-recipes`
  and the backend crates) with `default-features = false` and only the features its own code
  needs, and lets the application choose the transport (`reqwest`), the TLS (`rustls-*`) and RSA
  (`rsa-*`) backends.
  Features unify across the build, so a library's defaults (AWS-LC for TLS and RSA, `recipes`,
  `tokio`) would be forced on every application that uses it, with no way to turn them off.

## Public dependencies

These crates appear in anykms' public API, so their major versions are part of anykms' semver
contract: a major bump of any of them is a breaking anykms release (while on 0.x, a minor bump).
The SDK bridge crates count only with their feature on.

| Dependency | Where | Why |
|---|---|---|
| `rustls` 0.23 | `anykms_http::rustls` (re-export; the backends re-export `anykms_http`); `ReqwestTransportBuilder::crypto_provider` | pass a `CryptoProvider` built with the same rustls version anykms uses |
| `http` 1 | `anykms_http::http` (re-export); `HttpTransport::send` takes an `http::Request` and returns an `http::Response` | implement a transport, or build requests in a backend |
| `url` 2 | `anykms_http::url` (re-export); the backends build request URLs with it | for anykms backend authors only |
| `zeroize` 1 | `anykms::Zeroizing` (re-export) | plaintexts and data keys are returned in `Zeroizing` |
| `serde_json` 1 | `anykms_recipes::serde_json` (re-export) | JOSE: `jwks()` returns a `serde_json::Value` |
| `serde` 1 | `Serialize`/`Deserialize` impls (core feature `serde`) | `Ciphertext`, `Signature` and `Tag` in your own serde types |
| `aws-credential-types` 1 | `anykms_aws::credentials::SdkCredentials::new` (feature `aws-sdk-credentials`) | wrap an AWS SDK `ProvideCredentials` provider |
| `google-cloud-auth` 1 (≥ 1.3) | `anykms_gcp::Credentials::google_cloud_auth` (feature `gcp-google-cloud-auth`) | wrap Google's `AccessTokenCredentials` |
| `azure_core` 1 | `anykms_azure::AzureIdentity::new` (feature `azure-identity`) | wrap an `Arc<dyn azure_core::credentials::TokenCredential>` |
| `reqwest` 0.13 | none: `ReqwestTransport` wraps it without exposing it; `reqwest` is no longer a public dependency |
| `rustls-pki-types` 1 | `anykms_http::pem::private_key_from_pem` (`PrivateKeyDer`) | for anykms backend authors only |
| `tracing` 0.1 | `anykms_http::span::Span` (feature `tracing`) | for anykms backend authors only |

The bounds of the opaque handles' `full` constructors are frozen at the original part set: a
newer optional part is not set by `full` (backends set it with its `with_*` method), so adding one
does not break backends that call `full`.
