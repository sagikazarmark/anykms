# Guarantees and limits

What anykms promises, what it cannot promise, and the limits to plan around. The
[operator guides](operations.md) cover the server side.

- **Zeroization is defense in depth, not a guarantee.** anykms zeroizes the buffers it owns:
  request JSON, response bodies, decoded plaintexts, data keys, tokens and the mTLS key PEM
  (`Zeroizing`, grown without leaving unwiped copies). It cannot zeroize copies made by
  reqwest/hyper/rustls (including the request body reqwest sends and the token's
  `X-Vault-Token` header value), the token in the process environment (`VAULT_TOKEN`), the
  parsed mTLS key inside the crypto provider (ring does not wipe it; aws-lc does), kernel socket
  buffers, or the server.
- **Transport.** rustls (see [Cargo features](features.md#cargo-features)); `ca_pem` (or `ca_file`)
  replaces the system roots; there is no way to skip verification; redirects are never
  followed; plain HTTP only for literal loopback IPs. Rejected certificates are `Configuration` errors, not
  retried.
- **FIPS scope.** KMS operations (encrypt, decrypt, unwrap, sign, MAC) run in the KMS, under its
  own validation. TLS follows a FIPS provider only when one is configured (`crypto_provider`) or
  installed process-wide through the re-exported rustls 0.23; the `rustls-aws-lc-rs` feature
  builds aws-lc-rs without its `fips` feature. What runs in this process is not FIPS-validated:
  the envelope's payload encryption (RustCrypto `aes-gcm`, `hkdf`, `sha2`), AWS SigV4 request
  signing (`sha2`, `hmac`), local signature verification and RSA-OAEP wrapping (RustCrypto, or
  aws-lc-rs without `fips`) and GCP service-account token signing. anykms has no `fips` feature.
- **Namespaces are enforced by token policy.** anykms checks URIs against `allowed_namespaces`
  and `allowed_mounts`, but on Vault Enterprise and OpenBao a path segment can still select a
  child namespace (see [operations](operations.md#namespaces)). Scope the token's
  policy to the namespaces and mounts the service needs; that is the actual boundary.
- **RSA-PSS** always uses `salt_length=hash` (RFC 7518 `PS256`). RSA-PSS signatures from other
  transit clients using the default `auto` (maximum) salt do not verify through anykms.
- **Envelope format v1 is frozen.** Every future release decrypts it. See
  [`docs/envelope-format.md`](envelope-format.md) and the committed test vectors. Its
  review outside the project is **pending**, so it is not yet recommended for long-lived data;
  the release that completes the review announces the promotion in its release notes.
- **With an RSA KEK, every holder of the public key can write envelopes.** Wrapping needs only
  the public key, so such envelopes give confidentiality only, and the AAD does not authenticate
  the writer. An `EnvelopeKeyring` accepts envelopes under each of its KEKs, so a symmetric
  primary does not help while an RSA KEK stays in the ring.
- **Input size limits differ by backend.** `Aead` plaintexts, `Mac` messages and
  `MessageSigner` messages are capped by the KMS (AWS: 4 KiB plaintext, raw `Sign` and
  `GenerateMac` input; GCP: 64 KiB plaintext, AAD and messages; Azure: RSA-OAEP input of k−66
  bytes, and signing is digest-only; transit's limits are much larger). Portable code uses `EnvelopeAead` for data and
  `sign_message_hashed`/`DigestSigner` for large messages.
- **MSRV:** Rust 1.91 covers every crate with every feature, its tests and examples. The AWS SDK
  credential types (`aws-sdk-credentials`) are held by Cargo's MSRV-aware resolver on releases
  that support it; newer releases need a newer compiler.
- The HTTP backends (transit, aws, gcp, azure) need a tokio runtime; outside one an operation
  fails with `Configuration` (see [From synchronous code](guide.md#from-synchronous-code)). Core,
  recipes and local are runtime-agnostic (any async executor; you supply `Retry`'s sleep function
  and, optionally, its clock).
- **`wasm32-unknown-unknown` on a JS host** (browsers, Node.js, Cloudflare Workers): core,
  recipes, local and conformance build and run there with their `js` feature. `std::time` has no
  clock on that target, so the feature routes every clock read through `anykms_core::time`:
  `performance.now()` for the monotonic clock (`Retry`'s default clock, `CachedVerifier`, the DEK
  cache) and `Date.now()` for the wall clock (JWT `iat`/`exp`, local keyset timestamps), with no
  extra dependencies beyond the `js-sys`/`wasm-bindgen` that `getrandom`'s JS backend already
  brings. The same feature enables that backend; the application still passes
  `--cfg getrandom_backend="wasm_js"`. The RSA backend must be `rsa-rustcrypto` (aws-lc-rs does
  not build for wasm32). The conformance runner (`run`, `run_or_skip`) is native-only; a wasm host
  drives `anykms_conformance::run_async` on its own executor and reports the `Report`. Cloudflare
  Workers advance both clocks only across I/O. Without `js`, the target behaves as before (the
  std clock panics on first use); WASI targets have a working clock and never need it. The HTTP
  backends are **not** supported there: they need TLS control the host does not offer (see the
  `HttpTransport` discussion in the issue tracker).
- **Retries.** Backends never retry internally (apart from one re-authentication); retries live in
  `Retry` and `RetryLayer`. The budget caps retries at about 10% of requests per `RetryBudget`,
  and each `RetryLayer` has one. A layer on the registry (`RegistryBuilder::layer`) shares its
  budget across **every backend** behind it, so a struggling backend can spend the retries of a
  healthy one. For a bound per backend, give each backend's handles their own layer (or
  `RetryLayer::with_budget`).
