# Guarantees and limits

What anykms promises, what it cannot promise, and the limits to plan around. The
[operator guides](operations.md) cover the server side.

- **Zeroization is defense in depth, not a guarantee.** anykms zeroizes the buffers it owns:
  request JSON, response bodies, decoded plaintexts, data keys, tokens and the mTLS key PEM
  (`Zeroizing`, grown without leaving unwiped copies). Requests reach the `HttpTransport` with
  their body in a zeroizing buffer and responses come back in one; whether the bytes are wiped
  beyond that is the transport's business. The built-in `ReqwestTransport` cannot zeroize the
  copies reqwest/hyper/rustls make (including the request body reqwest sends and the token's
  `X-Vault-Token` header value). anykms also cannot zeroize the token in the process environment
  (`VAULT_TOKEN`), the parsed mTLS key inside the crypto provider (ring does not wipe it; aws-lc
  does), kernel socket buffers, or the server.
- **Transport.** Every HTTP backend moves bytes through one `anykms_http::HttpTransport`,
  injected with the builder's `.http_transport(..)` or, by default, the built-in
  `ReqwestTransport` (feature `reqwest`; without it, building a backend fails with
  `Configuration` unless a transport is given). TLS trust, client certificates, the crypto
  provider, proxying, timeouts and the HTTP version are properties of the transport
  (`ReqwestTransportBuilder`), not of the backends; the guarantees below hold for the built-in
  one, and a third-party transport is responsible for its own. `ReqwestTransport`: rustls (see
  [Cargo features](features.md#cargo-features)); `ca_pem` replaces the system roots; there is no
  way to skip verification; redirects are never followed; a configured proxy is bypassed for
  link-local and loopback hosts (the cloud metadata servers). The backends keep the host policy
  for key endpoints: plain HTTP only for literal loopback IPs, and only when opted in. The one
  plain-HTTP exception needs no opt-in: the built-in credential sources talk to the cloud
  metadata servers over `http://` on their link-local addresses (`169.254.169.254`,
  `169.254.170.2`, `fd00:ec2::254`, `metadata.google.internal`), as every cloud SDK does. Whatever the transport, the
  response limit is enforced twice (by the transport and again by the backend), so an oversized
  body never reaches a backend. Transport failures map to a fixed set of classes
  (`anykms_http::SendError`): a rejected or mismatched certificate is `Configuration` and not
  retried; DNS, connection, handshake and body failures are `Unavailable`; a timeout (the
  transport's, or a per-request `RequestTimeout` the metadata probes set) is `Timeout`.
  `TowerTransport` (feature `tower`) adapts any tower `Service`: it sets `content-length`,
  reads the body into the same bounded zeroizing buffer and passes a boxed `SendError` from the
  service through unchanged (anything else is `Unavailable`). It has **no timeout of its own**
  and **cannot control redirects**: the inner service must be configured not to follow them,
  and a 3xx that comes back is an error for the backend, as always. With the built-in client at
  the bottom (`ReqwestTransport::into_service`) both are the client's, and its failure classes
  are kept.
- **FIPS scope.** KMS operations (encrypt, decrypt, unwrap, sign, MAC) run in the KMS, under its
  own validation. TLS follows a FIPS provider only when one is configured
  (`ReqwestTransportBuilder::crypto_provider`) or installed process-wide through the re-exported
  rustls 0.23 (`anykms_http::rustls`), and only in the built-in transport; the `rustls-aws-lc-rs` feature
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
- The HTTP backends (transit, aws, gcp, azure) over the built-in transport need a tokio runtime;
  outside one an operation fails with `Configuration` before any credential is fetched (see
  [From synchronous code](guide.md#from-synchronous-code)). The runtime requirement is the
  transport's (`HttpTransport::ready`); another transport may have none, though the backends'
  credential caches still use tokio's synchronization primitives. Core, recipes and local are
  runtime-agnostic (any async executor; you supply `Retry`'s sleep function and, optionally, its
  clock).
- **`wasm32-unknown-unknown` on a JS host** (browsers, Node.js, Cloudflare Workers): core,
  recipes, local and conformance build and run there with their `js` feature. `std::time` has no
  clock on that target, so the feature routes every clock read through `anykms_core::time`:
  `performance.now()` for the monotonic clock (`Retry`'s default clock, `CachedVerifier`, the DEK
  cache) and `Date.now()` for the wall clock (JWT `iat`/`exp`, local keyset timestamps), with no
  extra dependencies beyond the `js-sys`/`wasm-bindgen` that `getrandom`'s JS backend already
  brings. The same feature enables that backend. The RSA backend must be `rsa-rustcrypto` (aws-lc-rs does
  not build for wasm32). The conformance runner (`run`, `run_or_skip`) is native-only; a wasm host
  drives `anykms_conformance::run_async` on its own executor and reports the `Report`. Cloudflare
  Workers advance both clocks only across I/O. Without `js`, the target behaves as before (the
  std clock panics on first use); WASI targets have a working clock and never need it. The HTTP
  backends (transit, aws, gcp, azure) and anykms-http have the same `js` feature: with it their
  clock reads (SigV4 signing time and skew, token and key-metadata expiry, the credential cache)
  go through `anykms_core::time` too, and with the `reqwest` feature off (and the `rustls-*`
  provider features with it) their dependency tree holds no reqwest, hyper or rustls. CI checks
  both, and runs `anykms-aws` over a `TowerTransport` under Node: a signed `Encrypt` on the JS
  clock. What they need on the host is a transport that runs there: the built-in one needs TLS
  control the host does not offer, so bring a `fetch`-based tower service (below). The one tokio
  dependency that remains is its `sync` and `time` types (no runtime), which build for the target.
- **Cloudflare Workers.** The shape is `TowerTransport::new(tower_worker_fetch::FetchService::new())`,
  or that service under layers, with `default-features = false`, a backend feature, `tower` and
  `js`: anykms ships no Workers transport and depends on no Workers crate. Two request extensions
  of `tower-worker-fetch` (0.2 or later) are **required**, set by a `map_request` layer on every
  request (the guide shows the layer):
  - `tower_worker_fetch::Redirect::Manual`. A Worker's outbound `fetch` follows redirects by
    default and forwards every header, `Authorization` included, to the target, so without it a
    signed or bearer-authenticated request can be silently redirected to a host of the server's
    choosing; the built-in transport never allows that. With it, a 3xx comes back as is and the
    backend rejects it, as on every other transport.
  - `tower_worker_fetch::Timeout` (an `AbortSignal.timeout`): `TowerTransport` has no timeout of
    its own, and the `RequestTimeout` a backend sets reaches the service but `FetchService` does
    not read it; map one into the other, or set a fixed one.

  What holds on a Worker regardless: TLS is the host's (Cloudflare's edge, the public CAs), so the
  public cloud KMS endpoints (AWS, GCP, Azure) are reachable, and Vault or OpenBao behind a private
  CA or client certificates is **not**. Only static or explicitly provided credentials make sense:
  the link-local metadata servers (EC2 IMDS, the GCP metadata server, Azure IMDS) are not
  reachable from a Worker, and on `wasm32-unknown-unknown` those sources fail with a
  `Configuration` error **before sending anything**, whether chosen explicitly or reached by a
  default chain (CI drives all three). Configure credentials explicitly:
  `AwsProviderBuilder::credentials` with `StaticCredentials`, `Credentials::from_json` or
  `static_token` for GCP, a `ClientSecret` for Azure.
- **Retries.** Backends never retry internally (apart from one re-authentication); retries live in
  `Retry` and `RetryLayer`. The budget caps retries at about 10% of requests per `RetryBudget`,
  and each `RetryLayer` has one. A layer on the registry (`RegistryBuilder::layer`) shares its
  budget across **every backend** behind it, so a struggling backend can spend the retries of a
  healthy one. For a bound per backend, give each backend's handles their own layer (or
  `RetryLayer::with_budget`).
