# anykms: implementation plan

Status: **approved v3 and implemented** (M0–M4). Signed off by all six reviewers after three
review rounds (architect, Rust engineer, KMS domain expert, security, end user, SRE). §15–17 record
the reviews; §18 records the implementation status and every deviation from this plan; §19
records the decisions of the 2026-10 review.
Inputs: `spec.md` (design notes; the committed copy was truncated in places and has since been
reconstructed; this plan interpreted the truncated text) and
`docs/research/vault-openbao-transit.md` (behavior verified on Vault 2.1.1 and
OpenBao 2.7.1).

## 0. Summary

anykms is a Rust library that gives applications one way to use key-management
services for **data-plane** operations (encrypt, rewrap, sign, MAC, describe)
without hiding how the services differ.

- **First release backends:** HashiCorp Vault transit, OpenBao transit, AWS KMS,
  GCP Cloud KMS, Azure Key Vault / Managed HSM, and an in-process software backend
  for tests. The cloud backends were planned for 0.2 and ship in 0.1.0 instead
  (§25 R1; designs in §23, §24 and `docs/cloud/`); Appendix A records how each
  maps onto the core types.
- **Shape:** capability traits on a *key handle*. The core exposes only what a
  backend natively does. Emulated or portable behavior lives in
  `anykms-recipes` and says what it emulates.
- **Proof:** a shared conformance suite, written before the second backend.
- **Client library:** neither `vaultrs` nor the `openbao` crate. A thin in-house
  transit client on `reqwest` (§6.1).

## 1. Goals and non-goals

Goals (v0.1):

1. On Vault and OpenBao transit: AEAD encrypt/decrypt, rewrap, data keys,
   sign/verify (digest and message), MAC, public keys, describe.
2. Make backend differences visible: compile errors for typed use, typed errors
   for config-driven use, never silent semantic drift.
3. Recipes: envelope AEAD with key commitment, emulated data keys, local
   verification, JWS/JWK helpers.
4. A conformance suite, plus a public software backend that downstream apps can
   use in their own tests.
5. Secret hygiene and production-grade failure behavior: no redirects, bounded
   retries, timeouts, tracing.

Non-goals (v0.1), each with where it goes:

- Key creation, deletion and policy management. That belongs to IaC; test
  fixtures do it outside the public API. `KeyLifecycle` comes in M5.
- Cloud providers (M5+). Vault login methods beyond token, token file and Agent
  proxy (AppRole and Kubernetes in M5; custom `TokenSource` implementations are
  possible from day one).
- Streaming/chunked envelope encryption, DEK caching, batch APIs,
  derived/convergent transit keys, RSA-OAEP / asymmetric decrypt backends
  (the core `KeyWrap` trait and `KeyWrapKey` handle exist since the 2026-10
  reviews, §19 and §20; an `AsymmetricDecrypt` trait is future work), BYOK, PQC. The envelope format reserves
  a version and flags for streaming.

## 2. Crate layout

```
anykms-core         traits, value types, errors, KeyUri, KeyVersion, Provider trait, dyn layer, Registry,
                    Retry (deps: zeroize, trait-variant, base64; sha2 behind the default `digest` feature;
                    optional tracing; no HTTP, no async runtime, no `url` in public API)
anykms-recipes      LocalVerifier, DER<->fixed, JWS/JWK (M1); EnvelopeAead, EmulatedDataKeys,
                    CachedVerifier, sign_message_hashed (M3). RustCrypto.
anykms-local        public software backend: LocalKeyset, fault injection. Tests/dev only.
anykms-http         shared HTTP plumbing (TLS provider precedence, no-redirect client, zeroizing
                    buffers, Retry-After, credential cache); for anykms backends only
anykms-transit      Vault + OpenBao transit (reqwest, rustls, serde_json on anykms-http; TLS provider
                    `rustls-aws-lc-rs` by default or `rustls-ring`, §25.3)
anykms-aws          AWS KMS                         } in-house REST clients on anykms-http, no
anykms-gcp          GCP Cloud KMS                   } cloud SDKs; same `rustls-*` and `rsa-*`
anykms-azure        Azure Key Vault / Managed HSM   } features; lazy credentials, no I/O on open
anykms-conformance  libtest-mimic harness + Fixture trait (published; dev-dependency of backends)
anykms              facade: re-exports, `with_default_providers()`, `retry_layer()`/`tokio_sleep()`
                    (default features: recipes, rsa-aws-lc-rs, tokio, rustls-aws-lc-rs,
                    gcp-service-account-key; optional:
                    transit, aws, gcp, azure, local, tracing, http2, rsa-rustcrypto,
                    rustls-aws-lc-rs)
```

All HTTP backends (transit, aws, gcp, azure) need a tokio runtime.

`anykms-recipes`, `anykms-local` and `anykms-transit` depend on `anykms-core`.
`anykms-conformance` depends on core and recipes. Nothing depends on the
facade. A backend **may** also depend on `anykms-recipes` to provide what its
service lacks natively, as long as the recipe's "Emulates / Enforced by" box
stays true: the GCP backend uses `LocalVerifier` so that `Provider::digest_verifier`
works even though Cloud KMS has no verify operation (§19). Recipes never depend
on a backend. The spec's `kms-envelope` and `kms-vault` are renamed to
`anykms-recipes` (it holds more than envelopes) and `anykms-transit` (it serves
both Vault and OpenBao).

Conventions:

- Edition 2024, MSRV 1.91 (raised from 1.85, §28), with `Cargo.lock` committed and the MSRV CI job
  building from it.
- `#![forbid(unsafe_code)]` everywhere. Dual MIT/Apache license.
- Lockstep workspace versions. In 0.x, any breaking change to `anykms-core`
  bumps the minor version of every crate. `cargo-semver-checks` runs in CI
  from 0.1.0. (Kept for 0.1 by the [release plan](release-plan.md), R-24:
  anykms-http's stability wording follows lockstep and the blocking semver
  job; independent versions stay possible after the first publish.)
- Every public struct and enum in core is `#[non_exhaustive]`, with
  constructors and accessors.

## 3. Core API (`anykms-core`)

### 3.1 Value types

```rust
#[non_exhaustive] pub struct KeyVersion(Arc<str>);   // opaque; transit "3", Azure 32-hex, GCP "1"; .as_u64() helper
#[non_exhaustive] pub struct Ciphertext(Vec<u8>);    // backend-native bytes, opaque (transit: b"vault:v3:...")
    // from_bytes/into_bytes/as_bytes. Native ciphertexts from other Vault clients are accepted unchanged.

#[non_exhaustive] pub struct Signature { alg: SignatureAlgorithm, key_version: Option<KeyVersion>, bytes: Vec<u8> }
    // bytes: DER for ECDSA, raw for RSA/Ed25519. Signature::from_parts(..) for verify-only callers.
#[non_exhaustive] pub struct Tag { alg: MacAlgorithm, key_version: Option<KeyVersion>, bytes: Vec<u8> }   // raw MAC bytes; Tag::from_parts(..)
    // Canonical storage encoding for Signature/Tag (keeps version + alg): `anykms_core::encoding::{encode, decode}` (M1).
    // Transit verify with key_version == None or a non-numeric version → InvalidArgument before I/O.
#[non_exhaustive] pub struct PublicKey { key_type: AsymmetricKeyType, spki_der: Vec<u8>, version: Option<KeyVersion> }
#[non_exhaustive] pub enum AsymmetricKeyType { EcP256, EcP384, EcP521, Rsa { bits: u32 }, Ed25519 }

#[non_exhaustive] pub enum HashAlgorithm { Sha256, Sha384, Sha512 }
#[non_exhaustive] pub struct Digest { alg: HashAlgorithm, bytes: [u8; 64], len: u8 }   // new() validates length; sha256(msg) etc. behind `digest`

#[non_exhaustive] pub enum SignatureAlgorithm {
    EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512,
    RsaPssSha256, RsaPssSha384, RsaPssSha512,          // salt length == hash length (enforced; see §6.3)
    RsaPkcs1v15Sha256, RsaPkcs1v15Sha384, RsaPkcs1v15Sha512,
    Ed25519,                                           // pure, message input
}
impl SignatureAlgorithm { pub fn jws_alg(&self) -> Option<&'static str>; pub fn hash(&self) -> Option<HashAlgorithm>; }
#[non_exhaustive] pub enum MacAlgorithm { HmacSha256, HmacSha384, HmacSha512 }

pub struct DataKey { plaintext: Zeroizing<Vec<u8>>, ciphertext: Ciphertext }   // boxed; no Clone, no Serialize; Debug redacts
    // plaintext() -> &[u8]; length checked against DataKeySpec
#[non_exhaustive] pub enum DataKeySpec { Aes256 }

#[non_exhaustive] pub struct KeyInfo {
    backend_key_type: String,          // native truth, e.g. "aes256-gcm96"
    capabilities: Capabilities,        // newtype bitset with assoc consts: AEAD, DATA_KEYS, REWRAP, SIGN, VERIFY, MAC, PUBLIC_KEY
    signature_algorithms: Vec<SignatureAlgorithm>,
    state: Option<KeyState>,           // None where state is per version only (GCP) or unreported
    primary_version: Option<KeyVersion>,   // None where the backend has none (GCP asymmetric/MAC keys)
    versions: Vec<KeyVersionInfo>,     // { version, state, created_at } — may omit versions a backend hides
}
#[non_exhaustive] pub enum KeyState { Enabled, Disabled, PendingDeletion, Destroyed, Unknown(String) }
```

Backend-specific metadata stays on backend types, not in the portable
`KeyInfo`. Example: `TransitKeyInfo` holds `min_decryption_version`,
`min_encryption_version`, `auto_rotate_period` and `derived`.

Rules:

- Native ciphertext is never reframed (spec §5). Transit ciphertexts stay
  readable by other Vault clients, in both directions. Empty AAD means exactly
  the same as transit's omitted `associated_data`, so existing AAD-less
  ciphertexts decrypt with `aad = b""` (verified on both servers).
- Every handle rejects inputs whose algorithm does not match its own before
  any I/O, with `InvalidArgument`. That covers a `Digest`, a `Signature` or a
  `Tag`. The servers check none of this (verified: P-256 accepts a 64-byte
  SHA-512 digest, P-521 accepts SHA-256).

### 3.2 Capability traits

Traits are declared with `#[trait_variant::make(Send)]`, which gives `Send`
futures only. There are no `!Send` variants. The traits themselves required
only `Send` (*superseded by the release plan, R-8: every capability trait,
`Preflight` and `ExtensionCalls` included, requires `Send + Sync`, so a generic
`Arc<K: Aead>` crosses tasks without an extra bound; the `+ Send + Sync`
bounds on implementations and helpers below are implied by the traits, and the
`DynX` traits keep theirs*).

```rust
pub trait Aead {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext>;
    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> { Ok(None) }   // local parse, no I/O;
                                                     // usable with decrypt-only permission to find stale rows
}
pub trait Rewrap {                                   // re-encrypt under the primary version without exposing plaintext to the caller
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext>;
}
pub trait DataKeys {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey>;
}
pub trait DigestSigner    { fn signature_algorithm(&self) -> SignatureAlgorithm; async fn sign_digest(&self, d: &Digest) -> Result<Signature>; }
pub trait MessageSigner   { fn signature_algorithm(&self) -> SignatureAlgorithm; async fn sign_message(&self, m: &[u8]) -> Result<Signature>; }
pub trait DigestVerifier  { async fn verify_digest(&self, d: &Digest, s: &Signature) -> Result<()>; }
pub trait MessageVerifier { async fn verify_message(&self, m: &[u8], s: &Signature) -> Result<()>; }
pub trait Mac {
    fn mac_algorithm(&self) -> MacAlgorithm;
    async fn mac(&self, data: &[u8]) -> Result<Tag>;
    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()>;   // server-side, or constant-time full-length locally
}
pub trait PublicKeys {
    async fn public_key(&self) -> Result<PublicKey>;                       // the version this handle signs with:
                                                                           // primary, or the pinned version (GCP)
    async fn public_key_version(&self, v: &KeyVersion) -> Result<PublicKey>;
}
pub trait Describe { async fn describe(&self) -> Result<KeyInfo>; }
```

- **Signer split.** Ed25519 cannot sign a digest: Vault rejects `prehashed`,
  and OpenBao silently ignores it and signs the digest bytes as a message. So
  ECDSA and RSA keys implement `DigestSigner`, and Ed25519 keys implement
  `MessageSigner`. For callers holding a message, `anykms-recipes` provides
  `sign_message_hashed()`, which hashes locally and so also avoids request-size
  limits.
- **Failure is an error.** Verification failure is
  `Err(VerificationFailed)`, never `Ok(false)`.
- **Transit `Rewrap`.** It only works when `aad` is empty; transit's rewrap
  silently ignores `associated_data` (verified). With non-empty AAD it returns
  `Unsupported` before any I/O. No client-side decrypt-and-re-encrypt fallback
  exists in core; that would expose plaintext and is a recipe decision.

### 3.3 Typed handles (static use)

Constructors take a key URI (`impl IntoKeyUri`: a `KeyUri` or a string), do no
I/O, and return types that implement exactly the matching traits:

```rust
let t = TransitProvider::from_env()?;
let kek:  TransitAeadKey   = t.aead_key("hashivault:///transit/keys/app-kek")?;              // Aead + Rewrap + DataKeys + Describe
let rel:  TransitDigestKey = t.digest_signing_key(&uri, SignatureAlgorithm::EcdsaP256Sha256)?; // DigestSigner + DigestVerifier + PublicKeys + Describe
let ed:   TransitEd25519Key = t.ed25519_key(&uri)?;                                          // MessageSigner + MessageVerifier + PublicKeys + Describe
let tok:  TransitMacKey    = t.mac_key(&uri, MacAlgorithm::HmacSha256)?;                     // Mac + Describe
```

**Key-type check.** The server does not catch a mismatched key type. A P-384
key signs a "P-256" request, an ECDSA key ignores `pss`, and an RSA key
"encrypts" as non-AEAD RSA-OAEP. None of these produce a warning (all
verified). So each handle checks the key type once, before its first
operation, using a cached `describe`:

- `Aead` is accepted only on aes128/256-gcm96 and chacha20-poly1305.
- Signing keys must match the asserted algorithm.
- Derived keys are refused.

- `mac_key` accepts only `hmac` keys. AES keys can also HMAC on transit, but
  allowing that would diverge from cloud keys, whose MAC algorithm is bound to
  the key.

The check needs `read` on `transit/keys/<name>`, which the policy docs include.
It costs one extra request on a handle's first operation. Applications can call
`preflight()` (the `Preflight` part, §25.2) at startup to pay it up front and fail fast. Handles
from the same provider share one describe cache per key.
`KeyTypeCheck::TrustCaller` is an explicit, documented opt-out for deployments
that cannot grant `read`.

For transit MAC, the algorithm is chosen by the caller, since transit lets you
pick the hash per request. Docs state that `describe` cannot confirm it.

### 3.4 Dynamic use: `Provider`, `Registry`, dyn layer

```rust
/// Concrete composite in core: Rust cannot express `dyn DynAead + DynRewrap`, and the blanket
/// `impl<T: Aead> DynAead for T` cannot detect `T: Rewrap` (no specialization). The provider knows
/// the concrete type at open time and fills in the optional parts.
#[non_exhaustive]
pub struct AeadKey { /* private: aead: Arc<dyn DynAead>, rewrap/data_keys/describe: Option<Arc<dyn DynX>>, backend: &'static str */ }
// impl Aead + Rewrap + DataKeys + Describe for AeadKey; a missing part → Unsupported before I/O; supports_rewrap()/...
// Public builder (no specialization, so parts are explicit): AeadKey::new("backend", aead).with_rewrap(..).with_data_keys(..);
// AeadKey::full("backend", k) for K: Aead + Rewrap + DataKeys + Describe + Send + Sync + 'static shares one Arc
// (every handle's `full` is bounded by the traits of all its parts; a key lacking one uses new + with_*).
// The same pattern gives opaque DigestSignerKey, MessageSignerKey, DigestVerifierKey, MessageVerifierKey (optional
// PublicKeys + Describe), MacKey (optional Describe), PublicKeysKey and DescribeKey (optional Describe), and
// KeyWrapKey (KeyWrap, optional Rewrap + Describe; §20).

pub trait Provider: Send + Sync {                          // object-safe; third parties can implement
    fn schemes(&self) -> &[&'static str];
    fn aead(&self, uri: &KeyUri, o: &OpenOptions) -> Result<AeadKey> { Err(unsupported()) }
    fn digest_signer(&self, uri: &KeyUri, alg: SignatureAlgorithm, o: &OpenOptions) -> Result<DigestSignerKey> { ... }
    // ... one per capability, all defaulting to Unsupported (adding a purpose is additive)
}
#[non_exhaustive] pub struct OpenOptions { key_type_check: KeyTypeCheck, /* + typed backend extensions */ }

let reg = Registry::builder()
    .provider(TransitProvider::from_env()?)
    .provider(LocalProvider::new(keyset).allow_ephemeral_local_keys())   // explicit runtime opt-in
    .build()?;
let kek: AeadKey = reg.aead(&uri)?;
kek.encrypt(b"..", b"aad").await?;          // AeadKey implements the static traits directly
```

`Registry::build()` fails when two providers claim the same scheme.

The dyn layer lives in core and ships in M1. One `macro_rules!` generates, for
each capability:

- an object-safe `DynX` trait with `dyn_*` method names that return
  `BoxFuture<'_, Result<T>>`, **sealed** (a private marker supertrait), so
  adding a method to it is not a breaking change;
- a blanket `impl<T: X + Send + Sync> DynX for T` (the only implementations);
- the bridges `impl<'a> X for dyn DynX + 'a` and
  `impl<T: X + ?Sized + Send + Sync> X for Arc<T>`.

The macro forwards **provided** methods (e.g. `Aead::ciphertext_version`)
explicitly through `DynX`, both bridges and `AeadKey`. Otherwise dyn callers
would silently get the default `Ok(None)`. A conformance case checks
`ciphertext_version` through `AeadKey` from the `Registry`.

Callers therefore always call the *static* method names (`encrypt`, not
`dyn_encrypt`), which avoids E0034 ambiguity. Recipes compose over dyn handles
(`EnvelopeAead<KeyWrapKey>` or `EnvelopeAead<Arc<dyn DynKeyWrap>>`), and the
resulting futures are `Send`. Spikes in rounds 1 and 2 compiled this pattern,
including the macro, `Rewrap` and the `Provider` defaults.

For testing, application code should depend on the traits, on `AeadKey`, or on
the `Registry`, not on `TransitAeadKey`. That way `anykms-local` can be swapped
in for tests (documented with an example).

Purpose-based opening is the only dynamic API in v0.1. Discovery through
`registry.open(uri)` and `KeyHandle` is deferred.

`local://` is resolved only when the `LocalProvider` was built with
`allow_ephemeral_local_keys()` (an opt-in on the provider, not on the registry). Cargo feature unification alone never enables
it, and every open logs a warning (§7).

### 3.5 Key URIs

Core `KeyUri` is `{ scheme, rest }`. The scheme must be lowercase
`[a-z][a-z0-9+.-]*`, and `rest` is opaque to core. Each provider parses `rest`
with its own strict parser and applies its own address policy. The cloud URIs
are implemented that way (`aws-kms://arn:…`, `gcp-kms://projects/…`,
`azure-kv://<host>/keys/…`, §23).

Transit grammar:

```
hashivault://[alias]/<mount path>/keys/<name>[?namespace=<ns>]
openbao://[alias]/<mount path>/keys/<name>[?namespace=<ns>]
```

- **Schemes.** `hashivault` and `openbao` are synonyms that both route to the
  transit provider. The flavor (Vault or OpenBao) is a property of the
  *configured server*, not of the URI. Moving a server from Vault to OpenBao
  therefore never forces stored URIs to change.
- **Alias.** `[alias]` names a configured server. An empty alias
  (`hashivault:///...`) means the default; an unknown alias is an error. A URI
  can never introduce a network address. The spec's `hashivault://transit/keys/k`
  would read `transit` as an alias, so it errors with a hint.
- **Segments.** Each mount and name segment matches `[A-Za-z0-9_.-]+`. Empty
  segments, `.`, `..`, percent-encoding, userinfo, fragments and unknown query
  keys are rejected. Segments are encoded again when building request URLs.
- **Namespace.** The namespace is set on `ServerConfig`. A URI `namespace`
  must equal it or appear in that server's `allowed_namespaces` list, because
  it changes authorization scope. An optional `allowed_mounts` list restricts
  mounts.
- The parser is fuzzed.

### 3.6 Errors

> **Superseded in part by §25.2 (A3):** the class of `KeyVersionUnusable` no longer depends on the
> operation (a disabled version the handle chose is `KeyStateInvalid`; `KeyVersionUnusable` is always
> input data), `UnknownKeyVersion` is new, a malformed URI is `Configuration`, and key wrapping is
> labeled `WrapKey`/`UnwrapKey`.

```rust
#[non_exhaustive] pub struct Error { kind: ErrorKind, backend: &'static str, op: Operation,
    detail: Option<BackendDetail>,   // { http_status, server_message, request_id, code }; never input data
        // server_message: pinned/known messages verbatim; any other message reduced to (length, SHA-256 prefix)
    retry_after: Option<Duration>,
    retry_hint: Option<Duration>,    // "retry once after at least this", for kinds that are not retryable (§20)
    source: Option<Box<dyn StdError + Send + Sync>> }

#[non_exhaustive] pub enum ErrorKind {
    NotFound, PermissionDenied, KeyStateInvalid,
    DecryptFailed,        // wrong key/AAD, tampered, truncated: deliberately indistinguishable
    VerificationFailed, InvalidArgument,
    KeyMismatch,          // key type/algorithm cannot do the operation (deployment problem, not input)
    Unsupported,
    Configuration,        // unknown alias, namespace not found, disallowed mount, insecure transport
    KeyVersionUnusable,   // the input's key version is below min_decryption_version, disabled or destroyed (§20)
    Throttled, Unavailable, Timeout,
    Backend,              // unclassified; detail attached
}
impl Error {
    pub fn is_retryable(&self) -> bool;     // Throttled | Unavailable | Timeout
    pub fn is_config_error(&self) -> bool;  // NotFound | PermissionDenied | KeyStateInvalid | KeyMismatch | Unsupported | Configuration | Backend
                                            // (+ KeyVersionUnusable from an operation that produces output under the unusable version)
    pub fn is_caller_error(&self) -> bool;  // InvalidArgument | DecryptFailed | VerificationFailed | KeyVersionUnusable (input side)
    pub fn retry_after(&self) -> Option<Duration>;
    pub fn app(kind: ErrorKind, message) -> Error;   // for application code and fakes reporting through the same type
}
// Error is Clone (source is an Arc).
```

- **Leak prevention.** No `Display`, `Debug` or `source()` chain may contain
  plaintext, AAD, tokens, data keys, request bodies or URL query strings. JSON
  decode errors on responses that carry secrets are replaced with a fixed
  message and never attached as `source`. reqwest errors are attached only
  after their URL is stripped.
- **Retry safety.** Data-plane operations are safe to retry, *provided upsert
  is disabled* on the transit mount (§6.5). Otherwise encrypt to a missing key
  creates it.
- **What retries cannot fix.** `KeyStateInvalid`, `DecryptFailed` and
  `NotFound` are permanent. The documented exception is an error carrying a
  retry hint, such as transit replica lag right after a rotation or key
  creation (§6.4).

## 4. Secret handling

- **Plaintext.** Inputs are `&[u8]`. Decrypted plaintext comes out as
  `Zeroizing<Vec<u8>>`. A `DataKey` is boxed and zeroized, with no `Clone`,
  `Serialize` or revealing `Debug`.
- **Tokens.** Tokens are `SecretString`, sent in a sensitive header, and
  fetched from the `TokenSource` per request.
- **Zeroization limits (stated in the README).** anykms zeroizes buffers it
  owns: request JSON goes into a pre-sized `Zeroizing<Vec<u8>>`, and the
  response is read into a `Zeroizing` buffer and deserialized from borrowed
  `&str`. The `zeroize` features of the RustCrypto AEAD crates are on. anykms
  cannot zeroize copies inside reqwest/hyper/rustls, kernel buffers or the
  server. This is defense in depth, not a guarantee.
- **Unexpected warnings fail closed.** Any `warnings` entry on a transit
  response that is not on an explicit allowlist of known-harmless messages
  (the allowlist ships empty, matches exact strings only, and every entry needs
  a test and a written reason)
  turns into `Unsupported`, and the result is discarded and zeroized.
- **Minimal parameters.** Each request sends only the parameters its operation
  needs. Warnings only flag *unknown* field names. Known fields that the server
  ignores (`context` on non-derived keys, `associated_data` on rewrap,
  `prehashed` on Ed25519 under OpenBao) produce no warning. Those cases are
  handled by never sending such fields, plus explicit local checks.

## 5. Recipes (`anykms-recipes`)

Each recipe's rustdoc opens with an **"Emulates / Enforced by"** box.

### 5.1 `EnvelopeAead<K: KeyWrap>` (implements `Aead`; M3)

`K` was `Aead` in the approved plan; since the 2026-10 review it is the core
`KeyWrap` trait (§19). An `Aead` KEK is adapted explicitly with `AeadKeyWrap`
(`key.into_key_wrap()`), which wraps by encrypting with empty AAD, and
`Registry::key_wrap` opens a `KeyWrapKey` the same way for transit and local
keys (§20), so the wire format and every vector are unchanged.

Wire format v1 (big-endian):

```
magic "AKE" | version 0x01 | flags u8 (=0; reserved: streaming, ...) |
commit[32] | nonce[12] |
u8 kek_id_len | kek_id (0..=255 bytes; opaque routing hint, NOT authenticated) |
u16 wrapped_dek_len (1..=4096) | wrapped_dek (NOT authenticated) |
gcm_ciphertext || tag[16]
```

- **Per message:** a fresh 32-byte DEK from `OsRng`, then
  `HKDF-SHA256(ikm = DEK, info = "anykms/envelope/v1")` → `enc_key[32] || commit[32]`.
  The payload is AES-256-GCM under `enc_key` with a random nonce. Each DEK
  encrypts exactly one message, so a random nonce is safe. The message size
  limit is enforced.
- **Key commitment:** on decrypt, `commit` is compared in constant time before
  GCM runs. This rules out multi-key ("invisible salamander") attacks, including
  keyring decrypt.
- **GCM AAD:** `magic | version | flags | commit | nonce`, followed by
  `u64(len(user_aad)) | user_aad`.
- **Deliberately unauthenticated fields.** `kek_id` and `wrapped_dek` are
  outside the GCM AAD. They form the *key-wrapping slot*, which can be replaced
  without touching the payload. Tampering with them gains nothing: a different
  DEK fails the commitment, and a rewritten `kek_id` only changes which KEK
  is tried. The commitment, not GCM, guards the slot. This enables:
  - `rewrap(&ct)`, for `K: Aead + Rewrap` (including `AeadKey` and
    `TransitAeadKey`): the KMS rewraps the DEK under the KEK's primary version.
    The DEK never leaves the KMS.
  - `rewrap_local(&ct)`, for any `K: KeyWrap`: unwrap and re-wrap under the same
    KEK. The DEK is briefly in local memory, held in a `Zeroizing` buffer, but
    the payload is never touched.
  - `rewrap_to(&ct, &new_kek, new_kek_id)`: unwrap with this KEK, wrap with
    another one (a different transit key, or a Vault → AWS migration), and
    rewrite `kek_id`. Same DEK exposure as `rewrap_local`. Covered by its own
    test vector.
- **`kek_id`** is an opaque label chosen by the caller, for example a logical
  name like `"app-kek"`. A key URI also works, but `hashivault://` and
  `openbao://` spell the same key differently, so a logical name is
  recommended. Decrypt **never** treats `kek_id` as a URI to open.
  - A single-KEK `EnvelopeAead` compares the blob's `kek_id` with its own
    configured one *before* any KMS call. On mismatch it returns
    `DecryptFailed`, with `BackendDetail` saying "kek_id mismatch"; nothing
    secret is revealed.
  - `EnvelopeKeyring` (M3) maps a fixed set of `kek_id` values to KEKs, so a
    table can hold rows under old and new KEKs during a migration. Every KEK
    in the ring is trusted for decryption, so retired KEKs must be removed
    promptly (`docs/operations.md`, "Retiring envelope KEKs").
- **KEK wrap:** `K::wrap_key(DEK)`, which for an AEAD KEK (`AeadKeyWrap`) is
  exactly `encrypt(DEK, aad = b"")`, as in Tink's `KmsEnvelopeAead`.
  Empty AAD keeps transit server-side rewrap working, since transit rewrap
  ignores AAD (verified), and keeps user AAD out of KMS audit logs. The docs
  state the consequences as **requirements**:
  - The KEK **MUST** be dedicated to envelopes. Any code that decrypts with
    empty AAD under the same KEK could unwrap DEKs, so do not mix native
    `DataKeys` or direct `Aead` use with `EnvelopeAead` on one KEK. A policy
    snippet gives envelope KEKs their own paths, and the transit `Aead` rustdoc
    carries a warning.
  - Anyone with `encrypt` on the KEK can forge envelopes for any AAD. The
    recipe therefore proves confidentiality and integrity, not who wrote the
    data.
- **Decrypt:** checks the magic, the version against an explicit accepted list
  (no downgrade), flags = 0, and exact lengths.
  - After unwrap, the DEK must be exactly 32 bytes.
  - KMS errors that are about *availability or authorization*
    (`PermissionDenied`, `Throttled`, `Unavailable`, `Timeout`, `NotFound`,
    `KeyStateInvalid`) propagate unchanged.
  - Everything that depends on the attacker-supplied wrapped DEK or payload
    becomes `DecryptFailed`, with no further distinction. That covers KMS
    `DecryptFailed` or `InvalidArgument`, a wrong DEK length, a commitment
    mismatch and a bad GCM tag.
- **Inspection:** `Envelope::parse(&bytes)` exposes `kek_id()` and
  `wrapped_dek()`. Pass the wrapped DEK to `Aead::ciphertext_version` to find
  rows still on old key versions.
- **Stability promise:** every future release decrypts v1. Test vectors are
  committed under `crates/anykms-recipes/tests/vectors/`. They cover:
  - a plain envelope;
  - after `rewrap`;
  - after `rewrap_to`, with a changed `kek_id`;
  - rejections: a swapped wrapped DEK, a flipped commitment byte,
    `flags != 0`, an unknown version, truncation, and a `kek_id` rewritten to
    another real KEK in an `EnvelopeKeyring`, which must give `DecryptFailed`.

  The format spec states that the commitment covers neither the user AAD nor
  `kek_id`, and doesn't need to: GCM covers the AAD, and `kek_id` is only a
  hint. It also notes that an unwrap error of `KeyStateInvalid` reveals
  the slot's KEK version (already public through `ciphertext_version`). The
  spec gets an external review before the M3 freeze.
- **KEK separation by convention:** the docs recommend a dedicated mount (e.g.
  `transit-envelope/`) so policy enforces it.

  The format spec lives in `docs/envelope-format.md`, frozen at the end of M3.
- **Out of scope:** streaming and large files. The reserved flag and the
  version byte leave room for a streaming segment format later (in the style of
  Tink streaming AEAD). For now the docs point to `DataKeys` plus a caller-side
  streaming AEAD.

### 5.2 `EmulatedDataKeys<K: Aead>` (implements `DataKeys`; M3)

The DEK is generated locally and wrapped with `K::encrypt(dek, aad)`. Use this
for portable AAD binding, for example on Vault, where native `DataKeys` with
AAD is `Unsupported`.

### 5.3 Verification and helpers

- **`LocalVerifier` (M1).** Supports P-256, P-384, P-521, Ed25519, and RSA
  PKCS#1 v1.5 and PSS with salt exactly equal to the hash length (the RSA
  crate is used for public-key operations only).
- **`CachedVerifier<P: PublicKeys>` (M3).** Fetches the public key for
  `Signature::key_version` and caches each version immutably.
- **ECDSA DER ↔ fixed-width (M1).** Includes P-521 long-form DER lengths.
- **JOSE helpers (M3).** `PublicKey::to_jwk(kid)`, plus a JWKS builder over the
  versions of a key. The default `kid` is `<key name>.<version>`, because a bare
  version collides across keys. `sign_message_hashed` / `verify_message_hashed`.

## 6. Transit backend (`anykms-transit`)

### 6.1 Client decision

Evaluated against Vault 2.1.1 and OpenBao 2.7.1 (see the research doc):

| | `vaultrs` 0.8 | `openbao` 2.2.2 | in-house |
|---|---|---|---|
| Works on both servers | ✅ | partial: asymmetric `read_key` fails to decode | ✅ |
| Server error messages | ✅ | ❌ dropped | ✅ |
| Response `warnings` visible | ❌ logged and discarded | n/a | ✅ |
| Redirect / timeout / TLS control | via rustify | ✅ | ✅ |
| Plaintext kept out of plain `String` | ❌ | ✅ | ✅ |
| Weight / churn | rustify, derive_builder, async-trait | ~93k LOC, multiple releases per month | reqwest + serde_json |

Decision: in-house. The HTTP client is ≤1.5k LOC, and the whole crate is about
3–4k LOC including token sources, configuration, error mapping, typed handles
and describe mapping. M2 is the largest milestone and is budgeted that way.

### 6.2 Configuration

```rust
TransitProvider::builder()
  .server("default", ServerConfig::new("https://vault.internal:8200", Flavor::Vault)
      .token_source(TokenSource::file("/vault/secrets/token"))   // or ::static_(..), ::env(), ::none() (Agent API proxy)
      .namespace("team-a").allowed_namespaces(["team-a/child"]).allowed_mounts(["transit"])
      .ca_pem(pem)                  // REPLACES system roots (no merging); no skip-verify API exists
      .client_identity(cert, key)   // optional mTLS
      .connect_timeout(2s).request_timeout(10s)   // per attempt
      .pool_idle_timeout(50s).tcp_keepalive(30s)
      .http_version(HttpVersion::Http1)           // default; Http2 multiplexes onto one node behind an LB
      .proxy(Proxy::None))          // env proxies ignored unless configured explicitly
  .build()?;
TransitProvider::from_env()?;  // documented variable list below
```

- **TLS.** reqwest is used with `default-features = false,
  features = ["rustls-no-provider", "json"]` and
  `ClientBuilder::use_preconfigured_tls(rustls::ClientConfig)`. Never use the
  `rustls` feature: it pulls in aws-lc-rs and the platform verifier. rustls
  with the ring provider is configured on the client itself;
  no process-global provider is installed. The default roots come from
  `rustls-native-certs`. Certificate files are read at build time; reload means
  rebuilding the provider (documented).
- **Plain `http://`.** It is accepted only for literal loopback IPs
  (`127.0.0.0/8`, `::1`; the hostname `localhost` is rejected), and only with
  `.allow_loopback_http()`. An explicit proxy plus `http://` is refused.
  `from_env` enables loopback HTTP automatically when `VAULT_ADDR`/`BAO_ADDR`
  is `http://` on a literal loopback IP. That covers Vault/Bao Agent API-proxy
  deployments and the compose tests. Any other HTTP address is a `Configuration` error.
- **Redirects** are never followed (`redirect::Policy::none()`). Otherwise a
  standby node's 307 would send the token and the plaintext body to another
  host. A 307 (a standby that cannot forward) becomes `Unavailable`; any other
  3xx (301/308, or 302/303 from a proxy or login page) is `Configuration`.
- **`from_env`.** For Vault: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TOKEN_FILE`,
  then `~/.vault-token` (the token source chosen is logged at INFO, never its
  value; the home-file fallback can be disabled with `.no_home_token()`), `VAULT_NAMESPACE`, `VAULT_CACERT`,
  `VAULT_CAPATH`, `VAULT_CLIENT_CERT`, `VAULT_CLIENT_KEY`. OpenBao uses the `BAO_*`
  equivalents (selected with `from_env_openbao()`, which falls back to
  `VAULT_*`). `*_SKIP_VERIFY=true` makes it **fail**. `VAULT_TOKEN_FILE` and
  `BAO_TOKEN_FILE` are anykms conventions; the Vault and OpenBao CLIs do not
  read them.
- **`TokenSource`.** It is object-safe:
  `fn token(&self) -> BoxFuture<'_, Result<Option<SecretString>>>` plus
  `fn invalidate(&self, rejected: &SecretString)`.
  - The `File` variant re-reads on mtime change and after `invalidate`. It
    trims a single trailing newline. It treats an empty file or one over 8 KiB
    as `Unavailable`. It warns when the file is group- or world-readable, and
    never echoes contents.
  - On a 403, the client calls `invalidate`. If the source then returns a
    *different* token, the request is retried exactly once. This is
    independent of, and not multiplied by, `Retry` (§11).

### 6.3 Operation mapping

| anykms op | Endpoint and parameters sent (nothing else) |
|---|---|
| `Aead::encrypt` / `decrypt` | `encrypt/:name`, `decrypt/:name`: `plaintext`/`ciphertext`, plus `associated_data` only if non-empty. |
| `Rewrap` | `rewrap/:name`: `ciphertext`. Non-empty AAD → `Unsupported` locally. `ciphertext_version` parses the `vault:vN:` prefix. |
| `DataKeys` | `datakey/plaintext/:name`: `bits=256`. **Vault:** non-empty AAD → `Unsupported` locally. **OpenBao:** `associated_data` is sent; OpenBao < 2.5 warns and fails closed. |
| `DigestSigner` / `DigestVerifier` | `sign/:name`, `verify/:name`: `input`, `prehashed=true`, `hash_algorithm` (never `none`), `marshaling_algorithm=asn1`, and for RSA `signature_algorithm` ∈ {`pss`, `pkcs1v15`}. PSS always sends `salt_length=hash` on both sign and verify. Verified: the server default is the maximum salt, and `auto` verification accepts any salt. |
| `MessageSigner` / `MessageVerifier` | Same endpoints. Ed25519 only, and `prehashed` is never sent. |
| key version | `sign` returns `key_version`. `Signature`/`Tag` hold the version, and the backend adds or strips the `vault:vN:` prefix. |
| `Mac` | `hmac/:name/:alg`, `verify/:name/:alg` with `hmac`. Server-side verify. |
| `PublicKeys` / `Describe` | `GET keys/:name`. PEM → SPKI DER. `soft_deleted` (OpenBao) → `PendingDeletion`. HMAC keys report `keys: null`, so their version list is empty (documented). |

### 6.4 Error mapping

Pinned by conformance and mock-server tests on every CI server version.

| Server response | ErrorKind |
|---|---|
| 400 `encryption key not found`; 404 on `keys/:name` | NotFound (see the lag note) |
| 400 `version is too new` (ciphertext, signature or HMAC) | DecryptFailed, with the replica-lag retry hint |
| 400 `cipher: message authentication failed`, other `invalid ciphertext: *` | DecryptFailed |
| 400 `... disallowed by policy (too old)`, `version is too old (disallowed by policy)` | KeyVersionUnusable |
| 400 `refusing to use soft-deleted key`; the same on 500 (OpenBao sign/verify) | KeyStateInvalid |
| 400 `does not support ...`, `not supported for key type`, `provided for non-AEAD cipher suite` | InvalidArgument |
| 500 `JSON string value exceeds allowed length`; 413 | InvalidArgument |
| 404 `namespace not found`; 404 `no handler for route`; 3xx other than 307 | Configuration |
| 403 | PermissionDenied (docs: with upsert disabled and no `create`, encrypt to a missing key is also 403) |
| 429 | Throttled; `Retry-After` parsed (OpenBao can send `0`) |
| 503 (sealed, standby); 502/504; 307; connection refused or reset; truncated response | Unavailable |
| 500 with a pinned transient message (`context deadline exceeded`, `active cluster node not found`, `local node not active`, raft leadership messages) | Unavailable |
| client-side connect/request timeout | Timeout |
| 412 | Unavailable. Only reachable if `X-Vault-Index` is sent, and v0.1 sends none. |
| 200 with a non-allowlisted warning | Unsupported |
| anything else, incl. other 500s | Backend (status and redacted message; logged by `tracing`) |

**Replica lag.** On performance standbys and secondaries, ciphertext from a
just-rotated key fails with "version is too new", and a just-created key
returns "not found". The docs explain this. Transit attaches a 500 ms retry
hint (`Error::retry_hint`) to "version is too new" and "encryption key not
found", and `Retry` exposes an opt-in `retry_on_hint` that allows one retry
after at least the hint (§20). When enabled, a real `NotFound` costs one extra
delay, even on single-node setups (documented).

### 6.5 Operator guidance (shipped docs)

- **Policies.** HCL snippets grant `update` on
  `transit/{encrypt,decrypt,rewrap,datakey/plaintext,sign,verify,hmac}/<k>`,
  `read` on `transit/keys/<k>`, and **never `create`**.
- **Upsert.** Set `transit/config/keys disable_upsert=true`, which needs
  `update` on that path. Verified on both servers.
- **Quotas.** Recommended settings include `enable_rate_limit_response_headers`.
- **Health checks.** Never gate application readiness on `/sys/health`, because
  standbys return 429 there.
- **Runbook.** A page lists each `ErrorKind` with its likely causes and the
  operator action.
- **Namespaces.** Vault CE silently ignores the namespace header.

### 6.6 Observability (M2, `tracing` feature)

- **Spans.** One span per operation with an allowlisted field set: `op`,
  `backend`, `server_alias`, `mount`, `key`, `key_version`, `outcome`,
  `error_kind`, `http_status`, `attempt`, `latency`.
- **Events.** One each for:
  - every retry and its reason,
  - a fallback to `Backend` (an unknown server message),
  - a fail-closed warning,
  - a token-file reload,
  - opening a local key.
- **Field-allowlist test.** It captures all output at TRACE, including
  reqwest and hyper, and asserts that marker secrets never appear.
- Metric decorators come in M5.

## 7. Software backend (`anykms-local`)

```rust
let ks = LocalKeyset::builder().aead("kek").hmac("tok").ecdsa_p256("sig").ed25519("ed").build();
let p  = LocalProvider::new(ks.clone()).allow_ephemeral_local_keys();   // LocalKeyset is a cheap Arc handle   // required, or every open fails with Configuration
ks.rotate("kek"); ks.disable("kek"); ks.inject(Fault::Throttled { times: 2 });   // public, for app tests
```

- **Keys and framing.** In-memory, versioned keys: AES-256-GCM (`Aead`,
  `Rewrap` including with AAD, `DataKeys` with AAD), HMAC-SHA2, ECDSA
  P-256/P-384/P-521, and Ed25519. Ciphertext framing is
  `local:v<N>:` + nonce + ciphertext + tag, and the parser is fuzzed.
- **No RSA private keys.** RSA conformance cases are *not applicable* on local.
- **Data loss.** Without persistence, keys vanish when the process exits.
  Docs, rustdoc and a warning on every open say so, which is why it requires a
  runtime opt-in.

## 8. Conformance suite (`anykms-conformance`)

```rust
#[trait_variant::make(Send)]
pub trait Fixture: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn probe(&self) -> FixtureCaps;   // runtime: rotate, disable, min_decrypt_version, throttle, datakey_aad, rsa, ...
    async fn create_key(&self, kind: TestKeyKind) -> Result<TestKey>;   // admin path, not public API
    fn provider(&self) -> Arc<dyn Provider>;  // cases run both through typed handles and through the Registry
    fn typed(&self) -> Arc<dyn TypedHandles>;
    fn missing_key_uri(&self) -> KeyUri;
    // Optional, each gated on a Feature and defaulting to "not available" (Unsupported / None):
    async fn rotate(&self, k: &TestKey) -> Result<()>;
    async fn disable(&self, k: &TestKey) -> Result<()>;
    async fn set_min_decryption_version(&self, k: &TestKey, v: &KeyVersion) -> Result<()>;
    async fn throttle(&self, k: &TestKey) -> Result<()>;   // + unthrottle; n/a on cloud KMS
    async fn encrypt_natively(&self, k: &TestKey, pt: &[u8]) -> Result<Option<Ciphertext>>;
    fn counting(&self) -> Option<Counting>;
    fn unauthorized_provider(&self) -> Option<Arc<dyn Provider>>;
    fn secret_markers(&self) -> Vec<String>;
}
// tests/conformance.rs, with `[[test]] harness = false`:
fn main() { anykms_conformance::run(async || TransitFixture::from_compose().await) }   // run() owns the runtime
```

- **Harness.** It is built on `libtest-mimic`, with one tokio runtime and one
  fixture per test binary. `probe()` runs once.
- **Kinds.** libtest-mimic has no ignore reason. The two ignore kinds are
  shown with `Trial::with_kind("n/a" | "skip")`, and every case body checks
  the capabilities again so that `--include-ignored` stays honest.
- **Outcomes.** Each case ends as *passed*, *failed*, *ignored: not applicable*
  (the backend lacks the algorithm or feature by design, as the research doc
  records), or *ignored: fixture lacks feature*. Nothing that was not run is
  reported as passed. M1 and M2 exit criteria allow only *not applicable*.
- **Transit policies.** The fixture runs the suite twice: under a
  least-privilege token with upsert disabled, and under a token with `create`
  and upsert enabled (to pin the 403 vs `NotFound` behavior).

Cases:

- **Aead:**
  - round trip (empty, 1 B, 64 KiB); output is non-deterministic;
  - wrong AAD, missing AAD, tampered, truncated, or another key's ciphertext
    → `DecryptFailed`;
  - decrypt after rotation; new encrypts use the new version;
  - below min decrypt version, or disabled/soft-deleted → `KeyStateInvalid`;
  - oversize input → `InvalidArgument`;
  - an existing native ciphertext with no AAD decrypts with `b""`.
- **Rewrap:** moves the ciphertext to the primary version and the result
  decrypts. With AAD it gives `Unsupported` on transit and works on local.
  `ciphertext_version` is correct.
- **DataKeys:**
  - the key is 32 bytes and decrypts via `Aead`;
  - with AAD, it is bound where supported, and otherwise `Unsupported` with
    zero requests;
  - a server that ignores the AAD fails closed (OpenBao 2.4 in the matrix,
    and a mock).
- **Signing, every algorithm:**
  - a backend signature verifies with the **independent** `LocalVerifier` and
    with the backend verifier;
  - PSS salt equals the hash length;
  - a mismatched digest algorithm or wrong length is rejected with zero
    requests;
  - an asserted algorithm that differs from the key's type → `InvalidArgument`
    (key-type check);
  - tampered input → `VerificationFailed`, and so is a structurally
    malformed signature (garbage bytes, truncated DER) with the right
    algorithm and version, on the backend and the local verifier;
  - Ed25519 works only through `MessageSigner`;
  - a pre-rotation signature still verifies afterwards (via its `key_version`);
  - `CachedVerifier` picks the right version.
- **Mac:** round trip; tampered, truncated, wrong algorithm, or wrong key →
  `VerificationFailed` / `InvalidArgument`.
- **PublicKeys / Describe:** SPKI parses and matches `key_type`; versions and
  state are reported.
- **Errors:**
  - a missing key gives `NotFound` for every operation;
  - bad token → `PermissionDenied`;
  - throttling → `Throttled` and retryable, with `retry_after` when headers are
    on;
  - sealed server → `Unavailable` (dedicated compose service);
  - unknown namespace → `Configuration` (OpenBao).
- **Mock-server cases (wiremock):**
  - a 307 to another port never receives the token;
  - an unknown warning → `Unsupported`;
  - `Retry-After: 0` gets clamped;
  - transient vs. other 500s;
  - truncated or malformed JSON;
  - a slow server hits the timeout.
- **Hygiene:** marker plaintext, AAD, token and data key never appear in any
  `Display` or `{:#?}`, anywhere in the `source()` chain, or in captured
  TRACE output.
- **Unversioned signatures:** transit verify of a `Signature` with no or a
  non-numeric `key_version` → `InvalidArgument` with zero requests.
- **Upsert:** encrypt to a missing key is pinned for both setups: 400
  `NotFound` with `disable_upsert`, and 403 for a token without `create`.
- **Recipes over every backend (M3):** `EnvelopeAead` round trip, rewrap,
  commitment, wrong-KEK and test vectors; `rewrap`/`rewrap_local`/`rewrap_to`
  through `AeadKey` from the `Registry` (this case must compile, which proves
  the CryptBox path typechecks); `EnvelopeKeyring`; `EmulatedDataKeys`;
  `CachedVerifier`. All of these run through the dyn layer as well.

## 9. Dev environment and CI

- **`compose.yaml`:**
  - `vault` on port 8200 and `openbao` on 8300, both in dev mode with root token
    `root`, images `${VAULT_IMAGE}` / `${OPENBAO_IMAGE}` (defaults pinned by tag
    and digest), healthchecks
    with `start_period`, and ports bound to loopback only;
  - one-shot `vault-init` / `openbao-init` services that mount transit, set
    `disable_upsert` (test policies and tokens are created by the fixture);
  - a separate `vault-sealed` service (compose profile `sealed`), sealed via
    `sys/seal`;
  - a `tls` profile running the servers with generated certificates, so the
    TLS path is tested rather than only loopback HTTP.
- **Scripts.** `scripts/probe-transit.sh` diffs semantics against new server
  releases. The root token is used only by fixtures and init containers.
- **CI (GitHub Actions):**
  - Static checks: fmt, clippy `-D warnings`, rustdoc, `cargo deny`, the MSRV
    build from the lockfile, and server-free tests (core, recipes, local, mock
    transit).
  - Integration matrix: `scripts/dev-up.sh`, then the suite. The script runs
    `docker compose up -d --wait vault openbao`, then
    `docker compose run --rm vault-init` and `... openbao-init`. Plain
    `up --wait` exits 1 once the one-shot init containers finish (verified).
    The `sealed` service is separate from the shared servers, so sealing it
    never disturbs parallel runs.
    Versions are Vault {oldest still-supported minor at M0, latest} and OpenBao
    {2.4.x (no datakey AAD), latest}. Exact patch tags are pinned and bumped by
    Dependabot.
  - Nightly fuzzing with `cargo fuzz`. Targets: KeyUri, the transit URI
    parser, envelope parse, envelope round-trip/differential, transit JSON
    response decoding, PEM→SPKI, DER↔fixed, `local:` framing, and
    `Digest::new`.
  - `cargo-semver-checks`: core is frozen when M1 exits; every published crate
    is checked on each PR against the base branch (a crate missing from the
    baseline is skipped); crates.io baselines take over from 0.1.0.
  - Every crate is also checked on its own with `--no-default-features
    --all-targets`, because workspace builds unify features and can hide code
    that compiles only thanks to another crate's features. The facade's docs
    are built with default and no default features under `-D warnings`.
- **`deny.toml`:**
  - add an `[advisories]` section;
  - make `wildcards = "deny"`;
  - add a scoped ignore for RUSTSEC-2023-0071 (Marvin), with the reason "rsa
    used for public-key verification only";
  - set reqwest to `default-features = false`.
- **`rsa` version.** At M1, pick the release that matches the
  digest-0.11/signature-3 stack (`0.10`; it is an RC today). Fall back to `0.9`
  and accept the duplicated RustCrypto tree, recording the choice.

## 10. Milestones

| M | Deliverable | Exit criteria |
|---|---|---|
| M0 | Workspace scaffold, compose (init, sealed, TLS profiles), CI skeleton, `deny.toml` updates, research doc | CI green; `scripts/dev-up.sh` exits 0 on all matrix versions; the sealed and TLS profiles come up |
| M1 | `anykms-core` (types, traits, dyn layer and bridges, `Provider`, `Registry` core, `KeyUri`), `anykms-local`, the M1 part of recipes (`LocalVerifier`, DER, digest helpers), the conformance harness, Appendix A reviewed | Suite green on local with only *not applicable* ignores; the trait/dyn pattern compiles with `Send` futures through `tokio::spawn` |
| M2 | `anykms-transit`: client, token sources, typed handles with key-type check, rewrap, error table, `tracing`, mock tests, policy docs | Suite green on all four server versions with only *not applicable* ignores; mock-server cases green |
| M3 | Rest of recipes (EnvelopeAead v1 + vectors + format doc, EmulatedDataKeys, CachedVerifier, JOSE helpers), `anykms` facade, `Retry` decorator | Recipe cases green over local and transit, typed and dyn; three examples (field encryption, JWT signing, HMAC tokens) |
| M4 | Hardening and 0.1.0 | Fuzzers clean for 1 CPU-hour per target; docs list every emulation, flavor difference and operator step; security review of the release diff; **external review of `docs/envelope-format.md` done** before 0.1 is promoted for long-lived data (§21) |
| M5+ | In order: transit AppRole/Kubernetes/JWT login with token renewal (first, ahead of cloud backends); decrypt-side DEK cache; metrics layer and layered extension handles; envelope v2 (multiple wrapped-key slots + streaming, §21); `KeyLifecycle` (separate handle), `Random`, `AsymmetricDecrypt`; ~~AWS via LocalStack; Azure standard-vault `KeyWrap` data keys~~ (moved to M6) | each with its own conformance additions |
| M6 | Cloud backends (§23): conformance redesign, `anykms-http`, AWS, GCP, Azure | per-backend mock + emulated/fake conformance green on every PR; live probes A0/T1/T3 pinned in `docs/research`; live nightly jobs green |

## 11. `RetryLayer` (M3)

A `Layer` that retries every part of a handle; `RetryLayer::call` retries any other future. (The
`Retry<T>` typed decorator that implemented the same traits as the handle it wrapped was removed
on 2026-11-02; see `docs/cloud/architecture-plan.md`.)

- **Backoff.** Exponential with *equal* jitter: the n-th retry waits between
  half and all of `min(base * 2^(n-1), cap)`. Defaults: base 300 ms, cap 5 s,
  max 6 attempts (5 retries, 4.65–9.3 s in total, which spans a leader
  step-down; see §18, review round 4), overall deadline 15 s. The delay math
  saturates instead of overflowing.
- **Retry budget.** A token bucket (`RetryBudget`): every call deposits
  `budget_ratio` (0.1) tokens up to `budget_cap` (10), every retry spends one,
  so at most about 10% of calls are retries. Each `Retry` and its clones share
  one budget; `Retry::with_budget(budget.clone())` (now
  `RetryLayer::with_budget`, §20) shares a budget across handles, which is how to bound retries **per backend** rather than per
  handle (`docs/operations.md`, "Retry budgets"). A shared budget overrides the
  policy's ratio and cap.
- **What is retried.** Only errors where `is_retryable()` is true (plus the
  opt-in replica-lag retry, §6.4). A `Retry-After` is a *floor* over the
  normal backoff: the retry waits `max(jittered backoff, Retry-After + random
  extra of up to base)`, so `Retry-After: 0` never shortens the schedule and
  clients throttled together do not retry in lockstep. Values above one day
  count as one day. If `Retry-After` is above the cap or the wait would pass
  the remaining deadline, `Throttled` (with the `Retry-After` value and the
  original error as `source()`) is returned at once instead of sleeping.
- **No retries below `Retry`.** Backends must not retry internally (documented
  on `Provider`); the only exception is one retry after refreshing rejected
  credentials, which is part of authenticating. So attempts never multiply.
- **Sleeping.** Runtime-agnostic through a caller-supplied `SleepFn`. The
  facade's `tokio` feature provides `tokio_sleep()`/`retry_layer()`; tests use
  `instant_sleep()`. The deadline is measured with `std::time::Instant`, so
  `Retry` does not work on `wasm32-unknown-unknown`. (Superseded: §20 made the
  clock injectable, `ClockFn`/`RetryLayer::with_clock`; see §19 "wasm".)
- **Token refresh.** The transit one-shot retry after a token refresh (§6.2)
  happens inside a single attempt and is never multiplied.
- **Timeouts** per attempt live in the HTTP client. The overall deadline lives
  in `Retry` and bounds the retry schedule, not an attempt in flight.

## 12. Risks and open questions

- **Error classification depends on message strings.** Mitigations: the mapping
  is pinned per server version, unknown messages fall back to `Backend` (less
  specific, never misclassified), and a `tracing` event fires on every
  fallback.
- **Ignored known parameters are invisible to warning detection.** Mitigated
  by sending only the parameters each operation needs and by local checks.
  The probe script is rerun for each new server release.
- **Request-size limits differ.** Docs steer bulk data to `EnvelopeAead`.
- **One transit round trip per field.** Docs give guidance on throughput.
  DEK caching is M5.
- **Post-quantum signing input.** AWS ML-DSA with `MessageType=EXTERNAL_MU` signs a 64-byte
  μ, which is neither a digest nor a message. When PQC lands it gets a separate `MuSigner` /
  `MuVerifier` trait pair; `DigestSigner` and `MessageSigner` never grow a third input mode (§21).
- **Spec interpretation.** The plan departs from the spec in a few places, each
  justified above: the signer split, the URI authority as an alias, the
  recipes crate name, and flavor living on the server config rather than the
  scheme.

## 13. CryptBox

`cryptbox-kms` depends on `anykms-core` and `anykms-recipes`.

- `Kek` becomes `AeadKey`, obtained from `Registry::aead`.
- Two-level wrapping becomes `EnvelopeAead<AeadKey>`, with `kek_id`
  holding a *logical* KEK name (not a URI), so blobs stay routable after a
  migration or a scheme change.
- KEK version rotation uses `EnvelopeAead::rewrap`, which works on `AeadKey`.
  A move to a different KEK uses `rewrap_to`, and `EnvelopeKeyring` handles
  mixed-KEK tables.

Nothing in anykms depends on CryptBox.

## 14. Example: user code against the proposed API

```rust
let t = TransitProvider::from_env()?;                                    // Agent sink via VAULT_TOKEN_FILE
// (a) field encryption
let env = EnvelopeAead::new(t.aead_key(&"hashivault:///transit/keys/app-kek".parse()?)?)
              .with_kek_id("app-kek");                                     // logical label
let ct  = env.encrypt(ssn, b"users/42/ssn").await?;    db.put(ct.as_bytes());   // BYTEA / BLOB column
let pt  = env.decrypt(&Ciphertext::from_bytes(row), b"users/42/ssn").await?;
let ct2 = env.rewrap(&ct).await?;                                        // after KEK rotation; payload untouched
// (b) JWT ES256
let k   = t.digest_signing_key(&uri, SignatureAlgorithm::EcdsaP256Sha256)?;
let sig = sign_message_hashed(&k, signing_input.as_bytes()).await?;      // Signature { key_version: Some("3"), .. }
let jws = format!("{signing_input}.{}", b64url(der_to_fixed(&sig)?));    // kid = "release.<sig.key_version()>"
let jwks = Jwks::from_versions(&k, &versions).await?;
// (c) HMAC tokens
let m   = t.mac_key(&uri, MacAlgorithm::HmacSha256)?;
let tag = m.mac(token_id).await?;   m.verify_mac(token_id, &tag).await?;
```

## 15. Review round 1: blocking issues and resolutions

| # | Raised by | Issue | Resolution |
|---|---|---|---|
| 1 | Arch, Eng, Domain, User | Signature/Tag lack key version; `u64` versions don't fit Azure/GCP | Opaque `KeyVersion`; `key_version` on `Signature`/`Tag`/`PublicKey`; `primary_version` (§3.1) |
| 2 | Arch, Sec | KeyUri/registry transit-shaped; URI namespace changes authz scope; third-party providers can't register | Core `KeyUri {scheme, rest}`, provider-owned parsing and address policy, object-safe `Provider` + `OpenOptions`, namespace/mount allowlists (§3.4–3.5) |
| 3 | Arch | Value types not forward-compatible; PublicKey tied to SignatureAlgorithm; fixed-size DataKey | `#[non_exhaustive]` everywhere, `PublicKey {key_type, spki}`, `DataKey` Vec, cargo-semver-checks (§2, §3.1) |
| 4 | Arch, Eng | Milestones inverted (conformance needs LocalVerifier and dyn layer) | LocalVerifier, DER and dyn layer moved to M1 (§10) |
| 5 | Eng | libtest can't skip at runtime; per-test runtimes; Fixture not Send | libtest-mimic `harness=false`, one runtime and fixture, NA vs skipped, `trait_variant` on Fixture (§8) |
| 6 | Eng | No `Local*` variants from trait_variant; TokenSource not object-safe; E0034 ambiguity; missing dyn→static bridge | Dropped `Local*`; BoxFuture TokenSource; `dyn_*` names + bridge impls via macro (§3.2, §3.4, §6.2) |
| 7 | Domain, Sec | RSA-PSS salt: server default is max, verify `auto` accepts any | `salt_length=hash` always; LocalVerifier enforces (§6.3) |
| 8 | Domain, Sec | Server doesn't catch wrong key type (P-384 as P-256, ECDSA ignoring pss, RSA as "Aead") | Cached-describe key-type check per handle; Aead only on AEAD key types (§3.3) |
| 9 | Domain | Constant KMS AAD breaks portability; Tink uses empty | KEK wrap with empty AAD; also required for transit rewrap (verified) (§5.1) |
| 10 | User | Envelope authenticates wrapped DEK, so rewrap is impossible; no stability promise or KEK id | Wrapped DEK unauthenticated + key commitment; `kek_id`; flags; vectors; forever-decrypt promise (§5.1) |
| 11 | User | No rewrap or rotation workflow | `Rewrap` trait, `ciphertext_version`, `EnvelopeAead::rewrap` (§3.2, §5.1) |
| 12 | User | Downstream testing undefined | Public `LocalKeyset` + fault injection (§7) |
| 13 | User | Migration of existing Vault ciphertexts | Native ciphertext accepted; empty AAD ≡ omitted (verified); derived keys unsupported, documented (§3.1) |
| 14 | Sec, SRE | Redirects leak token and body | `Policy::none()`, 3xx → Unavailable, mock test (§6.2) |
| 15 | Sec | Fail-closed relies on one string; overclaimed | Allowlist of harmless warnings, minimal parameters, claim removed, mock test (§4) |
| 16 | Sec | Leakage through `source()` chains | Secret-bearing parse errors replaced; URLs stripped; hygiene walks chain + TRACE output (§3.6, §8) |
| 17 | Sec, Arch | Local backend reachable via feature unification | Runtime `allow_ephemeral_local_keys()` + warning (§3.4, §7) |
| 18 | Sec | Envelope: DEK length, error swallowing, key commitment, downgrade | All four addressed (§5.1) |
| 19 | Sec | TLS defaults unspecified | ca_pem replaces roots, no skip-verify, SKIP_VERIFY fails, loopback-only HTTP, explicit proxy (§6.2) |
| 20 | SRE | Retry-After handling and retry limits | Retry-After as clamped minimum, attempts/deadline/budget, token retry not multiplied (§11) |
| 21 | SRE | Single timeout; pool/keepalive/HTTP2 | connect/request timeouts, pool idle, keepalive, HTTP version option (§6.2) |
| 22 | SRE | Namespace ignored by Vault CE; OpenBao 404 misclassified | Namespace from config + allowlist; `Configuration` kind; docs (§3.5, §6.4) |
| 23 | SRE | Failover 500s unclassified | Pinned transient-500 list → Unavailable; 412 clarified; replica-lag note (§6.4) |
| 24 | SRE, User | Observability deferred to M5 | `tracing` feature in M2 with field allowlist (§6.6) |

## Appendix A: core types per cloud provider (implemented, §23)

From the domain and architect reviews. The plan asked for a re-check before M1
exited; M1 shipped without it, so it was done against the code in the 2026-10
review (§19), which changed core where a row did not fit (optional
`KeyInfo::state`, pinned-version `public_key()`, `KeyWrap`, `KeyMismatch`,
opaque handles with optional parts). The second review round (§20) corrected
the AWS, GCP and Azure rows below and added the last four. Since the cloud
backends were built (§23, §24), the rows describe the implementation; interim
deviations that wait for a live probe are marked *interim*, and the one
remaining follow-up is marked *deferred*.

| Core concept | AWS KMS | GCP Cloud KMS | Azure Key Vault / MHSM |
|---|---|---|---|
| `KeyUri` rest | `arn:aws:kms:…` (opaque; colons fine); ARN only, with a region of the AWS region shape that belongs to the ARN's partition, so a derived endpoint is always a KMS host (§24) | `projects/…/cryptoKeys/k[/cryptoKeyVersions/n]`; the version is **required** for signing and MAC keys (no primary version); an opt-in "newest ENABLED version, re-resolved on an interval" mode is *deferred* (§24) so signing-key rotation needs no config change (§21); a URI whose version shape does not fit the family is `KeyMismatch` at open | vault host + `/keys/k[/ver]`. Provider checks the host against a configured allowlist (bearer tokens must not reach attacker vaults); the default allowlist covers Managed HSM hosts and the sovereign-cloud suffixes, not only `vault.azure.net` (§21). |
| `Aead` AAD bytes | EncryptionContext. The portable `aad: &[u8]` maps to one reserved context key, omitted when empty; native map contexts (interop with ciphertexts from other AWS tools) go through a backend-specific extension trait on the AWS handle. The portable trait promises no interop with foreign AWS ciphertexts. Context is logged in CloudTrail. **Encoding (decided, §21):** context values are UTF-8 strings, so the AAD bytes are stored as unpadded base64url under the reserved key (*superseded by the release plan D1: Tink's `{"associatedData": lowercase_hex(aad)}`, the cap binding only the operations that produce a ciphertext, 6144 hex characters*); the backend checks the encoded size against AWS's context limit before the request and fails with `InvalidArgument` (AWS documents no limit; the cap is 3072 AAD bytes (4096 base64url characters), about half the limit the A0 probe measured (an 8140-character context value), and may only rise (Q7)). This encoding is a wire format for every AWS ciphertext anykms produces and never changes. The native-map extension must be reached through a *layered* extension handle (retries, metrics), not a raw `downcast_ref`, which bypasses every layer. AWS rejects encryption context on asymmetric and HMAC keys, consistent with core (no AAD on `Mac` or signing). Plaintext limit 1–4096 bytes (use `EnvelopeAead`). **`Decrypt` always passes `KeyId` = the handle's key**: without it AWS decrypts with whatever key the blob names, and since an envelope's `kek_id` slot is unauthenticated, anyone able to encrypt under *any* key the principal can decrypt with could forge an envelope the service accepts. | `additionalAuthenticatedData` (bytes); plaintext limit 64 KiB | AES-GCM AAD on MHSM; Premium-vault oct-HSM AES keys are in **preview** (not promised by the conformance suite). Standard vaults (most users) have only RSA and EC keys: no `Aead`; RSA-OAEP keys implement `KeyWrap`. |
| `KeyWrap` (envelope KEK, `Provider::key_wrap` → `KeyWrapKey`) | every AEAD key through `AeadKeyWrap`; RSA-OAEP-SHA-256 keys: wrap locally with the pinned public key, unwrap with `Decrypt` | every AEAD key through `AeadKeyWrap`; `asymmetricDecrypt` RSA-OAEP-SHA-256 versions implemented (local wrap, server unwrap) | RSA-OAEP-256 `wrapKey`/`unwrapKey`; MHSM `A256KW` (a native `KeyWrap`, possible since §20 dropped the blanket impl) |
| `Ciphertext` | native blob (version embedded, not exposed) | opaque, undocumented format: nothing can be parsed from it, so `ciphertext_version` returns `None`; the only staleness signal is `DecryptResponse.usedPrimary`, surfaced through `Aead::decrypt_with_info` (version + used-primary, §20) | framed (interop cost documented): MHSM AES-GCM returns IV and tag separately, so `version ‖ iv ‖ ct ‖ tag` (lengths fixed by the algorithm); RSA-OAEP / AES-KW `version ‖ ct` |
| `Rewrap` | `ReEncrypt` with `SourceKeyId` and `DestinationKeyId` both the handle's key (same reason as `Decrypt`) | — (client-side only, recipe) | — |
| `DataKeys` | `GenerateDataKey` (AES-256 via `DataKeySpec`); wrapped-only via `WrappedDataKeys` (`GenerateDataKeyWithoutPlaintext`) | — → `EmulatedDataKeys` | — → MHSM: `EmulatedDataKeys` over the `Aead`. Standard vaults: `EmulatedDataKeys<K: Aead>` does **not** fit (no `Aead`); `KeyWrapDataKeys` via `Provider::data_keys` (`DataKeysKey`, Q3), which refuses non-empty AAD |
| `KeyVersion` | symmetric: none exposed (`None`; `ciphertext_version` returns `None`). Asymmetric and HMAC: the **resolved key ARN** that `Sign`, `GenerateMac` and `GetPublicKey` return in `KeyId`, so that after an alias is repointed the old and new keys get different JWKS `kid`s (§21). A handle accepts only the ARN of the key it opens (for an alias URI, the key the alias resolves to) as a version: any other ARN is `NotFound` before any request (the `PublicKeys::public_key_version` contract), because the version often comes from a token's `kid` and must never select a key, and AWS would serve `GetPublicKey` for any key the principal may read. To keep verifying tokens signed before an alias was repointed, configure the previous key as its own key-ID URI and route to it by `kid`: the trusted keys come from config, never from the token. An unversioned signature or tag verifies with the handle's key (no version choice exists per ARN). Symmetric: `KeyInfo` lists the ARN as the only version, no primary | "1", "2"… (primary ≠ latest) | 32-hex string |
| `DigestSigner` | ✅ (`MessageType=DIGEST`) | ✅ (the URI's version) | ✅ (ECDSA output raw r‖s, so convert to DER) |
| `MessageSigner` (Ed25519) | ✅ (pure Ed25519; the ph variant is out of scope: AWS `ED25519_PH_SHA_512` with `MessageType=DIGEST` hashes again inside the service, so it is not plain prehash semantics and must never be mapped onto `DigestSigner`) | ✅ pure | — |
| Verifier | ✅ | signatures: — native → `LocalVerifier` from `anykms-recipes` inside the backend, so `Registry::digest_verifier` works; `Mac` uses server-side `macVerify` | ✅ |
| `PublicKeys::public_key()` | the key's public key | the pinned version's (the handle's signing version) | the version in the URI, else the current one; a pinned handle's `public_key_version` serves only that version (`NotFound` otherwise, before any I/O) |
| `Mac` | ✅ (alg bound to key) | ✅ (alg bound to key; the URI's version) | MHSM HS256/384/512, experimental feature `mhsm-hmac` (Premium oct-HSM: not opened, Q15); standard vaults: — |
| `KeyState` / `KeyInfo::state` | Enabled/Disabled/PendingDeletion; `PendingImport`, `Creating`, `PendingReplicaDeletion` → `Unknown(name)` (verbatim) | key level: `None`; per version in `versions()`: ENABLED/DISABLED/DESTROY_SCHEDULED (→ `PendingDeletion`)/DESTROYED/PENDING_GENERATION (→ `Unknown`) | enabled flag + soft-delete; requests outside the key's `nbf`/`exp` activation window → `KeyStateInvalid` |
| Wrong key type or algorithm | `KeyMismatch` (from `KeySpec`/`KeyUsage`) | `KeyMismatch` (from `purpose`/`algorithm`); a URI whose version shape does not fit the family (versioned AEAD, unversioned signing/MAC) is `KeyMismatch` at open | `KeyMismatch` (from `kty`/`key_ops`) |
| Error detail | exception name in `BackendDetail`'s generic code field, request ID in its `request_id` (§20) | the `google.rpc.Status` name (`FAILED_PRECONDITION`) in the code field, `RequestInfo.requestId` as `request_id` when present | the innermost error code in the code field, `x-ms-request-id` as `request_id` |
| 401 vs 403 | 401/expired credentials → `Unauthenticated` (review plan 1.1); 403 → `PermissionDenied` | same | same |
| Integrity fields | — | Request CRC32Cs are sent (`plaintextCrc32c`, `additionalAuthenticatedDataCrc32c`, `ciphertextCrc32c`, `digestCrc32c`/`dataCrc32c`) and the response's `verified*Crc32c` flags must be `true`; response CRC32Cs are checked too. Either failure → `Unavailable` (retryable) | — |
| Credentials | SDK credential chain, initialized lazily on first operation | ADC, lazily | the `DefaultAzureCredential` sources, picked by environment without probing, lazily: `from_env` builds even with no credential configured, and the first operation is then `Configuration` (§24) |
| Key or version unusable | `DisabledException`, `KMSInvalidStateException` → `KeyStateInvalid`; `KeyUnavailableException` and disconnected custom key stores (`CustomKeyStoreInvalidStateException` and the like) → `Unavailable`, since the key is fine but its HSM is unreachable. `IncorrectKeyException` (the blob names another key, e.g. after an alias was repointed) → `DecryptFailed` with the hint "alias repointed? route old ciphertexts with `EnvelopeKeyring`" | a disabled or destroyed **version** (`FAILED_PRECONDITION`) → the version-scoped kind (§20) | disabled key → `KeyStateInvalid` (*interim*: `PermissionDenied` until T3 pins the inner error code); disabled version → the version-scoped kind |
| Backend-specific options | native EncryptionContext maps, grant tokens: through the handle extension mechanism (downcast / `OpenOptions` extensions, §20) | — | — |
| `Mac` / `MessageSigner` input size | 4096 bytes for `GenerateMac` and `Sign` with `MessageType=RAW` (AWS API reference); conformance adds a 4 KiB + 1 case | 64 KiB, enforced locally before the request (HSM keys have lower limits the server enforces; `docs/operations-gcp.md` "Limits and quotas"); to confirm with T1 | — (digest-only signing) |
| Multi-region keys | no MRK-aware matching needed: configure one replica ARN per region under a shared logical `kek_id`, so `Decrypt` passes the local replica's ARN (§21) | — | — |

## 16. Review round 2: blocking issues and resolutions

Round 2 verdicts: Architect **SIGN-OFF**, Security **SIGN-OFF**. User, Domain,
Engineer and SRE each raised one or two blockers, resolved below. Most
non-blocking notes were adopted too: `ciphertext_version` on `Aead`, `kid`
format, retry-after > cap fails fast, `possible_replica_lag`, loopback literal
IPs, token-source logging, redacted-message definition, `signature_algorithm()`
/ `mac_algorithm()` rename, `Fixture: Send + Sync + 'static` with an async
constructor, hmac-only `mac_key`, `Tag::from_parts`, Appendix A corrections,
core freeze at the end of M1, shared describe cache, duplicate-scheme
rejection.

| # | Raised by | Issue | Resolution |
|---|---|---|---|
| 25 | User, Domain (Arch, Sec non-blocking) | `kek_id` was GCM-authenticated, so moving an envelope to another KEK required re-encrypting the payload | `kek_id` moved out of the GCM AAD into an unauthenticated key-wrapping slot with `wrapped_dek` (the commitment guards it); `rewrap_to`, `EnvelopeKeyring`; mismatch checked before any KMS call; never opened as a URI; test vectors (§5.1) |
| 26 | Engineer, User (Arch non-blocking) | `EnvelopeAead::rewrap` can't typecheck over `Arc<dyn DynAead>` (no `dyn A + B`, no specialization) | Concrete `AeadKey` composite in core returned by `Provider`/`Registry::aead`, implementing `Aead + Rewrap + DataKeys` with `Unsupported` for missing parts; `rewrap_local` fallback for any `K: Aead`; compile-time conformance case; §13 updated (§3.4, §5.1, §8) |
| 27 | SRE | `docker compose up -d --wait` exits 1 once the init containers finish | `scripts/dev-up.sh` (up `--wait` servers, then `run --rm` init), verified to exit 0; §9 and M0 exit updated |
| 28 | Domain, Sec (non-blocking, adopted) | Empty KEK AAD lets other code on the same KEK unwrap DEKs; error kinds on unwrap could act as an oracle | "KEK MUST be dedicated", policy snippet, rustdoc warning; all wrapped-DEK-dependent failures → `DecryptFailed` (§5.1) |

## 17. Review round 3: sign-off

All six reviewers (architect, Rust engineer, KMS domain expert, security, end
user, SRE) gave **SIGN-OFF** on v3. Their non-blocking notes were folded in:

- `AeadKey` is `#[non_exhaustive]`, with a public builder.
- The dyn macro forwards provided methods such as `ciphertext_version`.
- The reqwest `rustls-no-provider` setup is explicit.
- §13 uses a logical `kek_id`.
- A keyring negative vector and the commitment-scope note are in the format
  spec.
- The `envelope-format.md` review happens before the M3 freeze.
- `dev-up.sh` changes to the repo root.
- The sealed-service naming and the replica-lag retry cost are documented.

Items to confirm during implementation (tracked, not blocking):

- Azure MAC in Appendix A.
- The final `rsa` crate version.
- The wiremock MSRV under the MSRV CI job.

## 18. Implementation status

| Milestone | Status | Evidence |
|---|---|---|
| M0 | done | `compose.yaml` (shared servers, init, `sealed` and `tls` profiles), `scripts/dev-up.sh`, `.github/workflows/ci.yaml`, `deny.toml` (advisories, wildcards, scoped RUSTSEC-2023-0071 ignore) |
| M1 | done | `anykms-core`, `anykms-local`, recipes M1 part, `anykms-conformance`; local suite green with only *n/a* ignores (RSA, native ciphertext, credentials) |
| M2 | done | `anykms-transit`; suites green on Vault 1.20.4 and 2.1.1 (only *n/a*: disabled keys) and OpenBao 2.4.4 and 2.7.1 (no ignores); 17 mock-server cases; 8 integration cases (sealed, TLS ×2, upsert ×2, namespaces ×2, data-key AAD); TRACE hygiene test (encrypt/decrypt/datakey, sign/verify, HMAC, token file, 403 retry, transport errors, Backend fallbacks; `source()` chains walked) |
| M3 | done | `EnvelopeAead` v1 + `EnvelopeKeyring` + committed vectors + `docs/envelope-format.md`, `EmulatedDataKeys`, `CachedVerifier`, JOSE, `Retry`, `anykms` facade, three examples run against local and Vault |
| M4 | done | 9 fuzz targets, 1 CPU-hour each, all clean (runs: core_values 2.2 B, der_fixed 2.3 B, envelope_parse 3.7 B, envelope_roundtrip 72 M, key_uri 741 M, transit_uri 790 M, local_framing 3.4 B, pem_spki 776 M, transit_response 206 M; no artifacts; those runs had no seeds, so `envelope_parse` and the decode half of `core_values` never got past the format magic: committed seeds (`fuzz/seeds`, from `fuzz/examples/gen_seeds.rs`) and dictionaries (`fuzz/dicts`) now feed the nightly runs, and those two targets have not had a CPU-hour since); clippy/rustdoc `-D warnings`; MSRV 1.85 checked; README, operations guide, runbook; release-diff security review. Since then: 23 fuzz targets (`jose_verify` removed with JWS verification, §27); the cloud targets have not had a CPU-hour yet |
| M6 shared | done | `anykms-http`; conformance redesign C1–C9, published; `WrappedDataKeys`; layered extensions; `DataKeysKey`; recipes R1–R3 |
| AWS | implemented | `anykms-aws`; Floci emulated conformance on every PR, LocalStack when `LOCALSTACK_AUTH_TOKEN` is set; **A0 probe done** (2026-10-07); live conformance on real AWS passed: 340 cases, 0 failed, 108 *n/a* (§24) |
| GCP | implemented | `anykms-gcp`; conformance against an in-process fake Cloud KMS on every PR; T1 probe run 2026-10-12, live conformance green (§24) |
| Azure | implemented | `anykms-azure`: release A (Key Vault) and Managed HSM code; Lowkey Vault conformance on every PR; T3 probe run 2026-10-12, live conformance green, key states classified on the inner error code; T13 not run; HMAC experimental (`mhsm-hmac`) (§24) |

Deviations from the plan, each deliberate:

- **`Retry` lives in `anykms-core`** (module `retry`), not in the facade. It needs no runtime
  (caller-supplied `SleepFn`); the facade's `tokio` feature provides `tokio_sleep()` and
  `with_retry()`. (Superseded: §20 removed `with_retry`; the facade now provides
  `retry_layer()`, `tokio_sleep()` and `tokio_clock()`.)
- **`with_default_providers()`** is a free function in the facade returning a `RegistryBuilder`;
  an inherent `Registry::with_default_providers` cannot be added from another crate.
  (Superseded: it returns `DefaultProviders`, see below.)
- **`AeadKey` also carries an optional `Describe` part** (additive, as the plan allows).
- **Local fault injection** offers `Throttled`, `Unavailable` and `Timeout`, and can be scoped to
  one key (`inject_for_key`). Latency injection was left out because it would need a runtime
  dependency.
- **Transit upsert pinning** lives in a dedicated integration test, not in a second full suite
  run. Running the suite twice could not work: with upsert enabled, the generic `missing_key` case
  must fail. Implementation also found that **a token without `create` gets 403 even with
  `disable_upsert=true`**: the server's existence check demands `create` before the handler runs,
  so 400 "encryption key not found" only reaches tokens that hold `create`. The default key-type
  check reads `keys/<name>` first, so callers still see `NotFound`. All three behaviors are pinned
  and documented.
- **Ed25519 public keys** come from transit as raw base64, not PEM; the backend wraps them in
  SPKI.
- **Vault 2.x HMAC keys** require `key_size` at creation (fixture concern only).
- **API shapes that differ from the plan's sketches** (same behavior):
  - Token sources are structs (`StaticToken`, `FileToken`, `EnvToken`, `NoToken`) behind the
    object-safe `TokenSource` trait, plus `ServerConfig::token/token_file/token_env/no_token`;
    `token_source` takes `Arc<dyn TokenSource>`.
  - `encoding::{encode, decode}` became `encode_signature`/`decode_signature`/`encode_tag`/`decode_tag`.
  - `PublicKey::to_jwk(kid)`/`Jwks::from_versions` became `jose::to_jwk(&pk, kid, alg)` and
    `jose::jwks_from_versions(..)`, since `PublicKey` lives in core and JOSE in recipes.
  - `rewrap_to(&ct, &new_kek, new_kek_id)` became `rewrap_to(&ct, &EnvelopeAead<K2>)`: the target
    envelope carries the new KEK and `kek_id`.
  - `AeadKey::full` requires `Describe` too (all built-in AEAD handles implement it).
  - `Fixture::throttle() -> ThrottleGuard` became `throttle(&key)`/`unthrottle(&key)`; guards cannot
    run async cleanup on drop. After the 2026-10 review, every feature-gated `Fixture` method
    has a default ("not available") and versions are `&KeyVersion` (§8, §19).
- **`xchacha20-poly1305`** is accepted as an AEAD key type by the transit key-type check, in case a
  server offers it; it is an AEAD with the same contract.
- **"kek_id mismatch"** is the error's (fixed, non-secret) message, not a `BackendDetail`.
- **The replica-lag retry hint** is also set on a 404 from `GET keys/<name>`, because the key-type
  check reads metadata before the operation, so a just-created key surfaces there first.
- **Tracing scope.** Spans are per HTTP request (`anykms.transit`), not per logical operation; a
  handle's first use emits a separate span for the metadata read. Recorded fields: `op`, `backend`,
  `server_alias`, `mount`, `key`, `http_status`, `outcome`, `error_kind`, `attempt`, `latency_ms`;
  `key_version` is not recorded. `http_status` is recorded on every response, success included;
  after a 403 token refresh it is the final request's status. Every fallback to `Backend` emits a
  warn event: server error messages carry the redacted fingerprint; unusable success responses
  (undecodable, oversized) log only op, alias, status and reason, never a body fingerprint, because
  success bodies carry plaintext or key material. `Retry` emits one event per retry (core `tracing` feature,
  enabled by the facade's `tracing`).
- **Server versions are bumped manually.** The CI matrix, the `compose.yaml` defaults and
  `scripts/probe-failover.sh` pin exact tags and their image digests (since the 2026-10-04
  round, §20); Dependabot cannot update any of them (workflow matrix values, and
  `${VAR:-default}` interpolation), so bumping them, digest included, is a manual
  release-checklist step.
- **Hardening beyond the plan**, from the implementation reviews:
  - The transit key-type cache expires after 10 minutes and is dropped on `NotFound`,
    `InvalidArgument` or `Unsupported`. A signature whose shape does not fit the asserted algorithm
    (a key recreated with another type) is refused.
  - `CachedVerifier` entries expire after 5 minutes, and `invalidate()` drops them, so version
    revocation takes effect locally.
  - Malformed `warnings` fields fail closed. The token file is read with a bounded read. Proxy
    credentials are redacted from `Debug`. A failed token re-fetch after a 403 reports the original
    `PermissionDenied`.
  - `verify_jws` rejects `crit`. The envelope test vectors are built in the test from AES-GCM and HKDF
    directly; the crate exposes no deterministic-encryption hook.
    `RetryPolicy` values are sanitized. With `ANYKMS_FAIL_ON_SKIP=1` (CI), `skip` cases fail
    instead of being ignored.
- **Review round 4 (post-implementation audit) decisions:**
  - **`DataKey` is returned by value, not boxed.** Its plaintext is already a heap-allocated
    `Zeroizing<Vec<u8>>`, so moving a `DataKey` copies only pointers and lengths, never key bytes;
    boxing would change the `DataKeys` signature in every backend for no secrecy gain. It is
    `#[non_exhaustive]`, zeroized, without `Clone`/`Serialize`, with a redacting `Debug`.
  - **`Retry` defaults are 300 ms base and 6 attempts, with equal jitter** (the approved plan
    said 100 ms, 3 attempts, full jitter; §11 has since been updated). `scripts/probe-failover.sh` measured how long a leader change leaves
    a three-node raft cluster unable to serve data-plane requests: on Vault 1.20.4 and 2.1.1 about
    5 s (up to 5.97 s) after a third to a half of step-downs, on OpenBao 2.4.4 once in 15, on
    OpenBao 2.7.1 at most 0.78 s; 8–22 s when the active node dies (none on OpenBao 2.7.1). In
    those windows every node fails (standbys 307, the old active node 500), and no response carries
    `Retry-After`. The old defaults retried for at most 0.3 s, so routine rolling upgrades surfaced
    as errors. Full jitter cannot guarantee a minimum total wait, so each retry now waits between
    half and all of the exponential step; the 5 retries span 4.65–9.3 s, covering step-downs while
    staying under the 15 s deadline. Hard failovers are left to server raft tuning and caller
    policy (`docs/operations.md`, "Failover"). A `Retry-After` gets an extra random delay of up to
    `base`, so clients throttled together do not retry in lockstep.
  - **`Retry`'s deadline bounds the retry schedule, not an attempt in flight.** It is checked
    before each backoff sleep; being runtime-agnostic, `Retry` cannot cancel a running attempt, so
    the worst case is the deadline plus one attempt. Per-attempt bounds come from the HTTP client
    timeout; callers needing a hard limit wrap the call in their runtime's timeout. A Retry-After
    above the cap or past the deadline returns `Throttled` (original error as `source()`).
  - **`KeyVersion` is not `Ord`** (string order would put `"10"` before `"9"`).
  - **`Operation::Construct`** labels validation errors from building value types
    (`Digest::new`); callers can relabel with `Error::with_operation`.
  - **`marshaling_algorithm=asn1` is sent for ECDSA only**: it affects only ECDSA and is the server
    default; sending it elsewhere would break the §4 minimal-parameters rule.
  - **`public_keys` honours `key_type_check`**, but always reads `keys/:name` for the PEM, so it
    checks the key type even under `TrustCaller`, at no extra request.
  - **Transient 500s** are matched on specific phrases, not bare words; a 500 maps to
    `InvalidArgument` only for "JSON string value exceeds allowed length". `Retry-After` accepts
    delay-seconds or an HTTP-date.
  - **Failover verified.** `scripts/probe-failover.sh` runs a three-node raft cluster
    (`scripts/ha/compose.yaml`), sends every data-plane request to every node, and forces six
    step-downs and two killed leaders. On Vault 1.20.4 and 2.1.1 and OpenBao 2.4.4 and 2.7.1 the
    only non-200 responses were: no response, a 307 from a standby, 500 "local node not active but
    active cluster node not found", and 503 "Vault is sealed", all mapped to `Unavailable`
    (baselines in `scripts/failover-baseline/`). The hashicorp/raft phrases ("node is not the
    leader", "leadership lost while committing log", "leadership transfer in progress", "raft is
    already shutdown", "timed out enqueuing operation") never appeared, since data-plane requests
    only read storage; they stay in the transient list because each is transient by definition.
    The probe also showed that **OpenBao standbys answer from their own storage**: a key created
    milliseconds earlier can return 400 "encryption key not found" there, the replica-lag case,
    so the replica-lag retry (now `retry_on_hint`, §20) applies to OpenBao raft clusters too (`docs/operations.md`). The
    probe is timing-dependent, so it is not in CI; `record` adds to a baseline and `diff` fails
    only on responses the baseline lacks.
  - **OpenBao env precedence is per prefix:** `BAO_TOKEN`, `BAO_TOKEN_FILE`, `VAULT_TOKEN`,
    `VAULT_TOKEN_FILE`, `~/.bao-token`, `~/.vault-token`.
  - **HTTP/2 applies to `https://` only**; plain-HTTP loopback always uses HTTP/1.1.
  - **Request URLs** are built segment by segment (`path_segments_mut`), so segments are
    percent-encoded again as §3.5 asks.
  - **Transit integration tests** run on libtest-mimic like the conformance suite: with no server
    they are reported as ignored (`skip`), never as passed.
  - **`der_to_fixed(&sig)` (§14)** became `ecdsa_der::der_to_fixed(der, scalar_len)` and
    `ecdsa_der::signature_to_fixed(&sig)`; both accept `scalar_len` in `1..=66` and return
    `InvalidArgument` otherwise.
  - **`EnvelopeKeyring::with_kek` returns `InvalidArgument` on a duplicate `kek_id`** (it
    first panicked, to keep the builder chain infallible; it now matches `with_primary`). `new`
    builds the default `Arc<dyn DynKeyWrap>` keyring from any `IntoKek` (a `KeyWrapKey`, an
    `Arc` of a `KeyWrap`, an `AeadKeyWrap`; §20) without casts; AEAD keys only once adapted with
    `.into_key_wrap()` (superseded the implicit adaptation, review plan 1.3); `typed` builds a keyring of one concrete KEK type. The `kek_id` check also covers `ciphertext_version`; rewrap
    errors are labelled `Operation::Rewrap`.
  - **`jose::verify_jws`** is generic over `DigestVerifier + MessageVerifier + PinnedVerifier`
    (works with `LocalVerifier` and `CachedVerifier`, also behind `Arc` or `Retry`) and takes the
    algorithm from the verifier; `verify_jws_as` names it for unpinned verifiers. `PinnedVerifier`
    lives in core with explicit impls (no blanket impl over `DigestSigner`, which kept
    `Retry<CachedVerifier>` from being pinned); a `<name>.<version>` kid supplies the signature's key
    version (`jose::kid_version`). `jwks_from_versions` rejects a backend that returns a different
    version than requested.
  - **Conformance paths.** `typed::` cases open keys through each backend's typed constructors via
    `Fixture::typed()` and pass them through the `Arc<K>` → `dyn DynX` bridges; `registry::` cases
    go through a `Registry`. Refusing a digest algorithm on a message signer is asserted on the
    registry path only (the typed API cannot express it). `Fixture` also has `counting()` (request
    counter, `Feature::RequestCount`) and `secret_markers()`; `FixtureCaps` gained
    `ciphertext_versions` and `hmac_versions_listed` (transit lists no versions for HMAC keys).
  - **Zero requests** is asserted by `sign::<alg>::rejected_before_io` through a counting
    `TokenSource` on transit (*n/a* on local, which is in-process). A wrong-length digest cannot be
    built (`Digest::new` refuses it).
  - **Recipe vectors per backend:** the committed vectors are deterministic (fixed local KEK) and
    run in recipes' own tests; every backend instead runs `recipes::envelope::format`, which decodes
    its envelopes independently against `docs/envelope-format.md`.
  - **`LocalKeyset` typed accessors** need no runtime opt-in (the caller holds the keyset) but log
    the same ephemeral-key warning as every `LocalProvider` open.
  - **Fuzzing:** `pem_spki` asserts no panic, not "never verifies" (the fuzzer controls the key
    too). The `local:` parser accepts 20-digit versions (up to `u64::MAX`), matching what encryption
    can emit; the round-trip check in `local_framing` found that gap. The fuzz crate is checked on
    every PR and covered by Dependabot.
  - **Probe script:** `scripts/probe-transit.sh record|diff` keeps normalized baselines per server
    version in `scripts/probe-baseline/`; bumping a server version includes recording a new
    baseline and reviewing the diff, and running `scripts/probe-failover.sh diff` for the new
    version.
  - **Examples:** `field_encryption` rotates the KEK and calls `env.rewrap` with local keys; transit
    rotation needs an admin token, so against Vault it demonstrates rewrap without rotating.
- **Open item:** an external review of `docs/envelope-format.md` (§5.1 asks for one before long-lived
  data relies on the format). Only internal design and security reviews have happened so far.
- **`run_or_skip`** was added to the conformance harness. When no server is reachable, every
  case is reported as ignored with kind `skip` and the reason; `ANYKMS_REQUIRE_FIXTURE=1` (CI)
  makes that a failure.

Items tracked in §17, resolved:

- **`rsa` version:** `0.10.0-rc.18` (a caret requirement since §20, so later 0.10 RCs and
  0.10.0 resolve; the lock file pins rc.18), on the digest-0.11/signature-3 stack, so there is no
  duplicate RustCrypto tree. Used for public-key verification only; RUSTSEC-2023-0071 is ignored
  with that reason.
- **Dev-dependency MSRV:** wiremock 0.6.5 (let-chains) and jsonwebtoken 11.1.0 (`rust-version`
  1.88) need a compiler newer than 1.85. The MSRV job checks the published libraries (`--lib
  --locked`) and, with `--cfg anykms_msrv` (which drops jsonwebtoken, a
  `cfg(not(anykms_msrv))` dev-dependency, and `tests/jose_interop.rs`), runs every unit and
  integration test suite except transit's (whose dev-dependencies include wiremock) and every
  doctest except recipes' (the `jose` docs use jsonwebtoken) on 1.85. Examples are left to the
  stable jobs.
- **Azure MAC:** Managed HSM has HS256/384/512 (API 7.6+, §23); `anykms-azure` ships it behind
  the experimental `mhsm-hmac` feature until T13 pins message-vs-digest semantics.

Server versions verified: Vault 1.20.4 and 2.1.1, OpenBao 2.4.4 and 2.7.1.

## 19. Decisions from the 2026-10 review

An integrator review and a cloud-readiness review (AWS, GCP, Azure) after the
0.1 implementation. Breaking core changes landed before the first publish;
everything else is recorded here as a decision or a planned follow-up.

Core changes (all in `anykms-core`):

- **Opaque handles.** `Provider` and `Registry` return `AeadKey`,
  `DigestSignerKey`, `MessageSignerKey`, `DigestVerifierKey`,
  `MessageVerifierKey`, `MacKey`, `PublicKeysHandle` and `DescribeHandle`
  (renamed `PublicKeysKey` and `DescribeKey` in §20) instead of `Arc<dyn DynX>`. Each holds one required part plus optional parts
  (`with_*`/`supports_*`, `Unsupported` before I/O when missing) and the backend
  name (`AeadKey::new(backend, ..)`), so new optional parts are additive. The
  `DynX` traits are sealed.
- **`KeyWrap`.** The capability envelope encryption needs from a KEK, with a
  blanket impl for every `Aead` (empty AAD). It exists so non-AEAD KEKs (Azure
  RSA-OAEP and AES-KW, AWS and GCP asymmetric decrypt) can back envelopes.
  `EnvelopeAead`, `EnvelopeKeyring` and the rewrap helpers are generic over it;
  envelope format v1 and the committed vectors are unchanged.
- **Errors.** `ErrorKind::KeyMismatch` separates "this key cannot do that"
  (deployment) from `InvalidArgument` (input). `is_config_error()` and
  `is_caller_error()` classify every kind (see the table on `ErrorKind`);
  `Error::app` lets application code and fakes report through the same type;
  `Error` is `Clone`.
- **Key metadata.** `KeyInfo::state()` is `Option` (GCP keeps state per version
  only); `KeyVersionInfo` has accessors. `PublicKeys::public_key()` means the
  version the handle signs with: the primary version where one exists, the
  pinned version otherwise.
- **Retry.** `Retry-After` is a floor over the backoff; `RetryBudget` can be
  shared with `Retry::with_budget` (now `RetryLayer::with_budget`, §20);
  `instant_sleep()` for tests (§11).
- **Algorithm codes.** Storage codes of `SignatureAlgorithm`/`MacAlgorithm` are
  explicit per variant and pinned by a test, so adding variants never shifts
  them.

Decisions for the cloud backends:

- **AWS EncryptionContext.** The portable `Aead` keeps `aad: &[u8]`. The AWS
  backend maps the bytes to a single reserved context key (omitted when empty)
  and exposes native map contexts through a backend-specific extension trait on
  its handle, for interop with ciphertexts produced by other tools. The portable
  trait does **not** promise to decrypt foreign AWS ciphertexts made with
  arbitrary contexts. The backend docs state that the context appears in
  CloudTrail (so AAD must not be secret) and that `Encrypt` takes at most
  4 KiB of plaintext (larger data goes through `EnvelopeAead`). The `Aead`
  rustdoc notes per-backend size limits.
- **GCP versions.** Signing and MAC keys require versioned key URIs
  (`…/cryptoKeyVersions/n`), because GCP has no primary version for them;
  `public_key()` returns that version's key, and key-level `KeyInfo::state` is
  `None` (per-version states are in `versions()`).
- **GCP verification.** Cloud KMS has no verify operation. Cloud backends may
  depend on `anykms-recipes`, so the GCP backend provides verification with
  `LocalVerifier` and `Registry::digest_verifier` works for GCP keys (§2). The
  recipe's "Emulates / Enforced by" box is surfaced in the backend docs:
  verification runs locally.
- **Async credentials.** `Provider` construction stays synchronous (as is
  `Registry::build`). Cloud providers initialize SDK clients and credential
  chains lazily, on the first operation, so credential problems surface as the
  first operation's error (`PermissionDenied`, `Configuration` or
  `Unavailable`). Docs recommend a startup `describe()` on each handle to fail
  fast.
- **No retries in backends.** Backends must not retry internally (SDK retries
  are turned off); the only exception is one retry after refreshing rejected
  credentials. All retrying lives in `Retry` with a shareable `RetryBudget`,
  so attempts never multiply (documented on `Provider`).
- **wasm.** `Retry` measures time with `std::time::Instant`, so the
  "runtime-agnostic" claim for core, recipes and local excludes
  `wasm32-unknown-unknown` (README). (Updated after §20: `Retry` takes an
  injected clock, but `CachedVerifier` reads `Instant` directly, JWT signing
  reads `SystemTime` unless `JwtOptions::with_now` is set, local keysets read
  `SystemTime`, and `getrandom` needs its `wasm_js` feature there, so the
  target stays only partly supported; the README lists what works.)
- **Operations.** `docs/operations.md` tells operators to remove retired KEKs
  from an `EnvelopeKeyring` promptly: every KEK in the ring is trusted for
  decryption, and anyone with encrypt rights on a retired KEK can forge
  envelopes the service accepts.

Planned follow-ups, all non-breaking now that the enums are
`#[non_exhaustive]`, the codes explicit and the handles have optional parts:

- wrapped-only data keys (transit `datakey/wrapped`, AWS
  `GenerateDataKeyWithoutPlaintext`) as a separate capability;
- an `Unauthenticated` error kind to separate 401 (bad or expired credentials)
  from 403 (policy);
- gRPC status codes and AWS exception names as `BackendDetail` fields;
- secp256k1 signatures and HMAC-SHA224;
- a `Provider::key_wrap()` open method (and a `KeyWrapKey` handle) for non-AEAD
  KEKs. `Provider` has none yet; adding it later is non-breaking because every
  provider method defaults to `Unsupported`. (Added in §20, together with
  `Registry::key_wrap`.)

Known constraint: the `KeyWrap` blanket impl for every `T: Aead` makes
`impl<T: KeyWrap> KeyWrap for Retry<T>` (or `Arc<T>`, or any generic decorator)
overlap with it, so decorators reach non-AEAD wrappers only through their `Aead`
impl, and an AEAD key cannot offer a native key-wrap operation instead of
`encrypt` with empty AAD. The plan is dedicated wrapper types (`RetryKeyWrap<T>`
and the like) for non-AEAD wrappers when the first one ships, added
non-breakingly next to the existing decorators; dropping the blanket impl would
be breaking and is not planned. (Superseded in §20: the blanket impl was dropped
before the first publish, in favour of the explicit `AeadKeyWrap` adapter.)

Done alongside (outside core):

- **Conformance.** `Fixture` methods beyond the required six default to "not
  available" and take `&KeyVersion`; `Support` and `DataKeyAad` are
  `#[non_exhaustive]`. Cloud fixtures implement only what their service can do
  (no throttling, no minimum decryption version) and declare the rest
  `not_applicable`. A new `sign::<alg>::malformed` case pins
  `VerificationFailed` for garbage and truncated-DER signatures, on the backend
  and the local verifier.
- **Facade and docs.** The README has a quick start without Vault (`local`
  feature); the examples need only `--features local`; the facade's `tokio`
  feature enables tokio's `time` only; docs build warning-free with default
  features, and every crate sets `[package.metadata.docs.rs] all-features`.
- **CI.** `cargo-semver-checks` for every published crate, a per-crate
  `--no-default-features` check, and a default-features docs build for the
  facade (§9).

## 20. Decisions from the second review round (2026-10-04)

A second integrator, security and cloud-readiness pass over the 0.1 code. All
accepted changes, at a high level:

- **Core extension points.** Opaque handles keep the backend's concrete key
  (`with_concrete`, set by `full`): `downcast_ref::<TransitAeadKey>()` /
  `downcast_arc` reach backend-specific APIs (bypassing layers).
  `OpenOptions::with_extension` / `extension` carry typed backend options (AWS
  context maps, grant tokens) with no new portable methods; `OpenOptions` is
  therefore no longer `PartialEq`. `BackendDetail::{request_id, code}` (AWS
  exception name, gRPC status, Azure error code) make the "planned" row in
  Appendix A the design. Vault and OpenBao send no request id on error
  responses (verified live), so transit never sets `request_id`.
- **Layers.** The `Layer` trait decorates every part of an opaque handle and
  keeps its type and optional parts (`handle.layer(&l)`,
  `handle.with_retry(&retry_layer)` (superseded: removed later in this
  section, "One retry entry point"), `RegistryBuilder::layer`); the sealed
  `OpaqueHandle` trait names the handle types. `RetryLayer` bundles policy,
  sleep, clock and one shared budget. `ClockFn` makes the retry clock
  injectable (`std_clock` default; the facade's `tokio_clock` follows paused
  tokio time); `RetryPolicy::immediate()` retries without delays in tests. The
  hinted retry (below) is an ordinary attempt (counts towards `max_attempts`).
  Signer handles (`DigestSignerKey`, `MessageSignerKey`) carry an optional
  verifier part (`with_verifier`, `supports_verifier`, `full_with_verifier`;
  superseded: `full_with_verifier` was folded into `full`, "Usability fixes"
  below).
- **Registry ergonomics.** Open methods take `impl IntoKeyUri` (`&str`,
  `String`, `KeyUri`) with default options; `*_with(uri, &opts)` take
  `OpenOptions`. Open errors carry the URI as the resource; an unknown scheme
  lists the registered ones.
- **Version-scoped key state.** `ErrorKind::KeyVersionUnusable` separates "this
  version is below the minimum, disabled or destroyed" (transit "too old",
  local min-version, GCP/Azure versions) from key-level `KeyStateInvalid`. It
  is a caller error: one row of data needs a rewrap, the key is fine.
- **Decrypt variants.** `Aead::decrypt_with_info` returns `Decrypted` (plaintext,
  version, `used_primary`: the only staleness signal GCP offers;
  `ciphertext_version` stays `None` there); no built-in backend sets
  `used_primary` yet. `Aead::decrypt_utf8` returns a `Zeroizing<String>`
  without an unzeroized copy. `Ciphertext::to_base64` / `from_base64` (and
  `_url`) for text columns.
- **Types and traits.** `Capabilities::KEY_WRAP` and `ASYMMETRIC_DECRYPT` (for
  RSA-OAEP and AES key wrap on cloud KMSs; `ASYMMETRIC_DECRYPT` was removed again
  and `KEY_WRAP` redefined, see "Capability bits" below), `KeyInfo::mac_algorithm`, and
  forwarding impls of every capability trait for `&T` and `Box<T>`.
- **Errors.** `Error::with_resource` names the resource; `Display` is
  `<backend> <op> [<resource>]: <kind>: <message>`. Transit labels every
  handle error with `<scheme>://<alias>/<mount>/keys/<name>` (plus the
  namespace), never a query string or token. `Error::new(kind, backend, op,
  msg)` is the constructor for backends and recipes; `Error::app` and the
  shorthands `Error::invalid_argument` / `unsupported` / `key_mismatch` are
  application errors (backend `"app"`). `Operation::ParseUri` for URI syntax
  errors; `ServerMessage::redacted`.
- **Transit.** rustls crypto provider per server, first of:
  `ServerConfig::crypto_provider`, the process default
  (`CryptoProvider::install_default`), aws-lc-rs (`rustls-aws-lc-rs`), ring
  (`rustls-ring`, default); else `Configuration`. The installed default wins
  over the features so that an application's FIPS provider is not silently
  replaced by the facade's default `rustls-ring` (review plan 1.2). Rejected
  server or client certificates are `Configuration` (not retried); DNS failures
  stay `Unavailable` with "DNS lookup failed". Request bodies are sized up front
  in zeroizing buffers that grow into fresh zeroizing buffers; response
  capacity trusts `Content-Length` only up to 64 KiB and never grows past
  `max_response_bytes`. `EnvConfig`: `*_CAPATH`, every setting from the prefix
  that supplied the address (no `VAULT_*`/`BAO_*` mixing), a missing token
  source fails at load unless `no_token()` / `ANYKMS_TRANSIT_NO_TOKEN=1` (renamed from
  `ANYKMS_NO_TOKEN`, §25.3). `FileToken`
  checks permissions with `fstat` on the opened file and re-reads on a changed
  mtime, size or inode (an in-place rewrite keeping both is caught by the
  403 re-read). File errors name path and reason, never contents. The facade's
  `with_default_providers()` returns `DefaultProviders` (`skipped()`, `layer`),
  and opening a skipped provider's scheme fails with the skip reason.
- **Recipes.** Algorithm pinning is mandatory: `LocalVerifier::new(pk, alg)`,
  `LocalVerifier::for_key(pk)` (ECDSA, Ed25519), `CachedVerifier::new(src,
  alg)`; another algorithm is `InvalidArgument` before any cryptography or
  lookup (conformance `recipes::algorithm_pinning::<alg>`). RSA verification
  backends `rsa` (default) and `aws-lc-rs` (wins when both are on; neither:
  `Unsupported`), facade `rsa-rustcrypto` / `rsa-aws-lc-rs`; ring cannot verify
  RSA prehashed digests. `CachedVerifier` caches lag-flagged lookup failures
  only briefly (min of negative TTL and refresh interval), drops its cache when
  the latest version decreases or a version's key changes (deleted and
  recreated keys) and re-checks once when a cached key fails. JOSE rejects
  `b64` and unencoded payloads and duplicate header/claim members, accepts
  `Ed25519` next to `EdDSA`, adds `JwtValidation::with_typ`, `JwtSigner` /
  `sign_jwt` with `JwtOptions`, `verify_jwt_as` for typed claims, and
  re-exports `serde_json`. Envelope `kek_id` length is checked at construction
  and mismatch errors name both ids.
- **Declined: inferring a signer's algorithm at open.** Opening does no I/O
  (§3.3), and an RSA key admits several algorithms, so the algorithm stays an
  `OpenOptions` input (`with_signature_algorithm`) rather than being read from
  the key.
- **Appendix A corrections.** AWS `Decrypt`/`ReEncrypt` always pass the
  handle's `KeyId`, and `KeyUnavailableException` / disconnected custom key
  stores map to `Unavailable`. GCP ciphertexts are opaque (no embedded-version
  claim), request CRC32Cs are sent and `verified_*_crc32c` confirmed. Azure
  MHSM AES-GCM framing carries the IV and tag.
- **Local backend.** Public keys follow the same usability rules as transit:
  a version below the minimum decryption version is `NotFound` and `describe`
  no longer lists it; a disabled key refuses public-key reads
  (`KeyStateInvalid`), as cloud KMSs do. New conformance cases
  `sign::<alg>::min_decryption_version` and `sign::<alg>::disabled_key` pin
  this on every backend; they found that OpenBao answers sign/verify on a
  soft-deleted key with HTTP 500 (now `KeyStateInvalid`) and still lists its
  public keys (transit now refuses them). A `MacAlgorithm` local keys do not
  implement is `Unsupported` (at open through `LocalProvider`), never a
  panic.
- **Local opens stay lazy.** `LocalProvider` could check at open that the key
  exists, but does not: opening does no I/O on any backend (§3.3), the
  `errors::missing_key` case requires a missing key to fail on first use, and
  tests written against local keys should fail where production code will. A
  key may also be inserted after its handle was opened.
- **Fuzzing.** Two more targets: `jose_verify` (compact JWS parsing and JWT
  claim checks, behind a stand-in verifier) and `transit_success` (decoding of
  encrypt/decrypt/datakey/sign/verify/hmac success bodies through a hidden
  transit hook), with seeds from `fuzz/examples/gen_seeds.rs`, in the nightly
  matrix.
- **Supply chain.** Server images in `compose.yaml`, the CI matrix and
  `scripts/probe-failover.sh` are pinned by digest as well as tag;
  `VAULT_IMAGE` / `OPENBAO_IMAGE` replace the tag-only `*_VERSION` variables
  (a digest wins over a tag, so overriding only the tag would silently run the
  default version).
- **JOSE trimmed to the KMS-specific parts.** `JwtValidation`, `VerifiedJwt`,
  `verify_jwt` and `verify_jwt_as` are removed: claim validation (`exp`, `nbf`,
  `iss`, `aud`, `typ`, leeway) is generic token logic that `jsonwebtoken`
  already does well, and owning it here only added security-relevant API
  surface. `jose` keeps kids, JWK/JWKS publishing, JWS/JWT signing and
  signature-only `verify_jws` / `verify_jws_for_key` (alg pinning, unique
  header members, `crit`/`b64` rejection). Relying parties verify tokens with
  `jsonwebtoken` against the published JWKS (`JwkSet::find(kid)`,
  `DecodingKey::from_jwk`, `Validation`); tokens signed on Vault transit were
  checked to verify for ES256, ES384, RS256/384/512, PS256/384/512 and EdDSA,
  and `tests/jose_interop.rs` pins this on local keys. jsonwebtoken has no
  ES512. `JwsHeader::new` no longer defaults `typ` to `"JWT"`: a JWS is not
  necessarily a JWT, and the default labelled arbitrary signed documents as
  JWTs (type confusion). `JwtSigner` / `sign_jwt` still set `typ: "JWT"` (and,
  since the [release plan](release-plan.md) D2, refuse a token without `exp`
  unless `JwtOptions::without_expiry()` is set). The
  `jose_verify` fuzz target now covers JWS parsing only (input `[alg, flags,
  jws]`).
- **Algorithms are open parameters, not options.** `Registry::digest_signer`,
  `digest_verifier`, `message_signer`, `message_verifier` and `public_keys`
  take a `SignatureAlgorithm`, and `mac` a `MacAlgorithm` (`*_with` adds
  `&OpenOptions`); so do the `Provider` methods. `OpenOptions` loses
  `signature_algorithm` / `mac_algorithm` and `require_*`: the option-free
  forms used to exist and always fail at runtime. `OpenOptions` keeps the
  key-type check and backend extensions.
- **One retry entry point per handle kind; retries never nest.** A
  `RetryLayer` is the only configuration. Registries and opaque handles take it
  as a `Layer` (`RegistryBuilder::layer`, `key.layer(&retry)`); anything else
  goes through `RetryLayer::call` (the typed `Retry<T>` decorator was removed on 2026-11-02).
  `Handle::with_retry`, `anykms::with_retry`, `anykms::tokio_retry`,
  `Retry::new` / `with_policy` / `with_budget` / `with_clock` are removed. A
  handle records that a retrying layer (`Layer::retries`) was applied and
  skips later ones, so the README's former registry layer plus `with_retry`
  (6 attempts each, up to 36 with two budgets) can no longer happen.
- **Every error is in exactly one class.** `Backend` (unclassified server
  error, unusable response, internal failure) is a config error: an operator
  has to look at it, known transient server errors are already `Unavailable`,
  and it does not depend on the input. `Error::is_config_error` /
  `is_caller_error` classify `KeyVersionUnusable` by operation (*superseded by §25.2, A3: the
  class depends on the kind alone*): from encrypt,
  data-key generation, sign or MAC it is a config error (the write version,
  e.g. a pinned GCP/Azure version, is disabled); from decrypt, rewrap, verify
  it stays a caller error (old data). The `ErrorKind` methods give the kind's
  class alone. `Ciphertext::from_base64` / `from_base64_url` fail with
  `DecryptFailed` (operation `Decrypt`), so a corrupt stored ciphertext needs
  no special case next to a tampered one.
- **Base64 for signatures and tags.** `Signature` and `Tag` gain
  `to_base64` / `from_base64` (and `_url`), over the canonical `encoding`
  format so the algorithm and key version survive. `encode_signature` /
  `encode_tag` stay fallible (so `to_base64` returns `Result`): the v1 length
  byte cannot hold a key version over 255 bytes, `KeyVersion` is an open
  string, and no backend issues such versions, so failing beats panicking or
  truncating. Decoding failures (and bad base64) are `VerificationFailed`, as
  for a malformed signature from a backend, so a corrupt stored value is
  handled like a forged one. Opaque handles document that they are cheap to
  clone (no `Arc` needed).
- **A backend-neutral retry hint replaces the replica-lag flag.**
  `BackendDetail::possible_replica_lag` and `RetryPolicy::retry_on_replica_lag` /
  `replica_lag_delay` named a Vault/transit condition in core. Now
  `Error::with_retry_hint(delay)` / `retry_hint()` says "this error's kind is
  not retryable, but it is often transient: retry once after at least `delay`",
  and `RetryPolicy::retry_on_hint` (default off, `with_retry_on_hint`) opts in.
  The backend owns the delay (it knows the condition), the policy only decides
  whether to act. The hinted retry is handled like a `Retry-After` of the hint:
  it waits at least the hint and never less than the normal backoff (plus the
  same random spread), values above one day count as one day, and a hint above
  `cap` or one whose wait would pass the deadline is not honored. Unlike an
  unhonorable `Retry-After` the error is then returned unchanged, not turned
  into `Throttled`: it was never retryable. It happens once per call, counts
  towards `max_attempts`, spends a budget token, and is ignored on retryable
  kinds (their backoff and `Retry-After` apply). Transit hints 500 ms (the
  former default delay) wherever it flagged lag; `CachedVerifier` hints its
  refresh interval on version-ceiling rejections (so the retry re-reads the
  latest version, with no coupling to a policy setting) and remembers hinted
  lookup failures for at most the hint; errors remapped by transit verify and
  envelope unwrap keep the hint. The same shape fits a GCP key version still in
  `PENDING_GENERATION`.
  `RetryPolicy::immediate()` has a zero cap, so it honors only zero hints, as it
  already failed fast on any non-zero `Retry-After`.
- **`BackendDetail::server_alias` removed.** It was transit's URI authority, and
  every transit error already names it in its resource
  (`<scheme>://<alias>/<mount>/keys/<name>`) and in the tracing span's
  `server_alias` field, so the core field only duplicated it. A generic
  endpoint label was considered and deferred: no planned backend sends one
  key's requests to several endpoints yet (the cloud backends' region or vault
  host is part of the resource), and `BackendDetail` is `#[non_exhaustive]`,
  so the field can be added without a breaking change when one does.
- **`rsa` requirement relaxed.** The workspace asked for `=0.10.0-rc.18`; it now
  asks for `0.10.0-rc.18` (caret), still the default RSA backend. An exact pin
  in a library forces every application onto that one RC and fails resolution
  as soon as another dependency needs a later 0.10 RC or 0.10.0. `Cargo.lock`
  still resolves rc.18 and `cargo deny check` passes. The trade-off: RCs may
  break their API, so an application that resolves a later RC can fail to
  build until anykms adapts (or pins `rsa` itself with `cargo update
  --precise`).
- **Sibling crates are caret requirements.** The workspace asked for `=0.1.0`
  of each anykms crate; it now asks for `0.1.0`. An exact pin would stop a
  third-party backend built on `anykms-core` 0.1.x from resolving next to an
  anykms that has taken a later core patch release. Patch releases stay
  compatible (`cargo-semver-checks` in CI).
- **Layers have a required catch-all.** `Layer::part(&self, cx: &LayerCx<'_>,
  part: Part<'_>)` is the one required method. `LayerCx` (`#[non_exhaustive]`)
  names the handle's backend and key (`resource`), so layers can label per key;
  it can gain fields without a breaking change. `Part` is a `#[non_exhaustive]` enum of slots
  (`Part::Aead(&mut Arc<dyn DynAead>)`, ..., `Part::KeyWrap(..)`) with
  `kind() -> PartKind`, so a layer can only put back a part of the same kind
  (`*p = Arc::new(Decorator(p.clone()))`, no runtime check needed), and leaves a
  slot untouched to pass the part through. The per-part methods (`aead`,
  `rewrap`, ..., `key_wrap`) stay as overridable defaults that call `part`; parts
  added later get such a default too, so they reach every third-party layer
  (metrics, auth) through its catch-all arm instead of a silent pass-through
  default. A generic method over a sealed part trait was rejected: it would make
  `Layer` not object-safe, and `&dyn Layer` is how handles and registries hold
  layers. `RetryLayer` matches `Part` exhaustively inside core, so a new part
  does not compile until it is retried. `retries()` and the no-nesting rule are
  unchanged; `supports_*` stays truthful because a layer only sees parts the
  handle has.
- **`KeyWrap` is explicit; no blanket impl for `Aead`.** `impl<T: Aead> KeyWrap
  for T` is gone (breaking, before the first publish): it blocked generic
  decorators (`Retry<T: KeyWrap>`, `Arc<T>`) and stopped an AEAD key from also
  offering a native wrap operation (Azure MHSM). An AEAD key becomes a KEK with
  `AeadKeyWrap::new(key)` / `key.into_key_wrap()` (a provided `Aead` method;
  `(&key).into_key_wrap()` lends it), which wraps with empty AAD and forwards
  `Rewrap` and `Describe`. `DynKeyWrap` now comes from the same macro as the
  other parts (bridges for `dyn`, `Arc`, `Box`, `&`), and `Retry` implements
  `KeyWrap`. `KeyWrapKey` is the opaque handle (`KeyWrap` plus optional
  `Rewrap` and `Describe`; `KeyWrapKey::from_aead` / `From<AeadKey>` keep an AEAD
  handle's parts, concrete key and retry state), opened by `Provider::key_wrap`
  (default `Unsupported`) and `Registry::key_wrap` / `key_wrap_with`. Transit and
  local implement it as `self.aead(uri, opts).map(KeyWrapKey::from_aead)`.
  Envelope users write `EnvelopeAead::new(registry.key_wrap(uri)?)`, or
  `EnvelopeAead::new(key.into_key_wrap())` for a typed or already-opened AEAD
  key. *Superseded (review plan 1.3):* `EnvelopeKeyring` follows the same rule;
  `IntoKek` covers `Arc<T: KeyWrap>`, `AeadKeyWrap<T>` and `KeyWrapKey`, and an
  AEAD key joins a keyring only as `key.into_key_wrap()`. The earlier implicit
  impls for `Arc<T: Aead>`, `Arc<dyn DynAead>` and `AeadKey` were removed: they
  hid the dedicated-KEK requirement and accepted an `Arc<EnvelopeAead<_>>` as a
  KEK.
  `EmulatedDataKeys` stays over `Aead` (it binds AAD, which `KeyWrap` has no
  slot for). Envelope format v1 and the vectors are unchanged.
- **Capability bits.** `ASYMMETRIC_DECRYPT` is removed: no trait, handle or
  `Provider` method opens such keys, so nothing could report it truthfully;
  re-adding it with the capability is non-breaking. `KEY_WRAP` stays, redefined
  as "opens as a `KeyWrapKey`" (natively or through `AeadKeyWrap`): transit and
  local AEAD keys report `AEAD | REWRAP | DATA_KEYS | KEY_WRAP`, and
  `describe::aead_key` checks on every backend that the bit is set exactly when
  `key_wrap` opens the key and a wrap/unwrap round trip works. The envelope
  conformance cases open their KEKs with `key_wrap` (and compare the wrapped key
  with an empty-AAD encrypt under the AEAD handle), so the case count is
  unchanged.
- **Recipes split by Cargo features, not crates.** `anykms-recipes` has `jose`
  (the `jose` module and the `serde_json` re-export; pulls in serde and
  serde_json) and `envelope` (`envelope`, `Envelope`, `EnvelopeAead`,
  `EnvelopeKeyring`, `IntoKek`; pulls in AES-GCM, HKDF, SHA-2 and subtle), both
  default next to `rsa`. Local verification (`LocalVerifier`, `CachedVerifier`,
  the hashed helpers, `ecdsa_der`, every curve) is always compiled: a backend
  that needs only to verify locally (GCP) depends on the crate with
  `default-features = false`. `EmulatedDataKeys` is ungated too: it needs only
  an `Aead`, the OS RNG and `zeroize` (no envelope format, no extra
  dependency), and backends without native data keys (GCP) are its users. A
  separate verification crate was rejected: one more crate to publish and
  version for what features already express. `sha2` is optional (`envelope`
  and `rsa` enable it). The facade's `recipes` feature enables both features,
  so facade users see no change; picking them one by one means depending on
  `anykms-recipes` directly. The RSA backend stays independent: the workspace
  imports the crate with `default-features = false`, and with neither `rsa`
  nor `aws-lc-rs` RSA verification fails at run time with `Unsupported`
  (documented on the crate; unchanged). CI clippies each feature alone.
- **Usability fixes after the round.** `EnvelopeAead::new` requires `K:
  KeyWrap`, and `KeyWrap` carries `#[diagnostic::on_unimplemented]`, so
  `EnvelopeAead::new(registry.aead(uri)?)` fails at the call (E0277, pointing
  to `registry.key_wrap(uri)` and `.into_key_wrap()`) instead of at the first
  `encrypt` inside macro-generated code. A KEK's `Rewrap` (`KeyWrapKey`,
  `AeadKeyWrap`) rewraps wrapped keys with empty AAD only; other AAD is
  `InvalidArgument` before any I/O, so a KEK opened from an AEAD key cannot
  rewrap that key's ordinary ciphertexts. `full` is bounded by every part of
  its handle (signers now need their verifier) and `full_with_verifier` is
  gone; a key lacking a part uses `new` plus `with_*`, and the bounds grow with
  new parts in 0.x. Handle names follow `<Trait>Key`: `PublicKeysHandle` is
  now `PublicKeysKey` and `DescribeHandle` is `DescribeKey`.
  `JwtSigner::jwks` / `jwks_message` publish the JWKS under the signer's key
  name and algorithm. The typed methods of `LocalProvider` and
  `TransitProvider` (`aead_key`, ...) take `impl IntoKeyUri` like the
  registry.

## 21. Decisions from the multi-agent review (2026-10-05)

The full review and its second pass are in `docs/review-plan.md`. Phase 0 of that plan
(decisions that fix wire formats or trait contracts) is recorded here.

- **Envelope v2 shape (0.1).** v1 keeps exactly one wrapped-key slot. v2 will carry **N
  wrapped-key slots and streaming frames together**, so one DEK can be wrapped under several KEKs
  (cross-region or break-glass recovery, as in the AWS Encryption SDK). Flag bits are reserved for
  this in `envelope-format.md`. Adopting the AWS Encryption SDK message format wholesale was
  rejected (AWS-centric, signature suites and a header-stored context); an ESDK-compatible
  *reader* stays possible later.
- **External envelope review (0.2).** A release gate for promoting 0.1 for long-lived data (M4
  exit criteria). The format stays frozen; the review can only add constraints to v2 or reject v1
  for new data.
- **AWS AAD encoding (0.3).** Unpadded base64url of the AAD bytes under one reserved
  encryption-context key, size-checked before the request (Appendix A). *Superseded by the
  release plan D1: Tink's `{"associatedData": lowercase_hex(aad)}`.*
- **Input size limits (0.4).** `Mac` and `MessageSigner` document that backends cap raw input
  (AWS: 4096 bytes). Portable code hashes large inputs (`sign_message_hashed`) or uses
  `EnvelopeAead`.
- **PQC (0.5).** A separate `MuSigner` trait, §12.
- **Public dependencies (0.6).** `rustls 0.23` (re-exported by `anykms-transit`) and `zeroize 1`
  (re-exported by `anykms-core`) are semver-coupled: a major bump of either is a breaking anykms
  release. While on 0.x, adding a part to an opaque handle breaks backends that call `full`
  (its bounds name every part). (Superseded by §22: `full`'s bounds are frozen.)
- **Cloud backend notes (roadmap 4.5–4.7).** Recorded in Appendix A: AWS resolved key ARN as
  `KeyVersion` for asymmetric and HMAC keys, `IncorrectKeyException` → `DecryptFailed` with a
  keyring hint, the multi-region-key pattern (one replica ARN per region, shared logical
  `kek_id`; no MRK-aware matching), a 4 KiB + 1 conformance case; Azure `KeyWrap`-based data keys
  on standard vaults, a host allowlist covering Managed HSM and sovereign clouds, `nbf`/`exp` →
  `KeyStateInvalid`, and preview status for Premium oct-HSM; GCP opt-in newest-enabled-version
  resolution for signing keys. A backend that relies on `LocalVerifier` (GCP) depends on an RSA
  feature of `anykms-recipes` explicitly, so RSA verification cannot fail at run time.
- **Algorithms (4.8).** secp256k1 and HMAC-SHA224 remain planned and additive
  (`#[non_exhaustive]` enums); transit has neither, so they arrive with the cloud backends.
- **wasm (4.10).** A non-`Send` trait variant (`trait_variant` local variant) is added only if a
  browser-fetch backend is pursued; until then every trait future is `Send`.
- **API-stability guard (1.8).** Already in place: CI job `semver` (`.github/workflows/ci.yaml`)
  runs `cargo-semver-checks` on every pull request against the PR's base branch until 0.1.0 is
  published, then against crates.io (§2 conventions). The review missed it. Breaking changes
  made deliberately before 0.1 (review plan Phase 1) show up there as expected failures.

## 22. Release-readiness decisions for 0.1 (2026-10-05)

From a multi-agent release review (architecture, security, KMS domain, integration UX, build and
packaging).

- **Default RSA backend: aws-lc-rs.** `anykms-recipes`' default feature is `aws-lc-rs`, the
  facade's is `rsa-aws-lc-rs`; RustCrypto `rsa` (a 0.10 release candidate, whose RCs may break
  their API) is opt-in, so no default build depends on a pre-release crate. aws-lc-rs still wins
  when both are on. The default TLS provider stays ring (`rustls-ring`), so `transit` with default
  features compiles both ring and aws-lc; switching TLS to aws-lc-rs too is open. *Superseded by
  §25.3 (C2): the default TLS provider is aws-lc-rs; ring is opt-in.* *Renamed by the release plan
  1.5 (R-7): the recipes features are `rsa-aws-lc-rs` and `rsa-rustcrypto`, as on the facade.*
- **`EnvelopeAead::new(kek_id, kek) -> Result`.** `with_kek_id` is gone; the `kek_id` is chosen
  explicitly (empty is still allowed), and a `kek_id` over 255 bytes is `InvalidArgument` on
  `Configure` in `EnvelopeAead::new`, `EnvelopeKeyring::new` and `::typed` instead of a panic.
- **Version accessors.** `PublicKey::key_version` and `Decrypted::key_version` (were `version`),
  matching `Signature` and `Tag`. `KeyVersionInfo::version` keeps its name.
- **Configuration parsing.** `FromStr` for `SignatureAlgorithm` (stable names and JOSE `alg`
  values) and `MacAlgorithm`; with `serde`, both and `KeyUri` (de)serialize as strings.
- **`full` is frozen.** The bounds of every opaque handle's `full` are the parts of 0.1. A part
  added later (native `KeyWrap` on AEAD handles, wrapped-only data keys, ...) is never set by
  `full`; backends add it with `with_*`. A compile-time test (`full_bounds_are_frozen` in
  `anykms-core/src/dynamic.rs`) fails if a bound is added. Each new part also needs a `Layer`
  method with a default, which `RetryLayer` and the observe layer override.
- **`anykms-conformance` is not published in 0.1** (*superseded: the redesigned suite is
  published, §24 and §25*; `publish = false`; the backends depend on it
  by path, and their conformance and integration test targets are excluded from their packages).
  Third-party backends cannot run the suite until it is published.

### Deferred: conformance suite capability redesign (with the AWS backend)

**Status:** done (tasks C1–C9 of `docs/cloud/shared.md` §8, with C8 of `docs/cloud/README.md`
§2.3); the suite is published. Where the implementation differs from the design below,
`docs/cloud/shared.md` §1.6 records it.

The fixture API assumes a transit-shaped backend: `aead::*`, `rewrap::*`, `datakeys::*` and
`describe::hmac_key` always run; `TypedHandles::aead` and `mac_key` are required; `bridge_aead`
requires `Aead + Rewrap + DataKeys + Describe`; there is no `TestKeyKind::KeyWrap`; and a feature
a fixture does not declare is silently skipped. GCP (no `Rewrap`, no `DataKeys`) and Azure
standard vaults (no `Aead`, no `Mac`) cannot pass without `Unsupported` stubs, which breaks the
rule that a handle implements exactly what its key supports.

**When:** together with the AWS backend, the first cloud backend, and before publishing the crate.
AWS itself has every transit capability, so it does not force the gating, but it brings the first
new parts (RSA `Decrypt` keys as native `KeyWrap`, `GenerateDataKeyWithoutPlaintext`) and the
layered extension hook (native encryption-context maps), which the suite must cover; the redesign
must be done before GCP or Azure in any case. Prove it with GCP-shaped and Azure-shaped proof
fixtures over the local backend.

**Design (about 1–1.5 days):**

1. *Capabilities.* New `Feature` variants `Aead`, `Rewrap`, `DataKeys`, `Mac`, `Describe`,
   `KeyWrap` (the enum is `#[non_exhaustive]`). `RewrapWithAad` and `FixtureCaps::datakey_aad`
   are read only when `Rewrap` / `DataKeys` is supported. A `supports_all(&[Feature])` helper.
2. *Undeclared fails.* `Support::Undeclared` for anything a fixture did not declare; a case
   gated on it fails (whatever `ANYKMS_FAIL_ON_SKIP` says) with "declare Feature::X", and a
   summary trial `conformance::declarations` lists every undeclared feature. A capability added
   later then fails third-party fixtures loudly instead of dropping coverage.
3. *`TypedHandles`.* `aead`, `mac_key`, `digest_key` and `message_key` default to `Unsupported`
   (gating guarantees they are called only when supported); `key_wrap` keeps its `from_aead`
   default and is overridden by native `KeyWrap` backends. `Ctx::describe` stops going through
   `typed.aead`. `TestKeyKind::KeyWrap`, gated on `Feature::KeyWrap`. Consider
   `#[non_exhaustive]` on the handle structs that still require `describe`.
4. *Bridges.* Replace `bridge_aead` with a builder bounded per part:
   `AeadBridge::new(k).rewrap().data_keys().describe().build()`.
5. *Gating.* `aead::*`, envelope roundtrip/format, emulated data keys and the AEAD error cases
   require `Aead`; `rewrap::*` and envelope rewrap `Aead + Rewrap`; `datakeys::*`
   `Aead + DataKeys`; `describe::aead_key` and `preflight` `Aead + Describe`;
   `describe::hmac_key` `Mac + Describe`; `mac::*` `Mac`. Split the mixed cases
   (`errors::missing_key`, `errors::local_checks_name_the_key`,
   `hygiene::errors_do_not_leak_inputs`) into one case per family rather than branching inside,
   so a case that did not run is never reported as passed.
6. *Consistency case* `capabilities::handles_match_declaration`: `supports_rewrap()` and
   `supports_data_keys()` match the declaration, and an undeclared part returns `Unsupported`
   (with no request sent, where the fixture counts requests).
7. *Migration.* The local and transit fixtures declare
   `supports_all(&[Aead, Rewrap, DataKeys, Mac, Describe])` and `KeyWrap` not applicable, and
   use `AeadBridge`; transit's `key_type(KeyWrap)` is `Unsupported`. Then drop
   `publish = false`, restore the version on the workspace dependency and the excluded test
   targets, and add the crate back to the CI `semver` matrix.


## 23. Cloud backends: plan and decisions (2026-10-05)

The plan for AWS KMS, GCP Cloud KMS and Azure Key Vault / Managed HSM lives in `docs/cloud/`
(`README.md` combines and reconciles `shared.md`, `aws.md`, `gcp.md`, `azure.md`). The questions
of `docs/cloud/README.md` §5 were answered with the recommended options so the work could start;
each is cheap to revisit before 0.2.0 is published unless marked *wire format*.

- **Q1** 0.2.0 ships the conformance redesign, the new core parts and AWS; GCP and Azure follow
  as 0.2.x unless one needs a core break. *Superseded by §25 R1: nothing is published yet, so
  every backend ships in 0.1.0.*
- **Q2** crate names `anykms-aws`, `anykms-gcp`, `anykms-azure`; facade features `aws`, `gcp`,
  `azure`.
- **Q3** Azure standard-vault data keys: a new `DataKeysKey` handle reached through
  `Provider::data_keys` (provided method, default `Unsupported`), backed by the
  `KeyWrapDataKeys` recipe. A KEK handle does not also hand out data keys.
- **Q4** shared HTTP code is extracted from transit into `anykms-http` (TLS provider precedence,
  no-redirect client builder, zeroizing buffers, `Retry-After` parsing, cached single-flight
  credential refresh). Its API is documented as for anykms backends only.
- **Q5** in-house REST clients, MSRV 1.85 for every crate. No official cloud SDK dependency.
- **Q6** live probes and live conformance runs are env-gated and wait for credentials; CI jobs
  are written but need the maintainer's accounts. AWS emulated runs use LocalStack when
  `LOCALSTACK_AUTH_TOKEN` is set, otherwise the job is skipped.
- **Q7** *wire format*: the reserved AWS encryption-context key is `anykms-aad`. The encoded
  AAD cap starts conservative (raised only after the A0 probe; it may only ever rise).
  *Superseded by the release plan D1: the key is Tink's `associatedData` (lowercase hex), and
  the cap binds only the operations that produce a ciphertext (R-50).*
- **Q8** AWS account and GCP project allowlists are optional; the Azure token scope comes from
  the allowed host, never from a 401 challenge.
- **Q9** *wire format*: the Azure ciphertext frame of `docs/cloud/azure.md` §7.
- **Q10** RSA-OAEP with SHA-256 only; SHA-1 OAEP keys are `KeyMismatch`.
- **Q11** `ClientRewrap` ships as an opt-in recipe whose box states that plaintext passes
  through the client.
- **Q12** Azure verifies on the server by default (local verification is an option); AWS
  rejects a version (ARN) other than the handle's resolved key with `NotFound` before any
  request (Appendix A).
- **Q13** the default TLS provider stays ring. *Superseded by §25.3 (C2): aws-lc-rs is the default.*
- **Q14** AWS clock skew: a skew rejection records the server offset and maps to a retryable
  `Unavailable`, so the next `Retry` attempt signs with the corrected clock; no retry inside the
  backend. `KeyMaterialId` is not used.
- **Q15** Azure Premium oct-HSM (preview) keys are not opened (`Unsupported`); the Azure CLI
  credential is opt-in.
- **Q16** TRACE hygiene tests stay per backend.
- **Q17** no MPL-2.0 exception is needed without SDKs.

Corrections to earlier sections, from the cloud research (`docs/cloud/README.md` §2.6): Managed
HSM has HMAC (HS256/384/512, API 7.6+), so the Azure MAC note in §19 and Appendix A is stale; GCP
has a server-side `macVerify`; AWS rejects empty input to `Encrypt`, `Sign` and `GenerateMac` and
documents no encryption-context size limit.

**Implementation (2026-10-06).** All three backends are built; §18 has their status rows and §24
what was built, the deviations, the decisions taken after the reviews and the open release
gates. The agreed conventions: D1 backend names are the crate suffix (`aws`, `gcp`, `azure`), D2
every cloud provider whose feature is on is registered by `with_default_providers()`, D3 one
tracing span schema, D4 transit-style handle names and openers, D5 operator docs named
`docs/operations-<backend>.md`, D6 a 3xx is `Configuration`.

## 24. Cloud backends: implementation status (2026-10-06)

Built on the `cloud-backends` branch from the plans in `docs/cloud/` and the answers of §23.
Two reviews followed: `docs/cloud/review-security.md` (no critical or high finding; one medium,
M1, GCP credential-file URLs) and `docs/cloud/review-consistency.md` (cross-backend consistency,
spec compliance, docs, tests). Their fixes have been applied (below); the plans in `docs/cloud/`
carry "Implementation notes" and "Implemented as: …" marks where the code departs from them.

**Review round (2026-10-06).** The [security review](cloud/review-security.md) found one medium
(M1, GCP credential-file URLs) and six lows (L1–L6: Azure pinned `public_key_version`, Azure CLI
output and expiry, AWS region shape, AWS endpoint cache, AWS `Admin` gating, GCP loopback
`AuthEndpoints`), all fixed. The [consistency review](cloud/review-consistency.md) led to
decisions D1–D6 (§24.3) and the per-backend fixes recorded in the "Implementation notes" of
`docs/cloud/{aws,gcp,azure}.md`. The items deliberately left open are in §24.4.

### 24.1 What was built

- **Shared (M6 shared):** `anykms-http` (TLS provider precedence, no-redirect reqwest client with
  timeouts, zeroizing buffers, `Retry-After`, transport-error classification, single-flight
  credential cache, `redact`); the conformance redesign C1–C9 with declared capabilities,
  published; `WrappedDataKeys`, layered extension calls, `DataKeysKey`/`Provider::data_keys`;
  recipes `KeyWrapDataKeys`, `ClientRewrap`, `rsa_oaep_sha256_encrypt`.
- **`anykms-aws`:** in-house JSON 1.1 client with SigV4 and the AWS credential chain; AEAD
  (AAD as an encryption-context entry, a wire format; `associatedData` since the release plan
  D1), rewrap, data keys and wrapped-only data keys, symmetric and RSA-OAEP-SHA-256 KEKs,
  ECDSA/RSA/Ed25519 signing, HMAC, native encryption contexts as a layered extension. Mock
  tests; Floci emulated conformance on every PR, LocalStack when a token is set; live nightly
  job.
- **`anykms-gcp`:** in-house REST client with Application Default Credentials (metadata server,
  service-account keys, `authorized_user`, workload identity federation, impersonation); AEAD
  with `used_primary`, AEAD and `asymmetricDecrypt` KEKs, ECDSA/RSA/Ed25519 signing with local
  verification, HMAC with server-side `macVerify`; CRC32C on every request and response. Mock
  tests and conformance against an in-process fake Cloud KMS on every PR; live nightly job.
- **`anykms-azure`:** in-house REST client with Entra ID credentials (workload identity, managed
  identity, client secret, opt-in Azure CLI); host allowlist with the token scope from the host;
  RSA/EC signing with server-side or local verification, RSA-OAEP-256 KEKs and `KeyWrapDataKeys`
  on standard vaults; on Managed HSM, AES-256-GCM AEAD, `A256KW` and experimental HMAC. Framed
  ciphertexts (`docs/azure-ciphertext.md`, a wire format). Mock tests; Lowkey Vault conformance on
  every PR; live nightly job.
- **Facade:** features `aws`, `gcp`, `azure`, with `rustls-*`, `rsa-*`, `tracing` and `http2`
  forwarded to each; registration per D2 (every enabled cloud provider is registered; a
  malformed environment is an error; `ANYKMS_AZURE_CREDENTIAL=none` is the one skip).
- **Operator docs:** `docs/operations-aws.md`, `docs/operations-gcp.md`,
  `docs/operations-azure.md`; findings and open facts in `docs/research/{aws-kms,gcp-kms,azure-kv}.md`.

### 24.2 Deviations reported by each backend

AWS:

- An **unversioned signature or tag verifies with the handle's key**: an ARN names one key, so
  absence cannot select a key (conformance `Unversioned::UsesCurrent`). GCP and Azure refuse
  unversioned input with `InvalidArgument`.
- **AAD cap 3072 bytes** (4096 base64url characters) and a **native context cap of 4096 bytes**:
  AWS documents no limit; A0 measured about twice both caps (one 8140-character value), and the
  caps are kept. They may only rise, and raising them is the maintainer's call (Q7).
  *Superseded in part by the release plan D1: the AAD is 6144 hex characters under
  `associatedData`, the measured limit about 1.3 times that; the AAD cap binds only the
  operations that produce a ciphertext.*
- **A0 done (2026-10-07, us-east-1)**, results in `docs/research/aws-kms.md`; the live
  conformance suite then passed on real AWS: **340 cases, 0 failed, 108 *n/a***. Findings:
  `GetPublicKey` **succeeds on a disabled key** (only `Sign`/`Verify` fail), so the fixture
  declared `with_public_key_when_disabled` (*superseded by §25.2 (f): the backend now refuses the
  public key of a disabled key itself*); a malformed ARN is `NotFoundException` "Invalid arn …" (now `Configuration`); an
  invalid grant token is accepted (AWS ignores tokens it does not need; not an error); the
  recorded error bodies are replayed by a mock test.
- **Floci** is the free emulator for per-PR conformance (LocalStack needs a paid token). Its
  deviations are listed in `docs/research/aws-kms.md`.

GCP:

- A URI whose **version shape does not fit the family** (a versioned AEAD key, an unversioned
  signing or MAC key) is `KeyMismatch` at open, not `Configuration`: the shape is the only pre-I/O
  signal of the key family. Malformed per-call versions stay `InvalidArgument`.
- **`asymmetricDecrypt` RSA KEKs are included** (a non-goal in the plan): local OAEP-SHA-256
  wrap, server unwrap.
- The opt-in **newest-ENABLED-version mode** for signing keys (Appendix A, §21) is **deferred**.

Azure:

- **Release B (Managed HSM) is code-only**: implemented and mock-tested, untested against a live
  HSM. HMAC is behind the experimental `mhsm-hmac` feature until T13 pins whether HS* `sign`
  takes the message or a digest.
- **405 → versioned-path fallback**: a host that refuses a versionless write with 405 (Lowkey
  Vault) is remembered per host, and its unversioned writes name the current version from the
  cached key bundle (`key_cache_ttl`), re-read once when that version is gone or refused.
- **Disabled key → `PermissionDenied`** (Appendix A: `KeyStateInvalid`), pending the T3 probe
  that pins Azure's inner error code.

### 24.3 Decisions taken after the reviews

`docs/cloud/review-consistency.md` §0:

| # | Decision |
|---|---|
| D1 | Backend name strings (`Error::backend()`, `Provider::name()`, `SkippedProvider::backend`) are the crate suffix, not the scheme: `transit`, `aws`, `gcp`, `azure`. |
| D2 | `with_default_providers()` always registers every cloud provider whose feature is on; a missing credential is a lazy `Configuration` error on first use. `ANYKMS_AZURE_CREDENTIAL=none` is the one explicit skip. A malformed environment variable is an error from `with_default_providers()`, never a skip. |
| D3 | One tracing schema for the four HTTP backends: `backend, op, resource, key_version, attempt, http_status, code, request_id, latency_ms, error_kind, outcome`; location goes in `resource` (`docs/cloud/shared.md` §5). |
| D4 | Typed openers and handles follow transit: `aead_key`, `key_wrap_key`, `digest_signing_key`, `ed25519_key`, `mac_key` returning `<Cloud>{Aead,KeyWrap,Digest,Ed25519,Mac}Key`. |
| D5 | Operator docs are `docs/operations-<backend>.md` (`docs/azure.md` became `docs/operations-azure.md`; transit stays in `docs/operations.md`). |
| D6 | A 3xx response is `Configuration` on every backend (redirects are never followed). |

### 24.4 Release gates still open

**Maintainer decisions (release review round 1, 2026-10-08; §26):**

- **Q1, publish gate: hold.** 0.1.0 is not published until probes T1 (GCP) and T3 (Azure) have
  run and their results are folded into the error mappings, the Azure disabled-key
  classification and the CHANGELOG's Known limitations. No "not live-verified" markers are
  added; the CHANGELOG's Known limitations say the publish waits for T1 and T3.
- **Q2, repository: `github.com/sagikazarmark/anykms`.** No code change; the repository must
  exist and be public before tagging (today's `origin` is `sagikazarmark/anykms.orig`).
- **Q3, first green CI: required.** One fully green GitHub `pull_request` run on the release
  commit (MSRV, semver on its non-blocking path, Floci, LocalStack, Lowkey, the Vault/OpenBao
  matrix) before tagging. `docs/releasing.md` lists it as a step. *Superseded in part
  ([`release-plan.md`](release-plan.md) 4.3, R-40):* LocalStack is no longer a gate (without
  its token the job skips every step and reports success); Floci runs with
  `ANYKMS_FAIL_ON_SKIP=1`, and the docs.rs job is a gate.

- **Live probes:** T1 (`scripts/probe-gcp.sh record`), T3 (`scripts/probe-azure.sh`) and T13
  (Managed HSM, needs HSM budget). Their results pin the remaining error mappings (Azure disabled
  key, GCP error texts) and the Azure HMAC semantics. A0 (`scripts/probe-aws.sh`) is done
  (2026-10-07); AWS keeps two open facts: `Retry-After` on throttling (not provoked) and the
  China dual-stack host. T1 is done (2026-10-12, `docs/research/gcp-kms.md` §2): it found the
  `getPublicKey` path bug (fixed), empty plaintext accepted, empty Ed25519/`macVerify` input
  refused, and a version GET that cannot tell a missing key from a missing version (handled).
  T3 is done (2026-10-12, `docs/research/azure-kv.md`): 403 inner codes `KeyDisabled`,
  `KeyNotYetValid`, `KeyExpired`, `KeyOperationForbidden` (now classified), a disabled key is
  readable, versionless operations work; the live fixture needed `Content-Length` on bodyless
  POSTs and 429 retries on key creation.
- **"To verify" rows** in `docs/research/aws-kms.md`, `docs/research/gcp-kms.md` and
  `docs/research/azure-kv.md` (listed in `docs/cloud/review-consistency.md` §3.5).
- **CI configuration** for the live and emulated jobs:
  - repository variables: AWS (`AWS_LIVE_ROLE_ARN`, `AWS_LIVE_ACCOUNT`, `AWS_LIVE_REGION`, the
    `ANYKMS_AWS_KEY_*` pool), GCP (`GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_*_SERVICE_ACCOUNT`,
    `ANYKMS_GCP_KEY_RING`), Azure (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `ANYKMS_AZURE_VAULT_URL`,
    `ANYKMS_AZURE_*_URI`);
  - OIDC roles and identities: the AWS role for GitHub OIDC, GCP workload identity federation,
    the Azure federated app;
  - secrets and keys: `LOCALSTACK_AUTH_TOKEN`; the AWS HMAC-384/512 pool keys
    (`ANYKMS_AWS_KEY_HMAC_384`/`_512`);
  - the repository-level variable `ANYKMS_GCP_LIVE=true` enables the `gcp-live` job (the GCP
    values stay in the `cloud-gcp` environment, which a job-level `if` cannot read);
  - ~~pin `google-github-actions/auth` by commit SHA~~ (done: v2.1.13, §26).
- **Review items deliberately left open** (everything else in both reviews is fixed):
  - Azure: classifying the inner error code `KeyDisabled` as `KeyStateInvalid` /
    `KeyVersionUnusable` waits for T3 to pin the code (disabled keys stay `PermissionDenied`);
  - Azure Z5: `from_env` does not narrow the host suffixes from `AZURE_AUTHORITY_HOST`;
  - ~~GCP: no `from_env_with(lookup)` testing seam~~ (done in §25.3, C4: every backend has one);
  - AWS: an RSA key without an RSA backend still fails at wrap with `Unsupported`, while GCP and
    Azure fail at open with `Configuration` (review-consistency §1.3 item 4);
  - the live probes above.
- **Fuzzing:** the cloud fuzz targets, `envelope_parse` and `core_values` have not had their
  CPU-hour (§18, M4).
- **First GitHub CI run** on the public repository (Q3 above).
- **Release prep done (X23, 2026-10-07):** one `[0.1.0]` CHANGELOG section; every gate green on
  the integration branch (lint and feature matrix, workspace tests, conformance counts, Floci,
  Lowkey, both Vault/OpenBao pairs, docs, `cargo deny`, live AWS: 356 passed, 0 failed); `cargo
  package --workspace --exclude anykms-testkit --locked` packages and verifies all ten published
  crates. **Not published**: the release review (§26) found blockers, now fixed, and the
  maintainer decided to hold the publish until T1 and T3 run and one GitHub CI run is green
  (Q1, Q3 above).

## 25. Architecture plan after the cloud backends (2026-10-07)

The plan is `docs/cloud/architecture-plan.md` (revision 2, signed off by the API, security and
implementation reviewers; its §8 is the review log). It runs in three phases before the first
publish; this section records each phase as it lands: §25.1 (consistency), §25.2 (core API) and
§25.3 (packaging and operations).

Decisions that change earlier sections:

- **R1. Every backend ships in 0.1.0.** 0.1.0 has not been published (no tag, crates.io answers
  404), so the three phases land before the first publish. That publish contains core, recipes,
  conformance, local, http, transit, aws, gcp, azure and the facade, and the two changelog
  sections merge into one `[0.1.0]` (X23). §23 Q1 ("0.2.0 ships AWS; GCP and Azure follow as
  0.2.x") is superseded. §24.4 probes T1 (GCP) and T3 (Azure) become 0.1.0 release gates (open
  question 1 of the plan: hold the publish until they run, or publish GCP and Azure marked "not
  live-verified"); probe T13 (Managed HSM) is not a gate.
- **R2. The semver job is non-blocking until the publish** (`continue-on-error: true`): it
  compares against the PR's base branch while Phase 2 breaks the API on purpose. After the
  publish it compares against crates.io and blocks.

### 25.1 Phase 1: consistency fixes (implemented)

One rule per behavior across the four HTTP backends (transit, AWS, GCP, Azure), with no new
portable API. Tasks X0–X5, merged in waves W1 and W2 (`9d01b0e`..`9e6e9cb`).

**Baselines (X0).** The GCP fake fixture declares `EmptyPlaintext` `not_applicable` (Cloud KMS
documents empty plaintext as refused; §24.4 probe T1 confirms; the live fixture keeps `lacks`),
which fixes the two `roundtrip_empty` failures under `ANYKMS_FAIL_ON_SKIP=1`. The
`scripts/aws-test-setup.sh` policy grants `kms:ListResourceTags`, so cleanup can run as the test
identity once the maintainer applies it. The transit conformance baselines are identical on both
CI image pairs (Vault 369 passed / 79 ignored; OpenBao 391 / 57).

**Shared code (X1).** `anykms-http` gains what the four backends had each written for themselves:

- `span`: the D3 request and token span schema (`REQUEST_FIELDS`, `TOKEN_FIELDS`), the
  `request_span!`/`token_span!` macros (no-ops without the `tracing` feature), `finish_request`,
  `finish_token`, and cfg-free helpers (`Span`, `instrument`, `record_attempt`);
- `client::send` (bounded, zeroizing response bodies; records `http_status`; strips URLs from
  transport errors) and `client::MIN_RESPONSE_BYTES` (64 KiB);
- `redact::{request_id, url_origin, contains_ci}`, `zbuf::token_file_error_kind`,
  `cache::jittered_ttl` (±10 %).

A new unpublished `anykms-testkit` crate (path-only dev-dependency) holds the hygiene-test
helpers: trace capture at TRACE, a span recorder, the D3 schema assertions and
`assert_debug_redacts`. Every backend's `tests/hygiene.rs` uses it and is excluded from the
package.

**Rules now uniform (X2 transit, X3 AWS, X4 GCP, X5 Azure).** Numbers refer to the plan's §2.1.

| # | Rule |
|---|---|
| P1-1 | `Debug` of any type holding a URL prints `scheme://host:port` only (proxies, endpoints, server addresses; `ClientOptions`). AWS `sigv4::Signed` prints the access key id and the credential scope, never the signature. Each hygiene test checks it. |
| P1-2 | Token files (web identity, container token, Azure federated, GCP subject, transit token and JWT) are classified by one function: a missing file is `Unavailable` (a rotation race); every other failure (permissions, a directory, too large, empty, not UTF-8, control characters) is `Configuration`. Several were `Unavailable` before. |
| P1-3 | GCP attaches `Retry-After` and `RetryInfo.retryDelay` whatever the kind. |
| P1-4 | Cached key metadata (type check, describe, Azure key bundle) is dropped only by a failed request that addressed the handle's own key or version; a version taken from input (a signature's, tag's, frame's or ciphertext's; `public_key_version`) never drops it, so forged versions cannot force a describe per request (a 100-forged-versions request-count test per backend). Transit's 400 "does not support … key type" is `KeyMismatch`. |
| P1-6 | Every error raised after the URI is parsed names the key, open-time shape checks included (asserted by the conformance `local_checks_name_the_key_*` cases for the HTTP backends). |
| P1-7 | GCP custom credential sources go through the credential cache and the token span (`credential = "custom"`). The GCP refresh lead stays 4 minutes. |
| P1-8 | Token span events: `debug!` on success, `warn!` on failure with `credential`, `error_kind` and the error, which names a failed token file. |
| P1-9 | One request-id filter (1–128 ASCII graphic characters) on every backend. |
| P1-10 | An empty allowlist, or an allowlist variable set to an empty value, is `Configuration` at `build()` (AWS, GCP). |
| P1-11 | `max_response_bytes` is at least 64 KiB on every backend. |
| P1-12 | The AWS KMS client is built in `build()`: TLS roots and the crypto provider fail there, with no network I/O. *Superseded for the facade defaults only ([release plan](release-plan.md) 2.3, R-33): `with_default_providers()` skips a cloud provider whose system trust store holds no usable root (`SkipCause::TlsRoots`); an explicitly built provider still fails.* |
| P1-13 | Local verifiers (GCP, Azure `local_verify`) trust a version's public key for at most the metadata TTL (±10 %), counted from the fetch; a failed re-read fails closed with its own error; a negative cache (64 entries, same TTL) bounds forged-version requests to one per version per TTL. |

Transit adopts the D3 schema: its request span is `anykms.transit` with exactly the shared
fields (`server_alias`, `mount` and `key` fold into `resource`), and a new `anykms.transit.token`
span covers logins, renewals and token-file reads.

**Deviations recorded in the plan's implementation notes:**

- The span macros also take `backend`, and field values are plain expressions (no `%`/`?`), so
  the no-op expansion compiles.
- Transit emits token spans only where a token is fetched (`kubernetes`, `jwt`, `token_file`);
  static, environment and no-token sources fetch nothing, so `token` and `agent` are unused.
  Transit errors carry no `code` or `request_id`.
- AWS names a failed token file in the `warn!`'s error message rather than in a separate `path`
  field (Azure the same). AWS keeps empty `ANYKMS_AWS_ALLOWED_*` values so they fail at `build()`.
- GCP's token-endpoint requests keep their own body reader; only the data-plane client moved to
  `send()`. A custom-source token without `expires_at` is kept until a 401.
- P1-5 (Azure `verify_with_describe`) was withdrawn in review: the Azure `Preflight` of Phase 2
  replaces it.

### 25.2 Phase 2: core API (implemented)

Tasks X7–X17, merged in waves W4–W8. Details, per task, are the "Implementation notes" of
`docs/cloud/architecture-plan.md` §3.

- **A3, error model (X7, X8a–X8e).** The class of an error depends on its kind alone.
  `ErrorKind::UnknownKeyVersion` (caller class) is a version from input that is not a version of
  this key (`public_key_version`); verifying with one is `VerificationFailed`. A disabled version
  the handle chose (its pin or the primary) is `KeyStateInvalid` for every operation;
  `KeyVersionUnusable` always names input data. A malformed URI is `Configuration`
  (`Operation::ParseUri`); key wrapping is `Operation::WrapKey`/`UnwrapKey`. **(f)** every backend
  refuses the public key of a disabled key or version: AWS with an uncached `DescribeKey` before
  `GetPublicKey` (the live probe showed `GetPublicKey` succeeds on a disabled key), GCP with the
  version's state; `CachedVerifier` therefore stops trusting it within its TTL.
- **A1, `KeySemantics` (X9, X11–X13).** Every opaque and typed handle reports what it does where
  backends differ (version model and shape, state scope, versions listed, whether ciphertexts
  reveal their version, `used_primary`, unversioned and pinned verification, server or local
  verification with its revocation lag, data-key source and AAD binding, size limits). The
  per-backend table is `docs/cloud/architecture-plan.md` §3.2; describe handles declare none (the
  URI does not say the key's family). The conformance suite reads them from the handles and fails
  a handle that declares none; `FixtureCaps` keeps only fixture facts.
- **A2, versioning (X10, X12a–X12d).** `Provider::pin`/`Registry::pin` build the URI naming one
  version (GCP, Azure; `Unsupported` elsewhere), forwarded by `forward_provider!` and `Arc<P>`.
  `KeyVersionInfo` carries each version's signature or MAC algorithm (GCP fills it).
- **A4, one `Call` through layers (X14, X15).** `Around`, `Call`, `CallCx`, `CallOutput`;
  `Part::wrap_around` decorates any part kind. `Layer` keeps `retries` and `part`; `RetryLayer`
  and `ObserveLayer` are `Around`s; extension calls are `Call`s with `PartKind::Extension`. The
  spike went straight to the full design (the allocation count could not be measured: a counting
  global allocator needs `unsafe`, which the workspace forbids; the typed path is unchanged).
- **A5, `Preflight` and backend metadata (X16).** An optional `Preflight` part on every opaque
  handle (the backend's key-type check); `KeyInfo::with_backend`/`backend`/`backend_type_id`
  (renamed `with_backend_info`/`backend_info`/`backend_info_type_id` in §26).
  Typed `verify_with_describe` became `impl Preflight`; the `*_info()` methods are replaced by the
  metadata every `describe()` attaches.
- **A6, `PublicKeys` on `KeyWrapKey` (X17).** RSA key-encryption keys publish their public key for
  offline wrapping (AWS, GCP; Azure's wrapped keys are framed with the version, tested against
  Lowkey).
- **A7 (a lower crypto crate) is not done** (plan §3.7).

### 25.3 Phase 3: packaging and operations (implemented)

Tasks X18–X21, merged in waves W3, W5 and W7.

- **C1, features (X18).** The facade's `gcp` no longer forces service-account keys
  (`gcp-service-account-key`, default); AWS's fixture admin API is behind the hidden
  `__test-fixtures` feature, refused without debug assertions; a CI `features` job runs
  `cargo hack --each-feature` and the cross-backend combinations, with inverted `cargo tree`
  guards.
- **C2, TLS default (X18).** aws-lc-rs is the default TLS provider of the facade and every HTTP
  backend (it was already compiled for RSA); `rustls-ring` is opt-in.
- **C3 and C7 (X19).** `deny.toml` denies duplicate versions (three explicit skips); the MSRV
  policy covers the libraries; the semver job compares published crates with crates.io and blocks
  (unpublished ones against the base branch, non-blocking); `docs/releasing.md` has the publish
  order and build requirements. Versioning stays lockstep while core is 0.x.
- **C4, configuration (X20).** `from_env_with(lookup)` on every backend and
  `with_default_providers_from` on the facade. Transit's six unprefixed variables are now
  `ANYKMS_TRANSIT_*`; an old name is a `Configuration` error naming its replacement (the check
  may be removed in a future release).
- **C6, fixture helpers (X21).** `anykms-conformance` feature `fixture-helpers`: `RunId`,
  `KeySpecTable`, `FreshKeys`, `typed_handles!`, adopted by the cloud and local shaped fixtures.

Gates after every wave: fmt, clippy (all and no default features, per crate), fuzz check, the
workspace tests, conformance counts that never dropped, Floci and Lowkey, both Vault/OpenBao
pairs, docs, the MSRV job's two steps on Rust 1.85 (added after the release review: the waves
did not run it, and a red MSRV job went unnoticed), and the live AWS suite (as `anykms-test`; 356
passed at the end of W8).

## 26. Release review round 1 (2026-10-08)

A four-lens review (API, security, correctness, release) of `cloud-backends` before the first
publish, with an independent analysis per lens and a judge's ruling. It found 53 items, three of
them blockers: the AWS RSA KEK wrapped to a disabled key, the undecided publish gate, and the
unconfirmed repository. Every FIX-NOW item was fixed in nine work packages (WP-1 to WP-9) on
`cloud-backends`.

### 26.1 Maintainer decisions

- **Q1, publish gate: (a) hold** until probes T1 and T3 run (§24.4). No "not live-verified"
  banners.
- **Q2, repository: (a)** `github.com/sagikazarmark/anykms`; no code change.
- **Q3, first green CI: (a)** one green GitHub `pull_request` run before tagging
  (`docs/releasing.md`).
- **Q4, gcp-live guard: (a)** the repository-level variable `ANYKMS_GCP_LIVE == 'true'` enables
  the job; the GCP values stay in the `cloud-gcp` environment.
- **Q5, auth action: (a)** `google-github-actions/auth` pinned by SHA to v2.1.13; v3 in a
  separate change once the job has run.
- **Q6, `pin` error kind: (b)** `Configuration` for a malformed version or a URI naming another
  version (GCP, Azure, core docs, architecture plan §3.3).
- **Q7, packaged tests: (b)** no published crate ships `tests/` (AWS keeps only the public SigV4
  vectors its unit test reads); the recipes unit tests over `anykms-local` moved to
  `tests/emulated.rs`.
- **Q8, credentials visible to builds:** `scripts/test-env.sh` strips every credential-shaped
  variable by name pattern (not `env -i`: the devenv C toolchain must survive); live runs opt in
  with `scripts/test-env.sh --dotenv env ANYKMS_<CLOUD>_LIVE=1 cargo …`, which loads `.env`
  inside the wrapper and strips the root keys again.

### 26.2 What changed

- **Public API names (frozen from 0.1.0):** `KeyInfo::with_backend_info`/`backend_info`/
  `backend_info_type_id` (were `with_backend`/`backend`/`backend_type_id`); `KeySemantics`
  `version_model()`/`version_shape()` (were `versions()`/`shape()`) and
  `reports_used_primary()`/`with_reports_used_primary()` (were `used_primary`/`with_used_primary`).
  Conformance: `Counting` is `#[non_exhaustive]` with `Counting::new`; the harness internals
  (`Ctx`, `Path`, `CaseResult`, `RequestCounter`) are no longer re-exported; the typed bridges
  carry a typed handle's `Preflight` (`AeadBridge`/`KeyWrapBridge::preflight`,
  `*KeyHandles::with_preflight`, the opt-in `preflight;` arm of `typed_handles!`).
- **Preflight refuses unusable keys again.** Core's `preflight()` runs the capability, algorithm
  and state checks after a backend's `Preflight` part too, all labelled `Operation::Describe`.
  Opaque handles `impl Preflight`, and `Preflight` is in the prelude. The AWS, Azure and transit
  typed `Preflight`s read fresh metadata, type-check even under `TrustCaller` and refuse a
  disabled, pending-deletion or soft-deleted key. GCP MAC and AEAD preflight still do not check
  the version state (a Known limitation, not a regression).
- **AWS:** an RSA KEK checks the key state before every wrap (lag up to the describe TTL, about
  11 minutes); `AwsKeyInfo` no longer derives `Deserialize`; STS body request ids pass the shared
  filter; docs.rs builds the public features only.
- **Azure:** a pinned handle reports its pinned version's state; data keys have a preflight; HMAC
  declares its 64 KiB input limit; local verification remembers a disabled version; the hidden
  `env_configured` is gone. A disabled input version stays `PermissionDenied` until T3
  (documented).
- **GCP:** an RSA KEK's `public_key_version` refuses any version but the pinned one before I/O;
  `conformance_cached` runs the fake suite with the default public-key cache.
- **Transit and local:** `key_wrap` semantics declare no data keys or plaintext limit (also core's
  `KeyWrapKey::from_aead`); `TransitKeyInfo` fields are documented.
- **Packaging and CI:** the MSRV job is green again (`#[allow(dead_code)]` on a test trait); fuzz
  runs without `-D warnings`.
- **Docs:** the README cloud quick start builds (`version = "0.1"`, the `SignatureAlgorithm`
  import); the README error-class rule follows the kind alone; the CHANGELOG is reshaped for a
  first release (the development history below moved here); `docs/releasing.md` gained the gate,
  repository, green-CI, merge and post-publish steps.

### 26.3 Development-branch history (moved from the CHANGELOG)

Changes to APIs that existed on the development branch before 0.1.0, as the CHANGELOG recorded
them before the release review. Names are those of the time.

- Consistency across the HTTP backends (transit, AWS, GCP, Azure; PLAN §25.1, one rule each):
  - `Debug` output prints URLs (proxies, endpoints, server addresses) as `scheme://host:port`
    only; AWS `sigv4::Signed` no longer prints the signature.
  - Token files (AWS web identity and container token, Azure federated token, GCP subject token,
    transit token and JWT files): a missing file is `Unavailable`; any other failure
    (permissions, a directory, too large, empty, not UTF-8, control characters) is now
    `Configuration` (several were `Unavailable`), and the error names the file.
  - Cached key metadata (the key-type check, describe, the Azure key bundle) is dropped only when
    a request for the handle's own key or version fails; a version taken from input (a
    signature's, tag's, frame's or ciphertext's, `public_key_version`) never drops it, so forged
    versions cannot force a metadata read per request. `InvalidArgument` no longer drops it.
  - Errors raised after the key URI is parsed name the key (`resource`), open-time shape checks
    included (AWS, Azure, transit).
  - Token refreshes are `debug` events and failures `warn` events with the credential, error kind
    and error, in a token span on every backend.
  - One request-id filter (1–128 printable ASCII characters; an empty id is dropped).
  - `max_response_bytes` below 64 KiB is `Configuration` at `build()`.
- `anykms-transit`: tracing follows the shared schema: the `anykms.transit` span has `backend,
  op, resource, key_version, attempt, http_status, code, request_id, latency_ms, error_kind,
  outcome` (`server_alias`, `mount` and `key` are now in `resource`), and a new
  `anykms.transit.token` span covers logins, renewals and token-file reads. A 400 saying the key
  type does not support the operation is `KeyMismatch` (was `InvalidArgument`).
- `anykms-aws`: the KMS client is built by `build()`, so missing TLS roots, a bad `ca_pem` or no
  crypto provider fail there. An empty `allowed_accounts`/`allowed_regions` (or an empty
  `ANYKMS_AWS_ALLOWED_*` variable) is `Configuration` at `build()`.
- `anykms-gcp`: `Retry-After` and `RetryInfo.retryDelay` are attached whatever the error kind.
  `Credentials::custom` sources are cached and traced like the built-in ones (`credential =
  "custom"`; they need no cache of their own). An empty allowlist (or an empty
  `ANYKMS_GCP_ALLOWED_*` variable) is `Configuration` at `build()`. Cached public keys expire
  `public_key_ttl` (±10 %) after their fetch, not after their last use, and a failed re-fetch
  fails closed; a signature or `public_key_version` naming an unknown version is remembered for
  the same TTL (up to 64 versions).
- `anykms-azure`: `local_verify()` trusts a version's public key for at most `key_cache_ttl`
  (±10 %) from its fetch (it used to cache it for the handle's lifetime, so a disabled version
  kept verifying); a failed re-read fails closed, and unknown versions are remembered for the
  same TTL (up to 64).
- `anykms-conformance` (unpublished before): every case requires the key family and parts it
  uses (`Feature::Aead`, `Rewrap`, `DataKeys`, `WrappedDataKeys`, `Mac`, `Describe`, `KeyWrap`,
  `Signing(alg)`, ...), and a required feature the fixture left undeclared fails the case and the
  `conformance::declarations` trial (`Support::Undeclared`). `TypedHandles` methods default to
  `Unsupported`; `bridge_aead` is replaced by `AeadBridge`/`KeyWrapBridge`; `create_key` takes a
  `KeyUse` (shared, possibly pooled keys or fresh ones); `rotate` returns the key to use for the
  new version (version-pinned URIs); rotation is declared per family (`Rotate`, `RotateMac`,
  `RotateSigning`); versions are checked by shape (`VersionShape`, `Unversioned`,
  `Fixture::malformed_version`, `without_primary_version`, `with_key_state_per_version`);
  `TestKey` gains `version` and `TestKeyKind::KeyWrap`; state changes may settle
  (`with_settle_time`); fixtures against an emulator declare `with_emulated_errors`. Mixed cases
  are split per family (`errors::missing_key::*`, `hygiene::errors_do_not_leak_inputs::*`, ...).
- `anykms-conformance`: HMAC test keys are asked for per algorithm
  (`TestKeyKind::Hmac(MacAlgorithm)`), for backends that bind the algorithm to the key (AWS, GCP,
  Azure Managed HSM); fixtures whose keys serve every algorithm ignore it. `Rotate` covers AEAD
  keys only and the new `Feature::RotateKeyWrap` native key-wrapping keys; a new
  `recipes::envelope_native::rewrap_unrotated` case covers server-side rewrap where KEKs never
  rotate. `Fixture::missing_key_uri` takes the key kind. The AWS conformance runs every MAC case
  (CI no longer skips HMAC-SHA-384/512; the live pool adds `ANYKMS_AWS_KEY_HMAC_384`/`_512`).
- `anykms-http`: `redact` (pinned server messages verbatim, others as their length and a keyed
  per-process fingerprint), shared by transit and the cloud backends instead of a copy in each;
  no behavior change.
- `anykms-core`: parts added after 0.1 are never set by an opaque handle's `full` (whose bounds
  stay those of 0.1); backends add them with `with_*`. A custom `Layer`'s catch-all `part` now
  also sees the extension slot every handle has (`PartKind::Extension`) and, on AEAD handles
  that have it, `PartKind::WrappedDataKeys`.

- **Breaking (core, A4):** `Layer` keeps `retries` and `part` only; the 13 per-part methods
  (`Layer::aead`, `Layer::extension`, ...) are gone: decorate in `part`, or implement `Around` and
  call `part.wrap_around`. `ExtensionCall`/`ExtensionOutput` are now `Call`/`CallOutput`.
  `ObserveLayer::wrap(inner)` takes no `PartKind`.
- **Breaking (core, A3):** the error class depends on the kind alone. A write with a version the
  handle chose that is disabled is `KeyStateInvalid` (config class); `KeyVersionUnusable` always
  means a version that came from input (caller class). A malformed key URI is `Configuration`
  (`Operation::ParseUri`). Metrics labels: key wrapping reports `wrap_key`/`unwrap_key` instead of
  `encrypt`/`decrypt`.
- **Breaking (AWS, GCP):** the public key of a disabled key is refused (`KeyStateInvalid`, or
  `KeyVersionUnusable` for a version from input), so `CachedVerifier` stops trusting it within its
  TTL. AWS checks with an uncached `DescribeKey` first (`kms:DescribeKey` is needed for public
  keys; one more request per read); GCP checks the version's state
  (`cloudkms.cryptoKeyVersions.get`).
- **Breaking (backends, A5):** typed handles' `verify_with_describe()` is now `impl Preflight`
  (`preflight()` returns the `KeyInfo`); `transit_info()`, `aws_info()`, `gcp_info()` and
  `azure_info()` are gone: read `describe().await?.backend_info::<XKeyInfo>()` (named
  `backend` until §26).
- **Breaking (conformance):** `FixtureCaps` lost its fallback fields and builders
  (`with_versions`, `with_max_plaintext`, `without_primary_version`, `with_used_primary`, ...) and
  the `DataKeyAad`, `VersionShape` and `Unversioned` types; declare `UsedPrimary`,
  `MacInputLimit` and `MessageInputLimit` as features and report the rest through `KeySemantics`.
  `TestKeyKind::Hmac` takes the algorithm; `Feature::RotateKeyWrap` is separate from `Rotate`.
- **TLS default (C2):** the facade and every HTTP backend default to aws-lc-rs (`rustls-aws-lc-rs`,
  which needs a C compiler to build; CMake only for FIPS); `rustls-ring` is opt-in for builds without a C
  toolchain.
- **Facade features (C1):** `gcp` no longer forces service-account keys; the new
  `gcp-service-account-key` feature (default) enables them. `rsa-*` features forward to
  `anykms-azure` too.
- **AWS `__test-fixtures` (C1):** the admin API used by the fixtures is behind the hidden
  `__test-fixtures` feature and refuses to build without debug assertions.
- **Transit environment (C4):** the six unprefixed variables are renamed `ANYKMS_TRANSIT_*`
  (`ANYKMS_TRANSIT_AUTH`, `_AUTH_MOUNT`, `_AUTH_ROLE`, `_AUTH_JWT_FILE`, `_NO_TOKEN`, `_ALLOW_INSECURE_TOKEN_FILE`); an old name, if set, is a
  `Configuration` error naming its replacement.
- **Supply chain (C3):** `deny.toml` denies duplicate dependency versions (three explicit skips);
  the MSRV policy covers the libraries (the HTTP backends' tests need a newer compiler for
  wiremock); the semver job compares published crates with crates.io and blocks.

## 27. JOSE verification removed (2026-10-12)

- **`jose` signs and publishes; it no longer verifies.** `verify_jws`, `verify_jws_as`,
  `verify_jws_for_key`, `verify_jws_for_key_as` and `kid_version` are removed, with their
  parser (unique header members, `crit`/`b64` rejection, alg-name checks) and the `jose_verify`
  fuzz target. This finishes the §19 trim: like claim validation, checking a JWS signature is
  generic token logic, and relying parties verify against the published JWKS with a JWT library
  (`jsonwebtoken`, which has no ES512). The KMS-specific parts stay: kids, JWK/JWKS from every
  enabled version, the DER to `r||s` conversion, digest vs. message signing, and `JwtSigner`'s
  cached kid. KMS signing cannot plug into `jsonwebtoken`'s `JwtSigner`: it is a synchronous
  `signature::Signer` built from an `EncodingKey` by a process-global `CryptoProvider`.
- Tests check the signing side with a test-only signature check (`tests/verify_jose.rs`,
  the conformance `jws` case); `tests/jose_interop.rs` still pins verification with
  `jsonwebtoken`. Raw signatures keep `LocalVerifier`, `CachedVerifier` and
  `verify_message_hashed`. The two checks are deliberately separate copies: the conformance
  crate is published (so it cannot use the unpublished testkit), a recipes dev-dependency on it
  would be a cycle, and a hidden helper in recipes would bring verification back.
- **Second relying-party example:** `examples/jwt_signing_jwt_simple.rs` verifies with
  jwt-simple 0.15 (`pure-rust`; `from_jwk`, algorithm pinned by key type), selecting the JWK by
  kid with jwk-simple 0.5 (no features). jsonwebtoken stays the documented default: jwt-simple
  does not require `exp`, defaults to 15 minutes of clock tolerance, needs cmake for its default
  BoringSSL build, has MSRV 1.89 and no ES512; it is the only one of the two that accepts the
  fully-specified `"Ed25519"` alg. jwk-simple's `jwt-simple` feature is not used: it targets
  jwt-simple 0.13 and refuses JWKs with `alg: "EdDSA"` (what `jose::to_jwk` publishes) when
  converting to an Ed25519 key. Both are fixable in jwk-simple (maintained alongside anykms);
  once fixed, the example can use that feature instead of `from_jwk`.
- **Lockfile:** `time` is locked at 0.3.47 in `Cargo.lock` (RUSTSEC-2026-0009, via
  x509-parser; `cargo deny` catches a downgrade), which needs Rust 1.88, like the other example
  dev-dependencies the MSRV job drops. jwt-simple's `pure-rust` build (superboring →
  aes-keywrap 0.9.1) requires `aes` 0.9.3, so the workspace's `aes` moves from 0.9.2 to 0.9.3;
  the re-resolve also moves errno to windows-sys 0.61 (one duplicate fewer).

## 28. Credentials: built-in workload sources and SDK bridges (implemented, 2026-10-12)

The maintainer accepts a higher MSRV, which reopens §23 Q5 for credentials (not for the KMS
clients). Implemented: MSRV 1.91 for every crate and feature; AWS profiles keep static keys only
(`credential_process` and profile web identity removed); the in-house Azure CLI credential
removed; optional SDK credential bridges `anykms-aws/sdk-credentials`, `anykms-gcp/google-cloud-auth`,
`anykms-azure/azure-identity`. Plan, decisions and deviations:
[`docs/cloud/credentials-plan.md`](cloud/credentials-plan.md).
