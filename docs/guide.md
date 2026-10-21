# Guide

How to open keys, configure backends and use the recipes. The
[quick start](../README.md#quick-start) shows the basics; terms such as *typed handle*, *opaque
handle* and *KEK* are defined in the [glossary](glossary.md). Each backend's operator guide
covers permissions, credentials and environment variables: [Vault and OpenBao](operations.md),
[AWS](operations-aws.md), [GCP](operations-gcp.md), [Azure](operations-azure.md).

- [Registries and default providers](#registries-and-default-providers)
- [Retries](#retries)
- [Configuring transit in code](#configuring-transit-in-code)
- [Typed handles](#typed-handles)
- [Checking keys at startup](#checking-keys-at-startup)
- [Reaching the backend's API](#reaching-the-backends-api)
- [Key URIs](#key-uris)
- [From synchronous code](#from-synchronous-code)
- [Ciphertexts as text](#ciphertexts-as-text)
- [JWTs and signatures](#jwts-and-signatures)
- [Generic code and shared state](#generic-code-and-shared-state)

## Registries and default providers

A [`Registry`] opens keys by URI. `anykms::with_default_providers()` starts one with every
backend whose Cargo feature is on, configured from the environment, as in the
[quick start](../README.md#with-vault-or-openbao).

`with_default_providers()` returns a `DefaultProviders` builder. Cloud providers whose feature is
on are always registered (credentials are resolved on first use; `ANYKMS_AZURE_CREDENTIAL=none`
opts out of Azure; with no system TLS roots they are skipped), and a malformed environment variable
is an error. Without `VAULT_ADDR`/`BAO_ADDR` transit is skipped, not an error: `skipped()` says
which provider and why (`cause()` tells a skip the application chose from one the environment
caused), and opening a `hashivault://` key then fails with that reason.

Code that wants to report the providers it could not register reads `skipped()` before
building:

```rust
use anykms::SkipCause;

let defaults = anykms::with_default_providers()?;
for s in defaults.skipped() {
    // A backend whose feature is off, or that the environment opts out of, was never wanted.
    if !matches!(s.cause(), SkipCause::FeatureDisabled | SkipCause::OptedOut) {
        eprintln!("{} not registered: {}", s.backend(), s.reason());
    }
}
let registry = defaults.layer(anykms::retry_layer()).build()?;
```

## Retries

`.layer(anykms::retry_layer())` retries every handle the registry opens, with one shared retry
budget. That is the one way to retry the opaque handles a registry opens; a typed handle (e.g.
`TransitAeadKey`) is wrapped with `anykms::retry_layer().wrap(key)` instead. A handle takes at most
one retry layer, so `key.layer(&retry)` on a handle from a retrying registry changes nothing
(attempts never nest); `key.replace_retry(&retry)` swaps the registry's policy for that one handle.

`retry_layer()` uses the default `RetryPolicy` (6 attempts, 15 s deadline), made for background
work. A registry whose handles serve requests takes the request-path preset:

```rust
use anykms::RetryPolicy;

let registry = anykms::with_default_providers()?
    .layer(anykms::retry_layer().with_policy(RetryPolicy::interactive())) // 3 attempts, 2 s deadline
    .build()?;
```

The deadline bounds the retry schedule, not an attempt in flight, which can run to the
transport's request timeout (10 s by default, `ReqwestTransportBuilder::request_timeout`): lower
that, or wrap the call in `tokio::time::timeout`, for a hard bound.

## Configuring transit in code

To adjust the environment configuration in code, load it with `EnvConfig` and continue with the
`ServerConfig` builder:

```rust
use anykms::transit::anykms_http::ReqwestTransport;
use anykms::transit::{EnvConfig, TransitProvider};

let server = EnvConfig::vault()
    .no_home_token() // never fall back to ~/.vault-token
    // .no_token()   // behind a Vault/Bao Agent API proxy (or ANYKMS_TRANSIT_NO_TOKEN=1)
    .load()?
    .allowed_namespaces(["team-a"]) // key URIs may select it with ?namespace=team-a
    // TLS, timeouts and proxying live on the transport (replaces VAULT_CACERT & co. here).
    .http_transport(
        ReqwestTransport::builder()
            .request_timeout(std::time::Duration::from_secs(5))
            .build()?,
    );
let registry = anykms::Registry::builder()
    .provider(TransitProvider::builder().server("default", server).build()?)
    .layer(anykms::retry_layer())
    .build()?;
```

`EnvConfig` reads every setting from the prefix that supplied the address (`VAULT_*` or `BAO_*`,
never mixed), refuses `*_SKIP_VERIFY`, and accepts `*_CACERT` (a PEM file) or `*_CAPATH` (a
directory of PEM files). See the [`anykms-transit` docs](https://docs.rs/anykms-transit) for every
variable.

## Typed handles

Typed handles give compile-time capabilities:

```rust
use anykms::transit::TransitProvider;
use anykms::{MacAlgorithm, SignatureAlgorithm};

let transit = TransitProvider::from_env()?;
let uri = "hashivault:///transit/keys/app-kek"; // or a parsed `KeyUri`
let kek = transit.aead_key(uri)?;                                                // Aead + Rewrap + DataKeys + Describe
let jwt = transit.digest_signing_key(uri, SignatureAlgorithm::EcdsaP256Sha256)?; // DigestSigner + DigestVerifier + PublicKeys + Describe
let ed = transit.ed25519_key(uri)?;                                              // MessageSigner + MessageVerifier + PublicKeys + Describe
let tok = transit.mac_key(uri, MacAlgorithm::HmacSha256)?;                       // Mac + Describe
```

## Checking keys at startup

Opening a key does no I/O, so a key of the wrong type or a missing key shows up on first use.
`preflight()` on any registry or typed handle checks it now with one describe request: the key
exists, supports the handle's operation (and, for signers, its algorithm) and is not disabled
(`KeyStateInvalid`):

```rust
let kek = registry.aead("hashivault:///transit/keys/app-kek")?;
kek.preflight().await?; // KeyMismatch, KeyStateInvalid, NotFound, ... at startup
```

## Reaching the backend's API

An opaque handle reaches the backend's typed handle, and with it the backend's own API, with
`downcast_ref` (calls through it bypass layers such as retries):

```rust
use anykms::Preflight;
use anykms::transit::{TransitAeadKey, TransitKeyInfo};

if let Some(transit_kek) = kek.downcast_ref::<TransitAeadKey>() {
    let info = transit_kek.preflight().await?; // transit's own key-type and state check
    let native: Option<&TransitKeyInfo> = info.backend_info(); // transit's metadata
}
```

## Key URIs

```text
hashivault://[alias]/<mount path>/keys/<name>[?namespace=<ns>]
openbao://[alias]/<mount path>/keys/<name>[?namespace=<ns>]
aws-kms://arn:<partition>:kms:<region>:<account>:key/<id>      (or :alias/<name>)
gcp-kms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>[/cryptoKeyVersions/<n>]
azure-kv://<vault or managed HSM host>/keys/<name>[/<version>]
local://<keyset>/<name>
```

- Cloud URIs are fully addressed; each provider checks them against its allowlists
  (`allowed_accounts`/`allowed_regions`, `allowed_projects`/`allowed_locations`,
  `allowed_vaults`), and Azure sends tokens only to allowlisted vault hosts.

- `hashivault` and `openbao` are synonyms. The flavor is a property of the configured server, so
  moving from Vault to OpenBao never changes stored URIs.
- The authority is a **server alias**, never an address: a URI cannot send your token anywhere
  new. Use three slashes (`hashivault:///...`) for the default server.
- A URI namespace must match the configured namespace or appear in `allowed_namespaces`.
- `Registry` open methods take a `&str`, `String` or `KeyUri` (`registry.aead("...")`), with
  default options; the `*_with(uri, &opts)` variants take `OpenOptions` (key-type check, backend
  extensions). Signers, verifiers and public-key sources take their `SignatureAlgorithm`, and MAC
  keys their `MacAlgorithm`, as a parameter: `registry.digest_signer(uri, alg)`,
  `registry.mac_with(uri, alg, &opts)`. `RegistryBuilder::layer` and `handle.layer(&layer)`
  return the same handle type.
- `registry.key_wrap(uri)` opens a `KeyWrapKey`, the key-wrapping key an `EnvelopeAead` or
  `EnvelopeKeyring` takes. An AEAD key is never a KEK implicitly: a typed handle (or an opaque
  `AeadKey`) becomes one with `key.into_key_wrap()`, which wraps by encrypting with empty AAD.
- A custom `Layer` (metrics, tracing, auth) implements `part`, which receives every part of
  every handle, including parts added in later releases, so a new part is never silently left
  undecorated; or it implements `Around` and calls `part.wrap_around`.

## From synchronous code

The HTTP backends (transit, AWS, GCP, Azure) run on a Tokio runtime: called outside one, an
operation fails with `Configuration` and sends nothing. Synchronous code builds a `current_thread`
runtime once, keeps it next to the registry, and blocks on each call:

```toml
[dependencies]
anykms = { version = "0.1", features = ["transit"] }
tokio = { version = "1", features = ["rt"] }
```

```rust
use anykms::prelude::*;

let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
let registry = anykms::with_default_providers()?.build()?;
let kek = registry.key_wrap("hashivault:///transit-envelope/keys/app-kek")?;

let data_key = [7u8; 32];
let wrapped = rt.block_on(kek.wrap_key(&data_key))?;
assert_eq!(&*rt.block_on(kek.unwrap_key(&wrapped))?, &data_key);
```

`block_on` must not be called from inside another runtime (an `async fn`, a `#[tokio::main]`
program); there, `.await` the call instead.

## Ciphertexts as text

Ciphertexts are bytes. For a text column or JSON, encode them with `to_base64` (or
`to_base64_url`) and decode with the matching `from_base64` (a value that is not valid base64
fails with `DecryptFailed`, like corrupt ciphertext). `Signature` and `Tag` have the same methods
over their canonical encoding (`anykms::encoding`), which keeps the algorithm and key version so
they still verify after a rotation:

```rust
use anykms::Ciphertext;

let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
let column: String = ct.to_base64();
let ct = Ciphertext::from_base64(&column)?;

// Zeroizing<String>; a plaintext that is not UTF-8 is `InvalidArgument`.
let ssn = envelope.decrypt_utf8(&ct, b"users/42/ssn").await?;

// Which KEK version decrypted it, e.g. to find data due for a rewrap. (`used_primary()` stays
// `None` unless the backend reports it; transit and local do not.)
let d = envelope.decrypt_with_info(&ct, b"users/42/ssn").await?;
let version = d.key_version();
```

## JWTs and signatures

The KMS signs; the kid and the JWKS are local. Claims are any `serde` type. anykms signs and
publishes keys but does not validate tokens: verify them with a JWT library such as
[`jsonwebtoken`](https://docs.rs/jsonwebtoken) against the published JWKS.

```rust
use std::time::Duration;

use anykms::recipes::jose::{JwtOptions, JwtSigner};
use anykms::SignatureAlgorithm;

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims { sub: String, iss: String, aud: String }

let alg = SignatureAlgorithm::EcdsaP256Sha256;
let uri = "hashivault:///transit/keys/release";

// Issuer: the kid is `release.<version>`, cached, so each token costs one KMS sign.
let signer = JwtSigner::new(registry.digest_signer(uri, alg)?, "release");
let claims = Claims { sub: "42".into(), iss: "https://issuer.example".into(), aud: "api".into() };
let jwt = signer.sign(&claims, &JwtOptions::new().with_ttl(Duration::from_secs(300))).await?;

// Publish at /.well-known/jwks.json: the public key of every enabled version.
let jwks = signer.jwks().await?;

// Relying party, with jsonwebtoken (`rust_crypto` or `aws_lc_rs` feature): the key by kid, the
// algorithm pinned, exp (required by default), iss and aud checked.
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
let jwks: JwkSet = serde_json::from_value(jwks)?;
// (`ok_or_else(|| anyhow!(..))` works with anyhow; with `Box<dyn Error>`, `ok_or("..")` does too.)
let kid = decode_header(&jwt)?.kid.ok_or_else(|| anyhow::anyhow!("token has no kid"))?;
let key = DecodingKey::from_jwk(jwks.find(&kid).ok_or_else(|| anyhow::anyhow!("unknown kid"))?)?;
let mut validation = Validation::new(Algorithm::ES256);
validation.set_issuer(&["https://issuer.example"]);
validation.set_audience(&["api"]);
let claims: Claims = decode(&jwt, &key, &validation)?.claims;
```

Tokens expire by default: signing without `with_ttl` or an `exp` claim fails with
`InvalidArgument`, and a token that never expires (e.g. a release statement) needs
`JwtOptions::without_expiry()`.

Cache the JWKS: each `jwks()` costs a describe plus one public-key request per enabled version.
How to rotate without breaking tokens differs per backend (a new version on transit and GCP, a
new key and an alias repoint on AWS, whose JWKS then has to merge both keys during the overlap);
see [publishing and rotating](https://docs.rs/anykms-recipes/latest/anykms_recipes/jose/#publishing-the-jwks-and-rotating).

Ed25519 keys sign with `JwtSigner::sign_message`. jsonwebtoken verifies every algorithm anykms
signs with except ES512 (P-521). anykms signs and publishes; it does not verify tokens, which is
generic JWT logic a JWT library already does.

For raw signatures (not tokens), **local verifiers are pinned to one algorithm**, as a KMS verify handle is:
`LocalVerifier::new(public_key, alg)`, `CachedVerifier::new(source, alg)`, or
`LocalVerifier::for_key(public_key)` for ECDSA and Ed25519 keys, whose type implies the algorithm
(RSA keys admit several, so they need `new`). A signature naming another algorithm fails with
`InvalidArgument` before any cryptography, so an attacker cannot pick the algorithm (no `alg`
confusion). See the [`jose` docs](https://docs.rs/anykms-recipes/latest/anykms_recipes/jose/).

**After a rotation, `CachedVerifier` can reject the new version's first tokens for up to 500 ms**
(its refresh interval), also on a single node: a `kid` above the latest version it knows is
rejected without a lookup if it read the latest version within that interval, so forged kids
cost no backend request. The rejection is `InvalidArgument` with a `retry_hint`; wrap the verifier
in a retry layer with `RetryPolicy::with_retry_on_hint(true)`
(`retry_layer().with_policy(..).wrap(verifier)`) so the token verifies on the hinted retry. See
[operations](operations.md#replica-lag-and-retry_on_hint).

## Generic code and shared state

The capability traits use `async fn`, so they are not dyn compatible: `Box<dyn Aead>` fails with
E0038. Be generic over the trait, or hold an opaque handle (`AeadKey`, which is `Clone` and cheap
to clone) or `Arc<dyn DynAead>`. Add `?Sized` to accept the `dyn` form too. Every capability
trait requires `Send + Sync` and returns `Send` futures, so a generic key needs no extra bounds to
cross tasks: an `Arc<K>` with `K: Aead + 'static` moves into `tokio::spawn` as it is.

```rust
use std::sync::Arc;

use anykms::prelude::*;
use anykms::{AeadKey, Ciphertext, DynAead, Result};

async fn seal<A: Aead + ?Sized>(key: &A, field: &str, value: &str) -> Result<Ciphertext> {
    key.encrypt(value.as_bytes(), field.as_bytes()).await
}

#[derive(Clone)]
struct AppState {
    kek: AeadKey, // Send + Sync + 'static; share it across tasks by cloning, no Arc needed
}

let state = AppState { kek: registry.aead("hashivault:///transit/keys/app-kek")? };
seal(&state.kek, "users/42/ssn", "123-45-6789").await?;

let dynamic: Arc<dyn DynAead> = Arc::new(state.kek.clone()); // any handle, typed or opaque
seal(&*dynamic, "users/42/ssn", "123-45-6789").await?;
```

[`Registry`]: https://docs.rs/anykms-core/latest/anykms_core/struct.Registry.html
