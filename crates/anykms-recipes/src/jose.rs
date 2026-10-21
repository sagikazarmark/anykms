//! JOSE helpers for KMS keys: JWK/JWKS from KMS public keys, compact JWS signing and JWT
//! signing.
//!
//! **Emulates:** nothing; formats only. Signing is done by the KMS (`DigestSigner` hashes the
//! signing input locally, `MessageSigner` sends it for Ed25519).
//!
//! # Key ids
//!
//! The default `kid` is `<key name>.<version>` ([`kid`]), because a bare version collides across
//! keys. The version is the backend's: transit `1`, `2`, ...; GCP the version number; Azure 32
//! hex characters; **AWS KMS the full key ARN**, so an AWS kid such as
//! `jwt.arn:aws:kms:us-east-1:111122223333:key/1234abcd-...` names the account, region and key
//! id in every token and JWKS. A public key that carries no version gets the bare key name
//! ([`kid_for`]).
//!
//! # JWTs
//!
//! [`JwtSigner`] signs typed claims (any `Serialize`) with header `typ: "JWT"`, sets the `kid`
//! without a KMS round trip per token, and can add `iat` and `exp` ([`JwtOptions`]); [`sign_jwt`]
//! is the one-off form. [`JwtSigner::jwks`] (or [`jwks`] for any key) publishes the public keys
//! that verify them.
//!
//! Tokens expire by default: signing fails with `InvalidArgument` unless the options set a TTL
//! ([`JwtOptions::with_ttl`]) or the claims carry `exp`. A token that never expires (e.g. a release
//! or software statement) needs [`JwtOptions::without_expiry`], because some verifiers check `exp`
//! only when it is present and accept such a token forever.
//!
//! # Publishing the JWKS and rotating
//!
//! [`jwks`] costs a describe plus one public-key request per enabled version, so **cache the
//! JWKS** in the issuer (refresh it every few minutes and after a rotation) rather than calling it
//! for every request to `/.well-known/jwks.json`; relying parties cache it too, and refetch it,
//! rate-limited, on an unknown `kid`. A rotation needs an **overlap period**: publish the new key
//! at least one JWKS cache lifetime before tokens are signed with it, where the backend allows,
//! and keep the old key published until the last token it signed has expired plus that cache
//! lifetime. Per backend:
//!
//! - **Transit, and Azure unversioned URIs:** rotating adds a version, and the signer uses it
//!   at once; [`jwks`] lists every enabled version, so the old one stays published while it is
//!   enabled. Relying parties with a cached JWKS see the new `kid` as unknown until they refetch.
//!   Raise the minimum version (or disable the Azure version) only after the overlap.
//! - **GCP, and Azure pinned URIs:** signing URIs name a version, so create the new version,
//!   publish it ([`jwks`] lists every enabled version of the key, also through a pinned handle
//!   on GCP; on Azure use the unversioned URI), switch the signing URI once relying parties have
//!   it, and disable the old version after the overlap.
//! - **AWS:** asymmetric keys do not rotate; a rotation is a new key and an alias repoint. The
//!   JWKS of an alias handle is that of the key the alias points to, so after the repoint the old
//!   key's `kid` disappears from it and its tokens stop verifying. Publish both keys during the
//!   overlap, opened by their ARNs, by merging their JWKS:
//!
//! ```no_run
//! # async fn f(old: anykms_core::DigestSignerKey, new: anykms_core::DigestSignerKey)
//! #     -> anykms_core::Result<()> {
//! use anykms_core::DigestSigner as _;
//! use anykms_recipes::jose;
//!
//! let alg = new.signature_algorithm();
//! let mut published = jose::jwks(&new, "jwt", alg).await?;
//! let old_keys = jose::jwks(&old, "jwt", alg).await?;
//! if let (Some(keys), Some(more)) = (published["keys"].as_array_mut(), old_keys["keys"].as_array())
//! {
//!     keys.extend(more.iter().cloned());
//! }
//! # Ok(()) }
//! ```
//!
//! # JSON types
//!
//! JWKs, JWKS documents and headers are [`serde_json::Value`]s on purpose: they are open JSON
//! objects that callers usually extend or embed (e.g. into an OpenID discovery document),
//! `serde_json` is the de facto JSON crate with a stable 1.x API, and a newtype would only
//! re-expose the same value. The crate re-exports it as
//! [`anykms_recipes::serde_json`](crate::serde_json).
//!
//! # Verifying tokens
//!
//! This module signs and publishes; it does not verify. Verification (signature, algorithm
//! pinning, `exp`, `nbf`, `iss`, `aud`, `typ`) is generic JWT logic, not KMS-specific, so leave it
//! to a JWT library and verify tokens against the published JWKS, for example with
//! [`jsonwebtoken`](https://docs.rs/jsonwebtoken) (its `rust_crypto` or `aws_lc_rs` feature):
//!
//! ```no_run
//! # fn f(jwks_json: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
//! use jsonwebtoken::jwk::JwkSet;
//! use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
//!
//! #[derive(serde::Deserialize)]
//! struct Claims {
//!     sub: String,
//! }
//!
//! // The issuer's `jose::jwks`, e.g. fetched from /.well-known/jwks.json.
//! let jwks: JwkSet = serde_json::from_str(jwks_json)?;
//! let kid = decode_header(token)?.kid.ok_or("token has no kid")?;
//! let key = DecodingKey::from_jwk(jwks.find(&kid).ok_or("unknown kid")?)?;
//! // The algorithm is pinned, never taken from the token; `exp` is required by default.
//! let mut validation = Validation::new(Algorithm::ES256);
//! validation.set_issuer(&["https://issuer.example"]);
//! validation.set_audience(&["api"]);
//! let claims = decode::<Claims>(token, &key, &validation)?.claims;
//! # Ok(()) }
//! ```
//!
//! jsonwebtoken supports every algorithm here except ES512 (P-521), and names Ed25519 only
//! `"EdDSA"` (see [`JwsHeader::fully_specified_alg`]). [`jwt-simple`](https://docs.rs/jwt-simple)
//! accepts both (see the `anykms` crate's `jwt_signing_jwt_simple` example).
//!
//! # ECDSA malleability
//!
//! An `ES256`/`ES384`/`ES512` signature can be re-encoded by anyone holding the token (`(r, s)`
//! to `(r, n - s)`) into a different signature that verifies just as well, so the same claims can
//! arrive as different token strings. Not every KMS normalizes its signatures to low-S (Vault and
//! OpenBao transit do not), so relying parties should not deduplicate or look up tokens by their
//! bytes or signature (replay caches, revocation lists); use a claim such as `jti`.

use std::sync::Mutex;
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use anykms_core::{
    AsymmetricKeyType, Describe, DigestSigner, Error, ErrorKind, KeyState, KeyVersion,
    MessageSigner, Operation, PublicKey, PublicKeys, Result, Signature, SignatureAlgorithm,
};
use base64::Engine as _;
use serde::Serialize;
use serde_json::{Map, Value, json};
use spki::der::Decode as _;

use crate::ecdsa_der::{ecdsa_scalar_len, signature_to_fixed};
use crate::hashed;

const BACKEND: &str = "jose";
const URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn invalid(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, op, m)
}

fn now_unix() -> u64 {
    #[cfg(target_arch = "wasm32")]
    use web_time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The default key id: `<key name>.<version>`.
pub fn kid(key_name: &str, version: &KeyVersion) -> String {
    format!("{key_name}.{version}")
}

/// The key id for a public key: `<key name>.<version>` ([`kid`]) when it has a version, else the
/// bare key name (backends without versions).
pub fn kid_for(key_name: &str, key: &PublicKey) -> String {
    match key.key_version() {
        Some(v) => kid(key_name, v),
        None => key_name.to_owned(),
    }
}

/// The kid of a signature made by `key_name`: as [`kid_for`], from the signature's version.
fn kid_of_signature(key_name: &str, sig: &Signature) -> String {
    match sig.key_version() {
        Some(v) => kid(key_name, v),
        None => key_name.to_owned(),
    }
}

/// A JWK (RFC 7517) for a public key, as a JSON object (see [JSON types](self#json-types)). Needs
/// no RSA backend.
pub fn to_jwk(key: &PublicKey, kid: &str, alg: SignatureAlgorithm) -> Result<Value> {
    let op = Operation::PublicKey;
    if !alg.is_compatible_with(&key.key_type()) {
        return Err(Error::new(
            ErrorKind::KeyMismatch,
            BACKEND,
            op,
            "algorithm does not match the key type",
        ));
    }
    let spki = spki::SubjectPublicKeyInfoRef::from_der(key.spki_der())
        .map_err(|_| invalid(op, "malformed SPKI"))?;
    let raw = spki.subject_public_key.raw_bytes();
    let mut jwk = match key.key_type() {
        AsymmetricKeyType::EcP256 | AsymmetricKeyType::EcP384 | AsymmetricKeyType::EcP521 => {
            let (crv, n) = match key.key_type() {
                AsymmetricKeyType::EcP256 => ("P-256", 32),
                AsymmetricKeyType::EcP384 => ("P-384", 48),
                _ => ("P-521", 66),
            };
            if raw.len() != 1 + 2 * n || raw[0] != 0x04 {
                return Err(invalid(op, "expected an uncompressed EC point"));
            }
            json!({"kty": "EC", "crv": crv, "x": URL.encode(&raw[1..1 + n]), "y": URL.encode(&raw[1 + n..])})
        }
        AsymmetricKeyType::Ed25519 => json!({"kty": "OKP", "crv": "Ed25519", "x": URL.encode(raw)}),
        AsymmetricKeyType::Rsa { .. } => {
            let k = crate::rsa_backend::parse_rsa_spki(key.spki_der())
                .ok_or_else(|| invalid(op, "malformed RSA key"))?;
            json!({"kty": "RSA", "n": URL.encode(k.n), "e": URL.encode(k.e)})
        }
        _ => return Err(invalid(op, "unsupported key type")),
    };
    let obj = jwk.as_object_mut().expect("object");
    obj.insert("kid".into(), kid.into());
    obj.insert("use".into(), "sig".into());
    let name = alg
        .jws_alg()
        .ok_or_else(|| invalid(op, "algorithm has no JOSE name"))?;
    obj.insert("alg".into(), name.into());
    Ok(jwk)
}

/// A JWKS over the given versions of one key, with `kid = <key name>.<version>`. Prefer [`jwks`],
/// which finds the versions itself.
pub async fn jwks_from_versions<P: PublicKeys + ?Sized>(
    source: &P,
    key_name: &str,
    alg: SignatureAlgorithm,
    versions: &[KeyVersion],
) -> Result<Value> {
    let mut keys = Vec::with_capacity(versions.len());
    for v in versions {
        let pk = source.public_key_version(v).await?;
        // A source that answers with another version would publish the wrong key under this kid.
        if pk.key_version() != Some(v) {
            return Err(Error::new(
                ErrorKind::Backend,
                BACKEND,
                Operation::PublicKey,
                "public key source returned a different key version than requested",
            ));
        }
        keys.push(to_jwk(&pk, &kid(key_name, v), alg)?);
    }
    Ok(json!({ "keys": keys }))
}

/// The JWKS of a key: describes it and publishes the public key of every enabled version
/// (`kid = <key name>.<version>`). A key whose backend lists no versions publishes its current
/// public key under [`kid_for`]; a key that is not enabled publishes no keys.
///
/// `key` is any handle with public keys and describe, e.g. the `DigestSignerKey` you sign with:
///
/// ```no_run
/// # async fn f(signer: anykms_core::DigestSignerKey) -> anykms_core::Result<()> {
/// use anykms_core::DigestSigner as _;
/// let jwks = anykms_recipes::jose::jwks(&signer, "release", signer.signature_algorithm()).await?;
/// # Ok(()) }
/// ```
pub async fn jwks<K: PublicKeys + Describe + ?Sized>(
    key: &K,
    key_name: &str,
    alg: SignatureAlgorithm,
) -> Result<Value> {
    let info = key.describe().await?;
    if info.state().is_some_and(|s| *s != KeyState::Enabled) {
        return Ok(json!({ "keys": [] }));
    }
    if info.versions().is_empty() {
        let pk = key.public_key().await?;
        return Ok(json!({ "keys": [to_jwk(&pk, &kid_for(key_name, &pk), alg)?] }));
    }
    let versions: Vec<KeyVersion> = info
        .versions()
        .iter()
        .filter(|v| *v.state() == KeyState::Enabled)
        .map(|v| v.version().clone())
        .collect();
    jwks_from_versions(key, key_name, alg, &versions).await
}

/// The protected header of a JWS created by [`sign_jws_with`]: `alg` (from the signer), `kid`,
/// `typ` if set, and any extra fields.
#[derive(Clone, Debug)]
pub struct JwsHeader {
    kid: String,
    typ: Option<String>,
    fully_specified_alg: bool,
    extra: Map<String, Value>,
}

impl JwsHeader {
    /// A header with `kid` and no `typ`: a JWS is not necessarily a JWT, so it is not labelled
    /// one unless asked ([`with_typ`](Self::with_typ); [`JwtSigner`] sets `typ: "JWT"`).
    pub fn new(kid: impl Into<String>) -> Self {
        Self {
            kid: kid.into(),
            typ: None,
            fully_specified_alg: false,
            extra: Map::new(),
        }
    }

    /// Sets `typ` (e.g. `"at+jwt"`), or omits it with `None`.
    pub fn with_typ(mut self, typ: Option<&str>) -> Self {
        self.typ = typ.map(str::to_owned);
        self
    }

    /// Writes the fully-specified algorithm name of RFC 9864: `"Ed25519"` instead of the
    /// deprecated, polymorphic `"EdDSA"`. Other algorithms' names are already fully specified.
    /// Check that your verifiers accept it before enabling it (jsonwebtoken does not).
    pub fn fully_specified_alg(mut self) -> Self {
        self.fully_specified_alg = true;
        self
    }

    /// Adds a header field. `alg`, `kid`, `typ`, `crit` and `b64` cannot be set this way
    /// (signing fails with `InvalidArgument`): `b64` (RFC 7797) is only valid listed in `crit`,
    /// which is not supported.
    pub fn with_field(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(name.into(), value.into());
        self
    }

    fn encode(&self, alg: SignatureAlgorithm) -> Result<String> {
        let op = Operation::Sign;
        let name = match (alg, self.fully_specified_alg) {
            (SignatureAlgorithm::Ed25519, true) => "Ed25519",
            _ => alg
                .jws_alg()
                .ok_or_else(|| invalid(op, "algorithm has no JOSE name"))?,
        };
        if ["alg", "kid", "typ", "crit", "b64"]
            .iter()
            .any(|k| self.extra.contains_key(*k))
        {
            return Err(invalid(
                op,
                "alg, kid, typ, crit and b64 are set by the signer, not as extra header fields",
            ));
        }
        let mut h = self.extra.clone();
        h.insert("alg".into(), name.into());
        h.insert("kid".into(), self.kid.clone().into());
        if let Some(t) = &self.typ {
            h.insert("typ".into(), t.clone().into());
        }
        Ok(URL.encode(serde_json::to_vec(&Value::Object(h)).expect("serializes")))
    }
}

fn jws_signature_bytes(sig: &Signature) -> Result<Vec<u8>> {
    if ecdsa_scalar_len(sig.algorithm()).is_some() {
        signature_to_fixed(sig)
    } else {
        Ok(sig.as_bytes().to_vec())
    }
}

fn signing_input(header: &JwsHeader, alg: SignatureAlgorithm, payload: &[u8]) -> Result<String> {
    Ok(format!("{}.{}", header.encode(alg)?, URL.encode(payload)))
}

fn compact(input: String, sig: &Signature) -> Result<String> {
    Ok(format!("{input}.{}", URL.encode(jws_signature_bytes(sig)?)))
}

/// Compact JWS signed by an ECDSA or RSA KMS key, with header `{alg, kid}`. The signing input is
/// hashed locally. `payload` is signed as is; for a JWT, use [`JwtSigner`] (which sets
/// `typ: "JWT"`).
pub async fn sign_jws<S: DigestSigner + ?Sized>(
    signer: &S,
    kid: &str,
    payload: &[u8],
) -> Result<String> {
    sign_jws_with(signer, &JwsHeader::new(kid), payload).await
}

/// [`sign_jws`] with a custom header.
pub async fn sign_jws_with<S: DigestSigner + ?Sized>(
    signer: &S,
    header: &JwsHeader,
    payload: &[u8],
) -> Result<String> {
    let input = signing_input(header, signer.signature_algorithm(), payload)?;
    let sig = hashed::sign_message_hashed(signer, input.as_bytes()).await?;
    compact(input, &sig)
}

/// Compact JWS signed by an Ed25519 KMS key (`alg: EdDSA`), with header `{alg, kid}`.
pub async fn sign_jws_message<S: MessageSigner + ?Sized>(
    signer: &S,
    kid: &str,
    payload: &[u8],
) -> Result<String> {
    sign_jws_message_with(signer, &JwsHeader::new(kid), payload).await
}

/// [`sign_jws_message`] with a custom header.
pub async fn sign_jws_message_with<S: MessageSigner + ?Sized>(
    signer: &S,
    header: &JwsHeader,
    payload: &[u8],
) -> Result<String> {
    let input = signing_input(header, signer.signature_algorithm(), payload)?;
    let sig = signer.sign_message(input.as_bytes()).await?;
    compact(input, &sig)
}

/// How [`JwtSigner`] and [`sign_jwt`] build a token around the claims.
///
/// Defaults: header `{alg, kid, typ: "JWT"}`, claims unchanged, the system clock, and an expiry
/// required: without [`with_ttl`](Self::with_ttl) the claims must carry `exp`, unless
/// [`without_expiry`](Self::without_expiry) is set. `Default` is the same as [`new`](Self::new).
#[derive(Clone, Debug, Default)]
pub struct JwtOptions {
    ttl: Option<Duration>,
    without_expiry: bool,
    issued_at: bool,
    typ: Option<Option<String>>,
    fully_specified_alg: bool,
    fields: Map<String, Value>,
    now: Option<u64>,
}

impl JwtOptions {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `iat` to now and `exp` to now plus `ttl` (whole seconds).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self.issued_at = true;
        self
    }

    /// Allows tokens without `exp`, which never expire (e.g. release or software statements).
    /// Without this, signing fails with `InvalidArgument` when no TTL is set and the claims carry
    /// no `exp`. A TTL or an `exp` claim still sets an expiry.
    pub fn without_expiry(mut self) -> Self {
        self.without_expiry = true;
        self
    }

    /// Sets `iat` to now.
    pub fn with_issued_at(mut self) -> Self {
        self.issued_at = true;
        self
    }

    /// Sets the header's `typ` (e.g. `"at+jwt"`), or omits it with `None` (default `"JWT"`, unlike
    /// [`JwsHeader::new`]).
    pub fn with_typ(mut self, typ: Option<&str>) -> Self {
        self.typ = Some(typ.map(str::to_owned));
        self
    }

    /// Writes `"Ed25519"` instead of `"EdDSA"` ([`JwsHeader::fully_specified_alg`]).
    pub fn fully_specified_alg(mut self) -> Self {
        self.fully_specified_alg = true;
        self
    }

    /// Adds a header field (same restrictions as [`JwsHeader::with_field`]).
    pub fn with_header_field(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.fields.insert(name.into(), value.into());
        self
    }

    /// Uses `unix_seconds` as the current time instead of the system clock (for tests). On
    /// `wasm32-unknown-unknown` the clock is `Date.now()` via `web_time`.
    pub fn with_now(mut self, unix_seconds: u64) -> Self {
        self.now = Some(unix_seconds);
        self
    }

    fn header(&self, kid: &str) -> JwsHeader {
        let typ = match &self.typ {
            Some(typ) => typ.as_deref(),
            None => Some("JWT"),
        };
        let mut h = JwsHeader::new(kid).with_typ(typ);
        if self.fully_specified_alg {
            h = h.fully_specified_alg();
        }
        h.extra = self.fields.clone();
        h
    }

    /// The JSON payload: the claims (which must serialize to a JSON object) plus `iat`/`exp`.
    /// Refuses a payload without `exp` unless [`without_expiry`](Self::without_expiry) is set.
    fn payload(&self, claims: &(impl Serialize + ?Sized)) -> Result<Vec<u8>> {
        let op = Operation::Sign;
        let Value::Object(mut obj) = serde_json::to_value(claims)
            .map_err(|_| invalid(op, "JWT claims do not serialize to JSON"))?
        else {
            return Err(invalid(op, "JWT claims must serialize to a JSON object"));
        };
        let now = self.now.unwrap_or_else(now_unix);
        let mut set = |name: &str, value: u64| {
            if obj.contains_key(name) {
                return Err(invalid(
                    op,
                    "JWT claims already contain a time claim the options set (iat or exp)",
                ));
            }
            obj.insert(name.to_owned(), value.into());
            Ok(())
        };
        if self.issued_at {
            set("iat", now)?;
        }
        if let Some(ttl) = self.ttl {
            set("exp", now.saturating_add(ttl.as_secs()))?;
        } else if !self.without_expiry && obj.get("exp").is_none_or(Value::is_null) {
            // `"exp": null` (an `Option` field left `None`) sets no expiry either.
            return Err(invalid(
                op,
                "JWT would never expire: set a TTL with JwtOptions::with_ttl (or an exp claim), \
                 or call JwtOptions::without_expiry() to sign a token without exp",
            ));
        }
        Ok(serde_json::to_vec(&Value::Object(obj)).expect("serializes"))
    }
}

/// The kid a [`JwtSigner`] last used, shared by its signing calls and its clones.
#[derive(Clone, Debug, Default)]
struct KidCache(std::sync::Arc<Mutex<Option<String>>>);

impl KidCache {
    fn get(&self) -> Option<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn set(&self, kid: String) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(kid);
    }

    /// The cached kid, or the current public key's ([`kid_for`]).
    async fn kid<P: PublicKeys + ?Sized>(&self, source: &P, key_name: &str) -> Result<String> {
        if let Some(k) = self.get() {
            return Ok(k);
        }
        let kid = kid_for(key_name, &source.public_key().await?);
        self.set(kid.clone());
        Ok(kid)
    }

    /// Checks that `sig` was made by the version `kid` names. If not (the key was rotated since
    /// the kid was read), remembers the signature's kid and returns it for one more attempt.
    fn settle(&self, key_name: &str, kid: &str, sig: &Signature) -> Option<String> {
        let actual = kid_of_signature(key_name, sig);
        if actual == kid {
            return None;
        }
        self.set(actual.clone());
        Some(actual)
    }
}

/// The error when the key version changed between two signing attempts.
fn rotated() -> Error {
    Error::new(
        ErrorKind::Unavailable,
        BACKEND,
        Operation::Sign,
        "the signing key version changed during two consecutive signing attempts",
    )
}

async fn sign_jwt_digest<S: DigestSigner + PublicKeys + ?Sized>(
    signer: &S,
    key_name: &str,
    cache: &KidCache,
    claims: &(impl Serialize + ?Sized),
    options: &JwtOptions,
) -> Result<String> {
    let payload = options.payload(claims)?;
    let alg = signer.signature_algorithm();
    let mut kid = cache.kid(signer, key_name).await?;
    for _ in 0..2 {
        let input = signing_input(&options.header(&kid), alg, &payload)?;
        let sig = hashed::sign_message_hashed(signer, input.as_bytes()).await?;
        match cache.settle(key_name, &kid, &sig) {
            None => return compact(input, &sig),
            Some(actual) => kid = actual,
        }
    }
    Err(rotated())
}

async fn sign_jwt_message_inner<S: MessageSigner + PublicKeys + ?Sized>(
    signer: &S,
    key_name: &str,
    cache: &KidCache,
    claims: &(impl Serialize + ?Sized),
    options: &JwtOptions,
) -> Result<String> {
    let payload = options.payload(claims)?;
    let alg = signer.signature_algorithm();
    let mut kid = cache.kid(signer, key_name).await?;
    for _ in 0..2 {
        let input = signing_input(&options.header(&kid), alg, &payload)?;
        let sig = signer.sign_message(input.as_bytes()).await?;
        match cache.settle(key_name, &kid, &sig) {
            None => return compact(input, &sig),
            Some(actual) => kid = actual,
        }
    }
    Err(rotated())
}

/// Signs JWTs with one KMS key, setting `kid` to `<key name>.<version>` ([`kid_for`]) without a
/// KMS round trip per token.
///
/// The first token reads the key's current public key to learn its version; later tokens reuse
/// that kid. Every signature reports the version that made it, so after a rotation the first
/// token signed with the new version is detected, re-signed once with the new kid, and the new kid
/// is used from then on: a token's kid always names the version that signed it. Keys without
/// versions use the bare key name.
///
/// ```no_run
/// # async fn f(signer: anykms_core::DigestSignerKey) -> anykms_core::Result<()> {
/// use anykms_recipes::jose::{JwtOptions, JwtSigner};
/// use std::time::Duration;
///
/// let jwt_signer = JwtSigner::new(signer, "release");
/// let claims = anykms_recipes::serde_json::json!({"sub": "42", "iss": "https://issuer"});
/// let jwt = jwt_signer
///     .sign(&claims, &JwtOptions::new().with_ttl(Duration::from_secs(300)))
///     .await?;
/// // The JWKS verifiers fetch, e.g. served at /.well-known/jwks.json.
/// let jwks = jwt_signer.jwks().await?;
/// # Ok(()) }
/// ```
///
/// Cloning (when `S` is `Clone`, as key handles are) is cheap, and clones share the cached kid.
#[derive(Clone, Debug)]
pub struct JwtSigner<S> {
    signer: S,
    key_name: String,
    kid: KidCache,
}

impl<S> JwtSigner<S> {
    /// Signs with `signer`, the key named `key_name` (the kid prefix).
    pub fn new(signer: S, key_name: impl Into<String>) -> Self {
        Self {
            signer,
            key_name: key_name.into(),
            kid: KidCache::default(),
        }
    }

    /// The signing key handle.
    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// The key name used in kids.
    pub fn key_name(&self) -> &str {
        &self.key_name
    }
}

impl<S: DigestSigner + PublicKeys> JwtSigner<S> {
    /// Signs `claims` (which must serialize to a JSON object) with an ECDSA or RSA key.
    /// `InvalidArgument` if they do not, if they already contain a claim `options` sets, or if the
    /// token would carry no `exp` and `options` does not allow it ([`JwtOptions::without_expiry`]).
    pub async fn sign(
        &self,
        claims: &(impl Serialize + Sync + ?Sized),
        options: &JwtOptions,
    ) -> Result<String> {
        sign_jwt_digest(&self.signer, &self.key_name, &self.kid, claims, options).await
    }
}

impl<S: DigestSigner + PublicKeys + Describe> JwtSigner<S> {
    /// The JWKS that verifies this signer's tokens: [`jwks`] with its key name and the signer's
    /// algorithm.
    pub async fn jwks(&self) -> Result<Value> {
        jwks(
            &self.signer,
            &self.key_name,
            self.signer.signature_algorithm(),
        )
        .await
    }
}

impl<S: MessageSigner + PublicKeys + Describe> JwtSigner<S> {
    /// [`jwks`](Self::jwks) for an Ed25519 key.
    pub async fn jwks_message(&self) -> Result<Value> {
        jwks(
            &self.signer,
            &self.key_name,
            self.signer.signature_algorithm(),
        )
        .await
    }
}

impl<S: MessageSigner + PublicKeys> JwtSigner<S> {
    /// [`sign`](Self::sign) with an Ed25519 key.
    pub async fn sign_message(
        &self,
        claims: &(impl Serialize + Sync + ?Sized),
        options: &JwtOptions,
    ) -> Result<String> {
        sign_jwt_message_inner(&self.signer, &self.key_name, &self.kid, claims, options).await
    }
}

/// Signs one JWT with an ECDSA or RSA key ([`JwtSigner::sign`]). Reads the key's public key for
/// the kid first, one extra KMS request: keep a [`JwtSigner`] to sign more than one token.
pub async fn sign_jwt<S: DigestSigner + PublicKeys + ?Sized>(
    signer: &S,
    key_name: &str,
    claims: &(impl Serialize + Sync + ?Sized),
    options: &JwtOptions,
) -> Result<String> {
    sign_jwt_digest(signer, key_name, &KidCache::default(), claims, options).await
}

/// [`sign_jwt`] with an Ed25519 key.
pub async fn sign_jwt_message<S: MessageSigner + PublicKeys + ?Sized>(
    signer: &S,
    key_name: &str,
    claims: &(impl Serialize + Sync + ?Sized),
    options: &JwtOptions,
) -> Result<String> {
    sign_jwt_message_inner(signer, key_name, &KidCache::default(), claims, options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_signer_clones_share_the_kid() {
        let a = JwtSigner::new((), "k");
        let b = a.clone();
        a.kid.set("k.2".into());
        assert_eq!(b.kid.get().as_deref(), Some("k.2"));
    }

    #[test]
    fn every_algorithm_has_a_jose_name() {
        for alg in SignatureAlgorithm::ALL {
            assert!(alg.jws_alg().is_some(), "{alg}");
        }
    }

    #[test]
    fn jwt_options_set_time_claims_and_refuse_conflicts() {
        let o = JwtOptions::new()
            .with_now(1000)
            .with_ttl(Duration::from_secs(60));
        let p: Value = serde_json::from_slice(&o.payload(&json!({"sub": "42"})).unwrap()).unwrap();
        assert_eq!(p, json!({"sub": "42", "iat": 1000, "exp": 1060}));
        let p: Value = serde_json::from_slice(
            &JwtOptions::new()
                .with_now(5)
                .with_issued_at()
                .without_expiry()
                .payload(&json!({}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(p, json!({"iat": 5}));
        // Untouched without options.
        let p: Value =
            serde_json::from_slice(&JwtOptions::new().payload(&json!({"exp": 7})).unwrap())
                .unwrap();
        assert_eq!(p, json!({"exp": 7}));
        // No TTL and no exp claim (or a null one): refused unless the caller opts out.
        for (o, claims) in [
            (JwtOptions::new(), json!({"sub": "42"})),
            (JwtOptions::default().with_issued_at(), json!({"sub": "42"})),
            (JwtOptions::new(), json!({"sub": "42", "exp": null})),
        ] {
            let e = o.payload(&claims).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument);
            let m = e.to_string();
            assert!(
                m.contains("with_ttl") && m.contains("without_expiry()"),
                "{m}"
            );
        }
        let p: Value = serde_json::from_slice(
            &JwtOptions::new()
                .without_expiry()
                .payload(&json!({"sub": "42"}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(p, json!({"sub": "42"}));
        for (claims, kind) in [
            (json!({"exp": 1}), ErrorKind::InvalidArgument),
            (json!({"iat": 1}), ErrorKind::InvalidArgument),
            (json!([1]), ErrorKind::InvalidArgument),
            (json!("x"), ErrorKind::InvalidArgument),
        ] {
            assert_eq!(o.payload(&claims).unwrap_err().kind(), kind, "{claims}");
        }
    }
}
