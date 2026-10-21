//! Typed key handles.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anykms_core::{
    Aead, AsymmetricKeyType, Ciphertext, Decrypted, Describe, Digest, DigestSigner, DigestVerifier,
    Error, ErrorKind, KeyInfo, KeyTypeCheck, KeyVersion, KeyWrap, Mac, MacAlgorithm, MessageSigner,
    MessageVerifier, Operation, Preflight, PublicKey, PublicKeys, Result, Signature,
    SignatureAlgorithm, Tag,
};
use anykms_http::cache::SingleFlight;
use anykms_http::http::Method;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::client::{Call, Client};
use crate::keyinfo::{Alg, GcpKeyInfo, KeyJson, ListJson, VersionJson, map_algorithm};
use crate::uri::GcpKeyRef;
use crate::wire::{
    b64, bad_response, body, check_crc, check_verified, crc, decode, decode_secret, int64,
};

/// The most a plaintext, AAD, MAC input or Ed25519 message may hold (Cloud KMS's documented
/// 64 KiB; HSM keys have lower limits, which the server enforces).
pub(crate) const MAX_INPUT: usize = 64 * 1024;

/// How long a passed key-type check is trusted before it runs again. Each entry gets ±10%
/// jitter, so keys opened together do not all re-check in the same instant.
const TYPE_CACHE_TTL: Duration = Duration::from_secs(600);

/// The most pages of versions `describe` reads (1000 versions each).
const MAX_LIST_PAGES: usize = 100;

/// The most input versions the negative public-key cache remembers (P1-13).
const MAX_UNKNOWN_VERSIONS: usize = 64;

/// Where a request's key version came from. It decides two things:
///
/// - **P1-4:** only a request that addressed the handle's own key or version ([`Handle`],
///   [`Ciphertext`]) may drop its cached checks; a version taken from input never does, so a
///   forged version cannot force a check on every caller.
/// - **A3:** a version that is not enabled is `KeyStateInvalid` when the handle chose it
///   ([`Handle`]) and `KeyVersionUnusable` when the input did ([`Ciphertext`], [`Input`]); a
///   missing input version is `UnknownKeyVersion` ([`Input`] only).
///
/// [`Handle`]: Origin::Handle
/// [`Ciphertext`]: Origin::Ciphertext
/// [`Input`]: Origin::Input
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The handle's key, or the version it chose (its URI pin, or the primary version the server
    /// encrypts with): the key-type checks, encrypt, sign, MAC, RSA wrap and unwrap,
    /// `public_key()`, describe.
    Handle,
    /// The handle's key, with the version the server takes from the ciphertext (symmetric
    /// decrypt; the version is opaque to the client).
    Ciphertext,
    /// A version taken from input: a signature's or tag's version (verify, MAC verification),
    /// `public_key_version`.
    Input,
}

/// A version's public key, as fetched and checked.
#[derive(Clone)]
pub(crate) struct VersionKey {
    pub(crate) key: PublicKey,
    pub(crate) alg: Alg,
}

/// State shared by every handle of one provider.
pub(crate) struct Shared {
    pub(crate) client: Client,
    /// Passed key-type checks: check id → expiry.
    checks: Mutex<HashMap<String, Instant>>,
    /// One run at a time of each check for concurrent misses (R-34), by check id.
    check_flights: SingleFlight<String, Result<()>>,
    /// Public keys per version resource name: (expiry, key). The expiry counts from the fetch
    /// (`public_key_ttl`, jittered), not from the last use.
    public_keys: Mutex<HashMap<String, (Instant, VersionKey)>>,
    /// Input versions refused by the version-state lookup or `getPublicKey`
    /// (`UnknownKeyVersion`, or `KeyVersionUnusable` without a retry hint), per version resource
    /// name: (expiry, the error). At most [`MAX_UNKNOWN_VERSIONS`], each for `public_key_ttl`,
    /// so a forged or disabled version costs at most one request per TTL.
    unknown_versions: Mutex<HashMap<String, (Instant, Error)>>,
    pub(crate) public_key_ttl: Duration,
    /// The handles' semantics (verification depends on `public_key_ttl`).
    pub(crate) semantics: crate::semantics::GcpSemantics,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("client", &self.client)
            .field("public_key_ttl", &self.public_key_ttl)
            .finish_non_exhaustive()
    }
}

impl Shared {
    pub(crate) fn new(client: Client, public_key_ttl: Duration) -> Self {
        Self {
            client,
            checks: Mutex::default(),
            check_flights: SingleFlight::new(),
            public_keys: Mutex::default(),
            unknown_versions: Mutex::default(),
            public_key_ttl,
            semantics: crate::semantics::GcpSemantics::new(public_key_ttl),
        }
    }
}

/// Everything a handle needs to reach one key.
#[derive(Clone)]
pub(crate) struct KeyCtx {
    pub(crate) shared: Arc<Shared>,
    pub(crate) key: GcpKeyRef,
    pub(crate) base: Arc<anykms_http::url::Url>,
    pub(crate) check: KeyTypeCheck,
    /// `gcp-kms://...` as opened, attached to every error of the handle.
    pub(crate) resource: Arc<str>,
}

impl std::fmt::Debug for KeyCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKey")
            .field("key", &self.key)
            .field(
                "endpoint",
                &anykms_http::redact::url_origin(self.base.as_str()),
            )
            .field("key_type_check", &self.check)
            .finish()
    }
}

fn invalid(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, op, m)
}

fn mismatch(op: Operation, m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::KeyMismatch, BACKEND, op, m)
}

fn other_key(op: Operation) -> Error {
    crate::errors::unusable_response(op, Some(200), "response for another key")
}

fn check_size(len: usize, op: Operation, what: &'static str) -> Result<()> {
    if len > MAX_INPUT {
        return Err(invalid(op, what));
    }
    Ok(())
}

/// The algorithm of a signing handle as a Cloud KMS digest field name.
fn digest_field(h: anykms_core::HashAlgorithm, op: Operation) -> Result<&'static str> {
    use anykms_core::HashAlgorithm as H;
    match h {
        H::Sha256 => Ok("sha256"),
        H::Sha384 => Ok("sha384"),
        H::Sha512 => Ok("sha512"),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            BACKEND,
            op,
            "hash algorithm is not supported by Cloud KMS",
        )),
    }
}

impl KeyCtx {
    /// Names this key on `e`, unless an inner layer already named a resource.
    pub(crate) fn label(&self, e: Error) -> Error {
        if e.resource().is_some() {
            e
        } else {
            e.with_resource(&*self.resource)
        }
    }

    /// Runs one handle operation, labeling any error with the key's resource.
    pub(crate) async fn scoped<T>(&self, f: impl Future<Output = Result<T>>) -> Result<T> {
        f.await.map_err(|e| self.label(e))
    }

    /// The pinned version (signing, MAC and RSA KEK handles are opened only with one).
    fn pinned(&self) -> u64 {
        self.key.version().expect("versioned at open")
    }

    fn call(
        &self,
        method: Method,
        version: Option<u64>,
        verb: Option<&'static str>,
        body: Option<Zeroizing<Vec<u8>>>,
        op: Operation,
    ) -> Call<'_> {
        Call {
            method,
            base: &self.base,
            key: &self.key,
            resource: &self.resource,
            version,
            collection: None,
            verb,
            query: Vec::new(),
            body,
            op,
            origin: Origin::Handle,
        }
    }

    /// Sends a call. Errors that may mean the key was deleted, recreated or reconfigured
    /// (`NotFound`, `KeyMismatch`, `Unsupported`, `KeyStateInvalid`) drop this key's cached
    /// checks so the next operation checks again, but only for requests that addressed the
    /// handle's own key or version ([`Origin::Handle`], [`Origin::Ciphertext`]): a version taken
    /// from input (a forged signature version) never drops them, so it cannot force a check on
    /// every caller. `origin` also classifies version errors (see [`Origin`]).
    async fn send(&self, mut call: Call<'_>, origin: Origin) -> Result<Zeroizing<Vec<u8>>> {
        call.origin = origin;
        let r = self.shared.client.call(call).await;
        if let Err(e) = &r
            && origin != Origin::Input
            && matches!(
                e.kind(),
                ErrorKind::NotFound
                    | ErrorKind::KeyMismatch
                    | ErrorKind::Unsupported
                    | ErrorKind::KeyStateInvalid
            )
        {
            self.forget_checks();
        }
        r
    }

    fn check_id(&self, what: &str) -> String {
        format!("{}|{what}", self.key.resource_name())
    }

    fn checked(&self, what: &str) -> bool {
        let now = Instant::now();
        self.shared
            .checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&self.check_id(what))
            .is_some_and(|exp| now < *exp)
    }

    fn mark_checked(&self, what: &str) {
        let now = Instant::now();
        let mut c = self
            .shared
            .checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.retain(|_, exp| now < *exp);
        c.insert(
            self.check_id(what),
            now + anykms_http::cache::jittered_ttl(TYPE_CACHE_TTL),
        );
    }

    fn forget_checks(&self) {
        let prefix = format!("{}|", self.key.resource_name());
        self.shared
            .checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|k, _| !k.starts_with(&prefix));
    }

    /// `cryptoKeys.get`.
    async fn get_key(&self, op: Operation) -> Result<KeyJson> {
        let body = self
            .send(self.call(Method::GET, None, None, None, op), Origin::Handle)
            .await?;
        let k: KeyJson = serde_json::from_slice(&body).map_err(|_| bad_response(op))?;
        if k.name != self.key.key_name() {
            return Err(other_key(op));
        }
        Ok(k)
    }

    /// `cryptoKeyVersions.get` of version `v`: the pinned version (the MAC key-type check), or
    /// any version before its public key is fetched (§3.1(f), `origin` as the version's).
    async fn get_version(&self, v: u64, op: Operation, origin: Origin) -> Result<VersionJson> {
        let body = self
            .send(self.call(Method::GET, Some(v), None, None, op), origin)
            .await?;
        let j: VersionJson = serde_json::from_slice(&body).map_err(|_| bad_response(op))?;
        if j.name != self.key.version_name(v) {
            return Err(other_key(op));
        }
        Ok(j)
    }

    /// An input version's lookup found nothing: Cloud KMS answers "CryptoKeyVersion … not found"
    /// whether the version or the whole key is missing (§24.4 probe T1), so one `cryptoKeys.get`
    /// tells them apart. A missing key is `NotFound`, as for every other request on it; anything
    /// else (the key exists, or the lookup cannot tell) keeps `e`. A cached public key of another
    /// version already shows the key exists and skips the request, so with the cache a forged
    /// version costs the lookup alone; without it (`public_key_ttl` zero, or a cold cache) it
    /// costs two requests, as many as an honest uncached verification.
    async fn missing_key_or(&self, e: Error, op: Operation) -> Error {
        let prefix = format!("{}/cryptoKeyVersions/", self.key.key_name());
        let now = Instant::now();
        let known = self
            .shared
            .public_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|(name, (expires, _))| now < *expires && name.starts_with(&prefix));
        if known {
            return e;
        }
        match self
            .send(self.call(Method::GET, None, None, None, op), Origin::Handle)
            .await
        {
            Err(k) if k.kind() == ErrorKind::NotFound => k,
            _ => e,
        }
    }

    /// `cryptoKeyVersions.list`, every page.
    async fn list_versions(&self, op: Operation) -> Result<Vec<VersionJson>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let mut call = self.call(Method::GET, None, None, None, op);
            call.collection = Some("cryptoKeyVersions");
            call.query.push(("pageSize", "1000".to_owned()));
            if let Some(t) = token.take() {
                call.query.push(("pageToken", t));
            }
            let body = self.send(call, Origin::Handle).await?;
            let page: ListJson = serde_json::from_slice(&body).map_err(|_| bad_response(op))?;
            let prefix = format!("{}/cryptoKeyVersions/", self.key.key_name());
            if page
                .crypto_key_versions
                .iter()
                .any(|v| !v.name.starts_with(&prefix))
            {
                return Err(other_key(op));
            }
            out.extend(page.crypto_key_versions);
            match page.next_page_token.filter(|t| !t.is_empty()) {
                Some(t) => token = Some(t),
                None => return Ok(out),
            }
        }
        Err(crate::errors::unusable_response(
            op,
            Some(200),
            "too many key versions to list",
        ))
    }

    /// The key's metadata.
    pub(crate) async fn info(&self, op: Operation) -> Result<GcpKeyInfo> {
        let key = self.get_key(op).await?;
        let versions = self.list_versions(op).await?;
        Ok(GcpKeyInfo::new(key, &versions, self.key.version()))
    }

    /// The public key of version `v`, from the cache or, on a miss, `cryptoKeyVersions.get` and
    /// then `getPublicKey` (P1-13, §3.1(f)). An entry expires `public_key_ttl` (jittered) after
    /// its fetch, whatever its use; a re-fetch that fails does not extend it: the call fails
    /// with the re-fetch's error. A fetch that finds the version unusable or missing drops the
    /// cached entry.
    ///
    /// **Disabled versions (§3.1(f)).** Before `getPublicKey`, the version's state must be
    /// `ENABLED`: Cloud KMS may serve the public key of a disabled version, and `CachedVerifier`
    /// relies on the refusal. (§24.4 probe T1, 2026-10: Cloud KMS refuses it too, with "is not
    /// enabled"; the lookup is kept so the check does not rest on undocumented behavior.) Another
    /// state is `KeyStateInvalid` for the handle's version and `KeyVersionUnusable` for an input
    /// version. The lookup fails closed: without `cloudkms.cryptoKeyVersions.get` it is
    /// `PermissionDenied`, and no public key is fetched.
    ///
    /// **Negative cache.** The lookup of an input version has the input's origin (it never drops
    /// the handle's checks), and an input version it refuses (`UnknownKeyVersion`, or
    /// `KeyVersionUnusable` without a retry hint) is remembered for the same TTL (at most
    /// [`MAX_UNKNOWN_VERSIONS`]), so a forged or disabled version costs at most one request per
    /// TTL.
    pub(crate) async fn version_key(
        &self,
        v: u64,
        op: Operation,
        origin: Origin,
    ) -> Result<VersionKey> {
        let name = self.key.version_name(v);
        let ttl = self.shared.public_key_ttl;
        if !ttl.is_zero() {
            let now = Instant::now();
            let cache = self
                .shared
                .public_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((expires, k)) = cache.get(&name)
                && now < *expires
            {
                return Ok(k.clone());
            }
            drop(cache);
            if origin == Origin::Input {
                let unknown = self
                    .shared
                    .unknown_versions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some((expires, e)) = unknown.get(&name)
                    && now < *expires
                {
                    return Err(e.clone().with_operation(op));
                }
            }
        }
        match self.fetch_public_key(v, &name, op, origin).await {
            Ok(k) => {
                if !ttl.is_zero() {
                    let now = Instant::now();
                    let mut cache = self
                        .shared
                        .public_keys
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    cache.retain(|_, (expires, _)| now < *expires);
                    cache.insert(
                        name.clone(),
                        (now + anykms_http::cache::jittered_ttl(ttl), k.clone()),
                    );
                    drop(cache);
                    self.shared
                        .unknown_versions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&name);
                }
                Ok(k)
            }
            Err(e) => {
                if matches!(
                    e.kind(),
                    ErrorKind::KeyVersionUnusable
                        | ErrorKind::KeyStateInvalid
                        | ErrorKind::UnknownKeyVersion
                        | ErrorKind::NotFound
                ) {
                    self.shared
                        .public_keys
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&name);
                }
                if origin == Origin::Input
                    && matches!(
                        e.kind(),
                        ErrorKind::UnknownKeyVersion | ErrorKind::KeyVersionUnusable
                    )
                    && e.retry_hint().is_none()
                    && !ttl.is_zero()
                {
                    self.remember_unknown(name, &e, ttl);
                }
                Err(e)
            }
        }
    }

    /// Remembers an input version that was refused (see
    /// [`version_key`](Self::version_key)), evicting the entry closest to expiry when full.
    fn remember_unknown(&self, name: String, e: &Error, ttl: Duration) {
        let now = Instant::now();
        let mut unknown = self
            .shared
            .unknown_versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unknown.retain(|_, (expires, _)| now < *expires);
        if unknown.len() >= MAX_UNKNOWN_VERSIONS
            && !unknown.contains_key(&name)
            && let Some(oldest) = unknown
                .iter()
                .min_by_key(|(_, (expires, _))| *expires)
                .map(|(k, _)| k.clone())
        {
            unknown.remove(&oldest);
        }
        unknown.insert(
            name,
            (now + anykms_http::cache::jittered_ttl(ttl), e.clone()),
        );
    }

    async fn fetch_public_key(
        &self,
        v: u64,
        name: &str,
        op: Operation,
        origin: Origin,
    ) -> Result<VersionKey> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            pem: String,
            algorithm: String,
            #[serde(default, deserialize_with = "int64")]
            pem_crc32c: Option<u64>,
            name: String,
            #[serde(default)]
            protection_level: String,
        }
        // §3.1(f): never hand out the public key of a version that is not enabled.
        let state = match self.get_version(v, op, origin).await {
            Err(e) if e.kind() == ErrorKind::UnknownKeyVersion => {
                return Err(self.missing_key_or(e, op).await);
            }
            r => r?,
        };
        if state.name != name {
            return Err(other_key(op));
        }
        if state.state != "ENABLED" {
            return Err(crate::errors::version_not_enabled(op, &state.state, origin));
        }
        // `GET .../cryptoKeyVersions/<n>/publicKey` (a sub-resource, not a `:verb`).
        let mut call = self.call(Method::GET, Some(v), None, None, op);
        call.collection = Some("publicKey");
        let body = self.send(call, origin).await?;
        let r: Resp = serde_json::from_slice(&body).map_err(|_| bad_response(op))?;
        check_crc(r.pem.as_bytes(), r.pem_crc32c, op, "pemCrc32c")?;
        if r.name != name {
            return Err(other_key(op));
        }
        if matches!(r.protection_level.as_str(), "EXTERNAL" | "EXTERNAL_VPC") {
            return Err(mismatch(
                op,
                "Cloud EKM (EXTERNAL, EXTERNAL_VPC) asymmetric keys are not supported (Cloud EKM \
                 signs data, not digests)",
            ));
        }
        let alg = map_algorithm(&r.algorithm);
        let expected = match alg {
            Alg::Sign(_, t) => t,
            Alg::OaepSha256(bits) => AsymmetricKeyType::Rsa { bits },
            _ if r.algorithm.starts_with("RSA_DECRYPT_") => {
                return Err(mismatch(
                    op,
                    "the key version is not an RSA_DECRYPT_OAEP_*_SHA256 key (RSA key wrapping \
                     needs OAEP with SHA-256)",
                ));
            }
            _ => {
                return Err(mismatch(
                    op,
                    "the key version's algorithm is not supported by anykms",
                ));
            }
        };
        let der = anykms_recipes::pem_to_der(&r.pem).map_err(|_| bad_response(op))?;
        let actual = anykms_recipes::spki_key_type(&der).map_err(|_| bad_response(op))?;
        if actual != expected {
            return Err(crate::errors::unusable_response(
                op,
                Some(200),
                "public key does not match its algorithm",
            ));
        }
        Ok(VersionKey {
            key: PublicKey::new(actual, der, Some(KeyVersion::from_u64(v))),
            alg,
        })
    }

    /// Runs the key-type check now, whatever the cache and the opt-out say, and caches a pass.
    async fn recheck(&self, check: Check, op: Operation) -> Result<()> {
        check.run(self, op).await?;
        self.mark_checked(&check.id());
        Ok(())
    }

    /// Runs the key-type check once (cached) unless the caller opted out. Concurrent misses for
    /// the check share one run and its result, a failure included.
    async fn ensure(&self, check: Check, op: Operation) -> Result<()> {
        let id = check.id();
        if self.check == KeyTypeCheck::TrustCaller || self.checked(&id) {
            return Ok(());
        }
        self.shared
            .check_flights
            .run(&self.check_id(&id), || async {
                // A flight that landed after the miss above has cached a pass.
                if self.checked(&id) {
                    return Ok(());
                }
                check.run(self, op).await?;
                self.mark_checked(&id);
                Ok(())
            })
            .await
            // The flight may have been another operation's.
            .map_err(|e| e.with_operation(op))
    }
}

/// The key-type checks.
#[derive(Clone, Copy, Debug)]
enum Check {
    /// `cryptoKeys.get`: `purpose == ENCRYPT_DECRYPT`.
    Aead,
    /// `getPublicKey` on the pinned version (which also seeds the public-key cache).
    Signing(SignatureAlgorithm),
    /// `cryptoKeyVersions.get` on the pinned version.
    Mac(MacAlgorithm),
    /// `getPublicKey` on the pinned version: an `RSA_DECRYPT_OAEP_*_SHA256` key.
    KeyWrap,
}

impl Check {
    fn id(self) -> String {
        match self {
            Check::Aead => "aead".to_owned(),
            Check::Signing(a) => format!("sign:{}", a.as_str()),
            Check::Mac(m) => format!("mac:{}", m.as_str()),
            Check::KeyWrap => "keywrap".to_owned(),
        }
    }

    async fn run(self, k: &KeyCtx, op: Operation) -> Result<()> {
        match self {
            Check::Aead => {
                let key = k.get_key(op).await?;
                match key.purpose.as_str() {
                    "ENCRYPT_DECRYPT" => Ok(()),
                    "RAW_ENCRYPT_DECRYPT" => Err(mismatch(
                        op,
                        "RAW_ENCRYPT_DECRYPT keys (raw AES with caller-managed IVs) are not \
                         supported; use an ENCRYPT_DECRYPT key",
                    )),
                    "ASYMMETRIC_DECRYPT" => Err(mismatch(
                        op,
                        "ASYMMETRIC_DECRYPT keys are RSA key-wrapping keys: open a version with \
                         key_wrap, not aead",
                    )),
                    _ => Err(mismatch(op, "the key's purpose is not ENCRYPT_DECRYPT")),
                }
            }
            Check::Signing(alg) => {
                let vk = k.version_key(k.pinned(), op, Origin::Handle).await?;
                signing_alg_matches(&vk, alg, op)
            }
            Check::Mac(alg) => {
                let v = k.get_version(k.pinned(), op, Origin::Handle).await?;
                match map_algorithm(&v.algorithm) {
                    Alg::Mac(m) if m == alg => Ok(()),
                    Alg::Mac(_) => Err(mismatch(
                        op,
                        "the key version's HMAC algorithm does not match the asserted MAC \
                         algorithm",
                    )),
                    Alg::Unmapped { planned: true } => Err(mismatch(
                        op,
                        "the key version's algorithm is not supported by anykms yet",
                    )),
                    _ => Err(mismatch(op, "the key version is not an HMAC key")),
                }
            }
            Check::KeyWrap => {
                let vk = k.version_key(k.pinned(), op, Origin::Handle).await?;
                oaep_alg_matches(&vk, op)
            }
        }
    }
}

fn signing_alg_matches(vk: &VersionKey, alg: SignatureAlgorithm, op: Operation) -> Result<()> {
    match vk.alg {
        Alg::Sign(a, _) if a == alg => Ok(()),
        Alg::Sign(..) => Err(mismatch(
            op,
            "the key version's algorithm does not match the asserted signature algorithm",
        )),
        _ => Err(mismatch(op, "the key version is not a signing key")),
    }
}

// ---------------------------------------------------------------------------------------------
// AEAD

/// A Cloud KMS `ENCRYPT_DECRYPT` key (`GOOGLE_SYMMETRIC_ENCRYPTION` at any protection level, or
/// `EXTERNAL_SYMMETRIC_ENCRYPTION`): [`Aead`] (with [`decrypt_with_info`](Aead::decrypt_with_info)
/// reporting `used_primary`) and [`Describe`].
///
/// Encrypt uses the primary version; decrypt finds the version itself, so the URI never names a
/// version. Ciphertexts are Cloud KMS's own (opaque: [`ciphertext_version`](Aead::ciphertext_version)
/// is `None`), readable by other Cloud KMS clients with the same AAD.
///
/// **Not native:** `Rewrap` and `DataKeys` (an `AeadKey` from the provider reports
/// `Unsupported` before any I/O). Use `EnvelopeAead::rewrap_local` or `ClientRewrap` and
/// `EmulatedDataKeys` from `anykms-recipes` explicitly.
///
/// **Envelope KEKs:** a key used as the KEK of `EnvelopeAead` MUST be dedicated to envelopes:
/// data keys are wrapped with empty AAD, so any other code that decrypts with empty AAD under the
/// same key could unwrap them.
#[derive(Clone, Debug)]
pub struct GcpAeadKey {
    pub(crate) k: KeyCtx,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptReq<'a> {
    plaintext: &'a str,
    plaintext_crc32c: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data_crc32c: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptResp {
    name: String,
    ciphertext: String,
    #[serde(default, deserialize_with = "int64")]
    ciphertext_crc32c: Option<u64>,
    #[serde(default)]
    verified_plaintext_crc32c: bool,
    #[serde(default)]
    verified_additional_authenticated_data_crc32c: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecryptReq<'a> {
    ciphertext: &'a str,
    ciphertext_crc32c: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data_crc32c: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptResp<'a> {
    #[serde(default, borrow)]
    plaintext: std::borrow::Cow<'a, str>,
    #[serde(default, deserialize_with = "int64")]
    plaintext_crc32c: Option<u64>,
    #[serde(default)]
    used_primary: bool,
}

fn opt_len(s: Option<&Zeroizing<String>>) -> usize {
    s.map_or(0, |s| s.len())
}

/// Builds an encrypt request body (also used by the fuzz hook).
fn encrypt_body(plaintext: &[u8], aad: &[u8]) -> Zeroizing<Vec<u8>> {
    let pt = b64(plaintext);
    let ad = (!aad.is_empty()).then(|| b64(aad));
    let req = EncryptReq {
        plaintext: &pt,
        plaintext_crc32c: crc(plaintext),
        additional_authenticated_data: ad.as_deref().map(String::as_str),
        additional_authenticated_data_crc32c: (!aad.is_empty()).then(|| crc(aad)),
    };
    body(&req, pt.len() + opt_len(ad.as_ref()))
}

/// Checks and decodes an encrypt response for `key_name`.
fn encrypt_result(
    resp: &[u8],
    key_name: &str,
    aad_sent: bool,
    op: Operation,
) -> Result<(Ciphertext, Option<u64>)> {
    let r: EncryptResp = serde_json::from_slice(resp).map_err(|_| bad_response(op))?;
    check_verified(r.verified_plaintext_crc32c, op, "verifiedPlaintextCrc32c")?;
    if aad_sent {
        check_verified(
            r.verified_additional_authenticated_data_crc32c,
            op,
            "verifiedAdditionalAuthenticatedDataCrc32c",
        )?;
    }
    let version = r
        .name
        .strip_prefix(key_name)
        .and_then(|s| s.strip_prefix("/cryptoKeyVersions/"))
        .and_then(crate::uri::parse_version)
        .ok_or_else(|| other_key(op))?;
    let ct = decode(&r.ciphertext, op)?;
    if ct.is_empty() {
        return Err(bad_response(op));
    }
    check_crc(&ct, r.ciphertext_crc32c, op, "ciphertextCrc32c")?;
    Ok((Ciphertext::from_bytes(ct), Some(version)))
}

/// Checks and decodes a decrypt response: the plaintext and `usedPrimary`.
fn decrypt_result(resp: &[u8], op: Operation) -> Result<(Zeroizing<Vec<u8>>, bool)> {
    let r: DecryptResp<'_> = serde_json::from_slice(resp).map_err(|_| bad_response(op))?;
    let used_primary = r.used_primary;
    let crc32c = r.plaintext_crc32c;
    let pt = decode_secret(r.plaintext, op)?;
    check_crc(&pt, crc32c, op, "plaintextCrc32c")?;
    Ok((pt, used_primary))
}

impl GcpAeadKey {
    /// Sets the key-type check (default [`KeyTypeCheck::Describe`]).
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    async fn decrypt_raw(&self, ct: &Ciphertext, aad: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool)> {
        let op = Operation::Decrypt;
        if ct.is_empty() {
            return Err(Error::new(
                ErrorKind::DecryptFailed,
                BACKEND,
                op,
                "decryption failed",
            ));
        }
        check_size(aad.len(), op, "AAD exceeds Cloud KMS's 64 KiB limit")?;
        self.k.ensure(Check::Aead, op).await?;
        let c = b64(ct.as_bytes());
        let ad = (!aad.is_empty()).then(|| b64(aad));
        let req = DecryptReq {
            ciphertext: &c,
            ciphertext_crc32c: crc(ct.as_bytes()),
            additional_authenticated_data: ad.as_deref().map(String::as_str),
            additional_authenticated_data_crc32c: (!aad.is_empty()).then(|| crc(aad)),
        };
        // The ciphertext's version is opaque to the client; the request addresses the key.
        let resp = self
            .k
            .send(
                self.k.call(
                    Method::POST,
                    None,
                    Some("decrypt"),
                    Some(body(&req, c.len() + opt_len(ad.as_ref()))),
                    op,
                ),
                Origin::Ciphertext,
            )
            .await?;
        decrypt_result(&resp, op)
    }
}

impl Preflight for GcpAeadKey {
    /// Runs the key-type check now (it otherwise runs before the first operation) and returns
    /// the key's metadata, with the backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        let check: Result<()> = async {
            self.k
                .scoped(self.k.recheck(Check::Aead, Operation::Describe))
                .await
        }
        .await;
        check?;
        Describe::describe(self).await
    }
}

impl Aead for GcpAeadKey {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::Encrypt;
                check_size(
                    plaintext.len(),
                    op,
                    "plaintext exceeds Cloud KMS's 64 KiB limit; use EnvelopeAead for bulk data",
                )?;
                check_size(aad.len(), op, "AAD exceeds Cloud KMS's 64 KiB limit")?;
                self.k.ensure(Check::Aead, op).await?;
                let resp = self
                    .k
                    .send(
                        self.k.call(
                            Method::POST,
                            None,
                            Some("encrypt"),
                            Some(encrypt_body(plaintext, aad)),
                            op,
                        ),
                        Origin::Handle,
                    )
                    .await?;
                // The request span records the version (`Client::call`).
                let (ct, _) = encrypt_result(&resp, &self.k.key.key_name(), !aad.is_empty(), op)?;
                Ok(ct)
            })
            .await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.k
            .scoped(async { Ok(self.decrypt_raw(ct, aad).await?.0) })
            .await
    }

    /// Cloud KMS ciphertexts are opaque: always `Ok(None)`. Use
    /// [`decrypt_with_info`](Aead::decrypt_with_info) and its `used_primary` to find data on
    /// older versions.
    fn ciphertext_version(&self, _ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        Ok(None)
    }

    /// Decrypts and reports `used_primary` (`DecryptResponse.usedPrimary`); the key version
    /// stays `None` (Cloud KMS does not report it).
    async fn decrypt_with_info(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Decrypted> {
        self.k
            .scoped(async {
                let (pt, primary) = self.decrypt_raw(ct, aad).await?;
                Ok(Decrypted::new(pt).with_used_primary(Some(primary)))
            })
            .await
    }
}

impl Describe for GcpAeadKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Signing

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignDigestReq<'a> {
    digest: HashMap<&'static str, &'a str>,
    digest_crc32c: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignDataReq<'a> {
    data: &'a str,
    data_crc32c: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignResp {
    name: String,
    signature: String,
    #[serde(default, deserialize_with = "int64")]
    signature_crc32c: Option<u64>,
    #[serde(default)]
    verified_digest_crc32c: bool,
    #[serde(default)]
    verified_data_crc32c: bool,
}

/// Plausible signature lengths for `alg` (DER ECDSA bands per curve, 64 bytes for Ed25519, the
/// modulus size for RSA).
fn signature_shape_ok(
    alg: SignatureAlgorithm,
    key_type: Option<AsymmetricKeyType>,
    sig: &[u8],
) -> bool {
    use SignatureAlgorithm::{EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, Ed25519};
    let der =
        |min: usize, max: usize| sig.len() >= min && sig.len() <= max && sig.first() == Some(&0x30);
    match alg {
        EcdsaP256Sha256 => der(8, 72),
        EcdsaP384Sha384 => der(73, 104),
        EcdsaP521Sha512 => der(105, 141),
        Ed25519 => sig.len() == 64,
        _ => match key_type {
            Some(AsymmetricKeyType::Rsa { bits }) => sig.len() * 8 == bits as usize,
            _ => sig.len() >= 256 && sig.len().is_multiple_of(128),
        },
    }
}

/// Checks and decodes an `asymmetricSign` response for `version_name`.
fn sign_result(
    resp: &[u8],
    version_name: &str,
    alg: SignatureAlgorithm,
    key_type: Option<AsymmetricKeyType>,
    digest: bool,
    op: Operation,
) -> Result<Vec<u8>> {
    let r: SignResp = serde_json::from_slice(resp).map_err(|_| bad_response(op))?;
    if digest {
        check_verified(r.verified_digest_crc32c, op, "verifiedDigestCrc32c")?;
    } else {
        check_verified(r.verified_data_crc32c, op, "verifiedDataCrc32c")?;
    }
    if r.name != version_name {
        return Err(other_key(op));
    }
    let sig = decode(&r.signature, op)?;
    check_crc(&sig, r.signature_crc32c, op, "signatureCrc32c")?;
    if !signature_shape_ok(alg, key_type, &sig) {
        return Err(mismatch(
            op,
            "signature does not match the asserted algorithm (key version type changed?)",
        ));
    }
    Ok(sig)
}

async fn sign_raw(k: &KeyCtx, alg: SignatureAlgorithm, input: SignInput<'_>) -> Result<Signature> {
    let op = Operation::Sign;
    k.ensure(Check::Signing(alg), op).await?;
    let v = k.pinned();
    let (req, digest) = match input {
        SignInput::Digest(d) => {
            let field = digest_field(d.algorithm(), op)?;
            let enc = b64(d.as_bytes());
            let mut m = HashMap::new();
            m.insert(field, enc.as_str());
            (
                body(
                    &SignDigestReq {
                        digest: m,
                        digest_crc32c: crc(d.as_bytes()),
                    },
                    enc.len(),
                ),
                true,
            )
        }
        SignInput::Message(msg) => {
            let enc = b64(msg);
            (
                body(
                    &SignDataReq {
                        data: &enc,
                        data_crc32c: crc(msg),
                    },
                    enc.len(),
                ),
                false,
            )
        }
    };
    let resp = k
        .send(
            k.call(Method::POST, Some(v), Some("asymmetricSign"), Some(req), op),
            Origin::Handle,
        )
        .await?;
    let key_type = k.cached_key_type(v);
    let sig = match sign_result(&resp, &k.key.version_name(v), alg, key_type, digest, op) {
        Ok(s) => s,
        Err(e) => {
            if e.kind() == ErrorKind::KeyMismatch {
                k.forget_checks();
            }
            return Err(e);
        }
    };
    Ok(Signature::from_parts(
        alg,
        Some(KeyVersion::from_u64(v)),
        sig,
    ))
}

enum SignInput<'a> {
    Digest(&'a Digest),
    Message(&'a [u8]),
}

impl KeyCtx {
    /// The key type of version `v`, if its public key is cached.
    fn cached_key_type(&self, v: u64) -> Option<AsymmetricKeyType> {
        self.shared
            .public_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&self.key.version_name(v))
            .map(|(_, k)| k.key.key_type())
    }
}

/// A version taken from a signature or tag that this key does not have: the signature or tag
/// does not verify (A3(a)); the original error stays as the source.
fn unknown_version_fails_verification(e: Error, op: Operation, what: &'static str) -> Error {
    if e.kind() == ErrorKind::UnknownKeyVersion {
        let mut out = Error::new(ErrorKind::VerificationFailed, BACKEND, op, what);
        if let Some(d) = e.detail() {
            out = out.with_detail(d.clone());
        }
        out.with_source(e)
    } else {
        e
    }
}

/// The signature's version, which must be decimal (it names a version of this key only).
fn signature_version(sig: &Signature, op: Operation) -> Result<u64> {
    sig.key_version()
        .and_then(|v| crate::uri::parse_version(v.as_str()))
        .ok_or_else(|| {
            invalid(
                op,
                "verification needs the signature's decimal key version (Cloud KMS version \
                 number)",
            )
        })
}

/// Verifies locally with the public key of the signature's version of this key.
async fn verify_local(
    k: &KeyCtx,
    alg: SignatureAlgorithm,
    input: SignInput<'_>,
    sig: &Signature,
) -> Result<()> {
    let op = Operation::Verify;
    if sig.algorithm() != alg {
        return Err(invalid(
            op,
            "signature algorithm does not match the key handle",
        ));
    }
    let v = signature_version(sig, op)?;
    let vk = k.version_key(v, op, Origin::Input).await.map_err(|e| {
        unknown_version_fails_verification(
            e,
            op,
            "the signature names a key version this key does not have",
        )
    })?;
    if signing_alg_matches(&vk, alg, op).is_err() {
        return Err(Error::new(
            ErrorKind::VerificationFailed,
            BACKEND,
            op,
            "the signature's key version uses another algorithm",
        ));
    }
    let verifier =
        anykms_recipes::LocalVerifier::new(vk.key, alg).map_err(|e| e.with_operation(op))?;
    let r = match input {
        SignInput::Digest(d) => verifier.verify_digest(d, sig).await,
        SignInput::Message(m) => verifier.verify_message(m, sig).await,
    };
    r.map_err(|e| {
        if e.kind() == ErrorKind::VerificationFailed {
            Error::new(
                ErrorKind::VerificationFailed,
                BACKEND,
                op,
                "signature verification failed",
            )
        } else {
            e.with_operation(op)
        }
    })
}

async fn public_key_raw(
    k: &KeyCtx,
    alg: SignatureAlgorithm,
    version: Option<&KeyVersion>,
) -> Result<PublicKey> {
    let op = Operation::PublicKey;
    let (v, origin) = match version {
        None => (k.pinned(), Origin::Handle),
        Some(v) => (
            crate::uri::parse_version(v.as_str())
                .ok_or_else(|| invalid(op, "Cloud KMS key versions are decimal numbers"))?,
            Origin::Input,
        ),
    };
    let vk = k.version_key(v, op, origin).await?;
    // Checked even under `KeyTypeCheck::TrustCaller`: it costs no I/O, and a key of another
    // algorithm is never labeled with the asserted one.
    signing_alg_matches(&vk, alg, op)?;
    Ok(vk.key)
}

/// A Cloud KMS `ASYMMETRIC_SIGN` key version for ECDSA (P-256, P-384) or RSA (PSS, PKCS#1 v1.5):
/// [`DigestSigner`], [`DigestVerifier`], [`PublicKeys`] and [`Describe`].
///
/// The URI must name a version (`.../cryptoKeyVersions/N`): Cloud KMS signing keys have no
/// primary version. Signatures carry that version as their `key_version`.
///
/// **Verification is local.** **Emulates:** a server-side verify. **Enforced by:** this process,
/// with the public key of the signature's version of *this* key (`cryptoKeyVersions.get`, which
/// must report `ENABLED`, then `getPublicKey`; cached for `public_key_ttl`, default 60 s) and
/// `LocalVerifier` from `anykms-recipes`. A disabled or destroyed version stops verifying once
/// its cached public key expires (Cloud KMS takes about a minute to propagate a disable); a
/// signature naming a version this key does not have is `VerificationFailed`.
///
/// **Public keys** of a disabled version are refused: `public_key()` (the pinned version) with
/// `KeyStateInvalid`, `public_key_version` with `KeyVersionUnusable`. Reading them needs
/// `cloudkms.cryptoKeyVersions.get` besides `viewPublicKey`.
///
/// **PSS vs PKCS#1:** the algorithm is bound to the key version. The key-type check
/// (`getPublicKey`, default) refuses a mismatch with `KeyMismatch`; under
/// `KeyTypeCheck::TrustCaller` a PSS handle on a PKCS#1 key would return PKCS#1 signatures
/// labeled PSS (they then fail to verify).
#[derive(Clone, Debug)]
pub struct GcpDigestKey {
    pub(crate) k: KeyCtx,
    pub(crate) alg: SignatureAlgorithm,
}

impl GcpDigestKey {
    /// Sets the key-type check (default [`KeyTypeCheck::Describe`]).
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    fn check_digest(&self, d: &Digest, op: Operation) -> Result<()> {
        if Some(d.algorithm()) != self.alg.hash() {
            return Err(invalid(
                op,
                "digest algorithm does not match the signature algorithm",
            ));
        }
        Ok(())
    }
}

impl Preflight for GcpDigestKey {
    /// Runs the key-type check now (it otherwise runs before the first operation) and returns
    /// the key's metadata, with the backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        let check: Result<()> = async {
            self.k
                .scoped(
                    self.k
                        .recheck(Check::Signing(self.alg), Operation::Describe),
                )
                .await
        }
        .await;
        check?;
        Describe::describe(self).await
    }
}

impl anykms_core::PinnedVerifier for GcpDigestKey {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl DigestSigner for GcpDigestKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        self.k
            .scoped(async {
                self.check_digest(digest, Operation::Sign)?;
                sign_raw(&self.k, self.alg, SignInput::Digest(digest)).await
            })
            .await
    }
}

impl DigestVerifier for GcpDigestKey {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        self.k
            .scoped(async {
                self.check_digest(digest, Operation::Verify)?;
                verify_local(&self.k, self.alg, SignInput::Digest(digest), sig).await
            })
            .await
    }
}

impl PublicKeys for GcpDigestKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k.scoped(public_key_raw(&self.k, self.alg, None)).await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(public_key_raw(&self.k, self.alg, Some(version)))
            .await
    }
}

impl Describe for GcpDigestKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

/// A Cloud KMS `EC_SIGN_ED25519` key version (pure Ed25519, software keys only):
/// [`MessageSigner`], [`MessageVerifier`], [`PublicKeys`] and [`Describe`].
///
/// The URI must name a version. Messages up to 64 KiB are sent (the exact Cloud KMS limit is
/// undocumented; larger ones may be refused by the server with `InvalidArgument`).
/// Verification is local, as on [`GcpDigestKey`].
#[derive(Clone, Debug)]
pub struct GcpEd25519Key {
    pub(crate) k: KeyCtx,
}

impl GcpEd25519Key {
    /// Sets the key-type check (default [`KeyTypeCheck::Describe`]).
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }
}

impl Preflight for GcpEd25519Key {
    /// Runs the key-type check now (it otherwise runs before the first operation) and returns
    /// the key's metadata, with the backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        let check: Result<()> = async {
            self.k
                .scoped(self.k.recheck(
                    Check::Signing(SignatureAlgorithm::Ed25519),
                    Operation::Describe,
                ))
                .await
        }
        .await;
        check?;
        Describe::describe(self).await
    }
}

impl anykms_core::PinnedVerifier for GcpEd25519Key {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}

impl MessageSigner for GcpEd25519Key {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        self.k
            .scoped(async {
                check_size(msg.len(), Operation::Sign, "message exceeds 64 KiB")?;
                sign_raw(
                    &self.k,
                    SignatureAlgorithm::Ed25519,
                    SignInput::Message(msg),
                )
                .await
            })
            .await
    }
}

impl MessageVerifier for GcpEd25519Key {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.k
            .scoped(verify_local(
                &self.k,
                SignatureAlgorithm::Ed25519,
                SignInput::Message(msg),
                sig,
            ))
            .await
    }
}

impl PublicKeys for GcpEd25519Key {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k
            .scoped(public_key_raw(&self.k, SignatureAlgorithm::Ed25519, None))
            .await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(public_key_raw(
                &self.k,
                SignatureAlgorithm::Ed25519,
                Some(version),
            ))
            .await
    }
}

impl Describe for GcpEd25519Key {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// MAC

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacSignResp {
    name: String,
    mac: String,
    #[serde(default, deserialize_with = "int64")]
    mac_crc32c: Option<u64>,
    #[serde(default)]
    verified_data_crc32c: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MacVerifyReq<'a> {
    data: &'a str,
    data_crc32c: String,
    mac: &'a str,
    mac_crc32c: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacVerifyResp {
    name: String,
    #[serde(default)]
    success: bool,
    #[serde(default)]
    verified_data_crc32c: bool,
    #[serde(default)]
    verified_mac_crc32c: bool,
    #[serde(default)]
    verified_success_integrity: bool,
}

/// Checks and decodes a `macSign` response.
fn mac_sign_result(
    resp: &[u8],
    version_name: &str,
    alg: MacAlgorithm,
    op: Operation,
) -> Result<Vec<u8>> {
    let r: MacSignResp = serde_json::from_slice(resp).map_err(|_| bad_response(op))?;
    check_verified(r.verified_data_crc32c, op, "verifiedDataCrc32c")?;
    if r.name != version_name {
        return Err(other_key(op));
    }
    let tag = decode(&r.mac, op)?;
    check_crc(&tag, r.mac_crc32c, op, "macCrc32c")?;
    if tag.len() != alg.tag_len() {
        return Err(mismatch(
            op,
            "tag length does not match the asserted MAC algorithm (key version type changed?)",
        ));
    }
    Ok(tag)
}

/// Checks a `macVerify` response: `Ok(success)`.
fn mac_verify_result(resp: &[u8], version_name: &str, op: Operation) -> Result<bool> {
    let r: MacVerifyResp = serde_json::from_slice(resp).map_err(|_| bad_response(op))?;
    check_verified(r.verified_data_crc32c, op, "verifiedDataCrc32c")?;
    check_verified(r.verified_mac_crc32c, op, "verifiedMacCrc32c")?;
    if r.success != r.verified_success_integrity {
        return Err(crate::errors::integrity_failure(
            op,
            "verifiedSuccessIntegrity",
        ));
    }
    if r.name != version_name {
        return Err(other_key(op));
    }
    Ok(r.success)
}

/// A Cloud KMS `MAC` key version (`HMAC_SHA256/384/512`): [`Mac`] and [`Describe`].
///
/// The URI must name a version. `mac` signs with it (`macSign`); `verify_mac` verifies on the
/// server (`macVerify`) with the version the tag names, which must be a version of this key.
/// Every tag's length is checked against the algorithm, even under `KeyTypeCheck::TrustCaller`.
#[derive(Clone, Debug)]
pub struct GcpMacKey {
    pub(crate) k: KeyCtx,
    pub(crate) alg: MacAlgorithm,
}

impl GcpMacKey {
    /// Sets the key-type check (default [`KeyTypeCheck::Describe`]).
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }
}

impl Preflight for GcpMacKey {
    /// Runs the key-type check now (it otherwise runs before the first operation) and returns
    /// the key's metadata, with the backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        let check: Result<()> = async {
            self.k
                .scoped(self.k.recheck(Check::Mac(self.alg), Operation::Describe))
                .await
        }
        .await;
        check?;
        Describe::describe(self).await
    }
}

impl Mac for GcpMacKey {
    fn mac_algorithm(&self) -> MacAlgorithm {
        self.alg
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        self.k
            .scoped(async {
                let op = Operation::Mac;
                check_size(data.len(), op, "MAC input exceeds Cloud KMS's 64 KiB limit")?;
                self.k.ensure(Check::Mac(self.alg), op).await?;
                let v = self.k.pinned();
                let enc = b64(data);
                let req = body(
                    &SignDataReq {
                        data: &enc,
                        data_crc32c: crc(data),
                    },
                    enc.len(),
                );
                let resp = self
                    .k
                    .send(
                        self.k
                            .call(Method::POST, Some(v), Some("macSign"), Some(req), op),
                        Origin::Handle,
                    )
                    .await?;
                let tag = mac_sign_result(&resp, &self.k.key.version_name(v), self.alg, op)
                    .inspect_err(|e| {
                        if e.kind() == ErrorKind::KeyMismatch {
                            self.k.forget_checks();
                        }
                    })?;
                Ok(Tag::from_parts(
                    self.alg,
                    Some(KeyVersion::from_u64(v)),
                    tag,
                ))
            })
            .await
    }

    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
        self.k
            .scoped(async {
                let op = Operation::VerifyMac;
                if tag.algorithm() != self.alg {
                    return Err(invalid(op, "tag algorithm does not match the key handle"));
                }
                if tag.as_bytes().len() != self.alg.tag_len() {
                    // A truncated or padded tag is a tag that does not verify.
                    return Err(Error::new(
                        ErrorKind::VerificationFailed,
                        BACKEND,
                        op,
                        "MAC verification failed",
                    ));
                }
                let v = tag
                    .key_version()
                    .and_then(|v| crate::uri::parse_version(v.as_str()))
                    .ok_or_else(|| {
                        invalid(op, "verification needs the tag's decimal key version")
                    })?;
                check_size(data.len(), op, "MAC input exceeds Cloud KMS's 64 KiB limit")?;
                self.k.ensure(Check::Mac(self.alg), op).await?;
                let enc = b64(data);
                let mac = b64(tag.as_bytes());
                let req = body(
                    &MacVerifyReq {
                        data: &enc,
                        data_crc32c: crc(data),
                        mac: &mac,
                        mac_crc32c: crc(tag.as_bytes()),
                    },
                    enc.len() + mac.len(),
                );
                // The tag's version: input.
                let resp = self
                    .k
                    .send(
                        self.k
                            .call(Method::POST, Some(v), Some("macVerify"), Some(req), op),
                        Origin::Input,
                    )
                    .await
                    .map_err(|e| {
                        unknown_version_fails_verification(
                            e,
                            op,
                            "the tag names a key version this key does not have",
                        )
                    })?;
                if mac_verify_result(&resp, &self.k.key.version_name(v), op)? {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::VerificationFailed,
                        BACKEND,
                        op,
                        "MAC verification failed",
                    ))
                }
            })
            .await
    }
}

impl Describe for GcpMacKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// RSA key-wrapping keys

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AsymmetricDecryptReq<'a> {
    ciphertext: &'a str,
    ciphertext_crc32c: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AsymmetricDecryptResp<'a> {
    #[serde(default, borrow)]
    plaintext: std::borrow::Cow<'a, str>,
    #[serde(default, deserialize_with = "int64")]
    plaintext_crc32c: Option<u64>,
    #[serde(default)]
    verified_ciphertext_crc32c: bool,
}

/// Checks and decodes an `asymmetricDecrypt` response.
fn asymmetric_decrypt_result(resp: &[u8], op: Operation) -> Result<Zeroizing<Vec<u8>>> {
    let r: AsymmetricDecryptResp<'_> =
        serde_json::from_slice(resp).map_err(|_| bad_response(op))?;
    check_verified(r.verified_ciphertext_crc32c, op, "verifiedCiphertextCrc32c")?;
    let crc32c = r.plaintext_crc32c;
    let pt = decode_secret(r.plaintext, op)?;
    check_crc(&pt, crc32c, op, "plaintextCrc32c")?;
    Ok(pt)
}

/// A Cloud KMS `ASYMMETRIC_DECRYPT` key version with an OAEP-SHA-256 algorithm
/// (`RSA_DECRYPT_OAEP_{2048,3072,4096}_SHA256`) as a key-wrapping key: [`KeyWrap`] and
/// [`Describe`]. Open it with [`GcpProvider::key_wrap_key`](crate::GcpProvider::key_wrap_key)
/// or [`Provider::key_wrap`](anykms_core::Provider::key_wrap) and a versioned URI.
///
/// **Wrap is local.** **Emulates:** a server-side encrypt (Cloud KMS has none for asymmetric
/// keys). **Enforced by:** this process, with RSA-OAEP-SHA-256 over the version's public key
/// (`getPublicKey`, cached for `public_key_ttl`); Cloud KMS enforces unwrap
/// (`asymmetricDecrypt`). Wrapping needs `cloudkms.cryptoKeyVersions.viewPublicKey` and
/// `cloudkms.cryptoKeyVersions.get` (the version must be `ENABLED` before its public key is
/// used), unwrapping `useToDecrypt` (plus both for the key-type check). Wrapped keys are as long
/// as the modulus. A disabled pinned version is `KeyStateInvalid` for wrap, unwrap and
/// [`public_key`](Self::public_key). Errors are labeled `WrapKey` and `UnwrapKey`.
///
/// **Key-type check:** wrapping always checks that the version is OAEP-SHA-256 (it needs the
/// public key anyway). Unwrapping checks it too before the first `asymmetricDecrypt`
/// (`getPublicKey`, cached like the other checks) unless the handle uses
/// [`KeyTypeCheck::TrustCaller`]: another algorithm (OAEP with SHA-1 or SHA-512, a signing or
/// AEAD key) is `KeyMismatch`.
#[derive(Clone, Debug)]
pub struct GcpKeyWrapKey {
    pub(crate) k: KeyCtx,
}

/// The algorithm check of an RSA key-wrapping key version.
fn oaep_alg_matches(vk: &VersionKey, op: Operation) -> Result<()> {
    match vk.alg {
        Alg::OaepSha256(_) => Ok(()),
        _ => Err(mismatch(
            op,
            "the key version is not an RSA_DECRYPT_OAEP_*_SHA256 key (RSA key wrapping needs \
             OAEP with SHA-256)",
        )),
    }
}

/// The public key the handle wraps with (the pinned version), to wrap offline with
/// `anykms_recipes::rsa_oaep_sha256_encrypt`. The handle unwraps with its pinned version only,
/// so `public_key_version` serves that version alone: another version is `UnknownKeyVersion`
/// before any request (open a handle on that version instead). A version that is not an
/// `RSA_DECRYPT_OAEP_*_SHA256` key is `KeyMismatch`; a disabled one is refused.
impl PublicKeys for GcpKeyWrapKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k
            .scoped(async { Ok(self.oaep_key(Operation::PublicKey).await?.key) })
            .await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        let op = Operation::PublicKey;
        self.k
            .scoped(async {
                let v = crate::uri::parse_version(version.as_str())
                    .ok_or_else(|| invalid(op, "Cloud KMS key versions are decimal numbers"))?;
                // A key wrapped to another version could not be unwrapped through this handle.
                if v != self.k.pinned() {
                    return Err(Error::new(
                        ErrorKind::UnknownKeyVersion,
                        BACKEND,
                        op,
                        "the key URI pins another version; this handle wraps and unwraps with \
                         that version only",
                    ));
                }
                let vk = self.k.version_key(v, op, Origin::Input).await?;
                oaep_alg_matches(&vk, op)?;
                Ok(vk.key)
            })
            .await
    }
}

impl GcpKeyWrapKey {
    /// Sets the key-type check (default [`KeyTypeCheck::Describe`]). It only affects unwrap:
    /// wrap always checks the algorithm of the public key it encrypts to.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    async fn oaep_key(&self, op: Operation) -> Result<VersionKey> {
        let vk = self
            .k
            .version_key(self.k.pinned(), op, Origin::Handle)
            .await?;
        oaep_alg_matches(&vk, op)?;
        Ok(vk)
    }
}

impl Preflight for GcpKeyWrapKey {
    /// Runs the key-type check now (it otherwise runs before the first operation) and returns
    /// the key's metadata, with the backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        let check: Result<()> = async {
            self.k
                .scoped(self.k.recheck(Check::KeyWrap, Operation::Describe))
                .await
        }
        .await;
        check?;
        Describe::describe(self).await
    }
}

impl KeyWrap for GcpKeyWrapKey {
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::WrapKey;
                let vk = self.oaep_key(op).await?;
                let wrapped = anykms_recipes::rsa_oaep_sha256_encrypt(vk.key.spki_der(), key)
                    .map_err(|e| Error::new(e.kind(), BACKEND, op, e.message().to_owned()))?;
                Ok(Ciphertext::from_bytes(wrapped))
            })
            .await
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        self.k
            .scoped(async {
                let op = Operation::UnwrapKey;
                if wrapped.is_empty() || wrapped.len() > 512 {
                    return Err(Error::new(
                        ErrorKind::DecryptFailed,
                        BACKEND,
                        op,
                        "decryption failed",
                    ));
                }
                // Q10: an OAEP-SHA-1 (or any other) version must not unwrap.
                self.k.ensure(Check::KeyWrap, op).await?;
                let c = b64(wrapped.as_bytes());
                let req = body(
                    &AsymmetricDecryptReq {
                        ciphertext: &c,
                        ciphertext_crc32c: crc(wrapped.as_bytes()),
                    },
                    c.len(),
                );
                let resp = self
                    .k
                    .send(
                        self.k.call(
                            Method::POST,
                            Some(self.k.pinned()),
                            Some("asymmetricDecrypt"),
                            Some(req),
                            op,
                        ),
                        Origin::Handle,
                    )
                    .await?;
                asymmetric_decrypt_result(&resp, op)
            })
            .await
    }
}

impl Describe for GcpKeyWrapKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Describe-only

/// A describe-only handle for any Cloud KMS key, with or without a version in the URI (a
/// version only picks the algorithm reported): [`Describe`], with [`GcpKeyInfo`] attached
/// ([`KeyInfo::backend_info`]). It cannot encrypt, sign or MAC, so it needs no key-type
/// check. Open it with [`GcpProvider::describe_key`](crate::GcpProvider::describe_key).
#[derive(Clone, Debug)]
pub struct GcpDescribeKey {
    pub(crate) k: KeyCtx,
}

impl Describe for GcpDescribeKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

/// Success-response decoding for the fuzz target: `which % 7` picks encrypt, decrypt, sign,
/// macSign, macVerify, getPublicKey-style key metadata, asymmetricDecrypt.
pub(crate) fn fuzz_decode_success(which: u8, body: &[u8]) -> bool {
    let key = "projects/p-123456/locations/global/keyRings/r/cryptoKeys/k";
    let ver = "projects/p-123456/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
    let algs = SignatureAlgorithm::ALL;
    let alg = algs[usize::from(which / 7) % algs.len()];
    match which % 7 {
        0 => encrypt_result(body, key, which & 0x80 != 0, Operation::Encrypt).is_ok(),
        1 => decrypt_result(body, Operation::Decrypt).is_ok(),
        2 => sign_result(
            body,
            ver,
            alg,
            None,
            !alg.is_message_signing(),
            Operation::Sign,
        )
        .is_ok(),
        3 => mac_sign_result(body, ver, MacAlgorithm::HmacSha256, Operation::Mac).is_ok(),
        4 => mac_verify_result(body, ver, Operation::VerifyMac).is_ok(),
        5 => serde_json::from_slice::<KeyJson>(body)
            .map(|k| GcpKeyInfo::new(k, &[], Some(1)).to_key_info())
            .is_ok(),
        _ => asymmetric_decrypt_result(body, Operation::UnwrapKey).is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encrypt_body_is_minimal() {
        let b = encrypt_body(b"hi", b"");
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(
            v,
            json!({"plaintext": "aGk=", "plaintextCrc32c": crc(b"hi")})
        );
        let b = encrypt_body(b"", b"ad");
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(
            v,
            json!({
                "plaintext": "",
                "plaintextCrc32c": "0",
                "additionalAuthenticatedData": "YWQ=",
                "additionalAuthenticatedDataCrc32c": crc(b"ad"),
            })
        );
    }

    #[test]
    fn encrypt_results_are_checked() {
        let key = "projects/p-123456/locations/global/keyRings/r/cryptoKeys/k";
        let ok = |name: &str, crc_v: serde_json::Value, flag: bool| {
            serde_json::to_vec(&json!({
                "name": name,
                "ciphertext": "AQID",
                "ciphertextCrc32c": crc_v,
                "verifiedPlaintextCrc32c": flag,
            }))
            .unwrap()
        };
        let good = ok(
            &format!("{key}/cryptoKeyVersions/3"),
            json!(crc(&[1, 2, 3])),
            true,
        );
        let (ct, v) = encrypt_result(&good, key, false, Operation::Encrypt).unwrap();
        assert_eq!(ct.as_bytes(), &[1, 2, 3]);
        assert_eq!(v, Some(3));
        // A number is accepted too.
        let num = ok(
            &format!("{key}/cryptoKeyVersions/3"),
            json!(crate::crc32c::crc32c(&[1, 2, 3])),
            true,
        );
        assert!(encrypt_result(&num, key, false, Operation::Encrypt).is_ok());
        let cases = [
            (
                ok(&format!("{key}/cryptoKeyVersions/3"), json!("1"), true),
                ErrorKind::Unavailable,
            ),
            (
                ok(
                    &format!("{key}/cryptoKeyVersions/3"),
                    json!(crc(&[1, 2, 3])),
                    false,
                ),
                ErrorKind::Unavailable,
            ),
            (
                ok(
                    &format!("{key}x/cryptoKeyVersions/3"),
                    json!(crc(&[1, 2, 3])),
                    true,
                ),
                ErrorKind::Backend,
            ),
            (ok(key, json!(crc(&[1, 2, 3])), true), ErrorKind::Backend),
        ];
        for (b, want) in cases {
            assert_eq!(
                encrypt_result(&b, key, false, Operation::Encrypt)
                    .unwrap_err()
                    .kind(),
                want
            );
        }
        // AAD sent but its flag missing.
        assert_eq!(
            encrypt_result(&good, key, true, Operation::Encrypt)
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
    }

    #[test]
    fn mac_verify_integrity() {
        let ver = "v";
        let r = |success: bool, integrity: bool| {
            serde_json::to_vec(&json!({
                "name": ver, "success": success, "verifiedDataCrc32c": true,
                "verifiedMacCrc32c": true, "verifiedSuccessIntegrity": integrity,
            }))
            .unwrap()
        };
        assert!(mac_verify_result(&r(true, true), ver, Operation::VerifyMac).unwrap());
        assert!(!mac_verify_result(&r(false, false), ver, Operation::VerifyMac).unwrap());
        assert_eq!(
            mac_verify_result(&r(true, false), ver, Operation::VerifyMac)
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(
            mac_verify_result(&r(false, true), ver, Operation::VerifyMac)
                .unwrap_err()
                .kind(),
            ErrorKind::Unavailable
        );
    }

    #[test]
    fn signature_shapes() {
        use SignatureAlgorithm::*;
        let mut der = vec![0x30];
        der.resize(70, 1);
        assert!(signature_shape_ok(EcdsaP256Sha256, None, &der));
        assert!(!signature_shape_ok(EcdsaP384Sha384, None, &der));
        assert!(signature_shape_ok(
            RsaPssSha256,
            Some(AsymmetricKeyType::Rsa { bits: 3072 }),
            &[0; 384]
        ));
        assert!(!signature_shape_ok(
            RsaPssSha256,
            Some(AsymmetricKeyType::Rsa { bits: 2048 }),
            &[0; 384]
        ));
        assert!(signature_shape_ok(Ed25519, None, &[0; 64]));
    }
}
