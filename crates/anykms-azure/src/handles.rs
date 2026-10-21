//! Typed key handles.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anykms_core::time::Instant;

// Key bundles and local verifiers' public keys are trusted for the provider's `key_cache_ttl`
// ±10% (keys can be deleted and recreated with another type, have `key_ops` changed, or
// versions disabled).
use anykms_http::cache::{SingleFlight, jittered_ttl};

use anykms_core::{
    Ciphertext, Describe, Digest, DigestSigner, DigestVerifier, Error, ErrorKind, KeyInfo,
    KeyState, KeyTypeCheck, KeyVersion, KeyWrap, Operation, Preflight, PublicKey, PublicKeys,
    Result, Signature, SignatureAlgorithm,
};
use anykms_http::http::Method;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::BACKEND;
use crate::client::{Call, SharedClient};
use crate::config::{Target, VaultKind};
use crate::errors::{ReqClass, unusable_response};
use crate::framing::{self, FrameAlg};
use crate::keyinfo::{AzureKeyInfo, AzureKeyType, B64URL, KeyBundle, parse_versions_page};
use crate::uri::{AzureKeyRef, parse_version};

/// The most `/versions` pages describe reads (then `versions_truncated` is set).
const MAX_VERSION_PAGES: usize = 10;

/// Where the key version a request addresses came from (P1-4): only a request for the handle's
/// own key or configured version may drop its cached bundle, never one whose version came from
/// input (a forged `kid` must not force a key read on every caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The URI's version, or the current version.
    Handle,
    /// A signature's or frame's version, `public_key_version`.
    Input,
}

/// (host, lowercase name, version).
pub(crate) type CacheKey = (String, String, Option<String>);

/// Key bundles read for the key-type check, shared per provider.
#[derive(Default)]
pub(crate) struct DescribeCache {
    entries: Mutex<HashMap<CacheKey, (Instant, Arc<KeyBundle>)>>,
    /// One key read at a time for concurrent misses (R-34).
    flights: SingleFlight<CacheKey, Result<Arc<KeyBundle>>>,
}

/// Everything a handle needs to reach one key.
#[derive(Clone)]
pub(crate) struct KeyCtx {
    pub(crate) client: SharedClient,
    pub(crate) target: Arc<Target>,
    pub(crate) uri: AzureKeyRef,
    pub(crate) check: KeyTypeCheck,
    pub(crate) cache: Arc<DescribeCache>,
    /// Non-secret identifier on every error of this handle: the URI.
    pub(crate) resource: Arc<str>,
}

impl std::fmt::Debug for KeyCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKey")
            .field("uri", &self.resource)
            .field("vault_kind", &self.target.kind)
            .field("key_type_check", &self.check)
            .finish()
    }
}

fn invalid(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, op, m)
}

fn mismatch(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::KeyMismatch, BACKEND, op, m)
}

fn decrypt_failed(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::DecryptFailed, BACKEND, op, m)
}

fn verification_failed(m: &'static str) -> Error {
    Error::new(ErrorKind::VerificationFailed, BACKEND, Operation::Verify, m)
}

/// base64url into a zeroizing, pre-sized string.
fn b64(data: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(data.len().div_ceil(3) * 4 + 4));
    B64URL.encode_string(data, &mut s);
    s
}

/// Serializes a request body into a zeroizing buffer sized for `hint` bytes of field values.
fn body<T: Serialize>(value: &T, hint: usize) -> Zeroizing<Vec<u8>> {
    anykms_http::zbuf::json_body(value, hint.saturating_add(256)).expect("request serializes")
}

/// Decodes base64url into a zeroizing buffer, wiping any owned intermediate string.
fn decode_secret(mut s: Cow<'_, str>) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 4 * 3 + 3));
    let r = B64URL.decode_vec(s.as_bytes(), &mut out);
    if let Cow::Owned(o) = &mut s {
        o.zeroize();
    }
    r.ok().map(|()| out)
}

#[derive(Serialize)]
struct OpReq<'a> {
    alg: &'a str,
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    iv: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aad: Option<&'a str>,
}

impl<'a> OpReq<'a> {
    fn new(alg: &'a str, value: &'a str) -> Self {
        Self {
            alg,
            value,
            iv: None,
            tag: None,
            aad: None,
        }
    }
}

#[derive(Serialize)]
struct VerifyReq<'a> {
    alg: &'a str,
    digest: &'a str,
    value: &'a str,
}

#[derive(Deserialize)]
struct OpResp<'a> {
    #[serde(default)]
    kid: Option<String>,
    #[serde(borrow)]
    value: Cow<'a, str>,
    #[serde(default)]
    iv: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

#[derive(Deserialize)]
struct VerifyResp {
    value: bool,
}

impl KeyCtx {
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

    fn bad_response(&self, op: Operation, m: &'static str) -> Error {
        unusable_response(op, &self.target.host, Some(200), m)
    }

    fn cache_key(&self) -> CacheKey {
        (
            self.target.host.clone(),
            self.uri.name().to_ascii_lowercase(),
            self.uri.version().map(str::to_owned),
        )
    }

    fn forget(&self) {
        self.cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.cache_key());
    }

    fn cached(&self) -> Option<Arc<KeyBundle>> {
        let now = Instant::now();
        self.cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&self.cache_key())
            .filter(|(exp, _)| now < *exp)
            .map(|(_, b)| b.clone())
    }

    fn url(&self, version: Option<&str>, action: Option<&str>) -> Result<anykms_http::url::Url> {
        let mut segs = vec!["keys", self.uri.name()];
        segs.extend(version);
        segs.extend(action);
        self.client.url(&self.target, &segs)
    }

    /// Sends a call. When it addressed the handle's own key or configured version
    /// (`Origin::Handle`), errors that may mean the key was deleted, recreated or changed
    /// (`NotFound`, `KeyMismatch`, `Unsupported`, `KeyStateInvalid`, and `PermissionDenied`, as a
    /// role change can mean a recreated key) drop the cached bundle (P1-4).
    async fn send(&self, origin: Origin, call: Call<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let r = self.client.call(&self.target, call).await;
        if let Err(e) = &r
            && origin == Origin::Handle
            && matches!(
                e.kind(),
                ErrorKind::NotFound
                    | ErrorKind::KeyMismatch
                    | ErrorKind::Unsupported
                    | ErrorKind::KeyStateInvalid
                    | ErrorKind::PermissionDenied
            )
        {
            self.forget();
        }
        r
    }

    /// The version a response's `kid` names, checked to be this key on this host (and
    /// `expected`, when the request named a version). Anything else is `Backend`: fail closed.
    fn returned_version(
        &self,
        kid: Option<&str>,
        expected: Option<&str>,
        op: Operation,
    ) -> Result<String> {
        let bad = || self.bad_response(op, "response names another key or version");
        let kid = AzureKeyRef::from_key_id(kid.ok_or_else(bad)?).map_err(|_| bad())?;
        if kid.host() != self.target.host || !kid.name().eq_ignore_ascii_case(self.uri.name()) {
            return Err(bad());
        }
        let v = kid.version().ok_or_else(bad)?;
        if expected.is_some_and(|e| e != v) {
            return Err(bad());
        }
        Ok(v.to_owned())
    }

    /// `GET /keys/<name>[/<version>]`, checked to describe this key (and version). `origin`
    /// says whether `version` came from input.
    async fn get_bundle(
        &self,
        origin: Origin,
        version: Option<&str>,
        op: Operation,
    ) -> Result<KeyBundle> {
        let url = self.url(version, None)?;
        let body = self
            .send(
                origin,
                Call {
                    method: Method::GET,
                    url,
                    body: None,
                    op,
                    class: ReqClass::Read,
                    key_seen: false,
                    resource: &self.resource,
                    key_version: version,
                },
            )
            .await?;
        let b = KeyBundle::parse(&body, self.target.kind)
            .map_err(|_| self.bad_response(op, "unexpected key bundle format"))?;
        self.returned_version(Some(&b.info.key_id), version, op)?;
        Ok(b)
    }

    /// The bundle of the URI's version (or the current one), cached for the key-type check.
    /// Concurrent misses for the key share one read and its result, a failure included (R-34).
    pub(crate) async fn bundle(&self, op: Operation) -> Result<Arc<KeyBundle>> {
        if let Some(b) = self.cached() {
            return Ok(b);
        }
        self.cache
            .flights
            .run(&self.cache_key(), || async {
                // A flight that landed after the miss above has filled the cache.
                if let Some(b) = self.cached() {
                    return Ok(b);
                }
                let b = Arc::new(
                    self.get_bundle(Origin::Handle, self.uri.version(), op)
                        .await?,
                );
                self.store(b.clone());
                Ok(b)
            })
            .await
            // The flight may have been another operation's.
            .map_err(|e| e.with_operation(op))
    }

    /// Caches `b` as the bundle of the URI's version (or the current one).
    fn store(&self, b: Arc<KeyBundle>) {
        let now = Instant::now();
        let mut cache = self
            .cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.retain(|_, (exp, _)| now < *exp);
        cache.insert(
            self.cache_key(),
            (now + jittered_ttl(self.client.cache_ttl), b),
        );
    }

    /// The `Preflight` of every handle: a fresh read of the key (the metadata `describe`
    /// returns), the key-type check on the fresh bundle (even under `KeyTypeCheck::TrustCaller`)
    /// and the state of the version the handle uses, every error labelled `Operation::Describe`.
    /// The fresh bundle replaces the cached one.
    pub(crate) async fn preflight(
        &self,
        check: impl Fn(&KeyBundle) -> Result<()>,
    ) -> Result<KeyInfo> {
        self.scoped(async {
            let op = Operation::Describe;
            let (b, info) = self.azure_info_with_bundle().await?;
            if let Err(e) = check(&b) {
                self.forget();
                return Err(e.with_operation(op));
            }
            let usable = check_usable(&b.info, op);
            self.store(Arc::new(b));
            usable?;
            Ok(info.to_key_info())
        })
        .await
    }

    /// Runs the key-type check (cached) unless the caller opted out; returns the bundle it read.
    async fn ensure(
        &self,
        op: Operation,
        check: impl Fn(&KeyBundle) -> Result<()>,
    ) -> Result<Option<Arc<KeyBundle>>> {
        if self.check == KeyTypeCheck::TrustCaller {
            return Ok(None);
        }
        let b = self.bundle(op).await?;
        if let Err(e) = check(&b) {
            self.forget();
            return Err(e.with_operation(op));
        }
        Ok(Some(b))
    }

    /// A write (`sign`, `wrapkey`, `encrypt`, HS* `sign`): on the URI's version, else
    /// versionless, else (once the host refused a versionless operation with 405) on the current
    /// version from the cached key bundle, read again once if that version is gone or refused.
    /// Returns the body and the version the request named.
    async fn post_write(
        &self,
        op: Operation,
        action: &str,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<(Zeroizing<Vec<u8>>, Option<String>)> {
        if let Some(v) = self.uri.version() {
            let r = self
                .post(op, Some(v), action, body, ReqClass::Write)
                .await?;
            return Ok((r, Some(v.to_owned())));
        }
        if !self.client.versionless_refused(&self.target.host) {
            match self
                .post(op, None, action, body.clone(), ReqClass::Write)
                .await
            {
                Err(e) if e.detail().and_then(|d| d.http_status) == Some(405) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        backend = BACKEND,
                        resource = &*self.resource,
                        "the server refuses versionless key operations; naming the current version"
                    );
                    self.client.refuse_versionless(&self.target.host);
                }
                r => return r.map(|b| (b, None)),
            }
        }
        let current = self.bundle(op).await?.info.version.clone();
        match self
            .post(op, Some(&current), action, body.clone(), ReqClass::Write)
            .await
        {
            // The cached current version may be stale (rotated, disabled, deleted): read the key
            // again once.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::NotFound
                        | ErrorKind::PermissionDenied
                        | ErrorKind::KeyStateInvalid
                        | ErrorKind::KeyVersionUnusable
                ) =>
            {
                self.forget();
                let fresh = self.bundle(op).await?.info.version.clone();
                if fresh == current {
                    return Err(e);
                }
                let r = self
                    .post(op, Some(&fresh), action, body, ReqClass::Write)
                    .await?;
                Ok((r, Some(fresh)))
            }
            r => r.map(|b| (b, Some(current))),
        }
    }

    /// `POST /keys/<name>[/<version>]/<action>`.
    async fn post(
        &self,
        op: Operation,
        version: Option<&str>,
        action: &str,
        body: Zeroizing<Vec<u8>>,
        class: ReqClass,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let url = self.url(version, Some(action))?;
        self.send(
            if class == ReqClass::InputVersion {
                Origin::Input
            } else {
                Origin::Handle
            },
            Call {
                method: Method::POST,
                url,
                body: Some(body),
                op,
                class,
                key_seen: self.check == KeyTypeCheck::Describe,
                resource: &self.resource,
                key_version: version,
            },
        )
        .await
    }

    /// A version taken from caller input (a signature, a frame): 32 hex characters, and the
    /// URI's version when the URI pins one.
    fn input_version(&self, v: &str, op: Operation) -> Result<String> {
        let verifying = matches!(op, Operation::Verify | Operation::VerifyMac);
        let fail = |m| {
            if verifying {
                Error::new(ErrorKind::VerificationFailed, BACKEND, op, m)
            } else {
                decrypt_failed(op, m)
            }
        };
        // A signature's malformed version is the caller's error; a ciphertext's is a failed
        // decryption, like any other damage to it.
        let v = parse_version(v).ok_or_else(|| {
            if verifying {
                invalid(
                    op,
                    "malformed key version (Azure versions are 32 hex characters)",
                )
            } else {
                fail("malformed key version")
            }
        })?;
        if self.uri.version().is_some_and(|p| p != v) {
            return Err(fail("input names another version than the key URI pins"));
        }
        Ok(v)
    }

    /// Fresh Azure metadata: the bundle of the URI's version (or the current one), the current
    /// version when the URI pins another, and every version of the key from `/versions` (paged).
    pub(crate) async fn azure_info(&self) -> Result<AzureKeyInfo> {
        Ok(self.azure_info_with_bundle().await?.1)
    }

    /// [`azure_info`](Self::azure_info) and the bundle of the URI's version (or the current one)
    /// it was read from.
    async fn azure_info_with_bundle(&self) -> Result<(KeyBundle, AzureKeyInfo)> {
        let op = Operation::Describe;
        let b = self
            .get_bundle(Origin::Handle, self.uri.version(), op)
            .await?;
        let mut info = b.info.clone();
        if self.uri.version().is_some() {
            let current = self.get_bundle(Origin::Handle, None, op).await?.info;
            if current.version != info.version {
                info.current = Some(current.version_info());
            }
        }
        let mut url = self.url(None, Some("versions"))?;
        for page in 0.. {
            if page == MAX_VERSION_PAGES {
                info.versions_truncated = true;
                break;
            }
            let body = self
                .send(
                    Origin::Handle,
                    Call {
                        method: Method::GET,
                        url: url.clone(),
                        body: None,
                        op,
                        class: ReqClass::Read,
                        key_seen: false,
                        resource: &self.resource,
                        key_version: None,
                    },
                )
                .await?;
            let (items, next) = parse_versions_page(&body, self.uri.name())
                .ok_or_else(|| self.bad_response(op, "unexpected version list format"))?;
            info.versions.extend(items);
            match next.and_then(|n| self.next_link(&url, &n)) {
                Some(n) => url = n,
                None => break,
            }
        }
        Ok((b, info))
    }

    /// A `nextLink`, followed only on the same scheme, host and path (else the list ends).
    fn next_link(
        &self,
        current: &anykms_http::url::Url,
        next: &str,
    ) -> Option<anykms_http::url::Url> {
        let n = anykms_http::url::Url::parse(next).ok()?;
        let same = n.scheme() == current.scheme()
            && n.host_str() == current.host_str()
            && n.port_or_known_default() == current.port_or_known_default()
            && n.path().eq_ignore_ascii_case(current.path())
            && n.username().is_empty()
            && n.password().is_none()
            && n.fragment().is_none();
        if !same {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                backend = BACKEND,
                resource = &*self.resource,
                "ignoring a version-list nextLink to another host or path"
            );
            return None;
        }
        // The pinned api-version, never one the server chose.
        let kept: Vec<(String, String)> = n
            .query_pairs()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("api-version"))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let mut n = n;
        n.query_pairs_mut()
            .clear()
            .extend_pairs(kept)
            .append_pair("api-version", self.client.api_version.as_str());
        Some(n)
    }

    pub(crate) async fn describe(&self) -> Result<KeyInfo> {
        Ok(self.azure_info().await?.to_key_info())
    }
}

/// Refuses a key whose version in use (`info`: the pinned or current version) is disabled, not
/// yet valid or expired (`KeyStateInvalid`). A bundle without an `enabled` flag passes.
fn check_usable(info: &AzureKeyInfo, op: Operation) -> Result<()> {
    let m = match info.state() {
        Some(KeyState::Disabled) => "the key version in use is disabled",
        Some(KeyState::Unknown(s)) if s == "not-yet-valid" => {
            "the key version in use is not yet valid (nbf)"
        }
        Some(KeyState::Unknown(_)) => "the key version in use has expired (exp)",
        _ => return Ok(()),
    };
    Err(Error::new(ErrorKind::KeyStateInvalid, BACKEND, op, m))
}

/// Azure's name for a signature algorithm.
fn azure_sig_alg(alg: SignatureAlgorithm, op: Operation) -> Result<&'static str> {
    use SignatureAlgorithm::{
        EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, RsaPkcs1v15Sha256, RsaPkcs1v15Sha384,
        RsaPkcs1v15Sha512, RsaPssSha256, RsaPssSha384, RsaPssSha512,
    };
    Ok(match alg {
        EcdsaP256Sha256 => "ES256",
        EcdsaP384Sha384 => "ES384",
        EcdsaP521Sha512 => "ES512",
        RsaPssSha256 => "PS256",
        RsaPssSha384 => "PS384",
        RsaPssSha512 => "PS512",
        RsaPkcs1v15Sha256 => "RS256",
        RsaPkcs1v15Sha384 => "RS384",
        RsaPkcs1v15Sha512 => "RS512",
        _ => {
            return Err(Error::new(
                ErrorKind::KeyMismatch,
                BACKEND,
                op,
                "Azure Key Vault has no keys for this signature algorithm",
            ));
        }
    })
}

/// The key-type check for signing with `alg`: an RSA (≥ 2048 bits) or EC key of the right curve,
/// whose `key_ops` allow `op_name` (`sign` or `verify`; `None`: no op needed).
fn check_signing(
    alg: SignatureAlgorithm,
    op_name: Option<&'static str>,
) -> impl Fn(&KeyBundle) -> Result<()> {
    move |b: &KeyBundle| {
        let ok = b
            .public
            .as_ref()
            .is_some_and(|pk| alg.is_compatible_with(&pk.key_type()));
        if !ok {
            return Err(mismatch(
                Operation::Open,
                "key type or curve does not match the asserted signature algorithm",
            ));
        }
        if b.info
            .rsa_bits
            .is_some_and(|bits| bits < anykms_recipes::MIN_RSA_BITS)
        {
            return Err(mismatch(
                Operation::Open,
                "RSA keys under 2048 bits are not supported",
            ));
        }
        if let Some(op) = op_name
            && !b.allows(op)
        {
            return Err(mismatch(
                Operation::Open,
                match op {
                    "sign" => "the key's key_ops do not allow sign",
                    _ => "the key's key_ops do not allow verify",
                },
            ));
        }
        Ok(())
    }
}

/// The modulus size in bytes, when known.
fn modulus_len(b: Option<&Arc<KeyBundle>>) -> Option<usize> {
    b.and_then(|b| b.info.rsa_bits)
        .map(|bits| bits.div_ceil(8) as usize)
}

// ---------------------------------------------------------------------------------------------
// Signing

/// Public keys fetched for local verification, per version (P1-13): each is trusted for the
/// provider's `key_cache_ttl` (jittered), counted from the fetch, so a version the vault stops
/// serving (disabled, deleted) stops verifying within that lag. An expired entry is dropped
/// before the re-read: a failed re-read fails closed. Versions that came back unknown are
/// remembered for the same time, and so are disabled versions (with their error), so a forged or
/// disabled version costs at most one request per TTL.
#[derive(Debug)]
pub(crate) struct LocalVerifiers {
    ttl: Duration,
    state: Mutex<LocalState>,
}

#[derive(Debug, Default)]
struct LocalState {
    /// Version → (expiry, verifier).
    keys: HashMap<String, (Instant, anykms_recipes::LocalVerifier)>,
    /// Versions that came back unknown or unusable (disabled) → (expiry, the error to repeat).
    unknown: HashMap<String, (Instant, Error)>,
}

/// The most entries each map of [`LocalVerifiers`] holds.
const MAX_LOCAL_ENTRIES: usize = 64;

/// Inserts into a bounded map: expired entries go first, then (still full) everything.
fn insert_bounded<V>(m: &mut HashMap<String, (Instant, V)>, k: String, v: (Instant, V)) {
    if m.len() >= MAX_LOCAL_ENTRIES {
        let now = Instant::now();
        m.retain(|_, (exp, _)| now < *exp);
        if m.len() >= MAX_LOCAL_ENTRIES {
            m.clear();
        }
    }
    m.insert(k, v);
}

impl LocalVerifiers {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: Mutex::default(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, LocalState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The cached verifier of `version`, or the error it is known to fail with. Expired entries
    /// are removed.
    fn lookup(&self, version: &str) -> Lookup {
        let now = Instant::now();
        let mut s = self.state();
        match s.keys.get(version) {
            Some((exp, v)) if now < *exp => return Lookup::Hit(v.clone()),
            Some(_) => {
                s.keys.remove(version);
            }
            None => {}
        }
        match s.unknown.get(version) {
            Some((exp, e)) if now < *exp => Lookup::Refused(e.clone()),
            Some(_) => {
                s.unknown.remove(version);
                Lookup::Miss
            }
            None => Lookup::Miss,
        }
    }

    fn insert(&self, version: String, v: anykms_recipes::LocalVerifier, fetched: Instant) {
        if self.ttl.is_zero() {
            return;
        }
        let exp = fetched + jittered_ttl(self.ttl);
        insert_bounded(&mut self.state().keys, version, (exp, v));
    }

    fn insert_refused(&self, version: String, e: Error, fetched: Instant) {
        if self.ttl.is_zero() {
            return;
        }
        let exp = fetched + jittered_ttl(self.ttl);
        insert_bounded(&mut self.state().unknown, version, (exp, e));
    }
}

enum Lookup {
    Hit(anykms_recipes::LocalVerifier),
    Refused(Error),
    Miss,
}

/// A Key Vault (or Managed HSM) RSA or EC key used with one asserted algorithm: `DigestSigner`,
/// `DigestVerifier`, `PublicKeys`, `Describe`.
///
/// - ECDSA signatures come from Azure as raw `r || s` and are returned as DER, like every anykms
///   ECDSA signature; verification converts back.
/// - RSA-PSS uses a salt as long as the hash (RFC 7518 `PS*`; confirmed live by T3).
/// - Signatures carry the key version from the response `kid`; verification needs it (the
///   signature's version picks the key version the vault verifies with).
/// - Verification is server-side (`verify`) unless opened with
///   [`AzureOptions::local_verify`](crate::AzureOptions::local_verify).
/// - On a URI that pins a version, verification and `public_key_version` accept that version
///   only (another is `VerificationFailed` / `UnknownKeyVersion`, before any request); open the
///   unversioned URI to serve every version's public key.
#[derive(Clone, Debug)]
pub struct AzureDigestKey {
    pub(crate) k: KeyCtx,
    pub(crate) alg: SignatureAlgorithm,
    pub(crate) local: Option<Arc<LocalVerifiers>>,
    pub(crate) sem: Arc<anykms_core::KeySemantics>,
}

impl AzureDigestKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    /// Whether verification is local.
    pub fn verifies_locally(&self) -> bool {
        self.local.is_some()
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

    async fn sign_inner(&self, digest: &Digest) -> Result<Signature> {
        let op = Operation::Sign;
        self.check_digest(digest, op)?;
        let alg_name = azure_sig_alg(self.alg, op)?;
        let bundle = self
            .k
            .ensure(op, check_signing(self.alg, Some("sign")))
            .await?;
        let value = b64(digest.as_bytes());
        let req = OpReq::new(alg_name, &value);
        let (resp, requested) = self
            .k
            .post_write(op, "sign", body(&req, value.len()))
            .await?;
        let r: OpResp<'_> = serde_json::from_slice(&resp)
            .map_err(|_| self.k.bad_response(op, "unexpected sign response format"))?;
        let version = self
            .k
            .returned_version(r.kid.as_deref(), requested.as_deref(), op)?;
        let raw = B64URL
            .decode(r.value.as_bytes())
            .map_err(|_| self.k.bad_response(op, "unexpected sign response format"))?;
        let bytes = if let Some(n) = anykms_recipes::ecdsa_der::ecdsa_scalar_len(self.alg) {
            if raw.len() != 2 * n {
                self.k.forget();
                return Err(self
                    .k
                    .bad_response(op, "ECDSA signature has an unexpected size"));
            }
            anykms_recipes::ecdsa_der::fixed_to_der(&raw, n)
                .map_err(|_| self.k.bad_response(op, "unexpected ECDSA signature"))?
        } else {
            let ok = match modulus_len(bundle.as_ref()) {
                Some(k) => raw.len() == k,
                None => (256..=2048).contains(&raw.len()),
            };
            if !ok {
                self.k.forget();
                return Err(self
                    .k
                    .bad_response(op, "RSA signature has an unexpected size"));
            }
            raw
        };
        Ok(Signature::from_parts(
            self.alg,
            Some(KeyVersion::new(version.as_str())),
            bytes,
        ))
    }

    /// The signature's version and the raw value Azure expects (`r || s` for ECDSA).
    fn verify_input(&self, sig: &Signature) -> Result<(String, Vec<u8>)> {
        let op = Operation::Verify;
        if sig.algorithm() != self.alg {
            return Err(invalid(
                op,
                "signature algorithm does not match the key handle",
            ));
        }
        let v = sig.key_version().ok_or_else(|| {
            invalid(
                op,
                "Azure verification needs the signature's key version (Signature::key_version)",
            )
        })?;
        let version = self.k.input_version(v.as_str(), op)?;
        let raw = if let Some(n) = anykms_recipes::ecdsa_der::ecdsa_scalar_len(self.alg) {
            anykms_recipes::ecdsa_der::der_to_fixed(sig.as_bytes(), n)
                .map_err(|_| verification_failed("malformed ECDSA signature"))?
        } else {
            if !(256..=2048).contains(&sig.as_bytes().len()) {
                return Err(verification_failed("malformed RSA signature"));
            }
            sig.as_bytes().to_vec()
        };
        Ok((version, raw))
    }

    async fn verify_server(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        let op = Operation::Verify;
        self.check_digest(digest, op)?;
        let alg_name = azure_sig_alg(self.alg, op)?;
        let (version, raw) = self.verify_input(sig)?;
        let bundle = self
            .k
            .ensure(op, check_signing(self.alg, Some("verify")))
            .await?;
        if let Some(k) = modulus_len(bundle.as_ref())
            && raw.len() != k
        {
            return Err(verification_failed(
                "RSA signature has the wrong size for the key",
            ));
        }
        let d = b64(digest.as_bytes());
        let value = b64(&raw);
        let req = VerifyReq {
            alg: alg_name,
            digest: &d,
            value: &value,
        };
        let resp = self
            .k
            .post(
                op,
                Some(&version),
                "verify",
                body(&req, d.len() + value.len()),
                ReqClass::InputVersion,
            )
            .await?;
        let r: VerifyResp = serde_json::from_slice(&resp)
            .map_err(|_| self.k.bad_response(op, "unexpected verify response format"))?;
        if r.value {
            Ok(())
        } else {
            Err(verification_failed("signature verification failed"))
        }
    }

    async fn verify_local(
        &self,
        local: &LocalVerifiers,
        digest: &Digest,
        sig: &Signature,
    ) -> Result<()> {
        let op = Operation::Verify;
        self.check_digest(digest, op)?;
        let (version, _) = self.verify_input(sig)?;
        let unknown = || verification_failed("signature names an unknown key version");
        let verifier = match local.lookup(&version) {
            Lookup::Hit(v) => v,
            Lookup::Refused(e) => return Err(e.with_operation(op)),
            Lookup::Miss => {
                let fetched = Instant::now();
                let pk = match self.public_key_inner(Some(&version)).await {
                    Ok(pk) => pk,
                    // The signature names a version this key does not have.
                    Err(e) if e.kind() == ErrorKind::UnknownKeyVersion => {
                        local.insert_refused(version, unknown(), fetched);
                        return Err(unknown());
                    }
                    // A disabled version: remembered like an unknown one (a signature naming
                    // it costs at most one read per TTL), with the same kind every time.
                    Err(e)
                        if e.kind() == ErrorKind::KeyVersionUnusable
                            && e.retry_after().is_none() =>
                    {
                        let e = e.with_operation(op);
                        local.insert_refused(version, e.clone(), fetched);
                        return Err(e);
                    }
                    // Fails closed: an expired entry is never used again.
                    Err(e) => return Err(e.with_operation(op)),
                };
                let v = anykms_recipes::LocalVerifier::new(pk, self.alg)?;
                local.insert(version, v.clone(), fetched);
                v
            }
        };
        verifier.verify_digest(digest, sig).await
    }

    async fn public_key_inner(&self, version: Option<&str>) -> Result<PublicKey> {
        let alg = self.alg;
        bundle_public_key(&self.k, version, move |b| check_signing(alg, None)(b)).await
    }
}

/// The public key of the handle's key (its pinned or current version, or `version`, which must be
/// a version of this key), checked with `kind` (even under `TrustCaller`: no I/O, and a key of
/// another type is never labeled with the asserted one) and refused when disabled.
async fn bundle_public_key(
    k: &KeyCtx,
    version: Option<&str>,
    kind: impl Fn(&KeyBundle) -> Result<()>,
) -> Result<PublicKey> {
    let op = Operation::PublicKey;
    let origin = if version.is_some() {
        Origin::Input
    } else {
        Origin::Handle
    };
    let version = match version {
        // Untrusted (often a JWT `kid`): checked before any I/O, never another key. A URI
        // that pins a version trusts that version only, as verification does.
        Some(v) => {
            let v = parse_version(v).ok_or_else(|| {
                invalid(
                    op,
                    "malformed key version (Azure versions are 32 hex characters)",
                )
            })?;
            if k.uri.version().is_some_and(|p| p != v) {
                return Err(Error::new(
                    ErrorKind::UnknownKeyVersion,
                    BACKEND,
                    op,
                    "the key URI pins another version",
                ));
            }
            Some(v)
        }
        None => k.uri.version().map(str::to_owned),
    };
    let b = match k.get_bundle(origin, version.as_deref(), op).await {
        Ok(b) => b,
        // A version from input that the vault does not have (P1-4 already kept the cache).
        Err(e) if origin == Origin::Input && e.kind() == ErrorKind::NotFound => {
            let mut u = Error::new(
                ErrorKind::UnknownKeyVersion,
                BACKEND,
                op,
                "no such key version",
            );
            if let Some(d) = e.detail() {
                u = u.with_detail(d.clone());
            }
            return Err(u);
        }
        Err(e) => return Err(e),
    };
    // Checked even under TrustCaller: it costs no I/O, and a key of another type is never
    // labeled with the asserted algorithm.
    kind(&b).map_err(|e| e.with_operation(op))?;
    if b.info.enabled == Some(false) {
        // Refused like the vault refuses to verify with it, so local verification stops
        // when the server's does. A version the handle chose (its URI pin, or the current
        // version) is the deployment's problem; one from input is the caller's (A3(b)).
        return Err(Error::new(
            if origin == Origin::Input {
                ErrorKind::KeyVersionUnusable
            } else {
                ErrorKind::KeyStateInvalid
            },
            BACKEND,
            op,
            "key version is disabled",
        ));
    }
    b.public
        .ok_or_else(|| k.bad_response(op, "key bundle has no public key"))
}

impl Preflight for AzureDigestKey {
    /// Reads the key afresh (as `describe`), runs the key-type check on that read (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key whose version in use (the pinned one, else the current one) is disabled, not yet
    /// valid or expired (`KeyStateInvalid`), every error labelled `Operation::Describe`. Returns
    /// the key's metadata, with [`AzureKeyInfo`] attached ([`KeyInfo::backend_info`]).
    ///
    /// The typed handle signs and verifies, so `key_ops` are not checked here; the opaque
    /// signer and verifier handles check the operation they need.
    async fn preflight(&self) -> Result<KeyInfo> {
        self.k.preflight(check_signing(self.alg, None)).await
    }
}

/// The algorithm the handle was opened for.
impl anykms_core::PinnedVerifier for AzureDigestKey {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl DigestSigner for AzureDigestKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        self.k.scoped(self.sign_inner(digest)).await
    }
}

impl DigestVerifier for AzureDigestKey {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        self.k
            .scoped(async {
                match &self.local {
                    Some(l) => self.verify_local(l, digest, sig).await,
                    None => self.verify_server(digest, sig).await,
                }
            })
            .await
    }
}

impl PublicKeys for AzureDigestKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k.scoped(self.public_key_inner(None)).await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(self.public_key_inner(Some(version.as_str())))
            .await
    }
}

impl Describe for AzureDigestKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k.scoped(self.k.describe()).await
    }
}

// ---------------------------------------------------------------------------------------------
// Key wrap

/// The wrap algorithm a key's type implies.
fn wrap_alg_of(b: &KeyBundle, op: Operation) -> Result<FrameAlg> {
    let t = &b.info.key_type;
    if t.is_rsa() {
        if b.info
            .rsa_bits
            .is_some_and(|bits| bits < anykms_recipes::MIN_RSA_BITS)
        {
            return Err(mismatch(op, "RSA keys under 2048 bits are not supported"));
        }
        return Ok(FrameAlg::RsaOaep256);
    }
    if *t == AzureKeyType::OctHsm {
        if b.info.vault_kind != VaultKind::ManagedHsm {
            return Err(Error::new(
                ErrorKind::Unsupported,
                BACKEND,
                op,
                "oct-HSM keys on Premium vaults (preview) are not supported",
            ));
        }
        return Ok(FrameAlg::A256Kw);
    }
    Err(mismatch(
        op,
        "key type cannot wrap keys (RSA, or oct-HSM on Managed HSM)",
    ))
}

impl Preflight for AzureKeyWrapKey {
    /// Reads the key afresh (as `describe`), runs the key-type check on that read (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key whose version in use (the pinned one, else the current one) is disabled, not yet
    /// valid or expired (`KeyStateInvalid`), every error labelled `Operation::Describe`. Returns
    /// the key's metadata, with [`AzureKeyInfo`] attached ([`KeyInfo::backend_info`]).
    ///
    /// The key must be able to wrap (RSA, or `oct-HSM` on Managed HSM) and its `key_ops` must
    /// allow both `wrapKey` and `unwrapKey` (`KeyMismatch`).
    async fn preflight(&self) -> Result<KeyInfo> {
        self.k.preflight(check_kek).await
    }
}

/// A key that can wrap (RSA, or `oct-HSM` on Managed HSM) and whose `key_ops` allow both
/// `wrapKey` and `unwrapKey`.
fn check_kek(b: &KeyBundle) -> Result<()> {
    wrap_alg_of(b, Operation::Describe)?;
    if !(b.allows("wrapKey") && b.allows("unwrapKey")) {
        return Err(mismatch(
            Operation::Describe,
            "the key's key_ops do not allow wrapKey and unwrapKey",
        ));
    }
    Ok(())
}

/// RSA key-wrapping keys: the public key to wrap offline (`anykms_recipes::rsa_oaep_sha256_encrypt`).
/// An `oct-HSM` key has none (`KeyMismatch`).
impl PublicKeys for AzureKeyWrapKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k
            .scoped(bundle_public_key(&self.k, None, check_rsa_wrap))
            .await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(bundle_public_key(
                &self.k,
                Some(version.as_str()),
                check_rsa_wrap,
            ))
            .await
    }
}

/// The key is an RSA key that can wrap (RSA-OAEP-256).
fn check_rsa_wrap(b: &KeyBundle) -> Result<()> {
    if wrap_alg_of(b, Operation::PublicKey)? != FrameAlg::RsaOaep256 {
        return Err(mismatch(
            Operation::PublicKey,
            "the key has no public key (not an RSA key)",
        ));
    }
    Ok(())
}

fn check_wrap(alg: FrameAlg, op_name: &'static str) -> impl Fn(&KeyBundle) -> Result<()> {
    move |b: &KeyBundle| {
        if wrap_alg_of(b, Operation::Open)? != alg {
            return Err(mismatch(
                Operation::Open,
                "wrapped key was made with another key type",
            ));
        }
        if !b.allows(op_name) {
            return Err(mismatch(
                Operation::Open,
                if op_name == "wrapKey" {
                    "the key's key_ops do not allow wrapKey"
                } else {
                    "the key's key_ops do not allow unwrapKey"
                },
            ));
        }
        Ok(())
    }
}

/// RSA-OAEP's overhead with SHA-256: `2 * 32 + 2` bytes.
const OAEP_SHA256_OVERHEAD: usize = 66;

/// A key-wrapping key: RSA-OAEP-256 on RSA keys (vaults and Managed HSM), RFC 3394 `A256KW` on
/// Managed HSM `oct-HSM` keys. Implements `KeyWrap` and `Describe`.
///
/// Wrapped keys are framed (`docs/azure-ciphertext.md`): the frame carries the algorithm and the
/// key version, which unwrapping uses. On a vault host the algorithm is RSA-OAEP-256; on a
/// Managed HSM it follows the key type, which needs `keys/read` even under
/// `KeyTypeCheck::TrustCaller` (for wrapping; unwrapping reads it from the frame).
///
/// RSA-OAEP input is limited to the modulus size minus 66 bytes (190 for RSA-2048), checked
/// before any request when the key size is known; `A256KW` takes multiples of 8 bytes, at least
/// 16. A KEK must be dedicated to wrapping (its `key_ops` should be `wrapKey`, `unwrapKey`).
#[derive(Clone, Debug)]
pub struct AzureKeyWrapKey {
    pub(crate) k: KeyCtx,
    pub(crate) sem: Arc<anykms_core::KeySemantics>,
}

impl AzureKeyWrapKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    /// The wrap algorithm: RSA on vaults; from the key type on Managed HSM.
    async fn wrap_alg(&self, op: Operation) -> Result<(FrameAlg, Option<Arc<KeyBundle>>)> {
        match self.k.target.kind {
            VaultKind::Vault => {
                let b = self
                    .k
                    .ensure(op, check_wrap(FrameAlg::RsaOaep256, "wrapKey"))
                    .await?;
                Ok((FrameAlg::RsaOaep256, b))
            }
            VaultKind::ManagedHsm => {
                let b = self.k.bundle(op).await?;
                let alg = wrap_alg_of(&b, op)?;
                if self.k.check == KeyTypeCheck::Describe {
                    check_wrap(alg, "wrapKey")(&b).map_err(|e| e.with_operation(op))?;
                }
                Ok((alg, Some(b)))
            }
        }
    }

    async fn wrap_inner(&self, key: &[u8]) -> Result<Ciphertext> {
        let op = Operation::WrapKey;
        if key.is_empty() {
            return Err(invalid(op, "nothing to wrap"));
        }
        let (alg, bundle) = self.wrap_alg(op).await?;
        let k_len = modulus_len(bundle.as_ref());
        match alg {
            FrameAlg::RsaOaep256 => {
                if let Some(k) = k_len
                    && key.len() > k - OAEP_SHA256_OVERHEAD
                {
                    return Err(invalid(
                        op,
                        "key too large for RSA-OAEP-256 with this key (modulus bytes - 66)",
                    ));
                }
            }
            _ => {
                if key.len() < 16 || !key.len().is_multiple_of(8) {
                    return Err(invalid(
                        op,
                        "A256KW wraps keys of a multiple of 8 bytes, at least 16",
                    ));
                }
            }
        }
        let value = b64(key);
        let req = OpReq::new(alg.azure_name(), &value);
        let (resp, requested) = self
            .k
            .post_write(op, "wrapkey", body(&req, value.len()))
            .await?;
        let r: OpResp<'_> = serde_json::from_slice(&resp).map_err(|_| {
            self.k
                .bad_response(op, "unexpected wrapkey response format")
        })?;
        let version = self
            .k
            .returned_version(r.kid.as_deref(), requested.as_deref(), op)?;
        let ct = B64URL.decode(r.value.as_bytes()).map_err(|_| {
            self.k
                .bad_response(op, "unexpected wrapkey response format")
        })?;
        let size_ok = match alg {
            FrameAlg::RsaOaep256 => match k_len {
                Some(k) => ct.len() == k,
                None => (256..=2048).contains(&ct.len()),
            },
            _ => ct.len() == key.len() + 8,
        };
        if !size_ok {
            self.k.forget();
            return Err(self
                .k
                .bad_response(op, "wrapped key has an unexpected size"));
        }
        let framed = framing::encode(alg, &version, &ct)
            .map_err(|_| self.k.bad_response(op, "wrapped key cannot be framed"))?;
        Ok(Ciphertext::from_bytes(framed))
    }

    async fn unwrap_inner(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        let op = Operation::UnwrapKey;
        let frame = framing::parse(wrapped.as_bytes())
            .map_err(|_| decrypt_failed(op, "not an Azure wrapped key"))?;
        let alg = frame.alg();
        if !matches!(alg, FrameAlg::RsaOaep256 | FrameAlg::A256Kw) {
            return Err(decrypt_failed(
                op,
                "not a wrapped key (an AEAD ciphertext?)",
            ));
        }
        if alg == FrameAlg::A256Kw && self.k.target.kind != VaultKind::ManagedHsm {
            return Err(decrypt_failed(
                op,
                "A256KW wrapped keys need a Managed HSM key",
            ));
        }
        let version = self.k.input_version(frame.version(), op)?;
        let bundle = self.k.ensure(op, check_wrap(alg, "unwrapKey")).await?;
        if alg == FrameAlg::RsaOaep256
            && let Some(k) = modulus_len(bundle.as_ref())
            && frame.body().len() != k
        {
            return Err(decrypt_failed(
                op,
                "wrapped key has the wrong size for the key",
            ));
        }
        let value = b64(frame.body());
        let req = OpReq::new(alg.azure_name(), &value);
        let resp = self
            .k
            .post(
                op,
                Some(&version),
                "unwrapkey",
                body(&req, value.len()),
                ReqClass::InputVersion,
            )
            .await?;
        let r: OpResp<'_> = serde_json::from_slice(&resp).map_err(|_| {
            self.k
                .bad_response(op, "unexpected unwrapkey response format")
        })?;
        decode_secret(r.value).ok_or_else(|| {
            self.k
                .bad_response(op, "unexpected unwrapkey response format")
        })
    }
}

/// The version in a frame (`InvalidArgument` if `bytes` is not a frame).
fn frame_version(bytes: &[u8], op: Operation) -> Result<Option<KeyVersion>> {
    let f = framing::parse(bytes).map_err(|_| invalid(op, "not an Azure ciphertext frame"))?;
    Ok(Some(KeyVersion::new(f.version())))
}

impl KeyWrap for AzureKeyWrapKey {
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        self.k.scoped(self.wrap_inner(key)).await
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        self.k.scoped(self.unwrap_inner(wrapped)).await
    }

    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        frame_version(wrapped.as_bytes(), Operation::UnwrapKey).map_err(|e| self.k.label(e))
    }
}

impl Describe for AzureKeyWrapKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k.scoped(self.k.describe()).await
    }
}

// ---------------------------------------------------------------------------------------------
// Managed HSM AES-GCM

impl Preflight for AzureAeadKey {
    /// Reads the key afresh (as `describe`), runs the key-type check on that read (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key whose version in use (the pinned one, else the current one) is disabled, not yet
    /// valid or expired (`KeyStateInvalid`), every error labelled `Operation::Describe`. Returns
    /// the key's metadata, with [`AzureKeyInfo`] attached ([`KeyInfo::backend_info`]).
    ///
    /// The key must be an `oct-HSM` key on a Managed HSM that allows encrypt and decrypt.
    async fn preflight(&self) -> Result<KeyInfo> {
        self.k.preflight(check_aead).await
    }
}

fn check_aead(b: &KeyBundle) -> Result<()> {
    if b.info.key_type != AzureKeyType::OctHsm {
        return Err(mismatch(Operation::Open, "AES-GCM needs an oct-HSM key"));
    }
    if b.info.vault_kind != VaultKind::ManagedHsm {
        return Err(Error::new(
            ErrorKind::Unsupported,
            BACKEND,
            Operation::Open,
            "oct-HSM keys on Premium vaults (preview) are not supported",
        ));
    }
    if !(b.allows("encrypt") && b.allows("decrypt")) {
        return Err(mismatch(
            Operation::Open,
            "the key's key_ops do not allow encrypt and decrypt",
        ));
    }
    Ok(())
}

/// A Managed HSM `oct-HSM` AES-256 key: `Aead` (`A256GCM`, framed: `docs/azure-ciphertext.md`)
/// and `Describe`; data keys through `EmulatedDataKeys` over it (AAD bound).
///
/// **To verify with T13** (no emulator covers Managed HSM): the service generates the 12-byte IV
/// and returns a 16-byte tag (any other size is `Backend`), and the plaintext limit. GA API
/// versions do not report an `oct-HSM` key's size, so an AES-128 or AES-192 key cannot be
/// refused before use: use AES-256 keys.
#[derive(Clone, Debug)]
pub struct AzureAeadKey {
    pub(crate) k: KeyCtx,
    pub(crate) sem: Arc<anykms_core::KeySemantics>,
}

impl AzureAeadKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    async fn encrypt_inner(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        let op = Operation::Encrypt;
        self.k.ensure(op, check_aead).await?;
        let value = b64(plaintext);
        let ad = (!aad.is_empty()).then(|| b64(aad));
        let mut req = OpReq::new("A256GCM", &value);
        req.aad = ad.as_deref().map(String::as_str);
        let (resp, requested) = self
            .k
            .post_write(
                op,
                "encrypt",
                body(&req, value.len() + ad.as_ref().map_or(0, |a| a.len())),
            )
            .await?;
        let bad = || {
            self.k
                .bad_response(op, "unexpected encrypt response format")
        };
        let r: OpResp<'_> = serde_json::from_slice(&resp).map_err(|_| bad())?;
        let version = self
            .k
            .returned_version(r.kid.as_deref(), requested.as_deref(), op)?;
        let ct = B64URL.decode(r.value.as_bytes()).map_err(|_| bad())?;
        let iv = B64URL
            .decode(r.iv.as_deref().ok_or_else(bad)?)
            .map_err(|_| bad())?;
        let tag = B64URL
            .decode(r.tag.as_deref().ok_or_else(bad)?)
            .map_err(|_| bad())?;
        if iv.len() != framing::GCM_IV_LEN || tag.len() != framing::GCM_TAG_LEN {
            return Err(self
                .k
                .bad_response(op, "AES-GCM IV or tag has an unexpected size"));
        }
        let framed = framing::encode_gcm(&version, &iv, &ct, &tag)
            .map_err(|_| self.k.bad_response(op, "ciphertext cannot be framed"))?;
        Ok(Ciphertext::from_bytes(framed))
    }

    async fn decrypt_inner(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let op = Operation::Decrypt;
        let frame = framing::parse(ct.as_bytes())
            .map_err(|_| decrypt_failed(op, "not an Azure AES-GCM ciphertext"))?;
        let (iv, body_ct, tag) = frame
            .gcm_parts()
            .ok_or_else(|| decrypt_failed(op, "not an AES-GCM ciphertext (a wrapped key?)"))?;
        let version = self.k.input_version(frame.version(), op)?;
        self.k.ensure(op, check_aead).await?;
        let value = b64(body_ct);
        let iv = b64(iv);
        let tag = b64(tag);
        let ad = (!aad.is_empty()).then(|| b64(aad));
        let mut req = OpReq::new("A256GCM", &value);
        req.iv = Some(&iv);
        req.tag = Some(&tag);
        req.aad = ad.as_deref().map(String::as_str);
        let resp = self
            .k
            .post(
                op,
                Some(&version),
                "decrypt",
                body(&req, value.len() + 64 + ad.as_ref().map_or(0, |a| a.len())),
                ReqClass::InputVersion,
            )
            .await?;
        let r: OpResp<'_> = serde_json::from_slice(&resp).map_err(|_| {
            self.k
                .bad_response(op, "unexpected decrypt response format")
        })?;
        decode_secret(r.value).ok_or_else(|| {
            self.k
                .bad_response(op, "unexpected decrypt response format")
        })
    }
}

impl anykms_core::Aead for AzureAeadKey {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        self.k.scoped(self.encrypt_inner(plaintext, aad)).await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.k.scoped(self.decrypt_inner(ct, aad)).await
    }

    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        frame_version(ct.as_bytes(), Operation::Decrypt).map_err(|e| self.k.label(e))
    }
}

impl Describe for AzureAeadKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k.scoped(self.k.describe()).await
    }
}

// ---------------------------------------------------------------------------------------------
// Data keys on Managed HSM: by key type.

/// Data keys from a Managed HSM key: `EmulatedDataKeys` over the AES-GCM key (AAD bound) for
/// `oct-HSM` keys, `KeyWrapDataKeys` over RSA-OAEP-256 for RSA keys (non-empty AAD refused).
/// Reads the key type (`keys/read`) before the first data key, even under
/// `KeyTypeCheck::TrustCaller`.
#[derive(Clone, Debug)]
pub(crate) struct MhsmDataKeys {
    pub(crate) aead: AzureAeadKey,
    pub(crate) wrap: AzureKeyWrapKey,
}

impl anykms_core::DataKeys for MhsmDataKeys {
    async fn generate_data_key(
        &self,
        spec: anykms_core::DataKeySpec,
        aad: &[u8],
    ) -> Result<anykms_core::DataKey> {
        let k = &self.aead.k;
        let b = k.scoped(k.bundle(Operation::GenerateDataKey)).await?;
        if b.info.key_type == AzureKeyType::OctHsm {
            anykms_recipes::EmulatedDataKeys::new(&self.aead)
                .generate_data_key(spec, aad)
                .await
        } else {
            anykms_recipes::KeyWrapDataKeys::new(&self.wrap)
                .generate_data_key(spec, aad)
                .await
        }
    }
}

impl Describe for MhsmDataKeys {
    async fn describe(&self) -> Result<KeyInfo> {
        self.aead.describe().await
    }
}

/// An `oct-HSM` key that allows encrypt and decrypt, or an RSA key whose `key_ops` allow
/// `wrapKey` and `unwrapKey`, plus the state check (see [`KeyCtx::preflight`]).
impl Preflight for MhsmDataKeys {
    async fn preflight(&self) -> Result<KeyInfo> {
        self.aead
            .k
            .preflight(|b: &KeyBundle| {
                if b.info.key_type == AzureKeyType::OctHsm {
                    check_aead(b)
                } else {
                    check_kek(b)
                }
            })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Managed HSM HMAC (experimental)

#[cfg(feature = "mhsm-hmac")]
pub use mac::AzureMacKey;

#[cfg(feature = "mhsm-hmac")]
pub(crate) mod mac {
    use anykms_core::{Mac, MacAlgorithm, Tag};

    use super::*;

    fn azure_mac_alg(alg: MacAlgorithm, op: Operation) -> Result<&'static str> {
        match alg {
            MacAlgorithm::HmacSha256 => Ok("HS256"),
            MacAlgorithm::HmacSha384 => Ok("HS384"),
            MacAlgorithm::HmacSha512 => Ok("HS512"),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                BACKEND,
                op,
                "MAC algorithm not supported by Azure",
            )),
        }
    }

    impl anykms_core::Preflight for AzureMacKey {
        /// Reads the key afresh (as `describe`), runs the key-type check on that read (an
        /// `oct-HSM` key that allows sign and verify; even under `KeyTypeCheck::TrustCaller`) and
        /// refuses a key whose version in use is disabled, not yet valid or expired
        /// (`KeyStateInvalid`), every error labelled `Operation::Describe`. Returns the key's
        /// metadata, with [`AzureKeyInfo`] attached ([`KeyInfo::backend_info`]).
        async fn preflight(&self) -> Result<KeyInfo> {
            self.k.preflight(check_mac).await
        }
    }

    fn check_mac(b: &KeyBundle) -> Result<()> {
        if b.info.key_type != AzureKeyType::OctHsm || b.info.vault_kind != VaultKind::ManagedHsm {
            return Err(mismatch(
                Operation::Open,
                "HMAC needs a Managed HSM oct-HSM key",
            ));
        }
        if !(b.allows("sign") && b.allows("verify")) {
            return Err(mismatch(
                Operation::Open,
                "the key's key_ops do not allow sign and verify",
            ));
        }
        Ok(())
    }

    /// The largest input sent to `sign` with HS* (to verify with T13).
    pub(crate) const MAX_MAC_INPUT: usize = 64 * 1024;

    /// A Managed HSM `oct-HSM` HMAC key (`HS256`/`HS384`/`HS512`, API 7.6+): `Mac` with
    /// server-side verification, and `Describe`. **Experimental** (feature `mhsm-hmac`): the
    /// input is sent as `sign`'s `value` on the assumption that Azure MACs the message itself;
    /// if the live probe (T13) shows it takes a digest, this handle is removed rather than
    /// computing a non-portable HMAC. Inputs above 64 KiB are refused before any request.
    #[derive(Clone, Debug)]
    pub struct AzureMacKey {
        pub(crate) k: KeyCtx,
        pub(crate) alg: MacAlgorithm,
        pub(crate) sem: Arc<anykms_core::KeySemantics>,
    }

    impl AzureMacKey {
        /// Sets the key-type check policy.
        pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
            self.k.check = check;
            self
        }

        async fn mac_inner(&self, data: &[u8]) -> Result<Tag> {
            let op = Operation::Mac;
            let alg = azure_mac_alg(self.alg, op)?;
            if data.len() > MAX_MAC_INPUT {
                return Err(invalid(op, "MAC input above 64 KiB"));
            }
            self.k.ensure(op, check_mac).await?;
            let value = b64(data);
            let req = OpReq::new(alg, &value);
            let (resp, requested) = self
                .k
                .post_write(op, "sign", body(&req, value.len()))
                .await?;
            let r: OpResp<'_> = serde_json::from_slice(&resp)
                .map_err(|_| self.k.bad_response(op, "unexpected sign response format"))?;
            let version = self
                .k
                .returned_version(r.kid.as_deref(), requested.as_deref(), op)?;
            let tag = B64URL
                .decode(r.value.as_bytes())
                .map_err(|_| self.k.bad_response(op, "unexpected sign response format"))?;
            if tag.len() != self.alg.tag_len() {
                return Err(self.k.bad_response(op, "HMAC tag has an unexpected size"));
            }
            Ok(Tag::from_parts(
                self.alg,
                Some(KeyVersion::new(version.as_str())),
                tag,
            ))
        }

        async fn verify_inner(&self, data: &[u8], tag: &Tag) -> Result<()> {
            let op = Operation::VerifyMac;
            let alg = azure_mac_alg(self.alg, op)?;
            if tag.algorithm() != self.alg {
                return Err(invalid(op, "tag algorithm does not match the key handle"));
            }
            if data.len() > MAX_MAC_INPUT {
                return Err(invalid(op, "MAC input above 64 KiB"));
            }
            let v = tag
                .key_version()
                .ok_or_else(|| invalid(op, "Azure MAC verification needs the tag's key version"))?;
            let version = self.k.input_version(v.as_str(), op)?;
            if tag.as_bytes().len() != self.alg.tag_len() {
                return Err(Error::new(
                    ErrorKind::VerificationFailed,
                    BACKEND,
                    op,
                    "tag has the wrong size",
                ));
            }
            self.k.ensure(op, check_mac).await?;
            let d = b64(data);
            let value = b64(tag.as_bytes());
            let req = VerifyReq {
                alg,
                digest: &d,
                value: &value,
            };
            let resp = self
                .k
                .post(
                    op,
                    Some(&version),
                    "verify",
                    body(&req, d.len() + value.len()),
                    ReqClass::InputVersion,
                )
                .await?;
            let r: VerifyResp = serde_json::from_slice(&resp)
                .map_err(|_| self.k.bad_response(op, "unexpected verify response format"))?;
            if r.value {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::VerificationFailed,
                    BACKEND,
                    op,
                    "MAC verification failed",
                ))
            }
        }
    }

    impl Mac for AzureMacKey {
        fn mac_algorithm(&self) -> MacAlgorithm {
            self.alg
        }

        async fn mac(&self, data: &[u8]) -> Result<Tag> {
            self.k.scoped(self.mac_inner(data)).await
        }

        async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
            self.k.scoped(self.verify_inner(data, tag)).await
        }
    }

    impl Describe for AzureMacKey {
        async fn describe(&self) -> Result<KeyInfo> {
            self.k.scoped(self.k.describe()).await
        }
    }
}

/// Fuzz hook: decodes the success bodies of sign/wrap/encrypt (`which % 3`) and verify.
pub(crate) fn fuzz_decode_success(which: u8, body: &[u8]) -> bool {
    match which % 3 {
        0 => serde_json::from_slice::<OpResp<'_>>(body)
            .ok()
            .and_then(|r| decode_secret(r.value))
            .is_some(),
        1 => serde_json::from_slice::<VerifyResp>(body).is_ok(),
        _ => KeyBundle::parse(body, VaultKind::Vault).is_ok(),
    }
}
