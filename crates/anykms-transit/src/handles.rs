//! Typed key handles.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anykms_core::time::Instant;
use anykms_core::{
    Aead, AsymmetricKeyType, Ciphertext, DataKey, DataKeySpec, DataKeys, Describe, Digest,
    DigestSigner, DigestVerifier, Error, ErrorKind, HashAlgorithm, KeyInfo, KeyTypeCheck,
    KeyVersion, Mac, MacAlgorithm, MessageSigner, MessageVerifier, Operation, Preflight, PublicKey,
    PublicKeys, Result, Rewrap, Signature, SignatureAlgorithm, Tag, WrappedDataKeys,
};
use anykms_http::cache::SingleFlight;
use anykms_http::http::Method;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::BACKEND;
use crate::client::{Call, Origin, Server};
use crate::config::Flavor;
use crate::keyinfo::{TransitKeyInfo, TransitKeyType};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// How long a cached key type is trusted before it is checked again (keys can be deleted and
/// recreated under the same name with another type). Each entry gets ±10% jitter, so keys opened
/// together (at startup, say) do not all expire and re-read `keys/:name` in the same instant.
const TYPE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// A key's identity in the type cache: server alias, namespace, mount, name.
pub(crate) type CacheKey = (String, Option<String>, String, String);

/// Cache of key types, shared per provider: key → (expiry, type, derived).
#[derive(Default)]
pub(crate) struct TypeCache {
    entries: Mutex<HashMap<Arc<CacheKey>, (Instant, TransitKeyType, bool)>>,
    /// One metadata read at a time for concurrent misses (R-34).
    flights: SingleFlight<Arc<CacheKey>, Result<(TransitKeyType, bool)>>,
}

/// Everything a handle needs to reach one key.
#[derive(Clone)]
pub(crate) struct KeyCtx {
    pub(crate) server: Arc<Server>,
    pub(crate) mount: String,
    pub(crate) name: String,
    pub(crate) namespace: Option<String>,
    pub(crate) check: KeyTypeCheck,
    pub(crate) cache: Arc<TypeCache>,
    /// This key's entry in `cache`, built once per handle.
    pub(crate) cache_key: Arc<CacheKey>,
    /// Non-secret identifier attached to every error of this handle (see [`KeyCtx::resource`]).
    pub(crate) resource: Arc<str>,
}

impl std::fmt::Debug for KeyCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitKey")
            .field("server", &self.server.alias)
            .field("namespace", &self.namespace)
            .field("mount", &self.mount)
            .field("name", &self.name)
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

fn bad_response(k: &KeyCtx, op: Operation) -> Error {
    // Fixed message: decode errors on secret-bearing responses must not be attached as sources,
    // and the body is never logged or fingerprinted (it may carry plaintext or key material).
    crate::errors::unusable_response(op, &k.server.alias, None, "unexpected response format")
}

/// Base64-encodes into a zeroizing, pre-sized string.
fn b64(data: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(data.len().div_ceil(3) * 4 + 4));
    B64.encode_string(data, &mut s);
    s
}

/// Room for field names and punctuation on top of a body's base64 fields.
const BODY_OVERHEAD: usize = 256;

/// Serializes a request body into a zeroizing buffer pre-sized for `hint` bytes of field values
/// (pass the sum of every variable-length field). If the hint is short the buffer grows into a
/// fresh zeroizing buffer, wiping the old one, instead of reallocating in place.
fn body<T: Serialize>(value: &T, hint: usize) -> Zeroizing<Vec<u8>> {
    let mut w = anykms_http::zbuf::Writer(Zeroizing::new(Vec::with_capacity(
        hint.saturating_add(BODY_OVERHEAD),
    )));
    serde_json::to_writer(&mut w, value).expect("request serializes");
    w.0
}

/// Length of an optional base64 field.
fn opt_len(s: Option<&Zeroizing<String>>) -> usize {
    s.map_or(0, |s| s.len())
}

/// Parses `vault:v<N>:<b64>`.
pub(crate) fn parse_versioned(s: &str) -> Option<(u64, &str)> {
    let rest = s.strip_prefix("vault:v")?;
    let (v, payload) = rest.split_once(':')?;
    if v.is_empty() || (v.len() > 1 && v.starts_with('0')) || !v.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let n: u64 = v.parse().ok()?;
    (n > 0).then_some((n, payload))
}

/// Transit's name for `h`. Hash algorithms added to anykms later are `Unsupported` here until
/// mapped, never silently replaced by another hash.
pub(crate) fn transit_hash(h: HashAlgorithm, op: Operation) -> Result<&'static str> {
    match h {
        HashAlgorithm::Sha256 => Ok("sha2-256"),
        HashAlgorithm::Sha384 => Ok("sha2-384"),
        HashAlgorithm::Sha512 => Ok("sha2-512"),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            BACKEND,
            op,
            "hash algorithm is not supported by the transit backend",
        )),
    }
}

/// The `hash_algorithm` path segment of HMAC endpoints.
pub(crate) fn mac_path(alg: MacAlgorithm, op: Operation) -> Result<&'static str> {
    transit_hash(alg.hash(), op)
}

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

impl KeyCtx {
    /// The resource string errors carry: `<scheme>://<server alias>/<mount>/keys/<name>`, with
    /// ` (namespace <ns>)` appended when a namespace applies. The alias is the resolved one (an
    /// empty URI alias shows the default server's name). Built from validated parts only, so it
    /// never holds a query string, token or address.
    pub(crate) fn resource(
        scheme: &str,
        alias: &str,
        mount: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> Arc<str> {
        let mut r = format!("{scheme}://{alias}/{mount}/keys/{name}");
        if let Some(ns) = namespace {
            r.push_str(" (namespace ");
            r.push_str(ns);
            r.push(')');
        }
        r.into()
    }

    /// Names this key on `e`, unless an inner layer already named a resource.
    pub(crate) fn label(&self, e: Error) -> Error {
        if e.resource().is_some() {
            e
        } else {
            e.with_resource(&*self.resource)
        }
    }

    /// Runs one handle operation, labeling any error with the key's resource. Every public handle
    /// method goes through this, so locally detected errors (validation, key-type checks,
    /// undecodable responses) are labeled as well as server errors.
    pub(crate) async fn scoped<T>(&self, f: impl Future<Output = Result<T>>) -> Result<T> {
        f.await.map_err(|e| self.label(e))
    }

    /// `<mount segments>/<tail...>`.
    fn segs<'a>(&'a self, tail: &[&'a str]) -> Vec<&'a str> {
        self.mount.split('/').chain(tail.iter().copied()).collect()
    }

    /// `<mount>/<action>/<name>`.
    fn path<'a>(&'a self, action: &'a str) -> Vec<&'a str> {
        self.segs(&[action, &self.name])
    }

    fn call<'a>(
        &'a self,
        method: Method,
        segments: Vec<&'a str>,
        body: Option<Zeroizing<Vec<u8>>>,
        op: Operation,
    ) -> Call<'a> {
        Call {
            method,
            segments,
            namespace: self.namespace.as_deref(),
            body,
            op,
            key_read: false,
            resource: &self.resource,
            key_version: None,
        }
    }

    /// Sends a call. Errors that may mean the key was deleted or recreated with another type
    /// (`NotFound`, `KeyMismatch`, `Unsupported`, `KeyStateInvalid`) drop the cached key type so
    /// the next operation checks again, but only for requests that addressed the handle's own key
    /// ([`Origin::Handle`]): a version taken from input (a forged signature version, a
    /// ciphertext of another key) never drops it, so it cannot force a metadata read on every
    /// caller.
    pub(crate) async fn send(&self, call: Call<'_>, origin: Origin) -> Result<Zeroizing<Vec<u8>>> {
        let r = self.server.call(call).await;
        if let Err(e) = &r
            && origin == Origin::Handle
            && matches!(
                e.kind(),
                ErrorKind::NotFound
                    | ErrorKind::KeyMismatch
                    | ErrorKind::Unsupported
                    | ErrorKind::KeyStateInvalid
            )
        {
            self.forget_type();
        }
        r
    }

    /// The cached key type and derived flag, if a check has run and has not expired.
    fn cached(&self) -> Option<(TransitKeyType, bool)> {
        let now = Instant::now();
        self.cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&*self.cache_key)
            .filter(|(expires, _, _)| now < *expires)
            .map(|(_, t, d)| (t.clone(), *d))
    }

    /// The cached key type, if a check has run within the cache TTL.
    fn cached_type(&self) -> Option<TransitKeyType> {
        self.cached().map(|(t, _)| t)
    }

    fn forget_type(&self) {
        self.cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&*self.cache_key);
    }

    pub(crate) fn flavor(&self) -> Flavor {
        self.server.cfg.flavor
    }

    /// The type-cache key for a key context's parts.
    pub(crate) fn cache_key_of(
        alias: &str,
        namespace: Option<&str>,
        mount: &str,
        name: &str,
    ) -> Arc<CacheKey> {
        Arc::new((
            alias.to_owned(),
            namespace.map(str::to_owned),
            mount.to_owned(),
            name.to_owned(),
        ))
    }

    /// Fetches fresh metadata (and refreshes the type cache).
    pub(crate) async fn read_info(&self, op: Operation) -> Result<TransitKeyInfo> {
        self.read_info_for(op, Origin::Handle, None).await
    }

    /// [`read_info`](Self::read_info) on behalf of a request whose version came from `origin`
    /// (`public_key_version` reads the key's metadata for an input version).
    async fn read_info_for(
        &self,
        op: Operation,
        origin: Origin,
        version: Option<u64>,
    ) -> Result<TransitKeyInfo> {
        let mut call = self.call(Method::GET, self.path("keys"), None, op);
        call.key_read = true;
        call.key_version = version;
        let body = self.send(call, origin).await?;
        let info = TransitKeyInfo::parse(&body).map_err(|e| {
            if e.kind() == ErrorKind::Backend {
                crate::errors::unusable_response(
                    op,
                    &self.server.alias,
                    Some(200),
                    "unexpected key metadata format",
                )
            } else {
                e.with_operation(op)
            }
        })?;
        let now = Instant::now();
        let mut cache = self
            .cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.retain(|_, (expires, _, _)| now < *expires);
        cache.insert(
            self.cache_key.clone(),
            (
                now + anykms_http::cache::jittered_ttl(TYPE_CACHE_TTL),
                info.parsed_type.clone(),
                info.derived,
            ),
        );
        Ok(info)
    }

    /// The [`Preflight`] check: reads fresh metadata (refreshing the type cache), refuses a
    /// derived key or a key `check` rejects (even under `KeyTypeCheck::TrustCaller`), then a
    /// soft-deleted key with `KeyStateInvalid`. Every error is labelled [`Operation::Describe`].
    async fn preflight_info(
        &self,
        check: impl Fn(&TransitKeyType) -> Result<()>,
    ) -> Result<TransitKeyInfo> {
        let op = Operation::Describe;
        self.scoped(async {
            let info = self.read_info(op).await?;
            if info.derived {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    BACKEND,
                    op,
                    "derived (context-based) transit keys are not supported",
                ));
            }
            check(&info.parsed_type).map_err(|e| e.with_operation(op))?;
            if info.soft_deleted {
                return Err(Error::new(
                    ErrorKind::KeyStateInvalid,
                    BACKEND,
                    op,
                    "the key is soft-deleted and cannot be used",
                ));
            }
            Ok(info)
        })
        .await
    }

    /// Runs the key-type check once (cached) unless the caller opted out.
    async fn ensure_type(
        &self,
        op: Operation,
        check: impl Fn(&TransitKeyType) -> Result<()>,
    ) -> Result<()> {
        if self.check == KeyTypeCheck::TrustCaller {
            return Ok(());
        }
        // Concurrent misses for the key share one read and its result, a failure included.
        let (t, derived) = match self.cached() {
            Some(c) => c,
            None => self
                .cache
                .flights
                .run(&self.cache_key, || async {
                    // A flight that landed after the miss above has filled the cache.
                    if let Some(c) = self.cached() {
                        return Ok(c);
                    }
                    let info = self.read_info(op).await?;
                    Ok((info.parsed_type, info.derived))
                })
                .await
                // The flight may have been another operation's.
                .map_err(|e| e.with_operation(op))?,
        };
        if derived {
            return Err(Error::new(
                ErrorKind::Unsupported,
                BACKEND,
                op,
                "derived (context-based) transit keys are not supported",
            ));
        }
        check(&t).map_err(|e| e.with_operation(op))
    }
}

// ---------------------------------------------------------------------------------------------
// AEAD

/// A transit AEAD key (aes128-gcm96, aes256-gcm96, chacha20-poly1305): `Aead`, `Rewrap`,
/// `DataKeys`, `WrappedDataKeys`, `Describe`.
///
/// **Envelope KEKs:** a key used as the KEK of `anykms_recipes::EnvelopeAead` MUST be dedicated to
/// envelopes. Data keys are wrapped with empty AAD, so any other code path that decrypts with empty
/// AAD under the same key could unwrap them.
///
/// **Key strength:** an `aes128-gcm96` key is accepted for every operation, including
/// [`DataKeys`] and as an envelope KEK, but then wraps 256-bit data keys at 128-bit strength. Use
/// `aes256-gcm96` (or `chacha20-poly1305`) for KEKs. With the `tracing` feature, a warning is
/// logged once per handle on a key known to be `aes128-gcm96` (the type is known unless the
/// key-type check is skipped with `KeyTypeCheck::TrustCaller`) by its first
/// [`generate_data_key`](DataKeys::generate_data_key), and by the first wrap of a key opened
/// as a KEK through [`Provider::key_wrap`](anykms_core::Provider::key_wrap) (the registry's
/// `key_wrap`). A typed handle adapted with `into_key_wrap()` is a plain AEAD to transit, so it
/// gets no warning. The key is not refused: it is a deliberate server-side choice and refusing it
/// would break existing data.
#[derive(Clone, Debug)]
pub struct TransitAeadKey {
    pub(crate) k: KeyCtx,
    /// Whether the weak-KEK warning was already emitted for this handle (and its clones).
    pub(crate) weak_kek_warned: Arc<std::sync::atomic::AtomicBool>,
}

impl TransitAeadKey {
    /// Warns once per handle (and its clones) when the key, known to be `aes128-gcm96`, wraps
    /// data keys. Silent while the type is unknown (`KeyTypeCheck::TrustCaller`).
    fn warn_if_weak_kek(&self, op: Operation) {
        if self.k.cached_type() == Some(TransitKeyType::Aes128Gcm96)
            && !self
                .weak_kek_warned
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                op = op.as_str(),
                backend = BACKEND,
                resource = &*self.k.resource,
                "aes128-gcm96 transit key wraps 256-bit data keys at 128-bit strength; \
                 use aes256-gcm96 for key-wrapping keys"
            );
            let _ = op;
        }
    }
}

/// A transit AEAD key used as a KEK: wraps with empty AAD like
/// [`AeadKeyWrap`](anykms_core::AeadKeyWrap), and also emits the weak-KEK warning (see
/// [`TransitAeadKey`]). [`Provider::key_wrap`](anykms_core::Provider::key_wrap) opens keys as this.
#[derive(Clone, Debug)]
pub(crate) struct TransitKek(pub(crate) TransitAeadKey);

impl anykms_core::KeyWrap for TransitKek {
    /// Errors are labeled [`Operation::WrapKey`], as with `AeadKeyWrap`.
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        let op = Operation::WrapKey;
        let wrapped = self
            .0
            .encrypt(key, b"")
            .await
            .map_err(|e| e.with_operation(op))?;
        self.0.warn_if_weak_kek(op);
        Ok(wrapped)
    }

    /// Errors are labeled [`Operation::UnwrapKey`].
    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        self.0
            .decrypt(wrapped, b"")
            .await
            .map_err(|e| e.with_operation(Operation::UnwrapKey))
    }

    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        self.0.ciphertext_version(wrapped)
    }
}

fn check_aead(t: &TransitKeyType) -> Result<()> {
    if t.is_aead() {
        Ok(())
    } else {
        Err(mismatch(
            Operation::Open,
            "transit key type is not an AEAD cipher (aes*-gcm96, chacha20-poly1305)",
        ))
    }
}

#[derive(Serialize)]
struct EncryptReq<'a> {
    plaintext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
}

/// The encrypt request body, sized for both base64 fields so it never grows.
fn encrypt_body(plaintext: &[u8], aad: &[u8]) -> Zeroizing<Vec<u8>> {
    let pt = b64(plaintext);
    let ad = (!aad.is_empty()).then(|| b64(aad));
    let req = EncryptReq {
        plaintext: &pt,
        associated_data: ad.as_deref().map(String::as_str),
    };
    body(&req, pt.len() + opt_len(ad.as_ref()))
}

#[derive(Serialize)]
struct DecryptReq<'a> {
    ciphertext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
}

#[derive(Deserialize)]
struct CiphertextResp {
    ciphertext: String,
}

#[derive(Deserialize)]
struct PlaintextResp<'a> {
    #[serde(borrow)]
    plaintext: std::borrow::Cow<'a, str>,
}

#[derive(Deserialize)]
struct DataKeyResp<'a> {
    #[serde(borrow)]
    plaintext: std::borrow::Cow<'a, str>,
    ciphertext: String,
}

/// Decodes base64 into a zeroizing buffer, wiping any owned intermediate string.
fn decode_secret(
    k: &KeyCtx,
    mut s: std::borrow::Cow<'_, str>,
    op: Operation,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 4 * 3 + 3));
    let r = B64.decode_vec(s.as_bytes(), &mut out);
    if let std::borrow::Cow::Owned(o) = &mut s {
        o.zeroize();
    }
    r.map_err(|_| bad_response(k, op))?;
    Ok(out)
}

/// A ciphertext the server returned, checked to be `vault:v<N>:<b64>` before it is handed out.
fn returned_ct(k: &KeyCtx, s: String, op: Operation) -> Result<Ciphertext> {
    if parse_versioned(&s).is_none() {
        return Err(bad_response(k, op));
    }
    Ok(Ciphertext::from_bytes(s.into_bytes()))
}

/// The version a transit ciphertext checked by [`ct_str`] names.
fn ct_version(ct: &str) -> Option<u64> {
    parse_versioned(ct).map(|(v, _)| v)
}

fn ct_str(ct: &Ciphertext, op: Operation) -> Result<&str> {
    let s = std::str::from_utf8(ct.as_bytes())
        .map_err(|_| Error::new(ErrorKind::DecryptFailed, BACKEND, op, "decryption failed"))?;
    if parse_versioned(s).is_none() {
        return Err(Error::new(
            ErrorKind::DecryptFailed,
            BACKEND,
            op,
            "decryption failed",
        ));
    }
    Ok(s)
}

impl TransitAeadKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    async fn encrypt_raw(&self, plaintext: &[u8], aad: &[u8], op: Operation) -> Result<Ciphertext> {
        self.k.ensure_type(op, check_aead).await?;
        let resp = self
            .k
            .send(
                self.k.call(
                    Method::POST,
                    self.k.path("encrypt"),
                    Some(encrypt_body(plaintext, aad)),
                    op,
                ),
                Origin::Handle,
            )
            .await?;
        let r: Data<CiphertextResp> =
            serde_json::from_slice(&resp).map_err(|_| bad_response(&self.k, op))?;
        returned_ct(&self.k, r.data.ciphertext, op)
    }
}

impl Preflight for TransitAeadKey {
    /// Reads the key's metadata now and runs the key-type check (it otherwise runs before the
    /// first operation; here it runs even under `KeyTypeCheck::TrustCaller`), refuses a
    /// soft-deleted key with `KeyStateInvalid`, and returns the metadata, with the backend's
    /// own attached ([`KeyInfo::backend_info`]). Its refusals are labelled
    /// [`Operation::Describe`].
    async fn preflight(&self) -> Result<KeyInfo> {
        Ok(self.k.preflight_info(check_aead).await?.to_key_info())
    }
}

impl Aead for TransitAeadKey {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async { self.encrypt_raw(plaintext, aad, Operation::Encrypt).await })
            .await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.k
            .scoped(async {
                let op = Operation::Decrypt;
                let ct = ct_str(ct, op)?;
                self.k.ensure_type(op, check_aead).await?;
                let ad = (!aad.is_empty()).then(|| b64(aad));
                let req = DecryptReq {
                    ciphertext: ct,
                    associated_data: ad.as_deref().map(String::as_str),
                };
                let mut call = self.k.call(
                    Method::POST,
                    self.k.path("decrypt"),
                    Some(body(&req, ct.len() + opt_len(ad.as_ref()))),
                    op,
                );
                call.key_version = ct_version(ct);
                let resp = self.k.send(call, Origin::Input).await?;
                let r: Data<PlaintextResp<'_>> =
                    serde_json::from_slice(&resp).map_err(|_| bad_response(&self.k, op))?;
                decode_secret(&self.k, r.data.plaintext, op)
            })
            .await
    }

    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        let bad = || {
            self.k
                .label(invalid(Operation::Decrypt, "not a transit ciphertext"))
        };
        let s = std::str::from_utf8(ct.as_bytes()).map_err(|_| bad())?;
        let (v, _) = parse_versioned(s).ok_or_else(bad)?;
        Ok(Some(KeyVersion::from_u64(v)))
    }
}

/// Only for ciphertexts encrypted with empty AAD: transit ignores `associated_data` on rewrap, so
/// non-empty `aad` is refused with `Unsupported` before any I/O (see [`Rewrap::rewrap`]).
impl Rewrap for TransitAeadKey {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::Rewrap;
                if !aad.is_empty() {
                    // Transit's rewrap silently ignores associated_data (verified on Vault and OpenBao).
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        BACKEND,
                        op,
                        "transit cannot rewrap ciphertexts that were encrypted with AAD",
                    ));
                }
                let ct = ct_str(ct, op)?;
                self.k.ensure_type(op, check_aead).await?;
                let req = DecryptReq {
                    ciphertext: ct,
                    associated_data: None,
                };
                let mut call = self.k.call(
                    Method::POST,
                    self.k.path("rewrap"),
                    Some(body(&req, ct.len())),
                    op,
                );
                call.key_version = ct_version(ct);
                let resp = self.k.send(call, Origin::Input).await?;
                let r: Data<CiphertextResp> =
                    serde_json::from_slice(&resp).map_err(|_| bad_response(&self.k, op))?;
                returned_ct(&self.k, r.data.ciphertext, op)
            })
            .await
    }
}

#[derive(Serialize)]
struct DataKeyReq<'a> {
    bits: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
}

impl TransitAeadKey {
    /// Calls `datakey/<kind>/<name>` (`kind` is `plaintext` or `wrapped`), with the same checks
    /// for both: the spec, Vault's ignored AAD (refused before any I/O), the key type and the
    /// weak-KEK warning. A server that ignores the AAD and says so in a warning (OpenBao < 2.5)
    /// fails closed in the client.
    async fn datakey(
        &self,
        kind: &'static str,
        spec: DataKeySpec,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let op = Operation::GenerateDataKey;
        let bits = match spec {
            DataKeySpec::Aes256 => 256,
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    BACKEND,
                    op,
                    "data key spec",
                ));
            }
        };
        if !aad.is_empty() && self.k.flavor() == Flavor::Vault {
            // Vault ignores associated_data on datakey (verified); refuse before any I/O.
            return Err(Error::new(
                ErrorKind::Unsupported,
                BACKEND,
                op,
                "Vault transit cannot bind AAD to data keys; use EmulatedDataKeys",
            ));
        }
        self.k.ensure_type(op, check_aead).await?;
        self.warn_if_weak_kek(op);
        let ad = (!aad.is_empty()).then(|| b64(aad));
        let req = DataKeyReq {
            bits,
            associated_data: ad.as_deref().map(String::as_str),
        };
        self.k
            .send(
                self.k.call(
                    Method::POST,
                    self.k.segs(&["datakey", kind, &self.k.name]),
                    Some(body(&req, opt_len(ad.as_ref()))),
                    op,
                ),
                Origin::Handle,
            )
            .await
    }
}

impl DataKeys for TransitAeadKey {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        self.k
            .scoped(async {
                let op = Operation::GenerateDataKey;
                let resp = self.datakey("plaintext", spec, aad).await?;
                let r: Data<DataKeyResp<'_>> =
                    serde_json::from_slice(&resp).map_err(|_| bad_response(&self.k, op))?;
                let DataKeyResp {
                    plaintext,
                    ciphertext,
                } = r.data;
                let pt = decode_secret(&self.k, plaintext, op)?;
                let wrapped = returned_ct(&self.k, ciphertext, op)?;
                DataKey::new(spec, pt, wrapped).map_err(|_| bad_response(&self.k, op))
            })
            .await
    }
}

/// `datakey/wrapped`: the same AAD rules as [`DataKeys`] (Vault: non-empty `aad` is
/// `Unsupported` before any I/O; OpenBao binds it, and a server warning about an ignored
/// parameter fails closed with `Unsupported`). Needs `update` on `transit/datakey/wrapped/<name>`.
impl WrappedDataKeys for TransitAeadKey {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::GenerateDataKey;
                let resp = self.datakey("wrapped", spec, aad).await?;
                let r: Data<CiphertextResp> =
                    serde_json::from_slice(&resp).map_err(|_| bad_response(&self.k, op))?;
                returned_ct(&self.k, r.data.ciphertext, op)
            })
            .await
    }
}

impl Describe for TransitAeadKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.read_info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Signing

fn check_signing(alg: SignatureAlgorithm) -> impl Fn(&TransitKeyType) -> Result<()> {
    move |t: &TransitKeyType| match t.asymmetric() {
        Some(at) if alg.is_compatible_with(&at) => Ok(()),
        _ => Err(mismatch(
            Operation::Open,
            "transit key type does not match the asserted signature algorithm",
        )),
    }
}

#[derive(Serialize)]
struct SignReq<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prehashed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_algorithm: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt_length: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    marshaling_algorithm: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
}

impl<'a> SignReq<'a> {
    fn new(alg: SignatureAlgorithm, input: &'a str, op: Operation) -> Result<Self> {
        use SignatureAlgorithm::{
            EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, RsaPkcs1v15Sha256,
            RsaPkcs1v15Sha384, RsaPkcs1v15Sha512, RsaPssSha256, RsaPssSha384, RsaPssSha512,
        };
        let digest = !alg.is_message_signing();
        let (sig_alg, salt) = match alg {
            RsaPssSha256 | RsaPssSha384 | RsaPssSha512 => (Some("pss"), Some("hash")),
            RsaPkcs1v15Sha256 | RsaPkcs1v15Sha384 | RsaPkcs1v15Sha512 => (Some("pkcs1v15"), None),
            _ => (None, None),
        };
        let marshaling =
            matches!(alg, EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512).then_some("asn1");
        Ok(Self {
            input,
            prehashed: digest.then_some(true),
            hash_algorithm: alg.hash().map(|h| transit_hash(h, op)).transpose()?,
            signature_algorithm: sig_alg,
            salt_length: salt,
            marshaling_algorithm: marshaling,
            signature: None,
        })
    }
}

#[derive(Deserialize)]
struct SignResp {
    signature: String,
}

#[derive(Deserialize)]
struct ValidResp {
    valid: bool,
}

/// Cheap structural check that a signature fits its algorithm's family.
fn signature_shape_ok(alg: SignatureAlgorithm, sig: &[u8]) -> bool {
    use SignatureAlgorithm::{EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, Ed25519};
    // DER ECDSA length bounds per curve (sequence of two integers of at most n+1 bytes). Shorter
    // signatures of a larger curve occur with negligible probability (~2^-100), so the bands
    // separate curves in practice.
    let der =
        |min: usize, max: usize| sig.len() >= min && sig.len() <= max && sig.first() == Some(&0x30);
    match alg {
        EcdsaP256Sha256 => der(8, 72),
        EcdsaP384Sha384 => der(73, 104),
        EcdsaP521Sha512 => der(105, 141),
        Ed25519 => sig.len() == 64,
        _ => sig.len() >= 256 && sig.len().is_multiple_of(128),
    }
}

async fn sign_raw(k: &KeyCtx, alg: SignatureAlgorithm, input: &[u8]) -> Result<Signature> {
    let op = Operation::Sign;
    k.ensure_type(op, check_signing(alg)).await?;
    let inp = b64(input);
    let req = SignReq::new(alg, &inp, op)?;
    let resp = k
        .send(
            k.call(
                Method::POST,
                k.path("sign"),
                Some(body(&req, inp.len())),
                op,
            ),
            Origin::Handle,
        )
        .await?;
    let r: Data<SignResp> = serde_json::from_slice(&resp).map_err(|_| bad_response(k, op))?;
    let (v, payload) = parse_versioned(&r.data.signature).ok_or_else(|| bad_response(k, op))?;
    let bytes = B64.decode(payload).map_err(|_| bad_response(k, op))?;
    if !signature_shape_ok(alg, &bytes) {
        // The key was likely deleted and recreated with another type since the cached check.
        k.forget_type();
        return Err(mismatch(
            op,
            "signature does not match the asserted algorithm (key type changed?)",
        ));
    }
    Ok(Signature::from_parts(
        alg,
        Some(KeyVersion::from_u64(v)),
        bytes,
    ))
}

async fn verify_raw(
    k: &KeyCtx,
    alg: SignatureAlgorithm,
    input: &[u8],
    sig: &Signature,
) -> Result<()> {
    let op = Operation::Verify;
    if sig.algorithm() != alg {
        return Err(invalid(
            op,
            "signature algorithm does not match the key handle",
        ));
    }
    let v = sig
        .key_version()
        .and_then(KeyVersion::as_u64)
        .ok_or_else(|| {
            invalid(
                op,
                "transit verification needs the signature's numeric key version",
            )
        })?;
    k.ensure_type(op, check_signing(alg)).await?;
    let inp = b64(input);
    let encoded = format!("vault:v{v}:{}", B64.encode(sig.as_bytes()));
    let mut req = SignReq::new(alg, &inp, op)?;
    req.signature = Some(&encoded);
    let mut call = k.call(
        Method::POST,
        k.path("verify"),
        Some(body(&req, inp.len() + encoded.len())),
        op,
    );
    call.key_version = Some(v);
    let resp = k.send(call, Origin::Input).await?;
    let r: Data<ValidResp> = serde_json::from_slice(&resp).map_err(|_| bad_response(k, op))?;
    if r.data.valid {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::VerificationFailed,
            BACKEND,
            op,
            "signature verification failed",
        ))
    }
}

async fn public_key_raw(
    k: &KeyCtx,
    alg: SignatureAlgorithm,
    version: Option<&KeyVersion>,
) -> Result<PublicKey> {
    let op = Operation::PublicKey;
    // Validate untrusted versions before any I/O.
    let requested = match version {
        None => None,
        Some(v) => Some(
            v.as_u64()
                .ok_or_else(|| invalid(op, "transit key versions are numeric"))?,
        ),
    };
    let info = match requested {
        None => k.read_info(op).await?,
        Some(v) => k.read_info_for(op, Origin::Input, Some(v)).await?,
    };
    // The metadata read is needed for the PEM anyway, so the type is checked even under
    // `KeyTypeCheck::TrustCaller`: it costs no I/O, and a key of another type is never labeled
    // with the asserted algorithm.
    check_signing(alg)(&info.parsed_type).map_err(|e| e.with_operation(op))?;
    // Without a context the key read lists no public key for a derived key; refuse it like
    // every other operation does instead of reporting a missing version.
    if info.derived {
        return Err(Error::new(
            ErrorKind::Unsupported,
            BACKEND,
            op,
            "derived (context-based) transit keys are not supported",
        ));
    }
    // The key read still lists public keys of a soft-deleted (OpenBao) key; refuse them like
    // every other operation on it, so local verification stops when the server's does.
    if info.soft_deleted {
        return Err(Error::new(
            ErrorKind::KeyStateInvalid,
            BACKEND,
            op,
            "key or key version cannot be used",
        ));
    }
    let v = requested.unwrap_or(info.latest_version);
    let pem = info.public_keys.get(&v).ok_or_else(|| {
        // A version from the input that this key does not have (or no longer publishes) is the
        // caller's (A3(a)); the latest version missing from the key read is the server's.
        let kind = if requested.is_some() {
            ErrorKind::UnknownKeyVersion
        } else {
            ErrorKind::NotFound
        };
        let e = Error::new(
            kind,
            BACKEND,
            op,
            "key version not found (or below the minimum decryption version)",
        );
        if v > info.latest_version {
            // A version newer than this node knows of: it may exist on the primary already
            // (rotation not yet replicated), so hint one delayed retry.
            e.with_retry_hint(crate::errors::REPLICA_LAG_HINT)
        } else {
            e
        }
    })?;
    // The server omits versions below the minimum decryption version (`UnknownKeyVersion` above, as
    // `describe` no longer lists them); refuse one it lists anyway, as verify would.
    if v < info.min_decryption_version {
        return Err(Error::new(
            ErrorKind::KeyVersionUnusable,
            BACKEND,
            op,
            "key version is below the minimum decryption version",
        ));
    }
    let key_type = info
        .parsed_type
        .asymmetric()
        .ok_or_else(|| bad_response(k, op))?;
    let der = if key_type == AsymmetricKeyType::Ed25519 && !pem.trim_start().starts_with("-----") {
        // Transit returns Ed25519 public keys as raw base64 (32 bytes), not PEM: wrap in SPKI.
        let raw = B64.decode(pem.trim()).map_err(|_| bad_response(k, op))?;
        if raw.len() != 32 {
            return Err(bad_response(k, op));
        }
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&raw);
        der
    } else {
        pem_to_der(pem).ok_or_else(|| bad_response(k, op))?
    };
    Ok(PublicKey::new(key_type, der, Some(KeyVersion::from_u64(v))))
}

/// SubjectPublicKeyInfo DER prefix for an Ed25519 key (OID 1.3.101.112), followed by 32 key bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PUBLIC KEY-----")?
        .strip_suffix("-----END PUBLIC KEY-----")?;
    let b: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    B64.decode(b).ok()
}

/// A transit ECDSA or RSA key used with one asserted algorithm: `DigestSigner`, `DigestVerifier`,
/// `PublicKeys`, `Describe`.
///
/// # RSA-PSS salt length
///
/// RSA-PSS always signs **and verifies** with `salt_length=hash` (salt length equal to the hash
/// length), as RFC 7518 requires for JWS `PS256`/`PS384`/`PS512`. Transit's own default is
/// `auto`, which signs with the **maximum** salt length (222 bytes for RSA-2048 with SHA-256).
/// Consequently, RSA-PSS signatures created by other Vault/OpenBao clients that left
/// `salt_length` at its default fail to verify here (`VerificationFailed`), and also with
/// `LocalVerifier`/`CachedVerifier` from anykms-recipes. Have those clients sign with
/// `salt_length=hash`, or verify such signatures through transit's API directly with
/// `salt_length=auto`. Signatures made by anykms verify anywhere that accepts hash-length salts
/// (including transit with `auto`).
#[derive(Clone, Debug)]
pub struct TransitDigestKey {
    pub(crate) k: KeyCtx,
    pub(crate) alg: SignatureAlgorithm,
}

impl TransitDigestKey {
    /// Sets the key-type check policy.
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

impl Preflight for TransitDigestKey {
    /// Reads the key's metadata now and runs the key-type check (it otherwise runs before the
    /// first operation; here it runs even under `KeyTypeCheck::TrustCaller`), refuses a
    /// soft-deleted key with `KeyStateInvalid`, and returns the metadata, with the backend's
    /// own attached ([`KeyInfo::backend_info`]). Its refusals are labelled
    /// [`Operation::Describe`].
    async fn preflight(&self) -> Result<KeyInfo> {
        Ok(self
            .k
            .preflight_info(check_signing(self.alg))
            .await?
            .to_key_info())
    }
}

/// The algorithm the handle was opened for.
impl anykms_core::PinnedVerifier for TransitDigestKey {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl DigestSigner for TransitDigestKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        self.k
            .scoped(async {
                self.check_digest(digest, Operation::Sign)?;
                sign_raw(&self.k, self.alg, digest.as_bytes()).await
            })
            .await
    }
}

impl DigestVerifier for TransitDigestKey {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        self.k
            .scoped(async {
                self.check_digest(digest, Operation::Verify)?;
                verify_raw(&self.k, self.alg, digest.as_bytes(), sig).await
            })
            .await
    }
}

impl PublicKeys for TransitDigestKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k
            .scoped(async { public_key_raw(&self.k, self.alg, None).await })
            .await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(async { public_key_raw(&self.k, self.alg, Some(version)).await })
            .await
    }
}

impl Describe for TransitDigestKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.read_info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

/// A transit Ed25519 key: `MessageSigner`, `MessageVerifier`, `PublicKeys`, `Describe`.
/// `prehashed` is never sent (Vault rejects it; OpenBao silently ignores it).
#[derive(Clone, Debug)]
pub struct TransitEd25519Key {
    pub(crate) k: KeyCtx,
}

impl TransitEd25519Key {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }
}

impl Preflight for TransitEd25519Key {
    /// Reads the key's metadata now and runs the key-type check (it otherwise runs before the
    /// first operation; here it runs even under `KeyTypeCheck::TrustCaller`), refuses a
    /// soft-deleted key with `KeyStateInvalid`, and returns the metadata, with the backend's
    /// own attached ([`KeyInfo::backend_info`]). Its refusals are labelled
    /// [`Operation::Describe`].
    async fn preflight(&self) -> Result<KeyInfo> {
        Ok(self
            .k
            .preflight_info(check_signing(SignatureAlgorithm::Ed25519))
            .await?
            .to_key_info())
    }
}

/// The algorithm the handle was opened for.
impl anykms_core::PinnedVerifier for TransitEd25519Key {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}

impl MessageSigner for TransitEd25519Key {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        self.k
            .scoped(async { sign_raw(&self.k, SignatureAlgorithm::Ed25519, msg).await })
            .await
    }
}

impl MessageVerifier for TransitEd25519Key {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.k
            .scoped(async { verify_raw(&self.k, SignatureAlgorithm::Ed25519, msg, sig).await })
            .await
    }
}

impl PublicKeys for TransitEd25519Key {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k
            .scoped(async { public_key_raw(&self.k, SignatureAlgorithm::Ed25519, None).await })
            .await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(async {
                public_key_raw(&self.k, SignatureAlgorithm::Ed25519, Some(version)).await
            })
            .await
    }
}

impl Describe for TransitEd25519Key {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.read_info(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// HMAC

/// A transit `hmac` key used with one asserted algorithm: `Mac`, `Describe`.
///
/// Transit chooses the hash per request, so `describe` cannot confirm the algorithm; it is the
/// caller's assertion. Only `hmac` keys are accepted (AES keys can HMAC on transit, but cloud keys
/// bind the algorithm to the key, and anykms keeps that model).
#[derive(Clone, Debug)]
pub struct TransitMacKey {
    pub(crate) k: KeyCtx,
    pub(crate) alg: MacAlgorithm,
}

fn check_hmac(t: &TransitKeyType) -> Result<()> {
    if *t == TransitKeyType::Hmac {
        Ok(())
    } else {
        Err(mismatch(Operation::Open, "transit key type is not hmac"))
    }
}

#[derive(Serialize)]
struct HmacReq<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac: Option<&'a str>,
}

#[derive(Deserialize)]
struct HmacResp {
    hmac: String,
}

impl TransitMacKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }
}

impl Preflight for TransitMacKey {
    /// Reads the key's metadata now and runs the key-type check (it otherwise runs before the
    /// first operation; here it runs even under `KeyTypeCheck::TrustCaller`), refuses a
    /// soft-deleted key with `KeyStateInvalid`, and returns the metadata, with the backend's
    /// own attached ([`KeyInfo::backend_info`]). Its refusals are labelled
    /// [`Operation::Describe`].
    async fn preflight(&self) -> Result<KeyInfo> {
        Ok(self
            .k
            .preflight_info(check_hmac)
            .await?
            .to_key_info()
            .with_mac_algorithm(Some(self.alg)))
    }
}

impl Mac for TransitMacKey {
    fn mac_algorithm(&self) -> MacAlgorithm {
        self.alg
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        self.k
            .scoped(async {
                let op = Operation::Mac;
                self.k.ensure_type(op, check_hmac).await?;
                let inp = b64(data);
                let req = HmacReq {
                    input: &inp,
                    hmac: None,
                };
                let path = self
                    .k
                    .segs(&["hmac", &self.k.name, mac_path(self.alg, op)?]);
                let resp = self
                    .k
                    .send(
                        self.k
                            .call(Method::POST, path, Some(body(&req, inp.len())), op),
                        Origin::Handle,
                    )
                    .await?;
                let r: Data<HmacResp> =
                    serde_json::from_slice(&resp).map_err(|_| bad_response(&self.k, op))?;
                let (v, payload) =
                    parse_versioned(&r.data.hmac).ok_or_else(|| bad_response(&self.k, op))?;
                let bytes = B64.decode(payload).map_err(|_| bad_response(&self.k, op))?;
                Ok(Tag::from_parts(
                    self.alg,
                    Some(KeyVersion::from_u64(v)),
                    bytes,
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
                let v = tag
                    .key_version()
                    .and_then(KeyVersion::as_u64)
                    .ok_or_else(|| {
                        invalid(
                            op,
                            "transit verification needs the tag's numeric key version",
                        )
                    })?;
                self.k.ensure_type(op, check_hmac).await?;
                let inp = b64(data);
                let encoded = format!("vault:v{v}:{}", B64.encode(tag.as_bytes()));
                let req = HmacReq {
                    input: &inp,
                    hmac: Some(&encoded),
                };
                let path = self
                    .k
                    .segs(&["verify", &self.k.name, mac_path(self.alg, op)?]);
                let mut call = self.k.call(
                    Method::POST,
                    path,
                    Some(body(&req, inp.len() + encoded.len())),
                    op,
                );
                call.key_version = Some(v);
                let resp = self.k.send(call, Origin::Input).await?;
                let r: Data<ValidResp> =
                    serde_json::from_slice(&resp).map_err(|_| bad_response(&self.k, op))?;
                if r.data.valid {
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

/// HMAC keys: transit reports `keys: null` for them, so [`KeyInfo::versions`] is empty; only the
/// latest and minimum versions are known.
impl Describe for TransitMacKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async {
                let info = self.k.read_info(Operation::Describe).await?.to_key_info();
                Ok(info.with_mac_algorithm(Some(self.alg)))
            })
            .await
    }
}

/// Fuzz hook (`__fuzz::decode_success`): decodes a success body with the response types and
/// steps of one operation (`which % 6`: encrypt/rewrap, decrypt, datakey, sign, verify, hmac;
/// `which / 6` picks the algorithm). Returns whether the body was accepted.
pub(crate) fn fuzz_decode_success(which: u8, body: &[u8]) -> bool {
    let versioned = |s: &str| {
        let (v, payload) = parse_versioned(s)?;
        Some((KeyVersion::from_u64(v), B64.decode(payload).ok()?))
    };
    let secret = |s: &str| {
        let mut out = Zeroizing::new(Vec::new());
        B64.decode_vec(s.as_bytes(), &mut out).ok().map(|()| out)
    };
    let sig_alg = SignatureAlgorithm::ALL[usize::from(which / 6) % SignatureAlgorithm::ALL.len()];
    let mac_alg = MacAlgorithm::ALL[usize::from(which / 6) % MacAlgorithm::ALL.len()];
    match which % 6 {
        0 => serde_json::from_slice::<Data<CiphertextResp>>(body).is_ok(),
        1 => serde_json::from_slice::<Data<PlaintextResp<'_>>>(body)
            .ok()
            .and_then(|r| secret(&r.data.plaintext))
            .is_some(),
        2 => serde_json::from_slice::<Data<DataKeyResp<'_>>>(body)
            .ok()
            .and_then(|r| {
                let pt = secret(&r.data.plaintext)?;
                let ct = Ciphertext::from_bytes(r.data.ciphertext.into_bytes());
                DataKey::new(DataKeySpec::Aes256, pt, ct).ok()
            })
            .is_some(),
        3 => serde_json::from_slice::<Data<SignResp>>(body)
            .ok()
            .and_then(|r| versioned(&r.data.signature))
            .filter(|(_, bytes)| signature_shape_ok(sig_alg, bytes))
            .map(|(v, bytes)| Signature::from_parts(sig_alg, Some(v), bytes))
            .is_some(),
        4 => serde_json::from_slice::<Data<ValidResp>>(body).is_ok_and(|r| r.data.valid),
        _ => serde_json::from_slice::<Data<HmacResp>>(body)
            .ok()
            .and_then(|r| versioned(&r.data.hmac))
            .map(|(v, bytes)| Tag::from_parts(mac_alg, Some(v), bytes))
            .is_some(),
    }
}

// ---------------------------------------------------------------------------------------------
// Semantics

/// Implements the inherent `semantics()` and [`Semantics`](anykms_core::Semantics) of a typed
/// handle from its server's value for the key family.
macro_rules! semantics {
    ($($Handle:ident => $family:ident),* $(,)?) => {$(
        impl $Handle {
            /// What this handle does where backends differ: floating, numeric versions; see [`KeySemantics`](anykms_core::KeySemantics).
            pub fn semantics(&self) -> &anykms_core::KeySemantics {
                &self.k.server.semantics.$family
            }
        }

        impl anykms_core::Semantics for $Handle {
            fn semantics(&self) -> Option<&anykms_core::KeySemantics> {
                Some($Handle::semantics(self))
            }
        }
    )*};
}

semantics! {
    TransitAeadKey => aead,
    TransitDigestKey => signing,
    TransitEd25519Key => signing,
    TransitMacKey => hmac,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_body_is_sized_for_large_aad() {
        // A body that outgrows its buffer would reallocate; the buffer must be pre-sized for the
        // AAD too (it used to be sized for the plaintext only).
        let aad = vec![7u8; 1 << 20];
        let b = encrypt_body(b"secret", &aad);
        let expected = b64(b"secret").len() + b64(&aad).len() + BODY_OVERHEAD;
        assert_eq!(b.capacity(), Vec::<u8>::with_capacity(expected).capacity());
        assert!(b.len() <= expected);
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(
            v["associated_data"].as_str().unwrap().len(),
            b64(&aad).len()
        );
        // A short hint still yields the whole body (grown through the zeroizing path).
        let small = body(&serde_json::json!({"x": "y".repeat(5000)}), 0);
        assert_eq!(small.len(), 5008);
    }

    #[test]
    fn signature_shape_bands() {
        use SignatureAlgorithm::*;
        let der = |n: usize| {
            let mut v = vec![0u8; n];
            v[0] = 0x30;
            v
        };
        assert!(signature_shape_ok(EcdsaP256Sha256, &der(71)));
        assert!(
            !signature_shape_ok(EcdsaP256Sha256, &der(103)),
            "P-384 signature labeled P-256"
        );
        assert!(signature_shape_ok(EcdsaP384Sha384, &der(103)));
        assert!(
            !signature_shape_ok(EcdsaP384Sha384, &der(139)),
            "P-521 signature labeled P-384"
        );
        assert!(signature_shape_ok(EcdsaP521Sha512, &der(139)));
        assert!(
            !signature_shape_ok(EcdsaP256Sha256, &[0u8; 256]),
            "RSA signature labeled ECDSA"
        );
        assert!(signature_shape_ok(RsaPssSha256, &[0u8; 256]));
        assert!(!signature_shape_ok(Ed25519, &der(71)));
    }

    #[test]
    fn versioned_prefix() {
        assert_eq!(parse_versioned("vault:v12:abc"), Some((12, "abc")));
        for bad in [
            "vault:v0:a",
            "vault:v01:a",
            "vault:v:a",
            "vault:vx:a",
            "vault:v1",
            "x:v1:a",
        ] {
            assert_eq!(parse_versioned(bad), None, "{bad}");
        }
    }

    #[test]
    fn sign_request_parameters_are_minimal() {
        let r = serde_json::to_string(
            &SignReq::new(SignatureAlgorithm::Ed25519, "aGk=", Operation::Sign).unwrap(),
        )
        .unwrap();
        assert_eq!(r, r#"{"input":"aGk="}"#);
        let r = serde_json::to_string(
            &SignReq::new(SignatureAlgorithm::RsaPssSha384, "aGk=", Operation::Sign).unwrap(),
        )
        .unwrap();
        assert_eq!(
            r,
            r#"{"input":"aGk=","prehashed":true,"hash_algorithm":"sha2-384","signature_algorithm":"pss","salt_length":"hash"}"#
        );
        let r = serde_json::to_string(
            &SignReq::new(SignatureAlgorithm::EcdsaP256Sha256, "aGk=", Operation::Sign).unwrap(),
        )
        .unwrap();
        assert_eq!(
            r,
            r#"{"input":"aGk=","prehashed":true,"hash_algorithm":"sha2-256","marshaling_algorithm":"asn1"}"#
        );
    }
}
