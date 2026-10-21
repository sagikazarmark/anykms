//! Typed key handles.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anykms_core::{
    Aead, AsymmetricKeyType, Ciphertext, DataKey, DataKeySpec, DataKeys, Describe, Digest,
    DigestSigner, DigestVerifier, Error, ErrorKind, KeyInfo, KeyTypeCheck, KeyVersion, KeyWrap,
    Mac, MacAlgorithm, MessageSigner, MessageVerifier, Operation, PinnedVerifier, Preflight,
    PublicKey, PublicKeys, Result, Rewrap, Signature, SignatureAlgorithm, Tag, WrappedDataKeys,
};
use anykms_http::cache::SingleFlight;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::BACKEND;
use crate::client::{Call, Kms};
use crate::context::{
    AadContext, EncryptionContext, GrantTokens, aad_context, decrypt_aad_context,
};
use crate::keyinfo::{AwsKeyInfo, RSA_OAEP, Spec, aws_mac_alg, aws_signing_alg};
use crate::uri::{AwsKeyRef, is_key_arn};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// AWS's plaintext and message limit for `Encrypt`, `Sign` (`RAW`) and `GenerateMac`.
pub(crate) const MAX_PLAINTEXT: usize = 4096;
/// AWS's ciphertext blob limit.
pub(crate) const MAX_CIPHERTEXT: usize = 6144;

/// How long cached key metadata is trusted before `DescribeKey` runs again (±10% jitter).
const DESCRIBE_TTL: Duration = Duration::from_secs(600);

/// Key metadata cache, shared per provider: URI ARN → (expiry, metadata).
#[derive(Default)]
pub(crate) struct DescribeCache {
    entries: Mutex<HashMap<String, (Instant, Arc<AwsKeyInfo>)>>,
    /// One `DescribeKey` at a time for concurrent misses (R-34), per URI ARN and grant tokens
    /// (a failure with one handle's grant tokens says nothing about another's).
    flights: SingleFlight<(String, usize), Result<Arc<AwsKeyInfo>>>,
}

/// Public keys of RSA wrapping keys, shared per provider: key ARN → SPKI DER. A key ARN's
/// material never changes for asymmetric keys, so entries never expire.
pub(crate) type PublicKeyCache = Mutex<HashMap<String, Arc<[u8]>>>;

/// Where the key version a request addresses came from (P1-4): only a request for the handle's
/// own key may drop its cached metadata, never one whose version came from input (a forged
/// `kid` must not force a `DescribeKey` on every caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    /// The handle's key (its URI or resolved ARN).
    Handle,
    /// A version from input: a signature's or tag's version, `public_key_version`.
    Input,
}

impl Origin {
    fn of(version: Option<&KeyVersion>) -> Self {
        if version.is_some() {
            Origin::Input
        } else {
            Origin::Handle
        }
    }
}

/// Everything a handle needs to reach one key.
#[derive(Clone)]
pub(crate) struct KeyCtx {
    pub(crate) kms: Arc<Kms>,
    pub(crate) key: Arc<AwsKeyRef>,
    pub(crate) endpoint: Arc<reqwest::Url>,
    pub(crate) check: KeyTypeCheck,
    pub(crate) cache: Arc<DescribeCache>,
    pub(crate) public_keys: Arc<PublicKeyCache>,
    pub(crate) resource: Arc<str>,
    pub(crate) grant_tokens: Option<GrantTokens>,
    /// The key ARN this handle resolves to: the URI's for key URIs, the alias target (from
    /// `DescribeKey` or a response's `KeyId`) for alias URIs.
    pub(crate) resolved: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for KeyCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKey")
            .field("arn", &self.key.arn)
            .field("key_type_check", &self.check)
            .field("grant_tokens", &self.grant_tokens)
            .finish()
    }
}

fn invalid(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, op, m)
}

fn bad_response(op: Operation) -> Error {
    // Fixed message: the body is never logged nor attached (it may carry plaintext or keys).
    crate::errors::unusable_response(op, Some(200), "unexpected response format")
}

/// Base64 into a zeroizing, pre-sized string.
fn b64(data: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(data.len().div_ceil(3) * 4 + 4));
    B64.encode_string(data, &mut s);
    s
}

/// A request body in a zeroizing buffer sized for `hint` bytes of field values.
fn body<T: Serialize>(value: &T, hint: usize) -> Zeroizing<Vec<u8>> {
    anykms_http::zbuf::json_body(value, hint.saturating_add(512)).expect("request serializes")
}

/// Decodes base64 into a zeroizing buffer, wiping any owned intermediate string.
fn decode_secret(mut s: Cow<'_, str>, op: Operation) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 4 * 3 + 3));
    let r = B64.decode_vec(s.as_bytes(), &mut out);
    if let Cow::Owned(o) = &mut s {
        o.zeroize();
    }
    r.map_err(|_| bad_response(op))?;
    Ok(out)
}

fn decode_blob(s: &str, op: Operation) -> Result<Vec<u8>> {
    let v = B64.decode(s).map_err(|_| bad_response(op))?;
    if v.is_empty() {
        return Err(bad_response(op));
    }
    Ok(v)
}

/// AWS encrypts 1 to 4096 bytes: checked before any request.
fn check_plaintext(plaintext: &[u8], op: Operation) -> Result<()> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        return Err(invalid(
            op,
            "AWS KMS encrypts 1 to 4096 bytes (use EnvelopeAead for more)",
        ));
    }
    Ok(())
}

/// A ciphertext blob AWS could have produced (1 to 6144 bytes); others fail before any request.
fn check_ciphertext(ct: &Ciphertext, op: Operation) -> Result<()> {
    if ct.is_empty() || ct.len() > MAX_CIPHERTEXT {
        return Err(Error::new(
            ErrorKind::DecryptFailed,
            BACKEND,
            op,
            "decryption failed",
        ));
    }
    Ok(())
}

/// The local checks of a signature to verify, before any request (including the key-type
/// check): its algorithm, its size and the form of its version.
fn precheck_signature(alg: SignatureAlgorithm, sig: &Signature) -> Result<()> {
    let op = Operation::Verify;
    if sig.algorithm() != alg {
        return Err(invalid(
            op,
            "signature algorithm does not match the key handle",
        ));
    }
    if sig.as_bytes().is_empty() || sig.as_bytes().len() > MAX_CIPHERTEXT {
        return Err(Error::new(
            ErrorKind::VerificationFailed,
            BACKEND,
            op,
            "signature is invalid",
        ));
    }
    check_version_form(sig.key_version(), op)
}

/// A caller-supplied version must be a KMS key ARN (`InvalidArgument` otherwise).
fn check_version_form(v: Option<&KeyVersion>, op: Operation) -> Result<()> {
    match v {
        Some(v) if !is_key_arn(v.as_str()) => {
            Err(invalid(op, "the key version is not a KMS key ARN"))
        }
        _ => Ok(()),
    }
}

/// A wire encryption context.
type Wire<'a> = BTreeMap<&'a str, &'a str>;

fn wire_of_aad(m: Option<&AadContext>) -> Option<Wire<'_>> {
    m.map(|m| m.iter().map(|(k, v)| (*k, v.as_str())).collect())
}

fn wire_of_ctx(c: &EncryptionContext) -> Option<Wire<'_>> {
    c.wire()
        .map(|m| m.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
}

fn ctx_len(w: Option<&Wire<'_>>) -> usize {
    w.map_or(0, |m| m.iter().map(|(k, v)| k.len() + v.len() + 8).sum())
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptReq<'a> {
    key_id: &'a str,
    plaintext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_context: Option<Wire<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_algorithm: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_tokens: Option<Vec<&'a str>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptReq<'a> {
    key_id: &'a str,
    ciphertext_blob: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_context: Option<Wire<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_algorithm: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_tokens: Option<Vec<&'a str>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ReEncryptReq<'a> {
    ciphertext_blob: &'a str,
    source_key_id: &'a str,
    destination_key_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_encryption_context: Option<Wire<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_encryption_context: Option<Wire<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_encryption_algorithm: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_encryption_algorithm: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_tokens: Option<Vec<&'a str>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DataKeyReq<'a> {
    key_id: &'a str,
    key_spec: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_context: Option<Wire<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_tokens: Option<Vec<&'a str>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct KeyIdReq<'a> {
    key_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_tokens: Option<Vec<&'a str>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SignReq<'a> {
    key_id: &'a str,
    message: &'a str,
    message_type: &'a str,
    signing_algorithm: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_tokens: Option<Vec<&'a str>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MacReq<'a> {
    key_id: &'a str,
    message: &'a str,
    mac_algorithm: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_tokens: Option<Vec<&'a str>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BlobResp {
    ciphertext_blob: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PlaintextResp<'a> {
    #[serde(borrow)]
    plaintext: Cow<'a, str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DataKeyResp<'a> {
    ciphertext_blob: String,
    #[serde(borrow)]
    plaintext: Cow<'a, str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SignResp {
    key_id: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VerifyResp {
    #[serde(default)]
    signature_valid: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MacResp {
    key_id: String,
    mac: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VerifyMacResp {
    #[serde(default)]
    mac_valid: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PublicKeyResp {
    key_id: String,
    public_key: String,
    #[serde(default)]
    key_spec: String,
    #[serde(default)]
    key_usage: String,
}

/// The AWS name of a data key spec.
fn aws_data_key_spec(spec: DataKeySpec, op: Operation) -> Result<&'static str> {
    match spec {
        DataKeySpec::Aes256 => Ok("AES_256"),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            BACKEND,
            op,
            "data key spec is not supported by AWS KMS",
        )),
    }
}

impl KeyCtx {
    /// The resource errors carry: the key URI (`aws-kms://arn:...`; no query exists).
    pub(crate) fn resource_of(key: &AwsKeyRef) -> Arc<str> {
        format!("aws-kms://{}", key.arn).into()
    }

    /// Names this key on `e`, unless an inner layer already did.
    pub(crate) fn label(&self, e: Error) -> Error {
        if e.resource().is_some() {
            e
        } else {
            e.with_resource(&*self.resource)
        }
    }

    pub(crate) async fn scoped<T>(&self, f: impl Future<Output = Result<T>>) -> Result<T> {
        f.await.map_err(|e| self.label(e))
    }

    fn grants(&self) -> Option<Vec<&str>> {
        self.grant_tokens.as_ref().map(GrantTokens::tokens)
    }

    pub(crate) fn arn(&self) -> &str {
        &self.key.arn
    }

    /// Sends one KMS request for the handle's own key (see [`call_from`](Self::call_from)).
    async fn call(
        &self,
        target: &'static str,
        op: Operation,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.call_from(Origin::Handle, target, op, body).await
    }

    /// Sends one KMS request. When it addressed the handle's own key (`Origin::Handle`), an
    /// error that may mean the key changed (`NotFound`, `KeyMismatch`, `Unsupported`,
    /// `KeyStateInvalid`) drops its cached metadata (P1-4); `InvalidArgument` never does.
    async fn call_from(
        &self,
        origin: Origin,
        target: &'static str,
        op: Operation,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // Signatures, tags and public keys are versioned by the resolved key ARN.
        let version = matches!(
            target,
            "Sign" | "Verify" | "GenerateMac" | "VerifyMac" | "GetPublicKey"
        )
        .then(|| {
            self.resolved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
        .flatten();
        let r = self
            .kms
            .call(Call {
                endpoint: &self.endpoint,
                region: &self.key.region,
                target,
                body,
                op,
                resource: Some(&self.resource),
                key_version: version.as_deref(),
            })
            .await;
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
            self.forget();
        }
        r
    }

    fn forget(&self) {
        self.cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key.arn);
    }

    fn cached(&self) -> Option<Arc<AwsKeyInfo>> {
        let now = Instant::now();
        self.cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&self.key.arn)
            .filter(|(exp, _)| now < *exp)
            .map(|(_, i)| i.clone())
    }

    /// One uncached `DescribeKey` of `key_id` (the URI's key or alias, or the resolved key
    /// ARN). The described ARN must be `key_id` when that is a key ARN, and must belong to this
    /// handle either way.
    async fn describe_key(
        &self,
        origin: Origin,
        key_id: &str,
        op: Operation,
    ) -> Result<Arc<AwsKeyInfo>> {
        let req = KeyIdReq {
            key_id,
            grant_tokens: self.grants(),
        };
        let resp = self
            .call_from(origin, "DescribeKey", op, body(&req, 0))
            .await?;
        let info = Arc::new(AwsKeyInfo::parse(&resp).map_err(|e| e.with_operation(op))?);
        self.check_response_arn(&info.arn, op)?;
        if is_key_arn(key_id) && info.arn != key_id {
            return Err(crate::errors::unusable_response(
                op,
                Some(200),
                "the response names another key",
            ));
        }
        Ok(info)
    }

    /// Fresh `DescribeKey` metadata (refreshes the cache and the resolved ARN).
    pub(crate) async fn describe(&self, op: Operation) -> Result<Arc<AwsKeyInfo>> {
        let info = self.describe_key(Origin::Handle, self.arn(), op).await?;
        let now = Instant::now();
        {
            let mut c = self
                .cache
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            c.retain(|_, (exp, _)| now < *exp);
            c.insert(
                self.key.arn.clone(),
                (
                    now + anykms_http::cache::jittered_ttl(DESCRIBE_TTL),
                    info.clone(),
                ),
            );
        }
        self.note_resolved(&info.arn);
        Ok(info)
    }

    /// The cached or fresh metadata. Concurrent misses for the key share one `DescribeKey` and
    /// its result, a failure included (R-34).
    async fn info(&self, op: Operation) -> Result<Arc<AwsKeyInfo>> {
        let i = if let Some(i) = self.cached() {
            i
        } else {
            let flight = (
                self.key.arn.clone(),
                self.grant_tokens.as_ref().map_or(0, GrantTokens::identity),
            );
            self.cache
                .flights
                .run(&flight, || async {
                    // A flight that landed after the miss above has filled the cache.
                    match self.cached() {
                        Some(i) => Ok(i),
                        None => self.describe(op).await,
                    }
                })
                .await
                // The flight may have been another operation's.
                .map_err(|e| e.with_operation(op))?
        };
        // A response may have resolved an alias more recently than the cached metadata.
        let mut r = self
            .resolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if r.is_none() {
            *r = Some(i.arn.clone());
        }
        Ok(i)
    }

    /// Runs the key-type check (cached per provider) unless the caller opted out.
    async fn ensure(&self, op: Operation, check: impl Fn(&AwsKeyInfo) -> Result<()>) -> Result<()> {
        if self.check == KeyTypeCheck::TrustCaller {
            return Ok(());
        }
        let info = self.info(op).await?;
        check(&info).map_err(|e| e.with_operation(op))
    }

    /// The `Preflight` of every handle: one fresh `DescribeKey` (refreshing the cache), the
    /// key-type check (even under `KeyTypeCheck::TrustCaller`) and the state check, every error
    /// labelled `Operation::Describe`.
    async fn preflight(&self, check: impl Fn(&AwsKeyInfo) -> Result<()>) -> Result<KeyInfo> {
        self.scoped(async {
            let op = Operation::Describe;
            let info = self.describe(op).await?;
            check(&info).map_err(|e| e.with_operation(op))?;
            check_enabled(&info, op)?;
            Ok(info.to_key_info())
        })
        .await
    }

    /// Records the key ARN an alias resolves to (a change is logged; the old ARN stops being
    /// accepted as a version).
    fn note_resolved(&self, arn: &str) {
        let mut r = self
            .resolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if r.as_deref() != Some(arn) {
            #[cfg(feature = "tracing")]
            if r.is_some() {
                tracing::info!(
                    backend = BACKEND,
                    resource = &*self.resource,
                    key_version = arn,
                    "alias now resolves to another key"
                );
            }
            *r = Some(arn.to_owned());
        }
    }

    /// A response's `KeyId`: must be a key ARN; for key URIs, the URI's; for alias URIs, a key
    /// of the alias's partition, region and account (an alias never names another account's
    /// key).
    fn response_key(&self, key_id: String, op: Operation) -> Result<KeyVersion> {
        if !is_key_arn(&key_id) {
            return Err(bad_response(op));
        }
        self.check_response_arn(&key_id, op)?;
        self.note_resolved(&key_id);
        Ok(KeyVersion::new(key_id))
    }

    /// A key ARN the server returned for this handle (a response `KeyId`, `DescribeKey`'s
    /// `Arn`): the URI's own ARN for key URIs; for alias URIs, a key in the alias's partition,
    /// region and account.
    fn check_response_arn(&self, arn: &str, op: Operation) -> Result<()> {
        let ok = if self.key.is_alias() {
            AwsKeyRef::parse_arn(arn).is_ok_and(|r| {
                r.partition == self.key.partition
                    && r.region == self.key.region
                    && r.account == self.key.account
            })
        } else {
            arn == self.key.arn
        };
        if ok {
            Ok(())
        } else {
            Err(crate::errors::unusable_response(
                op,
                Some(200),
                "the response names another key",
            ))
        }
    }

    /// The resolved key ARN; for an alias not yet resolved, one `DescribeKey` (even under
    /// `KeyTypeCheck::TrustCaller`).
    async fn resolved_arn(&self, op: Operation) -> Result<String> {
        if let Some(r) = self
            .resolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Ok(r);
        }
        Ok(self.info(op).await?.arn.clone())
    }

    /// A caller-supplied version (signature or tag): `None` verifies with this handle's key
    /// (an AWS key has exactly one version); a malformed value is `InvalidArgument`; another
    /// key's ARN is `VerificationFailed` before any request (a `kid` from a token must never
    /// select a key).
    async fn check_version(&self, v: Option<&KeyVersion>, op: Operation) -> Result<String> {
        let Some(v) = v else {
            return self.resolved_arn(op).await;
        };
        if !is_key_arn(v.as_str()) {
            return Err(invalid(op, "the key version is not a KMS key ARN"));
        }
        let resolved = self.resolved_arn(op).await?;
        if v.as_str() != resolved {
            return Err(Error::new(
                ErrorKind::VerificationFailed,
                BACKEND,
                op,
                "the key version names another key than this handle's",
            ));
        }
        Ok(resolved)
    }

    // -- symmetric and RSA encryption ------------------------------------------------------

    async fn encrypt_raw(
        &self,
        plaintext: &[u8],
        ctx: Option<Wire<'_>>,
        alg: Option<&str>,
        op: Operation,
    ) -> Result<Ciphertext> {
        check_plaintext(plaintext, op)?;
        let pt = b64(plaintext);
        let hint = pt.len() + ctx_len(ctx.as_ref());
        let req = EncryptReq {
            key_id: self.arn(),
            plaintext: &pt,
            encryption_context: ctx,
            encryption_algorithm: alg,
            grant_tokens: self.grants(),
        };
        let resp = self.call("Encrypt", op, body(&req, hint)).await?;
        let r: BlobResp = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        Ok(Ciphertext::from_bytes(decode_blob(&r.ciphertext_blob, op)?))
    }

    async fn decrypt_raw(
        &self,
        ct: &Ciphertext,
        ctx: Option<Wire<'_>>,
        alg: Option<&str>,
        op: Operation,
    ) -> Result<Zeroizing<Vec<u8>>> {
        check_ciphertext(ct, op)?;
        let blob = B64.encode(ct.as_bytes());
        let hint = blob.len() + ctx_len(ctx.as_ref());
        let req = DecryptReq {
            key_id: self.arn(),
            ciphertext_blob: &blob,
            encryption_context: ctx,
            encryption_algorithm: alg,
            grant_tokens: self.grants(),
        };
        let resp = self.call("Decrypt", op, body(&req, hint)).await?;
        let r: PlaintextResp<'_> = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        decode_secret(r.plaintext, op)
    }

    async fn reencrypt_raw(
        &self,
        ct: &Ciphertext,
        from: Option<Wire<'_>>,
        to: Option<Wire<'_>>,
        alg: Option<&str>,
        op: Operation,
    ) -> Result<Ciphertext> {
        check_ciphertext(ct, op)?;
        let blob = B64.encode(ct.as_bytes());
        let hint = blob.len() + ctx_len(from.as_ref()) + ctx_len(to.as_ref());
        let req = ReEncryptReq {
            ciphertext_blob: &blob,
            source_key_id: self.arn(),
            destination_key_id: self.arn(),
            source_encryption_context: from,
            destination_encryption_context: to,
            source_encryption_algorithm: alg,
            destination_encryption_algorithm: alg,
            grant_tokens: self.grants(),
        };
        let resp = self.call("ReEncrypt", op, body(&req, hint)).await?;
        let r: BlobResp = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        Ok(Ciphertext::from_bytes(decode_blob(&r.ciphertext_blob, op)?))
    }

    async fn data_key_raw(&self, spec: DataKeySpec, ctx: Option<Wire<'_>>) -> Result<DataKey> {
        let op = Operation::GenerateDataKey;
        let key_spec = aws_data_key_spec(spec, op)?;
        let req = DataKeyReq {
            key_id: self.arn(),
            key_spec,
            encryption_context: ctx,
            grant_tokens: self.grants(),
        };
        let resp = self.call("GenerateDataKey", op, body(&req, 0)).await?;
        let r: DataKeyResp<'_> = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        let DataKeyResp {
            ciphertext_blob,
            plaintext,
        } = r;
        let pt = decode_secret(plaintext, op)?;
        let wrapped = Ciphertext::from_bytes(decode_blob(&ciphertext_blob, op)?);
        DataKey::new(spec, pt, wrapped).map_err(|_| bad_response(op))
    }

    async fn wrapped_data_key_raw(
        &self,
        spec: DataKeySpec,
        ctx: Option<Wire<'_>>,
    ) -> Result<Ciphertext> {
        let op = Operation::GenerateDataKey;
        let key_spec = aws_data_key_spec(spec, op)?;
        let req = DataKeyReq {
            key_id: self.arn(),
            key_spec,
            encryption_context: ctx,
            grant_tokens: self.grants(),
        };
        let resp = self
            .call("GenerateDataKeyWithoutPlaintext", op, body(&req, 0))
            .await?;
        let r: BlobResp = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        Ok(Ciphertext::from_bytes(decode_blob(&r.ciphertext_blob, op)?))
    }

    // -- signing and MAC -------------------------------------------------------------------

    async fn sign_raw(
        &self,
        msg: &[u8],
        message_type: &'static str,
        alg: SignatureAlgorithm,
    ) -> Result<Signature> {
        let op = Operation::Sign;
        let name = aws_signing_alg(alg).ok_or_else(|| invalid(op, "unsupported algorithm"))?;
        let m = b64(msg);
        let req = SignReq {
            key_id: self.arn(),
            message: &m,
            message_type,
            signing_algorithm: name,
            signature: None,
            grant_tokens: self.grants(),
        };
        let resp = self.call("Sign", op, body(&req, m.len())).await?;
        let r: SignResp = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        let bytes = decode_blob(&r.signature, op)?;
        let v = self.response_key(r.key_id, op)?;
        Ok(Signature::from_parts(alg, Some(v), bytes))
    }

    async fn verify_raw(
        &self,
        msg: &[u8],
        message_type: &'static str,
        alg: SignatureAlgorithm,
        sig: &Signature,
    ) -> Result<()> {
        let op = Operation::Verify;
        precheck_signature(alg, sig)?;
        let failed = || {
            Error::new(
                ErrorKind::VerificationFailed,
                BACKEND,
                op,
                "signature is invalid",
            )
        };
        let resolved = self.check_version(sig.key_version(), op).await?;
        let name = aws_signing_alg(alg).ok_or_else(|| invalid(op, "unsupported algorithm"))?;
        let m = b64(msg);
        let s = B64.encode(sig.as_bytes());
        let req = SignReq {
            key_id: &resolved,
            message: &m,
            message_type,
            signing_algorithm: name,
            signature: Some(&s),
            grant_tokens: self.grants(),
        };
        let origin = Origin::of(sig.key_version());
        let resp = self
            .call_from(origin, "Verify", op, body(&req, m.len() + s.len()))
            .await?;
        let r: VerifyResp = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        match r.signature_valid {
            Some(true) => Ok(()),
            Some(false) => Err(failed()),
            None => Err(bad_response(op)),
        }
    }

    /// `GetPublicKey` for `key_id`; checks the response against `expect_usage` and `fits`.
    async fn public_key_raw(
        &self,
        origin: Origin,
        key_id: &str,
        expect_usage: &'static str,
        fits: impl Fn(AsymmetricKeyType) -> bool,
    ) -> Result<PublicKey> {
        let op = Operation::PublicKey;
        let req = KeyIdReq {
            key_id,
            grant_tokens: self.grants(),
        };
        let resp = self
            .call_from(origin, "GetPublicKey", op, body(&req, 0))
            .await?;
        let r: PublicKeyResp = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
        let mismatch = |m| Error::new(ErrorKind::KeyMismatch, BACKEND, op, m);
        let Spec::Asymmetric(t) = crate::keyinfo::spec(&r.key_spec) else {
            return Err(mismatch(
                "the AWS key's spec is not supported for this handle",
            ));
        };
        if r.key_usage != expect_usage || !fits(t) {
            return Err(mismatch(
                "the AWS key's type or usage does not match the handle",
            ));
        }
        let der = decode_blob(&r.public_key, op)?;
        let v = self.response_key(r.key_id, op)?;
        Ok(PublicKey::new(t, der, Some(v)))
    }
}

// ---------------------------------------------------------------------------------------------
// AEAD

/// An AWS KMS symmetric key (`SYMMETRIC_DEFAULT`): `Aead`, `Rewrap`, `DataKeys`,
/// `WrappedDataKeys`, `Describe`, and native encryption contexts through
/// [`EncryptionContextAead`](crate::EncryptionContextAead).
///
/// AAD is sent as the encryption context `{"associatedData": lowercase_hex(aad)}`, Tink's
/// mapping (see [`AAD_CONTEXT_KEY`](crate::AAD_CONTEXT_KEY)); empty AAD sends none. AAD is
/// capped at [`MAX_AAD_BYTES`](crate::MAX_AAD_BYTES) when producing a ciphertext, never on
/// `Decrypt`. Plaintexts are 1 to 4096
/// bytes (AWS rejects empty input; use `EnvelopeAead` for bulk data). `Decrypt` and `ReEncrypt`
/// always name this key. No key version is exposed (`ciphertext_version` is `None`).
///
/// **Envelope KEKs:** a key used as a KEK MUST be dedicated to envelopes (data keys are wrapped
/// with empty AAD).
#[derive(Clone, Debug)]
pub struct AwsAeadKey {
    pub(crate) k: KeyCtx,
}

impl AwsAeadKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    pub(crate) async fn encrypt_ctx(
        &self,
        pt: &[u8],
        ctx: &EncryptionContext,
    ) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::Encrypt;
                check_plaintext(pt, op)?;
                ctx.check(op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k.encrypt_raw(pt, wire_of_ctx(ctx), None, op).await
            })
            .await
    }

    pub(crate) async fn decrypt_ctx(
        &self,
        ct: &Ciphertext,
        ctx: &EncryptionContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.k
            .scoped(async {
                let op = Operation::Decrypt;
                check_ciphertext(ct, op)?;
                ctx.check(op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k.decrypt_raw(ct, wire_of_ctx(ctx), None, op).await
            })
            .await
    }

    pub(crate) async fn rewrap_ctx(
        &self,
        ct: &Ciphertext,
        from: &EncryptionContext,
        to: &EncryptionContext,
    ) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::Rewrap;
                check_ciphertext(ct, op)?;
                from.check(op)?;
                to.check(op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k
                    .reencrypt_raw(ct, wire_of_ctx(from), wire_of_ctx(to), None, op)
                    .await
            })
            .await
    }

    pub(crate) async fn data_key_ctx(
        &self,
        spec: DataKeySpec,
        ctx: &EncryptionContext,
    ) -> Result<DataKey> {
        self.k
            .scoped(async {
                let op = Operation::GenerateDataKey;
                ctx.check(op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k.data_key_raw(spec, wire_of_ctx(ctx)).await
            })
            .await
    }
}

impl Preflight for AwsAeadKey {
    /// Sends a fresh `DescribeKey`, runs the key-type check (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key that is not enabled (`KeyStateInvalid`; `Unavailable` while it is being created or
    /// updated), every error labelled `Operation::Describe`. Returns the key's metadata, with the
    /// backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        self.k.preflight(AwsKeyInfo::check_aead).await
    }
}

impl Aead for AwsAeadKey {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::Encrypt;
                check_plaintext(plaintext, op)?;
                let ctx = aad_context(aad, op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k
                    .encrypt_raw(plaintext, wire_of_aad(ctx.as_ref()), None, op)
                    .await
            })
            .await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.k
            .scoped(async {
                let op = Operation::Decrypt;
                check_ciphertext(ct, op)?;
                // Not capped: the cap binds the operations that produce a ciphertext.
                let ctx = decrypt_aad_context(aad);
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k
                    .decrypt_raw(ct, wire_of_aad(ctx.as_ref()), None, op)
                    .await
            })
            .await
    }
}

/// `ReEncrypt` under the same key, with the AAD as both source and destination context. The AAD
/// cap applies: the destination context is a new ciphertext's.
impl Rewrap for AwsAeadKey {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::Rewrap;
                check_ciphertext(ct, op)?;
                let ctx = aad_context(aad, op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                let w = wire_of_aad(ctx.as_ref());
                self.k.reencrypt_raw(ct, w.clone(), w, None, op).await
            })
            .await
    }
}

/// `GenerateDataKey` (`AES_256`), the AAD bound as the encryption context.
impl DataKeys for AwsAeadKey {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        self.k
            .scoped(async {
                let op = Operation::GenerateDataKey;
                aws_data_key_spec(spec, op)?;
                let ctx = aad_context(aad, op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k.data_key_raw(spec, wire_of_aad(ctx.as_ref())).await
            })
            .await
    }
}

/// `GenerateDataKeyWithoutPlaintext`, the AAD bound as the encryption context.
impl WrappedDataKeys for AwsAeadKey {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::GenerateDataKey;
                aws_data_key_spec(spec, op)?;
                let ctx = aad_context(aad, op)?;
                self.k.ensure(op, AwsKeyInfo::check_aead).await?;
                self.k
                    .wrapped_data_key_raw(spec, wire_of_aad(ctx.as_ref()))
                    .await
            })
            .await
    }
}

impl Describe for AwsAeadKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.describe(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Key wrapping

/// An AWS KMS key as an envelope KEK (`Provider::key_wrap`): `KeyWrap`, `Rewrap` (empty AAD
/// only), `Describe`.
///
/// - **Symmetric keys** wrap with `Encrypt` and no encryption context (like
///   [`AeadKeyWrap`](anykms_core::AeadKeyWrap)).
/// - **RSA `ENCRYPT_DECRYPT` keys** wrap locally with RSAES-OAEP-SHA-256 over the key's public
///   key (fetched once with `GetPublicKey` and pinned to the key ARN) and unwrap with `Decrypt`
///   (`RSAES_OAEP_SHA_256`; SHA-1 OAEP is never used). Rewrap is `ReEncrypt` with that algorithm.
///   Wrapping needs the crate's `rsa-aws-lc-rs` (default) or `rsa-rustcrypto` feature.
///   AWS serves the public key of a disabled key, so every RSA wrap first checks the key state
///   in the cached `DescribeKey` metadata and refuses a key that is not enabled
///   (`KeyStateInvalid`; `Unavailable` while it is being created or updated). That metadata is
///   cached for up to about 11 minutes (10 minutes ±10%): a key disabled or scheduled for
///   deletion in that window can still wrap until the cache expires, unless `describe` or
///   `preflight` refreshes it first.
///
/// The kind is read from `DescribeKey` before the first operation; with
/// `KeyTypeCheck::TrustCaller` the key is treated as symmetric (until `describe` or `preflight`
/// has cached its metadata).
#[derive(Clone, Debug)]
pub struct AwsKeyWrapKey {
    pub(crate) k: KeyCtx,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KekKind {
    Symmetric,
    Rsa,
}

impl AwsKeyWrapKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    /// The key's kind and the metadata it was read from (`None` only under
    /// `KeyTypeCheck::TrustCaller` with nothing cached: symmetric is assumed).
    async fn kind(&self, op: Operation) -> Result<(KekKind, Option<Arc<AwsKeyInfo>>)> {
        if self.k.check == KeyTypeCheck::TrustCaller && self.k.cached().is_none() {
            return Ok((KekKind::Symmetric, None));
        }
        let info = self.k.info(op).await?;
        Ok((kek_kind(&info, op)?, Some(info)))
    }

    /// The pinned public key of the resolved key ARN.
    async fn rsa_public_key(&self, op: Operation) -> Result<Arc<[u8]>> {
        let arn = self.k.resolved_arn(op).await?;
        if let Some(p) = self
            .k
            .public_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&arn)
        {
            return Ok(p.clone());
        }
        let pk = self
            .k
            .public_key_raw(Origin::Handle, &arn, "ENCRYPT_DECRYPT", |t| {
                matches!(t, AsymmetricKeyType::Rsa { .. })
            })
            .await
            .map_err(|e| e.with_operation(op))?;
        if pk.key_version().map(KeyVersion::as_str) != Some(arn.as_str()) {
            return Err(crate::errors::unusable_response(
                op,
                Some(200),
                "the response names another key",
            ));
        }
        let der: Arc<[u8]> = pk.spki_der().into();
        self.k
            .public_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(arn, der.clone());
        Ok(der)
    }
}

/// Symmetric or RSA (`ENCRYPT_DECRYPT` with `RSAES_OAEP_SHA_256`); any other key is
/// `KeyMismatch`.
fn kek_kind(info: &AwsKeyInfo, op: Operation) -> Result<KekKind> {
    if info.check_aead().is_ok() {
        return Ok(KekKind::Symmetric);
    }
    if info.check_rsa_wrap().is_ok() {
        return Ok(KekKind::Rsa);
    }
    Err(Error::new(
        ErrorKind::KeyMismatch,
        BACKEND,
        op,
        "the AWS key is neither a symmetric key nor an RSA encryption key with RSAES_OAEP_SHA_256",
    ))
}

impl Preflight for AwsKeyWrapKey {
    /// Sends a fresh `DescribeKey`, runs the key-type check (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key that is not enabled (`KeyStateInvalid`; `Unavailable` while it is being created or
    /// updated), every error labelled `Operation::Describe`. Returns the key's metadata, with the
    /// backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        self.k
            .preflight(|i| kek_kind(i, Operation::Describe).map(drop))
            .await
    }
}

impl KeyWrap for AwsKeyWrapKey {
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::WrapKey;
                match self.kind(op).await? {
                    (KekKind::Symmetric, _) => self.k.encrypt_raw(key, None, None, op).await,
                    (KekKind::Rsa, info) => {
                        // The wrap is local and AWS serves `GetPublicKey` for a disabled key, so
                        // nothing else refuses a disabled or pending-deletion key: check the
                        // state of the metadata the kind was read from, before the public key.
                        if let Some(info) = info {
                            check_enabled(&info, op)?;
                        }
                        let spki = self.rsa_public_key(op).await?;
                        let wrapped =
                            anykms_recipes::rsa_oaep_sha256_encrypt(&spki, key).map_err(|e| {
                                Error::new(e.kind(), BACKEND, op, e.message().to_owned())
                            })?;
                        Ok(Ciphertext::from_bytes(wrapped))
                    }
                }
            })
            .await
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        self.k
            .scoped(async {
                let op = Operation::UnwrapKey;
                let alg = match self.kind(op).await?.0 {
                    KekKind::Symmetric => None,
                    KekKind::Rsa => Some(RSA_OAEP),
                };
                self.k.decrypt_raw(wrapped, None, alg, op).await
            })
            .await
    }
}

/// `ReEncrypt` under the same key with empty AAD (the opaque `KeyWrapKey` refuses other AAD).
impl Rewrap for AwsKeyWrapKey {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        self.k
            .scoped(async {
                let op = Operation::Rewrap;
                if !aad.is_empty() {
                    return Err(invalid(
                        op,
                        "wrapped keys have empty AAD; aad must be empty",
                    ));
                }
                let alg = match self.kind(op).await?.0 {
                    KekKind::Symmetric => None,
                    KekKind::Rsa => Some(RSA_OAEP),
                };
                self.k.reencrypt_raw(ct, None, None, alg, op).await
            })
            .await
    }
}

impl Describe for AwsKeyWrapKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.describe(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Signing

/// An AWS KMS ECDSA or RSA signing key for one algorithm: `DigestSigner`, `DigestVerifier`,
/// `PublicKeys`, `Describe`.
///
/// Signs with `MessageType=DIGEST`; signatures carry the key ARN as their version (for an alias,
/// the key it resolves to). Verification is server-side (`Verify`, naming the resolved key ARN)
/// and only accepts this handle's key: a signature whose version is another key's ARN is
/// `VerificationFailed` before any request, a malformed version `InvalidArgument`; one without a
/// version verifies with this handle's key.
///
/// `public_key` and `public_key_version` send an uncached `DescribeKey` before `GetPublicKey`
/// and refuse a key that is not enabled (`KeyStateInvalid`; AWS would serve a disabled key's
/// public key). As a `public_key_version` argument, another key's ARN is `UnknownKeyVersion`.
#[derive(Clone, Debug)]
pub struct AwsDigestKey {
    pub(crate) k: KeyCtx,
    pub(crate) alg: SignatureAlgorithm,
}

impl AwsDigestKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    fn check_digest(&self, digest: &Digest, op: Operation) -> Result<()> {
        if Some(digest.algorithm()) != self.alg.hash() {
            return Err(invalid(
                op,
                "digest algorithm does not match the signature algorithm",
            ));
        }
        Ok(())
    }
}

impl Preflight for AwsDigestKey {
    /// Sends a fresh `DescribeKey`, runs the key-type check (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key that is not enabled (`KeyStateInvalid`; `Unavailable` while it is being created or
    /// updated), every error labelled `Operation::Describe`. Returns the key's metadata, with the
    /// backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        let alg = self.alg;
        self.k.preflight(|i| i.check_signing(alg)).await
    }
}

impl DigestSigner for AwsDigestKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        self.k
            .scoped(async {
                let op = Operation::Sign;
                self.check_digest(digest, op)?;
                let alg = self.alg;
                self.k.ensure(op, |i| i.check_signing(alg)).await?;
                self.k.sign_raw(digest.as_bytes(), "DIGEST", alg).await
            })
            .await
    }
}

impl DigestVerifier for AwsDigestKey {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        self.k
            .scoped(async {
                let op = Operation::Verify;
                self.check_digest(digest, op)?;
                let alg = self.alg;
                precheck_signature(alg, sig)?;
                self.k.ensure(op, |i| i.check_signing(alg)).await?;
                self.k
                    .verify_raw(digest.as_bytes(), "DIGEST", alg, sig)
                    .await
            })
            .await
    }
}

impl PinnedVerifier for AwsDigestKey {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

/// Refuses a key that is not `Enabled` (§3.1(f)): the transient states (`Creating`, `Updating`,
/// `Unavailable`) are `Unavailable` (retryable), every other state `KeyStateInvalid`.
fn check_enabled(info: &AwsKeyInfo, op: Operation) -> Result<()> {
    let (kind, m) = match info.key_state.as_str() {
        "Enabled" => return Ok(()),
        "Creating" | "Updating" | "Unavailable" => (
            ErrorKind::Unavailable,
            "the key is temporarily not usable (creating, updating or unavailable)",
        ),
        "Disabled" => (ErrorKind::KeyStateInvalid, "key is disabled"),
        _ => (
            ErrorKind::KeyStateInvalid,
            "key is not in a usable state (pending deletion or import)",
        ),
    };
    Err(Error::new(kind, BACKEND, op, m))
}

/// `public_key` and `public_key_version`. AWS serves `GetPublicKey` for a disabled key, so an
/// uncached `DescribeKey` of the same key runs first and refuses any key that is not enabled
/// (§3.1(f)): two requests per call. For an alias URI, `DescribeKey` resolves the alias (for a
/// version from input, the resolved key ARN is described) and `GetPublicKey` names the key ARN
/// that was described, never the alias. A missing `kms:DescribeKey` permission fails the call.
async fn public_key_of(
    k: &KeyCtx,
    alg: SignatureAlgorithm,
    version: Option<&KeyVersion>,
) -> Result<PublicKey> {
    public_key_for(
        k,
        version,
        "SIGN_VERIFY",
        |t| alg.is_compatible_with(&t),
        |info| info.check_signing(alg),
    )
    .await
}

/// The public key of an RSA key-wrapping key (`ENCRYPT_DECRYPT`), for wrapping offline.
async fn kek_public_key(k: &KeyCtx, version: Option<&KeyVersion>) -> Result<PublicKey> {
    public_key_for(
        k,
        version,
        "ENCRYPT_DECRYPT",
        |t| matches!(t, AsymmetricKeyType::Rsa { .. }),
        AwsKeyInfo::check_rsa_wrap,
    )
    .await
}

/// `GetPublicKey` for the handle's key (or `version`, which must be its ARN), after an uncached
/// `DescribeKey` that refuses a key that is not enabled or (unless the caller trusts it) not of
/// the expected kind.
async fn public_key_for(
    k: &KeyCtx,
    version: Option<&KeyVersion>,
    usage: &'static str,
    fits: impl Fn(AsymmetricKeyType) -> bool,
    kind: impl Fn(&AwsKeyInfo) -> Result<()>,
) -> Result<PublicKey> {
    let op = Operation::PublicKey;
    let usable = |info: &AwsKeyInfo| -> Result<()> {
        if k.check != KeyTypeCheck::TrustCaller {
            kind(info).map_err(|e| e.with_operation(op))?;
        }
        check_enabled(info, op)
    };
    let (origin, arn) = match version {
        None => {
            let info = k.describe(op).await?;
            usable(&info)?;
            (Origin::Handle, info.arn.clone())
        }
        Some(v) => {
            if !is_key_arn(v.as_str()) {
                return Err(invalid(op, "the key version is not a KMS key ARN"));
            }
            let resolved = k.resolved_arn(op).await?;
            if v.as_str() != resolved {
                return Err(Error::new(
                    ErrorKind::UnknownKeyVersion,
                    BACKEND,
                    op,
                    "the key version names another key than this handle's",
                ));
            }
            let info = k.describe_key(Origin::Input, &resolved, op).await?;
            usable(&info)?;
            (Origin::Input, resolved)
        }
    };
    let pk = k.public_key_raw(origin, &arn, usage, fits).await?;
    if pk.key_version().map(KeyVersion::as_str) != Some(arn.as_str()) {
        return Err(crate::errors::unusable_response(
            op,
            Some(200),
            "the response names another key",
        ));
    }
    Ok(pk)
}

/// RSA key-wrapping keys only (a symmetric KEK has no public key: `KeyMismatch`, or under
/// `KeyTypeCheck::TrustCaller` the service's refusal). Publish it to wrap data keys offline
/// (`anykms_recipes::rsa_oaep_sha256_encrypt`); unwrap through the handle.
impl PublicKeys for AwsKeyWrapKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k.scoped(kek_public_key(&self.k, None)).await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k.scoped(kek_public_key(&self.k, Some(version))).await
    }
}

impl PublicKeys for AwsDigestKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k.scoped(public_key_of(&self.k, self.alg, None)).await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(public_key_of(&self.k, self.alg, Some(version)))
            .await
    }
}

impl Describe for AwsDigestKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.describe(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

/// An AWS KMS Ed25519 key (`ECC_NIST_EDWARDS25519`): `MessageSigner`, `MessageVerifier`,
/// `PublicKeys`, `Describe`. Pure Ed25519 (`ED25519_SHA_512`, `MessageType=RAW`) over messages
/// of 1 to 4096 bytes; `ED25519_PH_SHA_512` is never used. Versions as for [`AwsDigestKey`].
#[derive(Clone, Debug)]
pub struct AwsEd25519Key {
    pub(crate) k: KeyCtx,
}

impl AwsEd25519Key {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }

    fn check_message(msg: &[u8], op: Operation) -> Result<()> {
        if msg.is_empty() || msg.len() > MAX_PLAINTEXT {
            return Err(invalid(op, "AWS KMS signs messages of 1 to 4096 bytes"));
        }
        Ok(())
    }
}

impl Preflight for AwsEd25519Key {
    /// Sends a fresh `DescribeKey`, runs the key-type check (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key that is not enabled (`KeyStateInvalid`; `Unavailable` while it is being created or
    /// updated), every error labelled `Operation::Describe`. Returns the key's metadata, with the
    /// backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        self.k
            .preflight(|i| i.check_signing(SignatureAlgorithm::Ed25519))
            .await
    }
}

impl MessageSigner for AwsEd25519Key {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        self.k
            .scoped(async {
                let op = Operation::Sign;
                Self::check_message(msg, op)?;
                self.k
                    .ensure(op, |i| i.check_signing(SignatureAlgorithm::Ed25519))
                    .await?;
                self.k
                    .sign_raw(msg, "RAW", SignatureAlgorithm::Ed25519)
                    .await
            })
            .await
    }
}

impl MessageVerifier for AwsEd25519Key {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.k
            .scoped(async {
                let op = Operation::Verify;
                Self::check_message(msg, op)?;
                precheck_signature(SignatureAlgorithm::Ed25519, sig)?;
                self.k
                    .ensure(op, |i| i.check_signing(SignatureAlgorithm::Ed25519))
                    .await?;
                self.k
                    .verify_raw(msg, "RAW", SignatureAlgorithm::Ed25519, sig)
                    .await
            })
            .await
    }
}

impl PinnedVerifier for AwsEd25519Key {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}

impl PublicKeys for AwsEd25519Key {
    async fn public_key(&self) -> Result<PublicKey> {
        self.k
            .scoped(public_key_of(&self.k, SignatureAlgorithm::Ed25519, None))
            .await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.k
            .scoped(public_key_of(
                &self.k,
                SignatureAlgorithm::Ed25519,
                Some(version),
            ))
            .await
    }
}

impl Describe for AwsEd25519Key {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.describe(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// MAC

/// An AWS KMS HMAC key (`HMAC_256/384/512`) for one algorithm: `Mac`, `Describe`. Messages are 1
/// to 4096 bytes (hash longer data first). Tags carry the key ARN as their version and verify
/// server-side (`VerifyMac`) under the same rules as signatures (see [`AwsDigestKey`]).
#[derive(Clone, Debug)]
pub struct AwsMacKey {
    pub(crate) k: KeyCtx,
    pub(crate) alg: MacAlgorithm,
}

impl AwsMacKey {
    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.k.check = check;
        self
    }
}

impl Preflight for AwsMacKey {
    /// Sends a fresh `DescribeKey`, runs the key-type check (even under
    /// `KeyTypeCheck::TrustCaller`; it otherwise runs before the first operation) and refuses a
    /// key that is not enabled (`KeyStateInvalid`; `Unavailable` while it is being created or
    /// updated), every error labelled `Operation::Describe`. Returns the key's metadata, with the
    /// backend's own attached ([`KeyInfo::backend_info`]).
    async fn preflight(&self) -> Result<KeyInfo> {
        let alg = self.alg;
        self.k.preflight(|i| i.check_mac(alg)).await
    }
}

impl Mac for AwsMacKey {
    fn mac_algorithm(&self) -> MacAlgorithm {
        self.alg
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        self.k
            .scoped(async {
                let op = Operation::Mac;
                if data.is_empty() || data.len() > MAX_PLAINTEXT {
                    return Err(invalid(op, "AWS KMS computes MACs of 1 to 4096 bytes"));
                }
                let alg = self.alg;
                self.k.ensure(op, |i| i.check_mac(alg)).await?;
                let name = aws_mac_alg(alg).ok_or_else(|| invalid(op, "unsupported algorithm"))?;
                let m = b64(data);
                let req = MacReq {
                    key_id: self.k.arn(),
                    message: &m,
                    mac_algorithm: name,
                    mac: None,
                    grant_tokens: self.k.grants(),
                };
                let resp = self.k.call("GenerateMac", op, body(&req, m.len())).await?;
                let r: MacResp = serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
                let tag = decode_blob(&r.mac, op)?;
                if tag.len() != alg.tag_len() {
                    return Err(bad_response(op));
                }
                let v = self.k.response_key(r.key_id, op)?;
                Ok(Tag::from_parts(alg, Some(v), tag))
            })
            .await
    }

    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
        self.k
            .scoped(async {
                let op = Operation::VerifyMac;
                if data.is_empty() || data.len() > MAX_PLAINTEXT {
                    return Err(invalid(op, "AWS KMS verifies MACs of 1 to 4096 bytes"));
                }
                if tag.algorithm() != self.alg {
                    return Err(invalid(op, "tag algorithm does not match the key handle"));
                }
                let failed =
                    || Error::new(ErrorKind::VerificationFailed, BACKEND, op, "MAC is invalid");
                if tag.as_bytes().len() != self.alg.tag_len() {
                    return Err(failed());
                }
                check_version_form(tag.key_version(), op)?;
                let alg = self.alg;
                self.k.ensure(op, |i| i.check_mac(alg)).await?;
                let resolved = self.k.check_version(tag.key_version(), op).await?;
                let name = aws_mac_alg(alg).ok_or_else(|| invalid(op, "unsupported algorithm"))?;
                let m = b64(data);
                let t = B64.encode(tag.as_bytes());
                let req = MacReq {
                    key_id: &resolved,
                    message: &m,
                    mac_algorithm: name,
                    mac: Some(&t),
                    grant_tokens: self.k.grants(),
                };
                let resp = self
                    .k
                    .call_from(
                        Origin::of(tag.key_version()),
                        "VerifyMac",
                        op,
                        body(&req, m.len() + t.len()),
                    )
                    .await?;
                let r: VerifyMacResp =
                    serde_json::from_slice(&resp).map_err(|_| bad_response(op))?;
                match r.mac_valid {
                    Some(true) => Ok(()),
                    Some(false) => Err(failed()),
                    None => Err(bad_response(op)),
                }
            })
            .await
    }
}

impl Describe for AwsMacKey {
    async fn describe(&self) -> Result<KeyInfo> {
        self.k
            .scoped(async { Ok(self.k.describe(Operation::Describe).await?.to_key_info()) })
            .await
    }
}

/// Success-body decoding of every operation, for the fuzz target (`which % 9`).
pub(crate) fn fuzz_decode_success(which: u8, body: &[u8]) -> bool {
    let op = Operation::Decrypt;
    match which % 9 {
        0 => serde_json::from_slice::<BlobResp>(body)
            .ok()
            .and_then(|r| decode_blob(&r.ciphertext_blob, op).ok())
            .is_some(),
        1 => serde_json::from_slice::<PlaintextResp<'_>>(body)
            .ok()
            .and_then(|r| decode_secret(r.plaintext, op).ok())
            .is_some(),
        2 => serde_json::from_slice::<DataKeyResp<'_>>(body)
            .ok()
            .and_then(|r| decode_secret(r.plaintext, op).ok())
            .is_some(),
        3 => serde_json::from_slice::<SignResp>(body)
            .is_ok_and(|r| is_key_arn(&r.key_id) && decode_blob(&r.signature, op).is_ok()),
        4 => serde_json::from_slice::<VerifyResp>(body).is_ok(),
        5 => serde_json::from_slice::<MacResp>(body).is_ok_and(|r| decode_blob(&r.mac, op).is_ok()),
        6 => serde_json::from_slice::<VerifyMacResp>(body).is_ok(),
        7 => serde_json::from_slice::<PublicKeyResp>(body)
            .is_ok_and(|r| decode_blob(&r.public_key, op).is_ok()),
        _ => AwsKeyInfo::parse(body)
            .map(|i| drop(i.to_key_info()))
            .is_ok(),
    }
}
