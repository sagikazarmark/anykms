//! Error taxonomy and hygiene cases, one per key family.

use std::error::Error as _;
use std::fmt::Write as _;

use anykms_core::prelude::*;
use anykms_core::{
    Ciphertext, DataKeySpec, Digest, ErrorClass, ErrorKind, KeyUri, KeyVersion, MacAlgorithm,
    OpenOptions, Operation, Signature, SignatureAlgorithm, Tag,
};
use base64::Engine as _;

use super::util::{marker, two};
use crate::ctx::{CaseResult, Check, Ctx, ensure, expect_kind, expect_kind_named};
use crate::fixture::{Feature, Fixture, TestKeyKind};

/// `describe` of the missing key is `NotFound`, where keys are described.
async fn missing_describe<F: Fixture>(c: &Ctx<F>, kind: TestKeyKind) -> CaseResult {
    if !c.caps.has(Feature::Describe) {
        return Ok(());
    }
    let d = c
        .describe_for(kind, &c.fx.missing_key_uri(kind))
        .ctx("open describe")?;
    expect_kind_named(d.describe().await, ErrorKind::NotFound, "describe")?;
    Ok(())
}

/// Every AEAD operation on a missing key is `NotFound` and names the key; opening does no I/O.
pub(crate) async fn missing_key_aead<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let real = c.key(TestKeyKind::Aead).await?;
    let ct = c
        .aead(&real.uri)
        .ctx("open")?
        .encrypt(b"x", b"")
        .await
        .ctx("encrypt")?;
    let uri = c.fx.missing_key_uri(TestKeyKind::Aead);
    let k = c
        .aead(&uri)
        .ctx("open missing key (opening must not do I/O)")?;
    expect_kind_named(k.encrypt(b"x", b"").await, ErrorKind::NotFound, "encrypt")?;
    expect_kind_named(k.decrypt(&ct, b"").await, ErrorKind::NotFound, "decrypt")?;
    if k.supports_data_keys() {
        expect_kind_named(
            k.generate_data_key(DataKeySpec::Aes256, b"").await,
            ErrorKind::NotFound,
            "generate_data_key",
        )?;
    }
    if k.supports_rewrap() {
        expect_kind_named(k.rewrap(&ct, b"").await, ErrorKind::NotFound, "rewrap")?;
    }
    missing_describe(&c, TestKeyKind::Aead).await
}

/// Wrapping and unwrapping with a missing native key-wrapping key is `NotFound`.
pub(crate) async fn missing_key_key_wrap<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let real = c.key(TestKeyKind::KeyWrap).await?;
    let wrapped = c
        .key_wrap(&real.uri)
        .ctx("open")?
        .wrap_key(&[7; 32])
        .await
        .ctx("wrap_key")?;
    let uri = c.fx.missing_key_uri(TestKeyKind::KeyWrap);
    let k = c
        .key_wrap(&uri)
        .ctx("open missing key (opening must not do I/O)")?;
    expect_kind_named(k.wrap_key(&[7; 32]).await, ErrorKind::NotFound, "wrap_key")?;
    expect_kind_named(
        k.unwrap_key(&wrapped).await,
        ErrorKind::NotFound,
        "unwrap_key",
    )?;
    missing_describe(&c, TestKeyKind::KeyWrap).await
}

/// MAC and verify with a missing HMAC key are `NotFound`.
pub(crate) async fn missing_key_mac<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let real = c.key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)).await?;
    let alg = MacAlgorithm::HmacSha256;
    // A real tag, so its version is well-formed for the backend.
    let tag = c
        .mac(&real.uri, alg)
        .ctx("open")?
        .mac(b"x")
        .await
        .ctx("mac")?;
    let m = c
        .mac(&c.fx.missing_key_uri(TestKeyKind::Hmac(alg)), alg)
        .ctx("open missing key (opening must not do I/O)")?;
    expect_kind_named(m.mac(b"x").await, ErrorKind::NotFound, "mac")?;
    expect_kind_named(
        m.verify_mac(b"x", &tag).await,
        ErrorKind::NotFound,
        "verify_mac",
    )?;
    missing_describe(&c, TestKeyKind::Hmac(alg)).await
}

/// Signing, verifying and reading the public key of a missing signing key are `NotFound`.
pub(crate) async fn missing_key_signing<F: Fixture>(
    c: Ctx<F>,
    alg: SignatureAlgorithm,
) -> CaseResult {
    let real = c.key(TestKeyKind::Signing(alg)).await?;
    let uri = c.fx.missing_key_uri(TestKeyKind::Signing(alg));
    if alg.is_message_signing() {
        // A real signature, so its version is well-formed for the backend.
        let sig = c
            .message_signer(&real.uri, alg)
            .ctx("open")?
            .sign_message(b"m")
            .await
            .ctx("sign")?;
        expect_kind_named(
            c.message_signer(&uri, alg)
                .ctx("open")?
                .sign_message(b"m")
                .await,
            ErrorKind::NotFound,
            "sign",
        )?;
        expect_kind_named(
            c.message_verifier(&uri, alg)
                .ctx("open")?
                .verify_message(b"m", &sig)
                .await,
            ErrorKind::NotFound,
            "verify",
        )?;
    } else {
        let d = Digest::compute(alg.hash().expect("digest algorithm"), b"m");
        let sig = c
            .digest_signer(&real.uri, alg)
            .ctx("open")?
            .sign_digest(&d)
            .await
            .ctx("sign")?;
        expect_kind_named(
            c.digest_signer(&uri, alg)
                .ctx("open")?
                .sign_digest(&d)
                .await,
            ErrorKind::NotFound,
            "sign",
        )?;
        expect_kind_named(
            c.digest_verifier(&uri, alg)
                .ctx("open")?
                .verify_digest(&d, &sig)
                .await,
            ErrorKind::NotFound,
            "verify",
        )?;
    }
    expect_kind_named(
        c.public_keys(&uri, alg).ctx("open")?.public_key().await,
        ErrorKind::NotFound,
        "public_key",
    )?;
    missing_describe(&c, TestKeyKind::Signing(alg)).await
}

/// The providers that name the key on every error raised after the URI is parsed, open-time
/// checks included (architecture plan P1-6): the four HTTP backends. Other providers (local,
/// the shaped test fixtures) are named by the `Registry` only, so their open-time errors are not
/// checked directly.
const NAMES_OPEN_ERRORS: &[&str] = &["transit", "aws", "gcp", "azure"];

/// Opening `uri` with an algorithm of the wrong signing shape (Ed25519 as a digest signer, ECDSA
/// as a message signer) fails at open with `KeyMismatch`, and the provider itself (not only the
/// `Registry`) names the key. The shape check comes before any key lookup, so any key's URI
/// works.
fn open_shape_errors_name_the_key<F: Fixture>(c: &Ctx<F>, uri: &KeyUri) -> CaseResult {
    let p = c.fx.provider();
    if !NAMES_OPEN_ERRORS.contains(&p.name()) {
        return Ok(());
    }
    let o = OpenOptions::new();
    expect_kind_named(
        p.digest_signer(uri, SignatureAlgorithm::Ed25519, &o)
            .map(drop),
        ErrorKind::KeyMismatch,
        "provider: open Ed25519 as a digest signer",
    )?;
    expect_kind_named(
        p.message_signer(uri, SignatureAlgorithm::EcdsaP256Sha256, &o)
            .map(drop),
        ErrorKind::KeyMismatch,
        "provider: open ECDSA P-256 as a message signer",
    )?;
    Ok(())
}

/// Errors from checks a backend makes before any request name the key too (the server errors of
/// the `missing_key` cases are checked there): MAC keys, and open-time shape checks.
pub(crate) async fn local_checks_name_the_key_mac<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)).await?;
    open_shape_errors_name_the_key(&c, &key.uri)?;
    let m = c.mac(&key.uri, MacAlgorithm::HmacSha256).ctx("open mac")?;
    // A tag of another algorithm, with a version that is well-formed for the backend.
    let real = m.mac(b"x").await.ctx("mac")?;
    let tag = Tag::from_parts(
        MacAlgorithm::HmacSha512,
        real.key_version().cloned(),
        vec![0; 64],
    );
    expect_kind_named(
        m.verify_mac(b"x", &tag).await,
        ErrorKind::InvalidArgument,
        "verify_mac with another algorithm's tag",
    )?;
    Ok(())
}

/// Like [`local_checks_name_the_key_mac`], for a digest signer.
pub(crate) async fn local_checks_name_the_key_signing<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    open_shape_errors_name_the_key(&c, &key.uri)?;
    expect_kind_named(
        c.digest_signer(&key.uri, alg)
            .ctx("open")?
            .sign_digest(&Digest::sha384(b"m"))
            .await,
        ErrorKind::InvalidArgument,
        "sign a digest of another hash",
    )?;
    Ok(())
}

/// Opens `uri` as `kind` and runs one operation: the first error, or `Ok` if both succeeded.
async fn open_and_use<F: Fixture>(
    c: &Ctx<F>,
    kind: TestKeyKind,
    uri: &KeyUri,
) -> anykms_core::Result<()> {
    match kind {
        TestKeyKind::Aead => c.aead(uri)?.encrypt(b"x", b"").await.map(drop),
        _ => c.key_wrap(uri)?.wrap_key(&[7; 32]).await.map(drop),
    }
}

/// A3(c): key URIs come from configuration, so a URI the provider's own grammar refuses is
/// `Configuration` (config class), labeled [`Operation::ParseUri`] (which applications that
/// accept URIs from users match on), on both paths. `kind` is `Aead` or `KeyWrap`.
pub(crate) async fn parse_uri_is_configuration<F: Fixture>(
    c: Ctx<F>,
    kind: TestKeyKind,
) -> CaseResult {
    {
        let key = c.key(kind).await?;
        let scheme = key.uri.scheme();
        // Valid for core (a scheme and a non-empty rest), refused by every provider's grammar:
        // no key at all, and a path that climbs out of any key namespace.
        for raw in [format!("{scheme}://"), format!("{scheme}:///../..")] {
            let uri = KeyUri::parse(&raw).map_err(|e| format!("core refused {raw:?}: {e}"))?;
            let e = match open_and_use(&c, kind, &uri).await {
                Ok(()) => return Err(format!("{kind:?}: {raw:?} was accepted")),
                Err(e) => e,
            };
            ensure!(
                e.kind() == ErrorKind::Configuration && e.operation() == Operation::ParseUri,
                "{kind:?}: {raw:?}: expected configuration from parse_uri, got {} from {}: {e}",
                e.kind(),
                e.operation()
            );
            ensure!(
                e.is_config_error() && e.class() == ErrorClass::Config,
                "{kind:?}: {raw:?}: {e} is not config class"
            );
        }
    }
    Ok(())
}

/// A well-formed version of the same shape as `own` that the key does not have: the trailing
/// run of hexadecimal digits (an AWS key id, an Azure version, a GCP or transit version number)
/// gets decimal digits, which every shape accepts. Distinct for each `i` below 1000.
fn forged_version(own: &KeyVersion, i: u64) -> KeyVersion {
    let s = own.as_str();
    let run = s.bytes().rev().take_while(u8::is_ascii_hexdigit).count();
    let head = &s[..s.len() - run];
    if run >= 8 {
        let keep = &s[s.len() - run..s.len() - 8];
        KeyVersion::new(format!("{head}{keep}{:08}", 90_000_000 + i))
    } else {
        KeyVersion::new(format!("{head}{}", 99_000_000 + i))
    }
}

/// One honest sign and verify; the number of requests it took, where counted.
async fn honest_round(
    signer: &anykms_core::DigestSignerKey,
    verifier: &anykms_core::DigestVerifierKey,
    d: &Digest,
    count: &(dyn Fn() -> Option<u64> + Sync),
) -> Result<Option<u64>, String> {
    let before = count();
    let sig = signer.sign_digest(d).await.ctx("sign")?;
    verifier.verify_digest(d, &sig).await.ctx("verify")?;
    Ok(count().zip(before).map(|(a, b)| a - b))
}

/// A3(a) and P1-4: forged versions (an attacker's `kid`) are caller errors that never drop the
/// handle's cached key metadata. Verifying with each of 32 forged, well-formed versions is
/// `VerificationFailed`, and reading its public key `UnknownKeyVersion`, both
/// [`ErrorClass::Caller`] even with a retry hint. Where the fixture counts requests, each forged
/// call costs at most one request per forged version, or the honest cost if higher (a
/// server-side check or read of the version, no `describe` or re-read on top: where the honest
/// call is served from a cache, a forged version still costs the one read that finds it
/// missing), and an honest sign and verify afterwards costs exactly what it cost before, so
/// no forged version dropped a cache.
pub(crate) async fn forged_versions_do_not_flush<F: Fixture>(c: Ctx<F>) -> CaseResult {
    const N: u64 = 32;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let (cc, requests) = if c.caps.has(Feature::RequestCount) {
        let (cc, r) = c.counting()?;
        (cc, Some(r))
    } else {
        (c.clone(), None)
    };
    let count = || requests.as_ref().map(|r| r());
    let d = Digest::sha256(b"anykms forged versions");
    let signer = cc.digest_signer(&key.uri, alg).ctx("open signer")?;
    let verifier = cc.digest_verifier(&key.uri, alg).ctx("open verifier")?;
    let pks = cc.public_keys(&key.uri, alg).ctx("open public keys")?;
    // Warm every cache, then measure an honest round.
    let sig = signer.sign_digest(&d).await.ctx("sign")?;
    verifier.verify_digest(&d, &sig).await.ctx("verify")?;
    let own = sig
        .key_version()
        .cloned()
        .ok_or("signature carries no key version")?;
    pks.public_key_version(&own)
        .await
        .ctx("public key of the signature's version")?;
    let base = honest_round(&signer, &verifier, &d, &count).await?;
    // What one honest verification and one public-key read of the signature's version cost
    // (with warm caches): a forged call may cost as much (a server-side check of the version),
    // or one request where the honest call costs none (a cached public key: the forged version
    // is read once to find it missing), never more. A `describe` or key re-read on top would
    // mean a forged version dropped the cache.
    let before = count();
    verifier.verify_digest(&d, &sig).await.ctx("verify")?;
    let verify_cost = count().zip(before).map(|(a, b)| a - b);
    let before = count();
    pks.public_key_version(&own)
        .await
        .ctx("public key of the signature's version")?;
    let read_cost = count().zip(before).map(|(a, b)| a - b);
    let within = |what: &str, each: Option<u64>, before: Option<u64>| -> CaseResult {
        if let (Some(a), Some(b), Some(each)) = (count(), before, each) {
            let bound = each.max(1);
            ensure!(
                a - b <= N * bound,
                "{N} {what} with forged versions cost {} requests, more than {bound} each (one \
                 request per forged version, or the {each} an honest one costs if higher)",
                a - b
            );
        }
        Ok(())
    };
    let forged: Vec<KeyVersion> = (0..N).map(|i| forged_version(&own, i)).collect();
    ensure!(
        !forged.contains(&own),
        "a forged version equals the key's own"
    );
    let before = count();
    for v in &forged {
        let s = Signature::from_parts(alg, Some(v.clone()), sig.as_bytes().to_vec());
        let e = expect_kind(
            verifier.verify_digest(&d, &s).await,
            ErrorKind::VerificationFailed,
            &format!("verify with forged version {v}"),
        )?;
        ensure!(
            e.class() == ErrorClass::Caller,
            "verify with forged version {v}: class {:?}, expected Caller",
            e.class()
        );
    }
    within("verifications", verify_cost, before)?;
    let before = count();
    for v in &forged {
        let e = expect_kind(
            pks.public_key_version(v).await,
            ErrorKind::UnknownKeyVersion,
            &format!("public key of forged version {v}"),
        )?;
        ensure!(
            e.is_caller_error() && e.class() == ErrorClass::Caller,
            "public key of forged version {v}: class {:?}, expected Caller",
            e.class()
        );
    }
    within("public-key reads", read_cost, before)?;
    let after = honest_round(&signer, &verifier, &d, &count).await?;
    ensure!(
        after == base,
        "an honest sign and verify cost {after:?} requests after the forged versions, {base:?} \
         before: a forged version dropped cached key metadata"
    );
    Ok(())
}

/// Denied credentials are `Unauthenticated` where the backend says so (Vault adds "invalid
/// token" to its 403), and `PermissionDenied` where it cannot be told from a policy denial
/// (OpenBao answers a plain 403 "permission denied"). Both are config errors.
fn expect_denied<T>(r: anykms_core::Result<T>, what: &str) -> CaseResult {
    match r {
        Ok(_) => Err(format!(
            "{what} with denied credentials: expected an error, got success"
        )),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::Unauthenticated | ErrorKind::PermissionDenied
            ) =>
        {
            ensure!(
                e.is_config_error(),
                "denied credentials: {e} is not a config error"
            );
            Ok(())
        }
        Err(e) => Err(format!(
            "{what} with denied credentials: expected unauthenticated or permission_denied, got {}: {e}",
            e.kind()
        )),
    }
}

pub(crate) async fn unauthorized_aead<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let p = c.unauthorized().ok_or("no unauthorized provider")?;
    let k = p.aead(&key.uri, &OpenOptions::new()).ctx("open")?;
    expect_denied(k.encrypt(b"x", b"").await, "encrypt")
}

pub(crate) async fn unauthorized_key_wrap<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::KeyWrap).await?;
    let p = c.unauthorized().ok_or("no unauthorized provider")?;
    let k = p.key_wrap(&key.uri, &OpenOptions::new()).ctx("open")?;
    expect_denied(k.wrap_key(&[7; 32]).await, "wrap_key")
}

pub(crate) async fn unauthorized_signing<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let p = c.unauthorized().ok_or("no unauthorized provider")?;
    let k = p
        .digest_signer(&key.uri, alg, &OpenOptions::new())
        .ctx("open")?;
    expect_denied(k.sign_digest(&Digest::sha256(b"m")).await, "sign")
}

pub(crate) async fn throttled<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    c.fx.throttle(&key).await.ctx("fixture throttle")?;
    let mut seen = None;
    for _ in 0..20 {
        if let Err(e) = k.encrypt(b"x", b"").await {
            seen = Some(e);
            break;
        }
    }
    c.fx.unthrottle(&key).await.ctx("fixture unthrottle")?;
    let e = seen.ok_or("no request was throttled")?;
    ensure!(
        e.kind() == ErrorKind::Throttled,
        "expected throttled, got {}: {e}",
        e.kind()
    );
    ensure!(e.is_retryable(), "throttled error is not retryable");
    if c.caps.throttle_retry_after {
        ensure!(
            e.retry_after().is_some(),
            "throttled error has no retry_after although the server sends Retry-After"
        );
    }
    Ok(())
}

/// Everything a caller might print: `Display`, `Debug` and `{:#?}` of the error and of every error
/// in its `source()` chain.
fn rendered(e: &anykms_core::Error) -> String {
    let mut s = format!("{e}\n{e:?}\n{e:#?}\n");
    let mut src = e.source();
    while let Some(x) = src {
        write!(s, "{x}\n{x:?}\n{x:#?}\n").expect("writing to a String cannot fail");
        src = x.source();
    }
    s
}

/// Hex of `bytes`, two digits per byte, lowercase or uppercase.
fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            if upper {
                write!(s, "{b:02X}")
            } else {
                write!(s, "{b:02x}")
            }
            .expect("writing to a String cannot fail");
            s
        })
}

/// The ways a secret could show up in text, each trimmed to a distinctive prefix.
fn encodings(secret: &[u8]) -> Vec<String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let mut v = vec![
        STANDARD.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
        hex(secret, false),
        hex(secret, true),
        // `{:?}` of a byte slice or Vec.
        secret
            .iter()
            .take(8)
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    ];
    if let Ok(s) = std::str::from_utf8(secret) {
        v.push(s.to_owned());
    }
    v.into_iter()
        .map(|e| e.chars().take(24).collect::<String>())
        .filter(|e| e.len() >= 8)
        .collect()
}

/// Errors and the secrets that must not appear in them.
struct Leaks {
    errors: Vec<(&'static str, anykms_core::Result<()>)>,
    secrets: Vec<(String, Vec<u8>)>,
}

impl Leaks {
    fn new<F: Fixture>(c: &Ctx<F>, secrets: &[(&str, &[u8])]) -> Self {
        let mut s: Vec<(String, Vec<u8>)> = secrets
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
            .collect();
        for (i, m) in c.fx.secret_markers().into_iter().enumerate() {
            s.push((format!("fixture secret #{i}"), m.into_bytes()));
        }
        Self {
            errors: Vec::new(),
            secrets: s,
        }
    }

    fn push<T>(&mut self, what: &'static str, r: anykms_core::Result<T>) {
        self.errors.push((what, r.map(drop)));
    }

    fn check(&self) -> CaseResult {
        for (what, r) in &self.errors {
            let e = r
                .as_ref()
                .err()
                .ok_or_else(|| format!("{what}: expected an error, got success"))?;
            let text = rendered(e);
            for (name, secret) in &self.secrets {
                for enc in encodings(secret) {
                    ensure!(
                        !text.contains(&enc),
                        "error output of '{what}' leaks the {name}:\n{text}"
                    );
                }
            }
        }
        Ok(())
    }
}

/// AEAD errors never contain the plaintext, AAD or credentials.
pub(crate) async fn hygiene_aead<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let pt = marker("PT");
    let aad = marker("AAD");
    let [key, other] = two(c.keys(TestKeyKind::Aead, 2).await?);
    let k = c.aead(&key.uri).ctx("open")?;
    let ko = c.aead(&other.uri).ctx("open other")?;
    let ct = k
        .encrypt(pt.as_bytes(), aad.as_bytes())
        .await
        .ctx("encrypt")?;
    let missing = c
        .aead(&c.fx.missing_key_uri(TestKeyKind::Aead))
        .ctx("open missing")?;
    let mut l = Leaks::new(&c, &[("plaintext", pt.as_bytes()), ("AAD", aad.as_bytes())]);
    l.push("wrong AAD", k.decrypt(&ct, b"wrong").await);
    l.push("another key", ko.decrypt(&ct, aad.as_bytes()).await);
    l.push(
        "plaintext as ciphertext",
        k.decrypt(
            &Ciphertext::from_bytes(pt.as_bytes().to_vec()),
            aad.as_bytes(),
        )
        .await,
    );
    l.push(
        "encrypt with a missing key",
        missing.encrypt(pt.as_bytes(), aad.as_bytes()).await,
    );
    // Denied credentials must not be echoed back.
    if let Some(p) = c.unauthorized() {
        let uk = p
            .aead(&key.uri, &OpenOptions::new())
            .ctx("open unauthorized")?;
        l.push(
            "denied credentials",
            uk.encrypt(pt.as_bytes(), aad.as_bytes()).await,
        );
    }
    l.check()
}

/// A data key never appears in errors, including when it is fed back in as an input.
pub(crate) async fn hygiene_data_keys<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let missing = c
        .aead(&c.fx.missing_key_uri(TestKeyKind::Aead))
        .ctx("open missing")?;
    let dk = k
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .ctx("generate_data_key")?;
    let dek = dk.plaintext().to_vec();
    let mut l = Leaks::new(&c, &[("data key", &dek)]);
    l.push(
        "data key under the wrong AAD",
        k.decrypt(dk.ciphertext(), b"wrong").await,
    );
    l.push(
        "data key as ciphertext",
        k.decrypt(&Ciphertext::from_bytes(dek.clone()), b"").await,
    );
    l.push(
        "data key as plaintext and AAD of a missing key",
        missing.encrypt(&dek, &dek).await,
    );
    if c.caps.has(Feature::Mac) {
        let m = c
            .mac(
                &c.fx
                    .missing_key_uri(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)),
                MacAlgorithm::HmacSha256,
            )
            .ctx("open missing mac")?;
        l.push("data key as MAC input of a missing key", m.mac(&dek).await);
    }
    l.check()
}

/// Key material passed to a key-wrapping key never appears in errors.
pub(crate) async fn hygiene_key_wrap<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let secret = marker("KEY");
    let [key, other] = two(c.keys(TestKeyKind::KeyWrap, 2).await?);
    let k = c.key_wrap(&key.uri).ctx("open")?;
    let ko = c.key_wrap(&other.uri).ctx("open other")?;
    let wrapped = k.wrap_key(secret.as_bytes()).await.ctx("wrap_key")?;
    let missing = c
        .key_wrap(&c.fx.missing_key_uri(TestKeyKind::KeyWrap))
        .ctx("open missing")?;
    let mut l = Leaks::new(&c, &[("wrapped key material", secret.as_bytes())]);
    l.push("another key", ko.unwrap_key(&wrapped).await);
    l.push(
        "key material as wrapped key",
        k.unwrap_key(&Ciphertext::from_bytes(secret.as_bytes().to_vec()))
            .await,
    );
    l.push(
        "wrap with a missing key",
        missing.wrap_key(secret.as_bytes()).await,
    );
    if let Some(p) = c.unauthorized() {
        let uk = p
            .key_wrap(&key.uri, &OpenOptions::new())
            .ctx("open unauthorized")?;
        l.push("denied credentials", uk.wrap_key(secret.as_bytes()).await);
    }
    l.check()
}

/// MAC input never appears in errors.
pub(crate) async fn hygiene_mac<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let data = marker("DATA");
    let key = c.key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)).await?;
    let alg = MacAlgorithm::HmacSha256;
    let m = c.mac(&key.uri, alg).ctx("open")?;
    let tag = m.mac(b"other").await.ctx("mac")?;
    let missing = c
        .mac(&c.fx.missing_key_uri(TestKeyKind::Hmac(alg)), alg)
        .ctx("open missing")?;
    let mut l = Leaks::new(&c, &[("MAC input", data.as_bytes())]);
    l.push("MAC with a missing key", missing.mac(data.as_bytes()).await);
    l.push(
        "verify another input's tag",
        m.verify_mac(data.as_bytes(), &tag).await,
    );
    l.check()
}
