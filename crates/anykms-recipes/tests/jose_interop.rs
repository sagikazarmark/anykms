//! Interop: JWTs signed here, over keys with several versions, verify with `jsonwebtoken` against
//! the JWKS `JwtSigner::jwks` publishes, including its `iss`, `aud` and `exp` checks. ECDSA and
//! Ed25519 keys are anykms-local's; RSA keys are in-process `rsa` keys behind `DigestSigner`.
//! ES512 is not covered: jsonwebtoken does not support it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anykms_core::{
    AsymmetricKeyType, Capabilities, Describe, Digest, DigestSigner, KeyInfo, KeyState, KeyVersion,
    KeyVersionInfo, PublicKey, PublicKeys, Result, Signature, SignatureAlgorithm,
};
use anykms_local::LocalKeyset;
use anykms_recipes::jose::{JwtOptions, JwtSigner};
use jsonwebtoken::errors::ErrorKind as JwtErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;

const ISS: &str = "https://issuer.example";
const AUD: &str = "api";

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
}

fn claims() -> Claims {
    Claims {
        sub: "42".into(),
        iss: ISS.into(),
        aud: AUD.into(),
    }
}

fn ttl() -> JwtOptions {
    JwtOptions::new().with_ttl(Duration::from_secs(300))
}

/// Verifies `token` the way a relying party would: the key by `kid` from the JWKS, the algorithm
/// pinned, `iss`, `aud` and `exp` checked.
fn verify(
    jwks: &Value,
    alg: SignatureAlgorithm,
    token: &str,
) -> jsonwebtoken::errors::Result<Claims> {
    let kid = decode_header(token)?.kid.expect("kid");
    verify_with(jwks, alg, token, &kid, ISS, AUD)
}

/// [`verify`] with the key named `kid` in the JWKS (whatever the token's header says), expecting
/// `iss` and `aud`.
fn verify_with(
    jwks: &Value,
    alg: SignatureAlgorithm,
    token: &str,
    kid: &str,
    iss: &str,
    aud: &str,
) -> jsonwebtoken::errors::Result<Claims> {
    let set: JwkSet = serde_json::from_value(jwks.clone()).unwrap();
    let key = DecodingKey::from_jwk(set.find(kid).expect("kid is in the JWKS"))?;
    // Decoded as a `Value` first: a claims struct whose `iss` and `aud` fields are required
    // would hide a validation that lets absent claims through (L34).
    let claims = relying_party_decode(alg, token, &key, iss, aud)?;
    Ok(serde_json::from_value(claims)?)
}

/// The relying-party recipe of docs/guide.md and examples/jwt_signing.rs.
fn relying_party_decode(
    alg: SignatureAlgorithm,
    token: &str,
    key: &DecodingKey,
    iss: &str,
    aud: &str,
) -> jsonwebtoken::errors::Result<Value> {
    if decode_header(token)?.typ.as_deref() != Some("JWT") {
        return Err(JwtErrorKind::InvalidToken.into());
    }
    let mut validation = Validation::new(alg.jws_alg().unwrap().parse::<Algorithm>().unwrap());
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_nbf = true;
    validation.set_issuer(&[iss]);
    validation.set_audience(&[aud]);
    Ok(decode::<Value>(token, key, &validation)?.claims)
}

fn kind(e: jsonwebtoken::errors::Error) -> JwtErrorKind {
    e.into_kind()
}

/// The token with its payload replaced (`sub` changed), keeping header and signature.
fn tampered(token: &str) -> String {
    use base64::Engine as _;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = token.split('.').collect();
    let mut payload: Value = serde_json::from_slice(&url.decode(parts[1]).unwrap()).unwrap();
    payload["sub"] = "admin".into();
    let payload = url.encode(serde_json::to_vec(&payload).unwrap());
    format!("{}.{payload}.{}", parts[0], parts[2])
}

/// Checks tokens signed by two versions of one key against its JWKS, and the rejections.
fn check(jwks: &Value, alg: SignatureAlgorithm, v1: &str, v2: &str, expired: &str) {
    let kids: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids.len(), 2, "{alg}: {jwks}");
    for (token, version) in [(v1, 1), (v2, 2)] {
        let kid = decode_header(token).unwrap().kid.unwrap();
        assert_eq!(kid.rsplit_once('.').unwrap().1, version.to_string());
        assert_eq!(
            verify(jwks, alg, token).unwrap(),
            claims(),
            "{alg} v{version}"
        );
        // The kid selects the key: under the other version's kid the signature does not verify.
        let other = format!("{}.{}", kid.rsplit_once('.').unwrap().0, 3 - version);
        let e = verify_with(jwks, alg, token, &other, ISS, AUD).unwrap_err();
        assert_eq!(kind(e), JwtErrorKind::InvalidSignature, "{alg} v{version}");
        // Another issuer or audience is refused.
        let e = verify_with(jwks, alg, token, &kid, "https://other", AUD).unwrap_err();
        assert_eq!(kind(e), JwtErrorKind::InvalidIssuer, "{alg} v{version}");
        let e = verify_with(jwks, alg, token, &kid, ISS, "other").unwrap_err();
        assert_eq!(kind(e), JwtErrorKind::InvalidAudience, "{alg} v{version}");
    }
    let e = verify(jwks, alg, &tampered(v2)).unwrap_err();
    assert_eq!(kind(e), JwtErrorKind::InvalidSignature, "{alg}");
    let e = verify(jwks, alg, expired).unwrap_err();
    assert_eq!(kind(e), JwtErrorKind::ExpiredSignature, "{alg}");
}

/// Signs a valid and an expired token with the key's current version.
async fn sign_both<S: DigestSigner + PublicKeys>(signer: &JwtSigner<S>) -> (String, String) {
    let valid = signer.sign(&claims(), &ttl()).await.unwrap();
    let expired = signer
        .sign(&claims(), &ttl().with_now(1_000_000))
        .await
        .unwrap();
    (valid, expired)
}

#[tokio::test]
async fn ecdsa_jwts_verify_with_jsonwebtoken() {
    for alg in [
        SignatureAlgorithm::EcdsaP256Sha256,
        SignatureAlgorithm::EcdsaP384Sha384,
    ] {
        let builder = LocalKeyset::builder();
        let ks = match alg {
            SignatureAlgorithm::EcdsaP256Sha256 => builder.ecdsa_p256("release"),
            _ => builder.ecdsa_p384("release"),
        }
        .build();
        let signer = JwtSigner::new(ks.digest_signing_key("release", alg), "release");
        let (v1, _) = sign_both(&signer).await;
        ks.rotate("release").unwrap();
        // The signer notices the rotation and re-signs with the new version's kid.
        let (v2, expired) = sign_both(&signer).await;
        let jwks = signer.jwks().await.unwrap();
        check(&jwks, alg, &v1, &v2, &expired);
    }
}

#[tokio::test]
async fn ed25519_jwts_verify_with_jsonwebtoken() {
    let alg = SignatureAlgorithm::Ed25519;
    let ks = LocalKeyset::builder().ed25519("release").build();
    let signer = JwtSigner::new(ks.ed25519_key("release"), "release");
    let v1 = signer.sign_message(&claims(), &ttl()).await.unwrap();
    ks.rotate("release").unwrap();
    let v2 = signer.sign_message(&claims(), &ttl()).await.unwrap();
    let expired = signer
        .sign_message(&claims(), &ttl().with_now(1_000_000))
        .await
        .unwrap();
    let jwks = signer.jwks_message().await.unwrap();
    check(&jwks, alg, &v1, &v2, &expired);
}

/// An in-process RSA key with two versions that signs with its current one, as a KMS would.
struct RsaKey {
    alg: SignatureAlgorithm,
    keys: &'static [rsa::RsaPrivateKey; 2],
    current: AtomicUsize,
}

/// Two 2048-bit RSA keys for all algorithms (key generation is slow in debug builds).
fn rsa_keys() -> &'static [rsa::RsaPrivateKey; 2] {
    static KEYS: std::sync::OnceLock<[rsa::RsaPrivateKey; 2]> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rsa::rand_core::UnwrapErr(getrandom::SysRng);
        [(); 2].map(|()| rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap())
    })
}

impl RsaKey {
    fn pk(&self, v: usize) -> PublicKey {
        use rsa::pkcs8::EncodePublicKey as _;
        let der = self.keys[v - 1]
            .to_public_key()
            .to_public_key_der()
            .unwrap();
        PublicKey::new(
            AsymmetricKeyType::Rsa { bits: 2048 },
            der.as_bytes().to_vec(),
            Some(KeyVersion::from_u64(v as u64)),
        )
    }
}

impl DigestSigner for RsaKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        use SignatureAlgorithm::*;
        use rsa::{Pkcs1v15Sign, Pss};
        use sha2::{Sha256, Sha384, Sha512};
        let v = self.current.load(Ordering::SeqCst);
        let key = &self.keys[v - 1];
        let d = digest.as_bytes();
        let mut rng = rsa::rand_core::UnwrapErr(getrandom::SysRng);
        let bytes = match self.alg {
            RsaPkcs1v15Sha256 => key.sign(Pkcs1v15Sign::new::<Sha256>(), d),
            RsaPkcs1v15Sha384 => key.sign(Pkcs1v15Sign::new::<Sha384>(), d),
            RsaPkcs1v15Sha512 => key.sign(Pkcs1v15Sign::new::<Sha512>(), d),
            RsaPssSha256 => key.sign_with_rng(&mut rng, Pss::<Sha256>::new(), d),
            RsaPssSha384 => key.sign_with_rng(&mut rng, Pss::<Sha384>::new(), d),
            RsaPssSha512 => key.sign_with_rng(&mut rng, Pss::<Sha512>::new(), d),
            _ => unreachable!(),
        }
        .unwrap();
        Ok(Signature::from_parts(
            self.alg,
            Some(KeyVersion::from_u64(v as u64)),
            bytes,
        ))
    }
}

impl PublicKeys for RsaKey {
    async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.pk(self.current.load(Ordering::SeqCst)))
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        Ok(self.pk(usize::try_from(version.as_u64().unwrap()).unwrap()))
    }
}

impl Describe for RsaKey {
    async fn describe(&self) -> Result<KeyInfo> {
        let versions = (1..=self.current.load(Ordering::SeqCst) as u64)
            .map(|v| KeyVersionInfo::new(KeyVersion::from_u64(v), KeyState::Enabled))
            .collect();
        Ok(KeyInfo::new("rsa-2048", Capabilities::SIGN)
            .with_state(Some(KeyState::Enabled))
            .with_versions(versions))
    }
}

#[tokio::test]
async fn rsa_jwts_verify_with_jsonwebtoken() {
    use SignatureAlgorithm::*;
    for alg in [
        RsaPkcs1v15Sha256,
        RsaPkcs1v15Sha384,
        RsaPkcs1v15Sha512,
        RsaPssSha256,
        RsaPssSha384,
        RsaPssSha512,
    ] {
        let key = RsaKey {
            alg,
            keys: rsa_keys(),
            current: 1.into(),
        };
        let signer = JwtSigner::new(key, "release");
        let (v1, _) = sign_both(&signer).await;
        signer.signer().current.store(2, Ordering::SeqCst);
        let (v2, expired) = sign_both(&signer).await;
        // Publishing needs no RSA backend.
        let jwks = signer.jwks().await.unwrap();
        check(&jwks, alg, &v1, &v2, &expired);
    }
}

/// L34: the relying-party recipe refuses tokens from the same key that lack `iss` or `aud`
/// (another token type, a `sign_jws` payload), that are not yet valid (`nbf`), or whose `typ`
/// is not `JWT`.
#[tokio::test]
async fn relying_party_recipe_requires_iss_aud_nbf_and_typ() {
    use serde_json::json;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let ks = LocalKeyset::builder().ecdsa_p256("release").build();
    let signer = JwtSigner::new(ks.digest_signing_key("release", alg), "release");
    let jwks = signer.jwks().await.unwrap();
    let set: JwkSet = serde_json::from_value(jwks.clone()).unwrap();
    let rp = |token: &str| {
        let kid = decode_header(token)?.kid.expect("kid");
        let key = DecodingKey::from_jwk(set.find(&kid).expect("kid"))?;
        relying_party_decode(alg, token, &key, ISS, AUD)
    };
    for partial in [
        json!({"sub": "42", "aud": AUD}),
        json!({"sub": "42", "iss": ISS}),
        json!({"sub": "42"}),
    ] {
        let token = signer.sign(&partial, &ttl()).await.unwrap();
        let e = rp(&token).unwrap_err();
        assert!(
            matches!(e.kind(), JwtErrorKind::MissingRequiredClaim(_)),
            "{partial}: {e:?}"
        );
    }
    // Not valid before an hour from now.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let early = json!({"sub": "42", "iss": ISS, "aud": AUD, "nbf": now + 3600});
    let token = signer.sign(&early, &ttl()).await.unwrap();
    assert_eq!(
        kind(rp(&token).unwrap_err()),
        JwtErrorKind::ImmatureSignature
    );
    // A JWS from the same key that is not typed as a JWT (`sign_jws`: header {alg, kid}), with
    // claims that would otherwise pass.
    let jwt = signer.sign(&claims(), &ttl()).await.unwrap();
    let kid = decode_header(&jwt).unwrap().kid.unwrap();
    let payload = json!({"sub": "42", "iss": ISS, "aud": AUD, "exp": now + 60});
    let token = anykms_recipes::jose::sign_jws(
        &ks.digest_signing_key("release", alg),
        &kid,
        &serde_json::to_vec(&payload).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(kind(rp(&token).unwrap_err()), JwtErrorKind::InvalidToken);
    // The full set passes.
    let token = signer.sign(&claims(), &ttl()).await.unwrap();
    rp(&token).unwrap();
}
