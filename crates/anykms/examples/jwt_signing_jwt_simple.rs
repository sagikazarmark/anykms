//! `jwt_signing` with another relying party: jwt-simple verifies the token, with the key picked
//! from the JWKS by jwk-simple.
//!
//!     cargo run -p anykms --features local --example jwt_signing_jwt_simple

#[path = "common/mod.rs"]
mod common;

use std::collections::HashSet;
use std::time::Duration;

use anykms::SignatureAlgorithm;
use anykms::recipes::jose::{JwtOptions, JwtSigner};
use anykms::recipes::serde_json::{self, Value, json};
use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet};
use jwt_simple::prelude::{
    ECDSAP256PublicKeyLike as _, ES256PublicKey, JWTClaims, Token, VerificationOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = common::registry()?;
    let uri = common::uri("ANYKMS_SIGNING_URI", "local://default/release")?;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;

    // The issuer, as in `jwt_signing`.
    let signer = JwtSigner::new(registry.digest_signer(&uri, alg)?, "release");
    let claims = json!({"sub": "42", "iss": "anykms-example", "aud": "api", "scope": "read"});
    let jwt = signer
        .sign(
            &claims,
            &JwtOptions::new().with_ttl(Duration::from_secs(300)),
        )
        .await?;
    let jwks = signer.jwks().await?;

    // The relying party: the JWK named by the token's (untrusted) kid, allowed for ES256 only.
    // jwk-simple only selects it: its own `jwt-simple` feature targets jwt-simple 0.13.
    let kid = Token::decode_metadata(&jwt)?
        .key_id()
        .ok_or("token has no kid")?
        .to_owned();
    let jwks: KeySet = serde_json::from_value(jwks)?;
    let jwk = jwks
        .selector(&[Algorithm::Es256])
        .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Es256).with_kid(&kid))?;
    // The key type pins the algorithm: the header must say ES256 and the JWK be a P-256 key.
    let key = ES256PublicKey::from_jwk(&serde_json::to_string(jwk)?)?;
    let options = VerificationOptions {
        allowed_issuers: Some(HashSet::from(["anykms-example".to_owned()])),
        allowed_audiences: Some(HashSet::from(["api".to_owned()])),
        // jwt-simple's default tolerance is 15 minutes.
        time_tolerance: Some(jwt_simple::prelude::Duration::from_secs(60)),
        ..Default::default()
    };
    let verified: JWTClaims<Value> = key.verify_token(&jwt, Some(options))?;
    // jwt-simple checks `exp` only when the token has one.
    verified.expires_at.ok_or("token has no exp")?;
    println!(
        "verified kid={kid} sub={:?} scope={}",
        verified.subject, verified.custom["scope"]
    );
    Ok(())
}
