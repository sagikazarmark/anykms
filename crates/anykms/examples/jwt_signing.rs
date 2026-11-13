//! Sign a JWT (ES256) with a KMS key, publish the JWKS, and verify the token from the JWKS with
//! `jsonwebtoken`, as a relying party would.
//!
//!     cargo run -p anykms --features local --example jwt_signing

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use anykms::SignatureAlgorithm;
use anykms::recipes::jose::{JwtOptions, JwtSigner};
use anykms::recipes::serde_json::{self, Value, json};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = common::registry()?;
    let uri = common::uri("ANYKMS_SIGNING_URI", "local://default/release")?;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;

    // One open: the signer handle also serves the public keys. `JwtSigner` sets the kid
    // (`release.<version>`) without a KMS round trip per token.
    let signer = JwtSigner::new(registry.digest_signer(&uri, alg)?, "release");
    let claims = json!({"sub": "42", "iss": "anykms-example", "aud": "anykms-example-api"});
    let jwt = signer
        .sign(
            &claims,
            &JwtOptions::new().with_ttl(Duration::from_secs(300)),
        )
        .await?;
    println!("JWT: {jwt}");

    // What a verifier would fetch from the issuer: every enabled version's public key.
    let jwks = signer.jwks().await?;
    println!("JWKS: {jwks}");

    // The relying party: check the token is typed as a JWT, pick the key by kid from the JWKS,
    // pin the algorithm, and require `exp`, `iss` and `aud` (`set_issuer` and `set_audience`
    // alone accept a token that lacks the claim, such as another token type signed by the same
    // key) and check `nbf`. anykms signs and publishes; it does not validate tokens.
    let jwks: JwkSet = serde_json::from_value(jwks)?;
    let header = decode_header(&jwt)?;
    if header.typ.as_deref() != Some("JWT") {
        return Err("not a JWT".into());
    }
    let kid = header.kid.ok_or("token has no kid")?;
    let key = DecodingKey::from_jwk(jwks.find(&kid).ok_or("unknown kid")?)?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_nbf = true;
    validation.set_issuer(&["anykms-example"]);
    validation.set_audience(&["anykms-example-api"]);
    let claims = decode::<Value>(&jwt, &key, &validation)?.claims;
    println!("verified kid={kid} claims={claims}");
    Ok(())
}
