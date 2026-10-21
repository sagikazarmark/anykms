//! `service_account` key files: a self-signed JWT used directly as the access token (RS256,
//! `scope` claim, one hour), so there is no token-endpoint round trip.
//!
//! The private key is decoded through zeroizing buffers and held by aws-lc-rs (which wipes it
//! when freed). Google recommends against service-account keys; prefer the metadata server or
//! workload identity federation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anykms_core::{BoxFuture, ErrorKind, Result};
use anykms_http::credentials::Expiring;
use base64::Engine as _;
use zeroize::Zeroizing;

use super::file::Secret;
use super::{CLOUD_PLATFORM_SCOPE, Fetch, Fetched, auth_err, config_err};

const LIFETIME: Duration = Duration::from_secs(3600);

pub(crate) struct SelfSignedJwt {
    email: String,
    key_id: Option<String>,
    key: aws_lc_rs::signature::RsaKeyPair,
    quota_project: Option<String>,
}

impl SelfSignedJwt {
    pub(crate) fn new(
        email: String,
        key_id: Option<String>,
        pem: &Secret,
        quota_project: Option<String>,
    ) -> Result<Self> {
        let der = anykms_http::pem::private_key_from_pem(crate::BACKEND, pem.0.as_bytes())
            .map_err(|_| config_err("cannot parse the service-account private key"))?;
        let rustls_pki_types::PrivateKeyDer::Pkcs8(pkcs8) = der else {
            return Err(config_err(
                "the service-account private key must be PKCS#8 (BEGIN PRIVATE KEY)",
            ));
        };
        let key = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(pkcs8.secret_pkcs8_der())
            .map_err(|_| config_err("the service-account private key is not a usable RSA key"))?;
        Ok(Self {
            email,
            key_id,
            key,
            quota_project,
        })
    }

    fn sign(&self) -> Result<Zeroizing<String>> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        if let Some(kid) = &self.key_id {
            header["kid"] = kid.clone().into();
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| auth_err(ErrorKind::Configuration, "system clock is before 1970"))?
            .as_secs();
        let claims = serde_json::json!({
            "iss": self.email,
            "sub": self.email,
            "scope": CLOUD_PLATFORM_SCOPE,
            "iat": now,
            "exp": now + LIFETIME.as_secs(),
        });
        let mut jwt = Zeroizing::new(String::with_capacity(1024));
        b64.encode_string(header.to_string(), &mut jwt);
        jwt.push('.');
        b64.encode_string(claims.to_string(), &mut jwt);
        let mut sig = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                jwt.as_bytes(),
                &mut sig,
            )
            .map_err(|_| auth_err(ErrorKind::Backend, "signing the service-account JWT failed"))?;
        jwt.push('.');
        b64.encode_string(&sig, &mut jwt);
        Ok(jwt)
    }
}

impl Fetch for SelfSignedJwt {
    fn kind(&self) -> &'static str {
        "service_account"
    }

    fn endpoint_host(&self) -> Option<String> {
        None
    }

    fn fetch(&self) -> BoxFuture<'_, Result<Expiring<Fetched>>> {
        Box::pin(async move {
            // A minute of slack against clock skew between here and Google.
            Ok(Fetched::valid_for(
                self.sign()?,
                LIFETIME.checked_sub(Duration::from_secs(60)).unwrap(),
            ))
        })
    }

    fn quota_project(&self) -> Option<&str> {
        self.quota_project.as_deref()
    }
}
