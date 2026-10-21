//! A stateful, in-process fake of the Cloud KMS REST API (v1), on wiremock, for end-to-end and
//! conformance tests.
//!
//! It implements the real request and response shapes, CRC32C fields included:
//!
//! - data plane: `cryptoKeys.encrypt`/`decrypt`, `cryptoKeyVersions.asymmetricSign`,
//!   `asymmetricDecrypt`, `macSign`, `macVerify`, `getPublicKey`, `cryptoKeys.get`,
//!   `cryptoKeyVersions.get` and `list` (paged);
//! - admin: `cryptoKeys.create`, `cryptoKeyVersions.create`, `updatePrimaryVersion`,
//!   `cryptoKeyVersions.patch` (state) and `destroy`;
//! - tokens: the metadata server, the OAuth token endpoint (refresh tokens), STS and
//!   `iamcredentials.generateAccessToken`, each issuing tokens the KMS endpoints accept.
//!
//! Crypto is real (aws-lc-rs): AES-256-GCM bound to the key name and AAD, ECDSA P-256/P-384,
//! Ed25519, RSA-PSS/PKCS#1 v1.5 (2048 bits), RSA-OAEP-SHA-256 and HMAC. Error responses use the
//! status codes and message texts pinned in `src/errors.rs` (to be confirmed against the real
//! service by `scripts/probe-gcp.sh`).

#![allow(dead_code, clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine as _;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// CRC32C (Castagnoli), independent of the crate's implementation.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn crc_str(data: &[u8]) -> String {
    crc32c(data).to_string()
}

/// The token the fake accepts by default.
pub const TOKEN: &str = "ya29.fake-kms-token";
/// A token the fake knows but denies everything (403).
pub const DENIED_TOKEN: &str = "ya29.fake-denied-token";
/// The refresh token, subject token and source token the token endpoints accept.
pub const REFRESH_TOKEN: &str = "1//fake-refresh-token";
pub const SUBJECT_TOKEN: &str = "eyJfake.subject.token";

enum Material {
    Aes([u8; 32]),
    Ec(aws_lc_rs::signature::EcdsaKeyPair, u16),
    Ed(aws_lc_rs::signature::Ed25519KeyPair),
    Rsa(aws_lc_rs::signature::RsaKeyPair),
    Oaep(aws_lc_rs::rsa::OaepPrivateDecryptingKey, Vec<u8>),
    Hmac(Vec<u8>),
}

struct Version {
    state: String,
    material: Material,
    create_time: String,
}

struct Key {
    purpose: String,
    algorithm: String,
    protection: String,
    primary: Option<u64>,
    versions: BTreeMap<u64, Version>,
}

#[derive(Default)]
struct State {
    keys: BTreeMap<String, Key>,
    tokens: HashSet<String>,
    denied: HashSet<String>,
    /// `getPublicKey` answers for versions that are not enabled (§3.1(f): Cloud KMS may).
    serve_disabled_public_keys: bool,
    /// `cryptoKeyVersions.get` is denied (an identity without the permission).
    deny_version_get: bool,
    throttled: HashSet<String>,
    /// Tokens issued by the fake's token endpoints.
    issued: u64,
    /// Ciphertexts produced by `encrypt`, for `NativeCiphertext`-style checks.
    requests: u64,
    /// Requests per (method, path suffix after the last `:` or `/`), for assertions.
    calls: HashMap<String, u64>,
    /// Success-response field overrides per call (same keys as `calls`).
    tamper: HashMap<String, Vec<(String, Value)>>,
}

/// The fake server.
#[derive(Clone)]
pub struct FakeKms {
    pub server: Arc<MockServer>,
    state: Arc<Mutex<State>>,
    counter: Arc<AtomicU64>,
}

fn now_rfc3339() -> String {
    // A fixed timestamp keeps responses deterministic.
    "2026-01-01T00:00:00.000000Z".to_owned()
}

fn status_body(code: u16, status: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(code).set_body_json(json!({
        "error": {"code": code, "status": status, "message": message, "details": [
            {"@type": "type.googleapis.com/google.rpc.RequestInfo", "requestId": "fake-req-1"}
        ]}
    }))
}

fn invalid(msg: &str) -> ResponseTemplate {
    status_body(400, "INVALID_ARGUMENT", msg)
}

fn not_found(what: &str) -> ResponseTemplate {
    status_body(404, "NOT_FOUND", &format!("{what} not found."))
}

fn precondition(msg: &str) -> ResponseTemplate {
    status_body(400, "FAILED_PRECONDITION", msg)
}

fn wrong_purpose(key: &str, purpose: &str) -> ResponseTemplate {
    precondition(&format!(
        "Operation requested for Key {key} has incorrect key purpose: {purpose}"
    ))
}

fn not_enabled(name: &str, state: &str) -> ResponseTemplate {
    precondition(&format!(
        "{name} is not enabled, current state is: {state}."
    ))
}

fn checksum(field: &str) -> ResponseTemplate {
    invalid(&format!(
        "The checksum in field {field}_crc32c did not match the data in field {field}."
    ))
}

thread_local! {
    /// The field overrides of the request being answered (see [`FakeKms::tamper`]).
    static TAMPER: std::cell::RefCell<Vec<(String, Value)>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn ok(mut v: Value) -> ResponseTemplate {
    TAMPER.with(|t| {
        for (field, value) in t.borrow().iter() {
            if let Some(o) = v.as_object_mut() {
                if value.is_null() {
                    o.remove(field);
                } else {
                    o.insert(field.clone(), value.clone());
                }
            }
        }
    });
    ResponseTemplate::new(200).set_body_json(v)
}

/// A base64 field, decoded, with its CRC verified when present: `Ok(Some((bytes, verified)))`.
fn field(body: &Value, name: &str) -> Result<Option<(Vec<u8>, bool)>, ResponseTemplate> {
    let Some(v) = body.get(name) else {
        return Ok(None);
    };
    let s = v
        .as_str()
        .ok_or_else(|| invalid(&format!("{name} must be bytes")))?;
    let bytes = B64
        .decode(s)
        .map_err(|_| invalid(&format!("Invalid value at '{name}' (TYPE_BYTES)")))?;
    let crc_name = format!("{name}Crc32c");
    let verified = match body.get(&crc_name) {
        None => false,
        Some(c) => {
            let n: u64 = match c {
                Value::String(s) => s.parse().map_err(|_| invalid("bad int64"))?,
                Value::Number(n) => n.as_u64().ok_or_else(|| invalid("bad int64"))?,
                _ => return Err(invalid("bad int64")),
            };
            if n != u64::from(crc32c(&bytes)) {
                let snake = match name {
                    "additionalAuthenticatedData" => "additional_authenticated_data",
                    other => other,
                };
                return Err(checksum(snake));
            }
            true
        }
    };
    Ok(Some((bytes, verified)))
}

fn algorithm_material(alg: &str) -> Option<Material> {
    use aws_lc_rs::signature as s;
    let rng = aws_lc_rs::rand::SystemRandom::new();
    Some(match alg {
        "GOOGLE_SYMMETRIC_ENCRYPTION" => {
            let mut k = [0u8; 32];
            aws_lc_rs::rand::fill(&mut k).ok()?;
            Material::Aes(k)
        }
        "EC_SIGN_P256_SHA256" => Material::Ec(
            s::EcdsaKeyPair::generate(&s::ECDSA_P256_SHA256_ASN1_SIGNING).ok()?,
            256,
        ),
        "EC_SIGN_P384_SHA384" => Material::Ec(
            s::EcdsaKeyPair::generate(&s::ECDSA_P384_SHA384_ASN1_SIGNING).ok()?,
            384,
        ),
        "EC_SIGN_ED25519" => Material::Ed(s::Ed25519KeyPair::generate().ok()?),
        a if a.starts_with("RSA_SIGN_") => {
            let size = if a.contains("_4096_") {
                aws_lc_rs::rsa::KeySize::Rsa4096
            } else if a.contains("_3072_") {
                aws_lc_rs::rsa::KeySize::Rsa3072
            } else {
                aws_lc_rs::rsa::KeySize::Rsa2048
            };
            Material::Rsa(s::RsaKeyPair::generate(size).ok()?)
        }
        // The SHA-1 key decrypts with SHA-256 here: anykms must refuse it before any decrypt.
        "RSA_DECRYPT_OAEP_2048_SHA256" | "RSA_DECRYPT_OAEP_2048_SHA1" => {
            let k =
                aws_lc_rs::rsa::PrivateDecryptingKey::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
                    .ok()?;
            let der = k.public_key().as_der().ok()?.as_ref().to_vec();
            Material::Oaep(aws_lc_rs::rsa::OaepPrivateDecryptingKey::new(k).ok()?, der)
        }
        "HMAC_SHA256" | "HMAC_SHA384" | "HMAC_SHA512" => {
            let len = match alg {
                "HMAC_SHA256" => 32,
                "HMAC_SHA384" => 48,
                _ => 64,
            };
            let mut k = vec![0u8; len];
            aws_lc_rs::rand::SecureRandom::fill(&rng, &mut k).ok()?;
            Material::Hmac(k)
        }
        _ => return None,
    })
}

fn purpose_of(alg: &str) -> &'static str {
    match alg {
        "GOOGLE_SYMMETRIC_ENCRYPTION" => "ENCRYPT_DECRYPT",
        a if a.starts_with("HMAC_") => "MAC",
        a if a.starts_with("RSA_DECRYPT_") => "ASYMMETRIC_DECRYPT",
        _ => "ASYMMETRIC_SIGN",
    }
}

fn pem(der: &[u8]) -> String {
    let b = B64.encode(der);
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

fn public_der(m: &Material) -> Option<Vec<u8>> {
    Some(match m {
        Material::Ec(k, _) => k.public_key().as_der().ok()?.as_ref().to_vec(),
        Material::Ed(k) => k.public_key().as_der().ok()?.as_ref().to_vec(),
        Material::Rsa(k) => k.public_key().as_der().ok()?.as_ref().to_vec(),
        Material::Oaep(_, der) => der.clone(),
        _ => return None,
    })
}

impl Key {
    fn version_json(&self, name: &str, n: u64) -> Value {
        let v = &self.versions[&n];
        json!({
            "name": format!("{name}/cryptoKeyVersions/{n}"),
            "state": v.state,
            "protectionLevel": self.protection,
            "algorithm": self.algorithm,
            "createTime": v.create_time,
        })
    }

    fn json(&self, name: &str) -> Value {
        let mut j = json!({
            "name": name,
            "purpose": self.purpose,
            "createTime": now_rfc3339(),
            "versionTemplate": {"protectionLevel": self.protection, "algorithm": self.algorithm},
            "destroyScheduledDuration": "86400s",
        });
        if let Some(p) = self.primary {
            j["primary"] = self.version_json(name, p);
        }
        j
    }

    fn add_version(&mut self) -> Option<u64> {
        let n = self.versions.keys().next_back().copied().unwrap_or(0) + 1;
        self.versions.insert(
            n,
            Version {
                state: "ENABLED".into(),
                material: algorithm_material(&self.algorithm)?,
                create_time: now_rfc3339(),
            },
        );
        Some(n)
    }
}

/// A parsed request path: `/v1/<resource>[:<verb>]`; `.../cryptoKeyVersions/<n>/publicKey` is
/// routed as the verb `getPublicKey` (which is refused as a `:verb`, as Cloud KMS does).
struct Route {
    key: String,
    version: Option<u64>,
    /// `cryptoKeys` (collection, under a key ring) or `cryptoKeyVersions` (under a key).
    collection: Option<String>,
    verb: Option<String>,
    ring: Option<String>,
}

fn route(path: &str) -> Option<Route> {
    let rest = path.strip_prefix("/v1/")?;
    let (resource, verb) = match rest.rsplit_once(':') {
        // A domain-scoped project contains ':' too; verbs come after the last segment only.
        Some((r, v)) if !v.contains('/') && v.chars().all(|c| c.is_ascii_alphabetic()) => {
            (r, Some(v.to_owned()))
        }
        _ => (rest, None),
    };
    if verb.as_deref() == Some("getPublicKey") {
        return None;
    }
    if let Some(r) = resource
        .strip_suffix("/publicKey")
        .filter(|_| verb.is_none())
    {
        let parts: Vec<&str> = r.split('/').collect();
        if parts.len() != 10 || parts[8] != "cryptoKeyVersions" {
            return None;
        }
        return Some(Route {
            key: parts[..8].join("/"),
            version: Some(parts[9].parse().ok()?),
            collection: None,
            verb: Some("getPublicKey".into()),
            ring: None,
        });
    }
    let parts: Vec<&str> = resource.split('/').collect();
    match parts.len() {
        // projects/p/locations/l/keyRings/r/cryptoKeys
        7 if parts[6] == "cryptoKeys" => Some(Route {
            key: String::new(),
            version: None,
            collection: Some("cryptoKeys".into()),
            verb,
            ring: Some(parts[..6].join("/")),
        }),
        8 => Some(Route {
            key: resource.to_owned(),
            version: None,
            collection: None,
            verb,
            ring: None,
        }),
        9 if parts[8] == "cryptoKeyVersions" => Some(Route {
            key: parts[..8].join("/"),
            version: None,
            collection: Some("cryptoKeyVersions".into()),
            verb,
            ring: None,
        }),
        10 if parts[8] == "cryptoKeyVersions" => Some(Route {
            key: parts[..8].join("/"),
            version: Some(parts[9].parse().ok()?),
            collection: None,
            verb,
            ring: None,
        }),
        _ => None,
    }
}

struct Responder(Arc<Mutex<State>>);

impl Respond for Responder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let mut st = self.0.lock().unwrap();
        st.requests += 1;
        let path = req.url.path().to_owned();
        let method = req.method.as_str().to_owned();
        let tail = path
            .rsplit([':', '/'])
            .next()
            .unwrap_or_default()
            .to_owned();
        let call = format!("{method} {tail}");
        *st.calls.entry(call.clone()).or_default() += 1;
        let tamper = st.tamper.get(&call).cloned().unwrap_or_default();
        TAMPER.with(|t| *t.borrow_mut() = tamper);
        let body: Value = if req.body.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => {
                    // Form bodies (token endpoints) are handled below.
                    Value::Null
                }
            }
        };
        // Token endpoints.
        if path == "/computeMetadata/v1/instance/service-accounts/default/token" {
            if req
                .headers
                .get("Metadata-Flavor")
                .map(wiremock::http::HeaderValue::as_bytes)
                != Some(b"Google")
            {
                return ResponseTemplate::new(403);
            }
            return st.issue(true);
        }
        if path == "/" && req.headers.get("Metadata-Flavor").is_some() {
            return ResponseTemplate::new(200).insert_header("Metadata-Flavor", "Google");
        }
        if path == "/token" || path == "/v1/token" {
            let form: HashMap<String, String> =
                anykms_gcp::anykms_http::url::form_urlencoded::parse(&req.body)
                    .into_owned()
                    .collect();
            let good = match form.get("grant_type").map(String::as_str) {
                Some("refresh_token") => {
                    form.get("refresh_token").map(String::as_str) == Some(REFRESH_TOKEN)
                }
                Some("urn:ietf:params:oauth:grant-type:token-exchange") => {
                    form.get("subject_token").map(String::as_str) == Some(SUBJECT_TOKEN)
                        && form
                            .get("scope")
                            .is_some_and(|s| s.contains("cloud-platform"))
                        && form.contains_key("audience")
                }
                _ => false,
            };
            if !good {
                return ResponseTemplate::new(400).set_body_json(
                    json!({"error": "invalid_grant", "error_description": "bad grant"}),
                );
            }
            return st.issue(false);
        }
        if path.starts_with("/v1/projects/-/serviceAccounts/")
            && path.ends_with(":generateAccessToken")
        {
            if !st.authorized(req) {
                return status_body(
                    401,
                    "UNAUTHENTICATED",
                    "Request had invalid authentication credentials.",
                );
            }
            st.issued += 1;
            let t = format!("ya29.impersonated-{}", st.issued);
            st.tokens.insert(t.clone());
            return ok(json!({"accessToken": t, "expireTime": "2099-01-01T00:00:00Z"}));
        }
        // Cloud KMS.
        if !st.authorized(req) {
            return status_body(
                401,
                "UNAUTHENTICATED",
                "Request had invalid authentication credentials. Expected OAuth 2 access token.",
            );
        }
        let token = bearer(req).unwrap_or_default();
        let Some(r) = route(&path) else {
            return not_found("Resource");
        };
        if st.denied.contains(&token) {
            return status_body(
                403,
                "PERMISSION_DENIED",
                &format!(
                    "Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied on resource '{}' (or it may not exist).",
                    r.key
                ),
            );
        }
        if !r.key.is_empty() && st.throttled.contains(&r.key) {
            return status_body(
                429,
                "RESOURCE_EXHAUSTED",
                "Quota exceeded for quota metric 'Cryptographic requests'.",
            )
            .insert_header("Retry-After", "1");
        }
        st.dispatch(&method, &r, &body, req)
    }
}

/// A service-account self-signed JWT: RS256, the cloud-platform scope, not expired. (The fake
/// does not check the signature: the unit tests of the signer do.)
fn self_signed_jwt_ok(t: &str) -> bool {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let (Ok(h), Ok(c), Ok(sig)) = (
        b64.decode(parts[0]),
        b64.decode(parts[1]),
        b64.decode(parts[2]),
    ) else {
        return false;
    };
    let (Ok(h), Ok(c)) = (
        serde_json::from_slice::<Value>(&h),
        serde_json::from_slice::<Value>(&c),
    ) else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    h["alg"] == "RS256"
        && c["scope"] == "https://www.googleapis.com/auth/cloud-platform"
        && c["iss"] == c["sub"]
        && c["exp"].as_u64().is_some_and(|e| e > now)
        && sig.len() >= 256
}

fn bearer(req: &Request) -> Option<String> {
    req.headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_owned)
}

impl State {
    fn authorized(&self, req: &Request) -> bool {
        bearer(req).is_some_and(|t| {
            self.tokens.contains(&t) || self.denied.contains(&t) || self_signed_jwt_ok(&t)
        })
    }

    fn issue(&mut self, metadata: bool) -> ResponseTemplate {
        self.issued += 1;
        let t = format!("ya29.issued-{}", self.issued);
        self.tokens.insert(t.clone());
        let r = ok(json!({"access_token": t, "expires_in": 3599, "token_type": "Bearer"}));
        if metadata {
            r.insert_header("Metadata-Flavor", "Google")
        } else {
            r
        }
    }

    fn dispatch(
        &mut self,
        method: &str,
        r: &Route,
        body: &Value,
        req: &Request,
    ) -> ResponseTemplate {
        // Admin: create a key under a key ring.
        if let Some(ring) = &r.ring {
            if method != "POST" {
                return invalid("unsupported");
            }
            let Some(id) = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "cryptoKeyId")
                .map(|(_, v)| v.into_owned())
            else {
                return invalid("cryptoKeyId is required");
            };
            let name = format!("{ring}/cryptoKeys/{id}");
            if self.keys.contains_key(&name) {
                return status_body(409, "ALREADY_EXISTS", "CryptoKey already exists.");
            }
            let alg = body
                .pointer("/versionTemplate/algorithm")
                .and_then(Value::as_str)
                .unwrap_or("GOOGLE_SYMMETRIC_ENCRYPTION")
                .to_owned();
            let purpose = body
                .get("purpose")
                .and_then(Value::as_str)
                .unwrap_or("ENCRYPT_DECRYPT")
                .to_owned();
            if purpose_of(&alg) != purpose {
                return invalid("algorithm does not match purpose");
            }
            let protection = body
                .pointer("/versionTemplate/protectionLevel")
                .and_then(Value::as_str)
                .unwrap_or("SOFTWARE")
                .to_owned();
            let mut key = Key {
                purpose,
                algorithm: alg,
                protection,
                primary: None,
                versions: BTreeMap::new(),
            };
            let Some(v) = key.add_version() else {
                return invalid("unsupported algorithm in the fake");
            };
            if key.purpose == "ENCRYPT_DECRYPT" {
                key.primary = Some(v);
            }
            let j = key.json(&name);
            self.keys.insert(name, key);
            return ok(j);
        }
        let name = r.key.clone();
        let Some(key) = self.keys.get_mut(&name) else {
            // As Cloud KMS does (§24.4 probe T1): a version's own GET names the version even when
            // the key is missing; every other request names the key.
            return match (method, r.version, &r.verb) {
                ("GET", Some(n), None) => {
                    not_found(&format!("CryptoKeyVersion {name}/cryptoKeyVersions/{n}"))
                }
                _ => not_found(&format!("CryptoKey {name}")),
            };
        };
        match (
            method,
            r.version,
            r.collection.as_deref(),
            r.verb.as_deref(),
        ) {
            ("GET", None, None, None) => ok(key.json(&name)),
            ("GET", None, Some("cryptoKeyVersions"), None) => {
                let size: usize = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "pageSize")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(25)
                    .clamp(1, 1000);
                let start: usize = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "pageToken")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                let all: Vec<u64> = key.versions.keys().copied().collect();
                let page: Vec<Value> = all
                    .iter()
                    .skip(start)
                    .take(size)
                    .map(|n| key.version_json(&name, *n))
                    .collect();
                let mut j = json!({"cryptoKeyVersions": page, "totalSize": all.len()});
                if start + size < all.len() {
                    j["nextPageToken"] = (start + size).to_string().into();
                }
                ok(j)
            }
            ("POST", None, Some("cryptoKeyVersions"), None) => match key.add_version() {
                Some(n) => ok(key.version_json(&name, n)),
                None => invalid("unsupported algorithm"),
            },
            ("POST", None, None, Some("updatePrimaryVersion")) => {
                let Some(n) = body
                    .get("cryptoKeyVersionId")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse().ok())
                else {
                    return invalid("cryptoKeyVersionId is required");
                };
                if key.purpose != "ENCRYPT_DECRYPT" {
                    return wrong_purpose(&name, &key.purpose);
                }
                match key.versions.get(&n) {
                    Some(v) if v.state == "ENABLED" => {
                        key.primary = Some(n);
                        ok(key.json(&name))
                    }
                    Some(v) => {
                        not_enabled(&format!("{name}/cryptoKeyVersions/{n}"), &v.state.clone())
                    }
                    None => not_found(&format!("CryptoKeyVersion {name}/cryptoKeyVersions/{n}")),
                }
            }
            ("POST", None, None, Some("encrypt")) => encrypt(&name, key, body),
            ("POST", None, None, Some("decrypt")) => decrypt(&name, key, body),
            (m, Some(n), None, verb) => {
                let vname = format!("{name}/cryptoKeyVersions/{n}");
                if !key.versions.contains_key(&n) {
                    return not_found(&format!("CryptoKeyVersion {vname}"));
                }
                match (m, verb) {
                    ("GET", None) if self.deny_version_get => status_body(
                        403,
                        "PERMISSION_DENIED",
                        &format!(
                            "Permission 'cloudkms.cryptoKeyVersions.get' denied on resource '{vname}' (or it may not exist)."
                        ),
                    ),
                    ("GET", None) => ok(key.version_json(&name, n)),
                    ("PATCH", None) => {
                        let Some(state) = body.get("state").and_then(Value::as_str) else {
                            return invalid("state is required");
                        };
                        if !matches!(state, "ENABLED" | "DISABLED") {
                            return invalid("state must be ENABLED or DISABLED");
                        }
                        state.clone_into(&mut key.versions.get_mut(&n).unwrap().state);
                        ok(key.version_json(&name, n))
                    }
                    ("POST", Some("destroy")) => {
                        key.versions.get_mut(&n).unwrap().state = "DESTROY_SCHEDULED".into();
                        if key.primary == Some(n) {
                            key.primary = None;
                        }
                        ok(key.version_json(&name, n))
                    }
                    (_, Some(verb)) => {
                        let state = key.versions[&n].state.clone();
                        let served = verb == "getPublicKey" && self.serve_disabled_public_keys;
                        if state != "ENABLED" && !served {
                            return not_enabled(&vname, &state);
                        }
                        version_op(&name, &vname, key, n, verb, body)
                    }
                    _ => invalid("unsupported method"),
                }
            }
            _ => invalid("unsupported method"),
        }
    }
}

fn gcm_aad(name: &str, aad: &[u8]) -> Vec<u8> {
    let mut a = name.as_bytes().to_vec();
    a.push(0);
    a.extend_from_slice(aad);
    a
}

fn encrypt(name: &str, key: &Key, body: &Value) -> ResponseTemplate {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    if key.purpose != "ENCRYPT_DECRYPT" {
        return wrong_purpose(name, &key.purpose);
    }
    let (pt, pt_ok) = match field(body, "plaintext") {
        Ok(Some(p)) => p,
        Ok(None) => return invalid("plaintext is required"),
        Err(e) => return e,
    };
    let (aad, aad_ok) = match field(body, "additionalAuthenticatedData") {
        Ok(a) => a.unwrap_or_default(),
        Err(e) => return e,
    };
    if pt.len() > 65536 || aad.len() > 65536 {
        return invalid("The request payload is too large.");
    }
    let Some(p) = key.primary else {
        return precondition(&format!("{name} has no primary version."));
    };
    let v = &key.versions[&p];
    let vname = format!("{name}/cryptoKeyVersions/{p}");
    if v.state != "ENABLED" {
        return not_enabled(&vname, &v.state);
    }
    let Material::Aes(k) = &v.material else {
        return invalid("bad key");
    };
    let mut nonce = [0u8; 12];
    aws_lc_rs::rand::fill(&mut nonce).unwrap();
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, k).unwrap());
    let mut buf = pt.clone();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(gcm_aad(name, &aad)),
            &mut buf,
        )
        .unwrap();
    let p32 = u32::try_from(p).expect("fake version numbers fit the 4-byte ciphertext prefix");
    let mut ct = p32.to_be_bytes().to_vec();
    ct.extend_from_slice(&nonce);
    ct.extend_from_slice(&buf);
    ok(json!({
        "name": vname,
        "ciphertext": B64.encode(&ct),
        "ciphertextCrc32c": crc_str(&ct),
        "verifiedPlaintextCrc32c": pt_ok,
        "verifiedAdditionalAuthenticatedDataCrc32c": aad_ok,
        "protectionLevel": key.protection,
    }))
}

const DECRYPT_FAILED: &str =
    "Decryption failed: verify that 'name' refers to the correct CryptoKey.";

fn decrypt(name: &str, key: &Key, body: &Value) -> ResponseTemplate {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    if key.purpose != "ENCRYPT_DECRYPT" {
        return wrong_purpose(name, &key.purpose);
    }
    let ct = match field(body, "ciphertext") {
        Ok(Some((c, _))) => c,
        Ok(None) => return invalid("ciphertext is required"),
        Err(e) => return e,
    };
    let aad = match field(body, "additionalAuthenticatedData") {
        Ok(a) => a.map(|a| a.0).unwrap_or_default(),
        Err(e) => return e,
    };
    if ct.len() < 4 + 12 + 16 {
        return invalid(DECRYPT_FAILED);
    }
    let n = u64::from(u32::from_be_bytes(ct[..4].try_into().unwrap()));
    let Some(v) = key.versions.get(&n) else {
        return invalid(DECRYPT_FAILED);
    };
    let Material::Aes(k) = &v.material else {
        return invalid(DECRYPT_FAILED);
    };
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, k).unwrap());
    let mut buf = ct[16..].to_vec();
    let nonce = Nonce::try_assume_unique_for_key(&ct[4..16]).unwrap();
    let Ok(pt) = opening.open_in_place(nonce, Aad::from(gcm_aad(name, &aad)), &mut buf) else {
        return invalid(DECRYPT_FAILED);
    };
    if v.state != "ENABLED" {
        return not_enabled(&format!("{name}/cryptoKeyVersions/{n}"), &v.state);
    }
    let mut j = json!({
        "plaintextCrc32c": crc_str(pt),
        "usedPrimary": key.primary == Some(n),
        "protectionLevel": key.protection,
    });
    // proto3 JSON omits empty bytes, as Cloud KMS does for an empty plaintext.
    if !pt.is_empty() {
        j["plaintext"] = B64.encode(&*pt).into();
    }
    ok(j)
}

fn version_op(
    name: &str,
    vname: &str,
    key: &Key,
    n: u64,
    verb: &str,
    body: &Value,
) -> ResponseTemplate {
    let v = &key.versions[&n];
    match verb {
        "getPublicKey" => {
            let Some(der) = public_der(&v.material) else {
                return wrong_purpose(name, &key.purpose);
            };
            let p = pem(&der);
            ok(json!({
                "pem": p,
                "algorithm": key.algorithm,
                "pemCrc32c": crc_str(p.as_bytes()),
                "name": vname,
                "protectionLevel": key.protection,
            }))
        }
        "asymmetricSign" => {
            if key.purpose != "ASYMMETRIC_SIGN" {
                return wrong_purpose(name, &key.purpose);
            }
            let (sig, verified_digest, verified_data) = match &v.material {
                Material::Ed(k) => {
                    // Cloud KMS refuses an empty message (§24.4 probe T1).
                    let (data, ok_) = match field(body, "data") {
                        Ok(Some(d)) if !d.0.is_empty() => d,
                        Ok(_) => {
                            return invalid(
                                "For algorithm EC_SIGN_ED25519 and protection level SOFTWARE, \
                                 data must be set.",
                            );
                        }
                        Err(e) => return e,
                    };
                    (k.sign(&data).as_ref().to_vec(), false, ok_)
                }
                m => {
                    let Some(digest) = body.get("digest").and_then(Value::as_object) else {
                        return invalid("digest is required");
                    };
                    let want = match key.algorithm.as_str() {
                        a if a.ends_with("SHA512") => "sha512",
                        a if a.ends_with("SHA384") => "sha384",
                        _ => "sha256",
                    };
                    let Some(d) = digest.get(want).and_then(Value::as_str) else {
                        return invalid("The digest type does not match the algorithm of the key.");
                    };
                    let Ok(d) = B64.decode(d) else {
                        return invalid("bad digest");
                    };
                    let verified = match body.get("digestCrc32c") {
                        None => false,
                        Some(c) => {
                            let c: u64 = c
                                .as_str()
                                .and_then(|s| s.parse().ok())
                                .or_else(|| c.as_u64())
                                .unwrap_or(u64::MAX);
                            if c != u64::from(crc32c(&d)) {
                                return checksum("digest");
                            }
                            true
                        }
                    };
                    let dalg = match want {
                        "sha512" => &aws_lc_rs::digest::SHA512,
                        "sha384" => &aws_lc_rs::digest::SHA384,
                        _ => &aws_lc_rs::digest::SHA256,
                    };
                    let Ok(digest) = aws_lc_rs::digest::Digest::import_less_safe(&d, dalg) else {
                        return invalid("The digest has the wrong length.");
                    };
                    let sig = match m {
                        Material::Ec(k, _) => match k.sign_digest(&digest) {
                            Ok(s) => s.as_ref().to_vec(),
                            Err(_) => return invalid("signing failed"),
                        },
                        Material::Rsa(k) => {
                            use aws_lc_rs::signature as s;
                            let enc: &'static dyn aws_lc_rs::signature::RsaEncoding =
                                match key.algorithm.as_str() {
                                    "RSA_SIGN_PSS_2048_SHA256"
                                    | "RSA_SIGN_PSS_3072_SHA256"
                                    | "RSA_SIGN_PSS_4096_SHA256" => &s::RSA_PSS_SHA256,
                                    "RSA_SIGN_PSS_4096_SHA512" => &s::RSA_PSS_SHA512,
                                    "RSA_SIGN_PKCS1_4096_SHA512" => &s::RSA_PKCS1_SHA512,
                                    _ => &s::RSA_PKCS1_SHA256,
                                };
                            let mut out = vec![0u8; k.public_modulus_len()];
                            if k.sign_digest(enc, &digest, &mut out).is_err() {
                                return invalid("signing failed");
                            }
                            out
                        }
                        _ => return wrong_purpose(name, &key.purpose),
                    };
                    (sig, verified, false)
                }
            };
            ok(json!({
                "signature": B64.encode(&sig),
                "signatureCrc32c": crc_str(&sig),
                "verifiedDigestCrc32c": verified_digest,
                "verifiedDataCrc32c": verified_data,
                "name": vname,
                "protectionLevel": key.protection,
            }))
        }
        "macSign" | "macVerify" => {
            let Material::Hmac(k) = &v.material else {
                return wrong_purpose(name, &key.purpose);
            };
            let (data, data_ok) = match field(body, "data") {
                Ok(d) => d.unwrap_or_default(),
                Err(e) => return e,
            };
            if data.len() > 65536 {
                return invalid("The request payload is too large.");
            }
            // macSign MACs empty data; macVerify refuses it (§24.4 probe T1).
            if verb == "macVerify" && data.is_empty() {
                return invalid("Request field data is required.");
            }
            let alg = match key.algorithm.as_str() {
                "HMAC_SHA384" => aws_lc_rs::hmac::HMAC_SHA384,
                "HMAC_SHA512" => aws_lc_rs::hmac::HMAC_SHA512,
                _ => aws_lc_rs::hmac::HMAC_SHA256,
            };
            let hk = aws_lc_rs::hmac::Key::new(alg, k);
            if verb == "macSign" {
                let tag = aws_lc_rs::hmac::sign(&hk, &data);
                ok(json!({
                    "name": vname,
                    "mac": B64.encode(tag.as_ref()),
                    "macCrc32c": crc_str(tag.as_ref()),
                    "verifiedDataCrc32c": data_ok,
                    "protectionLevel": key.protection,
                }))
            } else {
                let (mac, mac_ok) = match field(body, "mac") {
                    Ok(Some(m)) => m,
                    Ok(None) => return invalid("mac is required"),
                    Err(e) => return e,
                };
                let success = aws_lc_rs::hmac::verify(&hk, &data, &mac).is_ok();
                ok(json!({
                    "name": vname,
                    "success": success,
                    "verifiedDataCrc32c": data_ok,
                    "verifiedMacCrc32c": mac_ok,
                    "verifiedSuccessIntegrity": success,
                    "protectionLevel": key.protection,
                }))
            }
        }
        "asymmetricDecrypt" => {
            let Material::Oaep(oaep, _) = &v.material else {
                return wrong_purpose(name, &key.purpose);
            };
            let (ct, ct_ok) = match field(body, "ciphertext") {
                Ok(Some(c)) => c,
                Ok(None) => return invalid("ciphertext is required"),
                Err(e) => return e,
            };
            let mut out = vec![0u8; oaep.min_output_size()];
            match oaep.decrypt(&aws_lc_rs::rsa::OAEP_SHA256_MGF1SHA256, &ct, &mut out, None) {
                Ok(pt) => {
                    let pt = pt.to_vec();
                    ok(json!({
                        "plaintext": B64.encode(&pt),
                        "plaintextCrc32c": crc_str(&pt),
                        "verifiedCiphertextCrc32c": ct_ok,
                        "protectionLevel": key.protection,
                    }))
                }
                Err(_) => invalid("Decryption failed: the ciphertext is invalid."),
            }
        }
        _ => invalid("unsupported method"),
    }
}

impl FakeKms {
    /// Starts the fake; it accepts [`TOKEN`] and denies [`DENIED_TOKEN`].
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(State::default()));
        {
            let mut st = state.lock().unwrap();
            st.tokens.insert(TOKEN.to_owned());
            st.denied.insert(DENIED_TOKEN.to_owned());
        }
        Mock::given(wiremock::matchers::any())
            .respond_with(Responder(state.clone()))
            .mount(&server)
            .await;
        Self {
            server: Arc::new(server),
            state,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The server's base URL (`http://127.0.0.1:<port>`).
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// The key ring every test key lives in.
    pub const RING: &'static str = "projects/fake-project/locations/global/keyRings/test";

    /// Creates a key with one enabled version (the primary for `ENCRYPT_DECRYPT`) and returns
    /// its resource name.
    pub fn create_key(&self, algorithm: &str) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let name = format!("{}/cryptoKeys/k{n}", Self::RING);
        let mut key = Key {
            purpose: purpose_of(algorithm).to_owned(),
            algorithm: algorithm.to_owned(),
            protection: "SOFTWARE".to_owned(),
            primary: None,
            versions: BTreeMap::new(),
        };
        let v = key.add_version().expect("algorithm supported by the fake");
        if key.purpose == "ENCRYPT_DECRYPT" {
            key.primary = Some(v);
        }
        self.state.lock().unwrap().keys.insert(name.clone(), key);
        name
    }

    /// Adds a version (made primary for `ENCRYPT_DECRYPT` keys) and returns its number.
    pub fn rotate(&self, name: &str) -> u64 {
        let mut st = self.state.lock().unwrap();
        let key = st.keys.get_mut(name).expect("known key");
        let v = key.add_version().unwrap();
        if key.purpose == "ENCRYPT_DECRYPT" {
            key.primary = Some(v);
        }
        v
    }

    /// Sets a version's state (`ENABLED`, `DISABLED`, `DESTROYED`, `PENDING_GENERATION`, ...).
    pub fn set_state(&self, name: &str, version: u64, state: &str) {
        let mut st = self.state.lock().unwrap();
        state.clone_into(
            &mut st
                .keys
                .get_mut(name)
                .expect("known key")
                .versions
                .get_mut(&version)
                .expect("known version")
                .state,
        );
    }

    /// Throttles (or stops throttling) every request on `name`.
    pub fn throttle(&self, name: &str, on: bool) {
        let mut st = self.state.lock().unwrap();
        if on {
            st.throttled.insert(name.to_owned());
        } else {
            st.throttled.remove(name);
        }
    }

    /// Accepts another bearer token.
    pub fn accept_token(&self, t: &str) {
        self.state.lock().unwrap().tokens.insert(t.to_owned());
    }

    /// Stops accepting a token (it is answered with 401).
    pub fn revoke_token(&self, t: &str) {
        self.state.lock().unwrap().tokens.remove(t);
    }

    /// Overrides `field` in every success response to `call` (`"POST encrypt"`,
    /// `"GET publicKey"`, ...; the keys of [`calls`](Self::calls)) with `value`, or removes it
    /// when `value` is `null`: a corrupted CRC32C, a missing `verified*` flag, another key's
    /// `name`.
    pub fn tamper(&self, call: &str, field: &str, value: Value) {
        self.state
            .lock()
            .unwrap()
            .tamper
            .entry(call.to_owned())
            .or_default()
            .push((field.to_owned(), value));
    }

    /// Stops every [`tamper`](Self::tamper).
    pub fn clear_tamper(&self) {
        self.state.lock().unwrap().tamper.clear();
    }

    /// Serves the public keys of versions that are not enabled (as Cloud KMS may, §3.1(f)).
    pub fn serve_disabled_public_keys(&self, on: bool) {
        self.state.lock().unwrap().serve_disabled_public_keys = on;
    }

    /// Denies `cryptoKeyVersions.get` (an identity without `cloudkms.cryptoKeyVersions.get`).
    pub fn deny_version_get(&self, on: bool) {
        self.state.lock().unwrap().deny_version_get = on;
    }

    /// Requests served so far.
    pub fn requests(&self) -> u64 {
        self.state.lock().unwrap().requests
    }

    /// Requests whose last path element (method name or resource id) is `tail`, e.g.
    /// `"POST encrypt"`, `"GET publicKey"`.
    pub fn calls(&self, what: &str) -> u64 {
        self.state
            .lock()
            .unwrap()
            .calls
            .get(what)
            .copied()
            .unwrap_or(0)
    }
}
