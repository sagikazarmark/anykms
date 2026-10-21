//! Captures every log line at TRACE (including reqwest/hyper via the log bridge, through
//! `anykms-testkit`) while running operations whose requests and responses carry marker secrets,
//! and asserts the markers never appear in logs or errors: `Display`, `Debug`, and every error in
//! the `source()` chain. Also asserts the span schema (`anykms_http::span`: the request span
//! `anykms.transit` and the token span `anykms.transit.token`) and that `Debug` of every config,
//! builder and credential type redacts proxy userinfo, tokens and file contents (P1-1).
//!
//! Covered: encrypt, decrypt, data keys, rewrap (server error echoing input), digest and message
//! signing and verification, HMAC and its verification, a token-file source, a JWT login and a
//! login whose JWT file is missing, the 403 token-refresh retry, a transport error carrying a
//! reqwest source, an oversized response and an undecodable response, and a refused token file.
//! Every error must name its key (a resource without query string). Run with
//! `--features tracing`.

#![cfg(feature = "tracing")]

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anykms_core::prelude::*;
use anykms_core::{
    BoxFuture, Ciphertext, DataKeySpec, Digest, KeyTypeCheck, KeyUri, KeyVersion, MacAlgorithm,
    Signature, SignatureAlgorithm, Tag,
};
use anykms_transit::{
    FileToken, Flavor, Login, Proxy, ServerConfig, StaticToken, Token, TokenSource, TransitProvider,
};
use base64::Engine as _;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PT: &str = "HYGIENEPLAINTEXT0123456789";
const JWT: &str = "eyJhbGciOiJFUzI1NiJ9.HYGIENEJWT0123456789.c2ln";
const LOGIN_TOKEN: &str = "s.HYGIENELOGINTOKEN0123456789";
const PROXY_SECRET: &str = "HYGIENEPROXYSECRET0123456789";
const AAD: &str = "HYGIENEAAD0123456789";
const TOKEN: &str = "s.HYGIENETOKEN0123456789";
const FILE_TOKEN: &str = "s.HYGIENEFILETOKEN0123456789";
const OLD_TOKEN: &str = "s.HYGIENEOLDTOKEN0123456789";
const NEW_TOKEN: &str = "s.HYGIENENEWTOKEN0123456789";
const MSG: &str = "HYGIENEMESSAGE0123456789";
const MAC_DATA: &str = "HYGIENEMACDATA0123456789";
const DEK: &[u8; 32] = b"HYGIENEDATAKEY0123456789abcdefgh";

fn b64(s: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// `Display`, `Debug` and the whole `source()` chain of an error, each rendered both ways.
fn render(e: &anykms_core::Error) -> String {
    // Every handle error names its key, as a URI without query string.
    let r = e.resource().unwrap_or_else(|| panic!("no resource on {e}"));
    assert!(
        r.starts_with("hashivault://default/transit/keys/") && !r.contains('?'),
        "{r}"
    );
    let mut out = format!("{e}\n{e:?}\n");
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    let mut depth = 0;
    while let Some(s) = src {
        writeln!(out, "source[{depth}]: {s}\n{s:?}").unwrap();
        src = s.source();
        depth += 1;
    }
    out
}

/// Returns `old` until invalidated, then `new` (a refreshable source).
#[derive(Debug, Default)]
struct Rotating {
    rotated: AtomicBool,
}

impl TokenSource for Rotating {
    fn token(&self) -> BoxFuture<'_, anykms_core::Result<Option<Token>>> {
        let t = if self.rotated.load(Ordering::SeqCst) {
            NEW_TOKEN
        } else {
            OLD_TOKEN
        };
        Box::pin(async move { Ok(Some(Token::from(t))) })
    }

    fn invalidate(&self, rejected: &Token) {
        if rejected.expose() == OLD_TOKEN {
            self.rotated.store(true, Ordering::SeqCst);
        }
    }
}

async fn ok(server: &MockServer, m: &str, p: &str, body: serde_json::Value) {
    Mock::given(method(m))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn key_type(server: &MockServer, name: &str, t: &str) {
    ok(
        server,
        "GET",
        &format!("/v1/transit/keys/{name}"),
        json!({"data": {"type": t, "latest_version": 1}}),
    )
    .await;
}

fn uri(name: &str) -> KeyUri {
    format!("hashivault:///transit/keys/{name}")
        .parse()
        .unwrap()
}

fn provider(cfg: ServerConfig) -> TransitProvider {
    TransitProvider::builder()
        .server("default", cfg.allow_loopback_http())
        .build()
        .unwrap()
}

/// P1-1: `Debug` of every public config, builder and credential type holding a proxy with
/// userinfo, an address with userinfo, a token or a JWT path prints none of the secrets.
#[test]
fn debug_output_redacts_secrets() {
    let proxy_url = format!("http://user:{PROXY_SECRET}@proxy.example:3128/p?token={PROXY_SECRET}");
    let cfg = ServerConfig::new(
        format!("https://user:{PROXY_SECRET}@vault.example:8200"),
        Flavor::Vault,
    )
    .token(TOKEN)
    .proxy(Proxy::Url(proxy_url.clone()));
    let secrets = [PROXY_SECRET, TOKEN];
    anykms_testkit::assert_debug_redacts(&cfg, &secrets);
    anykms_testkit::assert_debug_redacts(&Proxy::Url(proxy_url), &secrets);
    assert!(format!("{cfg:?}").contains("proxy.example:3128"), "{cfg:?}");
    let builder = TransitProvider::builder().server("default", cfg.clone());
    anykms_testkit::assert_debug_redacts(&builder, &secrets);
    anykms_testkit::assert_debug_redacts(&Token::from(TOKEN), &secrets);
    anykms_testkit::assert_debug_redacts(&StaticToken::new(TOKEN), &secrets);
    let login = ServerConfig::new("https://vault.example:8200", Flavor::Vault)
        .proxy(Proxy::Url(format!(
            "http://u:{PROXY_SECRET}@proxy.example:3128"
        )))
        .login(Login::jwt("ci", "/run/jwt"));
    anykms_testkit::assert_debug_redacts(&login, &secrets);
    anykms_testkit::assert_debug_redacts(&FileToken::new("/run/token"), &secrets);
}

#[tokio::test(flavor = "current_thread")]
async fn trace_output_and_errors_never_contain_secrets() {
    let capture = anykms_testkit::capture();

    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    key_type(&server, "ec", "ecdsa-p256").await;
    key_type(&server, "ed", "ed25519").await;
    key_type(&server, "mac", "hmac").await;
    ok(
        &server,
        "POST",
        "/v1/transit/encrypt/k",
        json!({"data": {"ciphertext": "vault:v1:AAAA"}}),
    )
    .await;
    ok(
        &server,
        "POST",
        "/v1/transit/decrypt/k",
        json!({"data": {"plaintext": b64(PT)}}),
    )
    .await;
    ok(
        &server,
        "POST",
        "/v1/transit/datakey/plaintext/k",
        json!({"data": {"plaintext": b64(DEK), "ciphertext": "vault:v1:BBBB"}}),
    )
    .await;
    // A server error echoing input: redacted to a fingerprint.
    Mock::given(method("POST"))
        .and(path("/v1/transit/rewrap/k"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"errors": [format!("odd failure {PT} {}", b64(PT))]})),
        )
        .mount(&server)
        .await;
    // A success body over the 64 KiB response limit, carrying the plaintext.
    key_type(&server, "big", "aes256-gcm96").await;
    ok(
        &server,
        "POST",
        "/v1/transit/decrypt/big",
        json!({"data": {"plaintext": b64(PT.repeat(4000))}}),
    )
    .await;
    // Undecodable success body carrying the plaintext.
    ok(
        &server,
        "POST",
        "/v1/transit/decrypt/bad",
        json!({"data": {"plaintext": format!("!{PT}!")}}),
    )
    .await;
    key_type(&server, "bad", "aes256-gcm96").await;

    // Signing: ECDSA (digest) and Ed25519 (message).
    let der_sig = {
        let mut v = vec![0x30, 0x44];
        v.extend_from_slice(&[1u8; 68]);
        v
    };
    ok(
        &server,
        "POST",
        "/v1/transit/sign/ec",
        json!({"data": {"signature": format!("vault:v1:{}", b64(&der_sig))}}),
    )
    .await;
    ok(
        &server,
        "POST",
        "/v1/transit/verify/ec",
        json!({"data": {"valid": true}}),
    )
    .await;
    ok(
        &server,
        "POST",
        "/v1/transit/sign/ed",
        json!({"data": {"signature": format!("vault:v1:{}", b64([2u8; 64]))}}),
    )
    .await;
    // Verification error echoing the input.
    Mock::given(method("POST"))
        .and(path("/v1/transit/verify/ed"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"errors": [format!("bad input {MSG} {}", b64(MSG))]})),
        )
        .mount(&server)
        .await;

    // HMAC.
    ok(
        &server,
        "POST",
        "/v1/transit/hmac/mac/sha2-256",
        json!({"data": {"hmac": format!("vault:v1:{}", b64([3u8; 32]))}}),
    )
    .await;
    ok(
        &server,
        "POST",
        "/v1/transit/verify/mac/sha2-256",
        json!({"data": {"valid": false}}),
    )
    .await;

    // Token-dependent paths: the token file, and the 403 → refresh → retry.
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/tok"))
        .and(header("X-Vault-Token", OLD_TOKEN))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/tok"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"ciphertext": "vault:v2:CCCC"}})),
        )
        .mount(&server)
        .await;

    let mut text = String::new();

    // AEAD.
    let p = provider(ServerConfig::new(server.uri(), Flavor::OpenBao).token(TOKEN));
    let k = p.aead_key(uri("k")).unwrap();
    k.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap();
    let pt = k
        .decrypt(
            &Ciphertext::from_bytes(b"vault:v1:AAAA".to_vec()),
            AAD.as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(&*pt, PT.as_bytes());
    let dk = k
        .generate_data_key(DataKeySpec::Aes256, AAD.as_bytes())
        .await
        .unwrap();
    assert_eq!(dk.plaintext(), DEK);
    let e = k
        .rewrap(&Ciphertext::from_bytes(b"vault:v1:AAAA".to_vec()), b"")
        .await
        .unwrap_err();
    text.push_str(&render(&e));
    let e = p
        .aead_key(uri("bad"))
        .unwrap()
        .decrypt(
            &Ciphertext::from_bytes(b"vault:v1:AAAA".to_vec()),
            AAD.as_bytes(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), anykms_core::ErrorKind::Backend, "{e}");
    text.push_str(&render(&e));
    writeln!(text, "{dk:?}\n{p:?}\n{k:?}").unwrap();

    // Oversized response carrying the plaintext.
    let small = provider(
        ServerConfig::new(server.uri(), Flavor::OpenBao)
            .token(TOKEN)
            .max_response_bytes(64 * 1024),
    );
    let e = small
        .aead_key(uri("big"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .decrypt(
            &Ciphertext::from_bytes(b"vault:v1:AAAA".to_vec()),
            AAD.as_bytes(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.kind(), anykms_core::ErrorKind::Backend, "{e}");
    text.push_str(&render(&e));

    // Signing and verification.
    let ec = p
        .digest_signing_key(uri("ec"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let digest = Digest::sha256(MSG.as_bytes());
    let sig = ec.sign_digest(&digest).await.unwrap();
    ec.verify_digest(&digest, &sig).await.unwrap();
    let ed = p.ed25519_key(uri("ed")).unwrap();
    let sig = ed.sign_message(MSG.as_bytes()).await.unwrap();
    let e = ed.verify_message(MSG.as_bytes(), &sig).await.unwrap_err();
    text.push_str(&render(&e));
    let forged = Signature::from_parts(
        SignatureAlgorithm::Ed25519,
        Some(KeyVersion::from_u64(1)),
        vec![0u8; 64],
    );
    writeln!(text, "{ec:?}\n{ed:?}\n{sig:?}\n{forged:?}").unwrap();

    // HMAC.
    let mac = p.mac_key(uri("mac"), MacAlgorithm::HmacSha256).unwrap();
    let tag = mac.mac(MAC_DATA.as_bytes()).await.unwrap();
    let e = mac.verify_mac(MAC_DATA.as_bytes(), &tag).await.unwrap_err();
    assert_eq!(e.kind(), anykms_core::ErrorKind::VerificationFailed);
    text.push_str(&render(&e));
    let other = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::from_u64(1)),
        vec![0u8; 32],
    );
    writeln!(text, "{mac:?}\n{tag:?}\n{other:?}").unwrap();

    // Token file.
    let dir = std::env::temp_dir().join(format!("anykms-hygiene-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("token");
    std::fs::write(&file, format!("{FILE_TOKEN}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let fp = provider(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token_source(Arc::new(FileToken::new(&file))),
    );
    let fk = fp
        .aead_key(uri("tok"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    fk.encrypt(PT.as_bytes(), b"").await.unwrap();
    writeln!(text, "{fp:?}\n{fk:?}").unwrap();
    // A refused (group-readable) token file: the error names the path, never the contents.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        let e = fk.encrypt(PT.as_bytes(), b"").await.unwrap_err();
        assert!(e.to_string().contains(&*file.to_string_lossy()), "{e}");
        text.push_str(&render(&e));
    }
    std::fs::remove_dir_all(&dir).unwrap();

    // A JWT login, then a login whose JWT file is missing (a token span with an error).
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": {"client_token": LOGIN_TOKEN, "lease_duration": 3600, "renewable": true}
        })))
        .mount(&server)
        .await;
    let dir = std::env::temp_dir().join(format!("anykms-hygiene-jwt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwt_file = dir.join("jwt");
    std::fs::write(&jwt_file, format!("{JWT}\n")).unwrap();
    let lp =
        provider(ServerConfig::new(server.uri(), Flavor::Vault).login(Login::jwt("ci", &jwt_file)));
    let lk = lp
        .aead_key(uri("tok"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    lk.encrypt(PT.as_bytes(), b"").await.unwrap();
    writeln!(text, "{lp:?}\n{lk:?}").unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let missing = provider(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .login(Login::jwt("ci", "/nonexistent/anykms/hygiene/jwt")),
    );
    let e = missing
        .aead_key(uri("tok"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(PT.as_bytes(), b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), anykms_core::ErrorKind::Unavailable, "{e}");
    text.push_str(&render(&e));

    // 403 → token refresh → one retry.
    let rp = provider(
        ServerConfig::new(server.uri(), Flavor::Vault).token_source(Arc::new(Rotating::default())),
    );
    let rk = rp
        .aead_key(uri("tok"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        rk.encrypt(PT.as_bytes(), AAD.as_bytes())
            .await
            .unwrap()
            .as_bytes(),
        b"vault:v2:CCCC"
    );
    writeln!(text, "{rp:?}\n{rk:?}").unwrap();

    // Transport error: nothing listens on the port; the error carries a reqwest source.
    let dead = provider(ServerConfig::new("http://127.0.0.1:1", Flavor::Vault).token(TOKEN));
    let e = dead
        .aead_key(uri("k"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(PT.as_bytes(), AAD.as_bytes())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), anykms_core::ErrorKind::Unavailable, "{e}");
    assert!(
        std::error::Error::source(&e).is_some(),
        "transport errors carry their reqwest source"
    );
    text.push_str(&render(&e));

    text.push_str(&capture.text());
    assert!(
        text.contains("anykms.transit"),
        "spans were not captured:\n{text}"
    );
    assert!(
        text.contains("http_status=200"),
        "http_status is recorded on success:\n{text}"
    );
    assert!(
        text.contains("cannot use the JWT file")
            && text.contains("/nonexistent/anykms/hygiene/jwt"),
        "a failed login logs the JWT file:\n{text}"
    );

    // The shared span schema, and the values the transit spans record.
    let spans = capture.spans();
    anykms_testkit::assert_request_schema(spans, "transit");
    anykms_testkit::assert_token_schema(spans, "transit");
    let requests = spans.named("anykms.transit");
    let find = |op: &str, resource: &str| {
        requests
            .iter()
            .find(|s| s.value("op") == Some(op) && s.value("resource") == Some(resource))
            .unwrap_or_else(|| panic!("no {op} span for {resource}: {requests:?}"))
    };
    let enc = find("encrypt", "hashivault://default/transit/keys/k");
    assert_eq!(enc.value("outcome"), Some("ok"), "{enc:?}");
    assert_eq!(enc.value("http_status"), Some("200"), "{enc:?}");
    assert_eq!(enc.value("attempt"), Some("1"), "{enc:?}");
    assert_eq!(enc.value("key_version"), None, "{enc:?}");
    let dec = find("decrypt", "hashivault://default/transit/keys/k");
    assert_eq!(dec.value("key_version"), Some("1"), "{dec:?}");
    let rewrap = find("rewrap", "hashivault://default/transit/keys/k");
    assert_eq!(rewrap.value("outcome"), Some("error"), "{rewrap:?}");
    assert_eq!(rewrap.value("error_kind"), Some("backend"), "{rewrap:?}");
    assert_eq!(rewrap.value("http_status"), Some("500"), "{rewrap:?}");
    assert!(
        requests
            .iter()
            .any(|s| s.value("attempt") == Some("2") && s.value("outcome") == Some("ok")),
        "the 403 retry records attempt 2: {requests:?}"
    );
    let tokens = spans.named("anykms.transit.token");
    for (credential, outcome) in [("jwt", "ok"), ("jwt", "error"), ("token_file", "ok")] {
        assert!(
            tokens
                .iter()
                .any(|s| s.value("credential") == Some(credential)
                    && s.value("outcome") == Some(outcome)),
            "no {credential} token span with outcome {outcome}: {tokens:?}"
        );
    }
    let login = tokens
        .iter()
        .find(|s| s.value("credential") == Some("jwt") && s.value("outcome") == Some("ok"))
        .unwrap();
    assert_eq!(login.value("expires_in_s"), Some("3600"), "{login:?}");
    let failed = tokens
        .iter()
        .find(|s| s.value("credential") == Some("jwt") && s.value("outcome") == Some("error"))
        .unwrap();
    assert_eq!(
        failed.value("error_kind"),
        Some("unavailable"),
        "{failed:?}"
    );
    assert!(
        text.contains("token refreshed after 403"),
        "the 403 retry path ran:\n{text}"
    );
    assert!(
        text.contains("reporting Backend"),
        "Backend fallbacks emit events:\n{text}"
    );
    assert!(
        text.contains("fp "),
        "the Backend fallback event carries the fingerprint:\n{text}"
    );
    let dek = String::from_utf8_lossy(DEK).into_owned();
    for secret in [
        PT,
        AAD,
        TOKEN,
        FILE_TOKEN,
        OLD_TOKEN,
        NEW_TOKEN,
        MSG,
        MAC_DATA,
        JWT,
        LOGIN_TOKEN,
        dek.as_str(),
    ] {
        for enc in [secret.to_owned(), b64(secret)] {
            let probe = &enc[..enc.len().min(20)];
            assert!(
                !text.contains(probe),
                "captured output contains a secret ({probe}):\n{text}"
            );
        }
    }
}

/// An `aes128-gcm96` key opened as a KEK through the provider warns once on its first wrap; an
/// `aes256-gcm96` KEK does not warn. Wrapping uses empty AAD and the KEK still rewraps.
#[test]
fn weak_kek_warns_on_wrap() {
    let buf = anykms_testkit::Buf::default();
    let b2 = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || b2.clone())
        .with_ansi(false)
        .finish();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            let server = MockServer::start().await;
            key_type(&server, "weak", "aes128-gcm96").await;
            key_type(&server, "strong", "aes256-gcm96").await;
            for k in ["weak", "strong"] {
                ok(
                    &server,
                    "POST",
                    &format!("/v1/transit/encrypt/{k}"),
                    json!({"data": {"ciphertext": "vault:v1:AAAA"}}),
                )
                .await;
            }
            let p = provider(ServerConfig::new(server.uri(), Flavor::Vault).token("s.mock-token"));
            let opts = anykms_core::OpenOptions::default();
            let strong = anykms_core::Provider::key_wrap(&p, &uri("strong"), &opts).unwrap();
            strong.wrap_key(&[7; 32]).await.unwrap();
            assert_eq!(buf.contents(), "");
            assert!(strong.supports_rewrap());

            let weak = anykms_core::Provider::key_wrap(&p, &uri("weak"), &opts).unwrap();
            weak.wrap_key(&[7; 32]).await.unwrap();
            weak.wrap_key(&[7; 32]).await.unwrap();
            let out = buf.contents();
            assert_eq!(out.matches("128-bit strength").count(), 1, "{out}");
        });
    });
}

/// R-32: calls dropped before their response arrives (a timeout around them) close their request
/// spans with `outcome=cancelled`, and an `ObserveLayer` reports each once, as cancelled.
#[tokio::test(flavor = "current_thread")]
async fn cancelled_calls_are_recorded() {
    use std::sync::Mutex;
    use std::time::Duration;

    let capture = anykms_testkit::capture();
    let server = MockServer::start().await;
    key_type(&server, "slow", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"ciphertext": "vault:v1:AAAA"}}))
                .set_delay(Duration::from_secs(30)),
        )
        .mount(&server)
        .await;
    type Events = Vec<(bool, bool, &'static str)>;
    let events: Arc<Mutex<Events>> = Arc::default();
    let e = events.clone();
    let observe = anykms_core::ObserveLayer::new(move |ev: &anykms_core::OpEvent<'_>| {
        e.lock()
            .unwrap()
            .push((ev.is_ok(), ev.is_cancelled(), ev.outcome()));
    });
    let p = provider(ServerConfig::new(server.uri(), Flavor::Vault).token("s.mock-token"));
    let opts = anykms_core::OpenOptions::default();
    let k = anykms_core::Provider::aead(&p, &uri("slow"), &opts)
        .unwrap()
        .layer(&observe);
    for _ in 0..3 {
        let r = tokio::time::timeout(Duration::from_millis(300), k.encrypt(b"x", b"")).await;
        assert!(r.is_err(), "the call finished: {r:?}");
    }

    assert_eq!(
        *events.lock().unwrap(),
        [(false, true, "cancelled"); 3],
        "one cancelled event per call"
    );
    // The first span is the handle's metadata read, which was answered.
    let spans = capture.spans().named("anykms.transit");
    assert_eq!(spans.len(), 4, "{spans:?}");
    assert_eq!(spans[0].value("outcome"), Some("ok"), "{spans:?}");
    for s in &spans[1..] {
        assert_eq!(s.value("op"), Some("encrypt"), "{s:?}");
        assert_eq!(s.value("outcome"), Some("cancelled"), "{s:?}");
        assert_eq!(s.value("error_kind"), None, "{s:?}");
        assert!(s.value("latency_ms").is_some(), "{s:?}");
    }
}
