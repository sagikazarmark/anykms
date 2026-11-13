//! The Azure backend and its credentials over an injected [`ScriptedTransport`]: no network, no
//! reqwest. Managed identity (IMDS and App Service), workload identity and client secret all go
//! through the provider's transport ([`AzureCredential::bind_transport`]); IMDS requests carry
//! the per-request timeout; vault requests carry the configured limit.

use std::path::PathBuf;
use std::time::Duration;

use anykms_azure::{
    AzureCredential, AzureProvider, ClientSecret, ManagedIdentity, StaticToken, WorkloadIdentity,
};
use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck, SignatureAlgorithm};
use anykms_testkit::{Scripted, ScriptedTransport, SeenRequest};
use serde_json::json;

const KEY: &str = "azure-kv://kv1.vault.azure.net/keys/k";
const IMDS_TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn temp_file(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anykms-azure-scripted-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn token_json(t: &str) -> String {
    json!({"token_type": "Bearer", "expires_in": 3599, "access_token": t}).to_string()
}

fn wrap_ok() -> String {
    // A 256-byte "wrapped key" (RSA-2048), base64url without padding.
    let value = "A".repeat(256 * 4 / 3 + 1);
    json!({"kid": "https://kv1.vault.azure.net/keys/k/0123456789abcdef0123456789abcdef", "value": value}).to_string()
}

fn provider(t: &ScriptedTransport, cred: impl AzureCredential + 'static) -> AzureProvider {
    AzureProvider::builder()
        .credential(cred)
        .http_transport(t.clone())
        .max_response_bytes(256 * 1024)
        .build()
        .unwrap()
}

/// Wraps a key with the versionless `wrapkey` (one vault request, no key-bundle read).
async fn wrap(p: &AzureProvider) -> anykms_core::Result<()> {
    p.key_wrap_key(KEY)?
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .wrap_key(&[0u8; 32])
        .await
        .map(drop)
}

fn assert_vault(r: &SeenRequest, token: &str) {
    assert!(
        r.uri
            .starts_with("https://kv1.vault.azure.net/keys/k/wrapkey?"),
        "{r:?}"
    );
    assert_eq!(r.limit, 256 * 1024);
    assert_eq!(r.timeout, None);
    let auth = r.headers.get("authorization").unwrap();
    assert!(auth.is_sensitive());
    assert_eq!(auth, &format!("Bearer {token}"));
}

#[tokio::test]
async fn managed_identity_through_the_injected_transport() {
    // IMDS, system-assigned.
    let t = ScriptedTransport::new();
    t.reply(200, token_json("mi-token")).reply(200, wrap_ok());
    let p = provider(&t, ManagedIdentity::system());
    wrap(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen[0]
            .uri
            .starts_with("http://169.254.169.254/metadata/identity/oauth2/token?"),
        "{:?}",
        seen[0]
    );
    assert!(
        seen[0]
            .uri
            .contains("resource=https%3A%2F%2Fvault.azure.net"),
        "{:?}",
        seen[0]
    );
    assert_eq!(seen[0].headers.get("metadata").unwrap(), "true");
    assert_eq!(seen[0].timeout, Some(IMDS_TIMEOUT));
    assert_eq!(seen[0].limit, 64 * 1024);
    assert_vault(&seen[1], "mi-token");

    // App Service: the identity header is sensitive.
    let t = ScriptedTransport::new();
    t.reply(200, token_json("as-token")).reply(200, wrap_ok());
    let cred = ManagedIdentity::system()
        .app_service("http://127.0.0.1:41000/msi/token", "HEADER-SECRET")
        .unwrap();
    let p = provider(&t, cred);
    wrap(&p).await.unwrap();
    let seen = t.seen();
    assert!(
        seen[0].uri.starts_with("http://127.0.0.1:41000/msi/token?"),
        "{:?}",
        seen[0]
    );
    let h = seen[0].headers.get("x-identity-header").unwrap();
    assert_eq!(h, "HEADER-SECRET");
    assert!(h.is_sensitive());
    assert_vault(&seen[1], "as-token");

    // A transport failure reaching IMDS keeps anykms-http's classification.
    let t = ScriptedTransport::new();
    t.push(Scripted::Fail(
        anykms_azure::anykms_http::SendError::Timeout("t".into()),
    ));
    let e = wrap(&provider(&t, ManagedIdentity::system()))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
}

#[tokio::test]
async fn entra_credentials_through_the_injected_transport() {
    // Client secret.
    let t = ScriptedTransport::new();
    t.reply(200, token_json("cs-token")).reply(200, wrap_ok());
    let p = provider(
        &t,
        ClientSecret::new("my-tenant", "my-client", "S3CRET").unwrap(),
    );
    wrap(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(
        seen[0].uri,
        "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token"
    );
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].timeout, Some(TOKEN_REQUEST_TIMEOUT));
    assert_eq!(seen[0].limit, 64 * 1024);
    let body = String::from_utf8(seen[0].body.clone()).unwrap();
    assert!(body.contains("client_secret=S3CRET"), "{body}");
    assert!(
        body.contains("scope=https%3A%2F%2Fvault.azure.net%2F.default"),
        "{body}"
    );
    assert_vault(&seen[1], "cs-token");

    // Workload identity (federated token file).
    let file = temp_file("federated", "assertion-one\n");
    let t = ScriptedTransport::new();
    t.reply(200, token_json("wi-token")).reply(200, wrap_ok());
    let p = provider(
        &t,
        WorkloadIdentity::new("my-tenant", "my-client", &file).unwrap(),
    );
    wrap(&p).await.unwrap();
    let seen = t.seen();
    let body = String::from_utf8(seen[0].body.clone()).unwrap();
    assert!(body.contains("client_assertion=assertion-one"), "{body}");
    assert_vault(&seen[1], "wi-token");

    // A 503 from the token endpoint is `Unavailable` with its Retry-After.
    let t = ScriptedTransport::new();
    t.push(Scripted::ReplyWith(
        503,
        vec![("Retry-After", "4".into())],
        b"{}".to_vec(),
    ));
    let e = wrap(&provider(&t, ClientSecret::new("t", "c", "s").unwrap()))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(4)));
}

#[tokio::test]
async fn an_oversized_body_from_a_misbehaving_transport_is_rejected() {
    let t = ScriptedTransport::new();
    t.push(Scripted::Oversized(200, vec![b'x'; 256 * 1024 + 1]));
    let e = wrap(&provider(&t, StaticToken::new("tok")))
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("response exceeds the maximum size"),
        "{e}"
    );
}

/// A built-in credential keeps the first transport it is bound to; a clone starts unbound, so it
/// can serve a second provider with another transport.
#[tokio::test]
async fn a_credential_binds_to_its_first_provider_and_a_clone_to_the_next() {
    let cred = ManagedIdentity::system();
    let t1 = ScriptedTransport::new();
    let t2 = ScriptedTransport::new();
    t1.reply(200, token_json("mi-1")).reply(200, wrap_ok());
    t2.reply(200, token_json("mi-2")).reply(200, wrap_ok());
    let p1 = provider(&t1, cred.clone());
    let p2 = provider(&t2, cred.clone());
    wrap(&p1).await.unwrap();
    wrap(&p2).await.unwrap();
    assert_eq!(t1.count(), 2, "{:?}", t1.seen());
    assert_eq!(t2.count(), 2, "{:?}", t2.seen());
    assert_vault(&t1.seen()[1], "mi-1");
    assert_vault(&t2.seen()[1], "mi-2");

    // The same (uncloned) credential in two providers: the first binding wins.
    let shared = std::sync::Arc::new(ManagedIdentity::system());
    let t3 = ScriptedTransport::new();
    let t4 = ScriptedTransport::new();
    // Each provider has its own token cache, so both fetch a token: through t3 both times.
    t3.reply(200, token_json("mi-3"))
        .reply(200, wrap_ok())
        .reply(200, token_json("mi-3b"));
    t4.reply(200, wrap_ok());
    let p3 = AzureProvider::builder()
        .credential_arc(shared.clone())
        .http_transport(t3.clone())
        .max_response_bytes(256 * 1024)
        .build()
        .unwrap();
    let p4 = AzureProvider::builder()
        .credential_arc(shared)
        .http_transport(t4.clone())
        .max_response_bytes(256 * 1024)
        .build()
        .unwrap();
    wrap(&p3).await.unwrap();
    wrap(&p4).await.unwrap();
    assert_eq!(t3.count(), 3, "{:?}", t3.seen());
    assert_eq!(t4.count(), 1, "{:?}", t4.seen());
    assert_vault(&t4.seen()[0], "mi-3b");
}

/// A token fetched before the credential joins a provider (a warm-up) goes through the default
/// transport; binding the provider's transport afterwards still takes effect.
#[tokio::test]
async fn a_default_transport_does_not_block_the_providers_binding() {
    // Standalone: no transport bound, so the default one is built (it is not reachable here, but
    // it must be the one used: the scripted transport sees nothing).
    let cred = ManagedIdentity::system()
        .app_service("http://127.0.0.1:1/msi/token", "h")
        .unwrap();
    let e = cred
        .token("https://vault.azure.net/.default")
        .await
        .unwrap_err();
    assert_ne!(e.kind(), ErrorKind::Configuration, "{e}");
    // Now the provider binds its transport, which replaces the default.
    let t = ScriptedTransport::new();
    t.reply(200, token_json("as-token")).reply(200, wrap_ok());
    let p = provider(&t, cred);
    wrap(&p).await.unwrap();
    assert_eq!(t.count(), 2, "{:?}", t.seen());
}

/// A path's scripted answers: (delay in seconds, status, body).
type Queue = std::collections::VecDeque<(u64, u16, String)>;

/// Answers each request from a per-path queue (the path without the query), after holding it
/// for the answer's delay, and records the path of every request.
#[derive(Default)]
struct Delayed {
    answers: std::sync::Mutex<std::collections::HashMap<&'static str, Queue>>,
    seen: std::sync::Mutex<Vec<String>>,
}

impl Delayed {
    /// Answers the next request for `path` with 200 and `body` after `secs` seconds.
    fn answer(&self, path: &'static str, secs: u64, body: String) -> &Self {
        self.answer_status(path, secs, 200, body)
    }

    /// Answers the next request for `path` with `status` and `body` after `secs` seconds.
    fn answer_status(&self, path: &'static str, secs: u64, status: u16, body: String) -> &Self {
        self.answers
            .lock()
            .unwrap()
            .entry(path)
            .or_default()
            .push_back((secs, status, body));
        self
    }

    fn paths(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl anykms_azure::anykms_http::HttpTransport for Delayed {
    fn send(
        &self,
        req: anykms_azure::anykms_http::transport::Request,
        _limit: usize,
    ) -> anykms_core::BoxFuture<
        '_,
        Result<
            anykms_azure::anykms_http::transport::Response,
            anykms_azure::anykms_http::SendError,
        >,
    > {
        let path = req.uri().path().to_owned();
        self.seen.lock().unwrap().push(path.clone());
        let next = self
            .answers
            .lock()
            .unwrap()
            .get_mut(path.as_str())
            .and_then(std::collections::VecDeque::pop_front);
        Box::pin(async move {
            let (secs, status, body) = next.ok_or_else(|| {
                anykms_azure::anykms_http::SendError::Other(format!("unscripted {path}").into())
            })?;
            tokio::time::sleep(Duration::from_secs(secs)).await;
            let mut r = anykms_azure::anykms_http::http::Response::new(zeroize::Zeroizing::new(
                body.into_bytes(),
            ));
            *r.status_mut() =
                anykms_azure::anykms_http::http::StatusCode::from_u16(status).unwrap();
            r.headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            Ok(r)
        })
    }
}

const KID: &str = "https://kv1.vault.azure.net/keys/k/0123456789abcdef0123456789abcdef";

/// `k` as an RSA-2048 key (after it was recreated).
fn rsa_bundle() -> String {
    use base64::Engine as _;
    let der = anykms_recipes::pem_to_der(include_str!("data/rsa_2048.spki.pem")).unwrap();
    let n = &der[der.len() - 5 - 256..der.len() - 5];
    let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    json!({
        "key": {"kid": KID, "kty": "RSA-HSM", "n": b64u(n), "e": b64u(&[1, 0, 1]),
                "key_ops": ["wrapKey", "unwrapKey"]},
        "attributes": {"enabled": true, "created": 1_700_000_000}
    })
    .to_string()
}

/// `k` as an EC P-256 key (before it was recreated).
fn ec_bundle() -> String {
    json!({
        "key": {"kid": "https://kv1.vault.azure.net/keys/k/fedcba9876543210fedcba9876543210",
                "kty": "EC", "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "key_ops": ["sign", "verify"]},
        "attributes": {"enabled": true, "created": 1_600_000_000}
    })
    .to_string()
}

/// A transport may hold a request for any time after it is handed over, so of two overlapping
/// key reads the one sent first may reach the vault last, after the key was recreated. Neither
/// is trusted over the other: the later-sent read's older bundle does not replace the bundle
/// the earlier-sent one cached, and the next request reads the key again.
#[tokio::test(start_paused = true)]
async fn overlapping_key_reads_that_disagree_are_read_again() {
    let t = std::sync::Arc::new(Delayed::default());
    let versions = || json!({"value": []}).to_string();
    // Sent first, it reaches the vault after the key was recreated.
    t.answer("/keys/k", 5, rsa_bundle())
        // Sent later, it was answered before.
        .answer("/keys/k", 10, ec_bundle())
        .answer("/keys/k", 0, rsa_bundle())
        .answer("/keys/k/versions", 0, versions())
        .answer("/keys/k/versions", 0, versions())
        .answer("/keys/k/wrapkey", 0, wrap_ok());
    let p = AzureProvider::builder()
        .credential(StaticToken::new("tok"))
        .http_transport(t.clone())
        .build()
        .unwrap();
    let kek = p.key_wrap_key(KEY).unwrap();
    let signer = p
        .digest_signing_key(KEY, SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let earlier = tokio::spawn({
        let kek = kek.clone();
        async move { kek.preflight().await }
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    signer.preflight().await.unwrap();
    earlier.await.unwrap().unwrap();
    assert_eq!(t.paths().len(), 4, "{:?}", t.paths());

    kek.wrap_key(&[0u8; 32])
        .await
        .expect("the later-sent read's older bundle was kept");
    assert_eq!(t.paths()[4..], ["/keys/k", "/keys/k/wrapkey"]);
}

/// Dropping one key's cached bundle (a request found that key missing) does not discard a read
/// of another key that was in flight meanwhile: that key's bundle is cached, and its next
/// request reads no key.
#[tokio::test(start_paused = true)]
async fn dropping_one_keys_bundle_keeps_a_concurrent_read_of_another_key() {
    let t = std::sync::Arc::new(Delayed::default());
    t.answer("/keys/k", 5, rsa_bundle())
        .answer("/keys/k/wrapkey", 0, wrap_ok())
        .answer("/keys/k/wrapkey", 0, wrap_ok())
        .answer_status(
            "/keys/b/wrapkey",
            0,
            404,
            json!({"error": {"code": "KeyNotFound", "message": "no key b"}}).to_string(),
        );
    let p = AzureProvider::builder()
        .credential(StaticToken::new("tok"))
        .http_transport(t.clone())
        .build()
        .unwrap();
    let a = p.key_wrap_key(KEY).unwrap();
    let in_flight = tokio::spawn({
        let a = a.clone();
        async move { a.wrap_key(&[0u8; 32]).await.map(drop) }
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(t.paths(), ["/keys/k"]);

    // Key `b` is found missing (and its bundle dropped) while `k`'s read is in flight.
    let e = p
        .key_wrap_key("azure-kv://kv1.vault.azure.net/keys/b")
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .wrap_key(&[0u8; 32])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    in_flight.await.unwrap().unwrap();
    assert_eq!(t.paths().len(), 3, "{:?}", t.paths());

    a.wrap_key(&[0u8; 32]).await.unwrap();
    assert_eq!(
        t.paths()[3..],
        ["/keys/k/wrapkey"],
        "another key's dropped bundle discarded this key's read"
    );
}
