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
use anykms_core::{ErrorKind, KeyTypeCheck};
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
