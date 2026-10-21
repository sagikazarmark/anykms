//! The GCP backend and its credential sources over an injected [`ScriptedTransport`]: no
//! network, no reqwest. The metadata server, the OAuth refresh of an `authorized_user`, an
//! `external_account` through STS and impersonation all go through the one transport; metadata
//! requests carry the short per-request timeout; KMS requests carry the configured limit.

mod common;

use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck};
use anykms_gcp::{Credentials, GcpProvider};
use anykms_testkit::{Scripted, ScriptedTransport, SeenRequest};
use base64::Engine as _;
use serde_json::json;

const KEY: &str = "projects/my-project/locations/global/keyRings/r/cryptoKeys/k";
const METADATA_TIMEOUT: Duration = Duration::from_secs(3);

fn crc(data: &[u8]) -> String {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
        }
    }
    (!c).to_string()
}

fn encrypt_ok() -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    json!({
        "name": format!("{KEY}/cryptoKeyVersions/1"),
        "ciphertext": b64.encode(b"ct"),
        "ciphertextCrc32c": crc(b"ct"),
        "verifiedPlaintextCrc32c": true,
    })
    .to_string()
}

fn token_json(t: &str) -> String {
    json!({"access_token": t, "expires_in": 3599, "token_type": "Bearer"}).to_string()
}

fn provider(t: &ScriptedTransport, creds: Credentials) -> GcpProvider {
    GcpProvider::builder()
        .credentials(creds)
        .http_transport(t.clone())
        .max_response_bytes(1024 * 1024)
        .build()
        .unwrap()
}

async fn encrypt(p: &GcpProvider) -> anykms_core::Result<()> {
    p.aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"x", b"")
        .await
        .map(drop)
}

fn assert_kms(r: &SeenRequest, token: &str) {
    assert_eq!(
        r.uri,
        format!("https://cloudkms.googleapis.com/v1/{KEY}:encrypt"),
        "{r:?}"
    );
    assert_eq!(r.limit, 1024 * 1024);
    assert_eq!(r.timeout, None);
    let auth = r.headers.get("authorization").unwrap();
    assert!(auth.is_sensitive());
    assert_eq!(auth, &format!("Bearer {token}"));
}

#[tokio::test]
async fn metadata_server_through_the_injected_transport() {
    let t = ScriptedTransport::new();
    t.push(Scripted::ReplyWith(
        200,
        vec![("Metadata-Flavor", "Google".into())],
        token_json("ya29.meta").into_bytes(),
    ))
    .reply(200, encrypt_ok());
    let p = provider(&t, Credentials::metadata_server());
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(
        seen[0].uri,
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
    );
    assert_eq!(seen[0].headers.get("Metadata-Flavor").unwrap(), "Google");
    assert_eq!(seen[0].timeout, Some(METADATA_TIMEOUT));
    assert_eq!(seen[0].limit, 64 * 1024);
    assert_kms(&seen[1], "ya29.meta");

    // A timeout from the transport is `Timeout`; any other failure `Unavailable`.
    let t = ScriptedTransport::new();
    t.push(Scripted::Fail(anykms_gcp::anykms_http::SendError::Timeout(
        "t".into(),
    )));
    let e = encrypt(&provider(&t, Credentials::metadata_server()))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
    assert!(e.to_string().contains("metadata server"), "{e}");
}

#[tokio::test]
async fn adc_probes_the_metadata_server_with_the_short_timeout() {
    // No ADC file anywhere: the chain probes the metadata server (GET /, Metadata-Flavor).
    let dir = std::env::temp_dir().join(format!("anykms-gcp-scripted-adc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let home = dir.display().to_string();
    let t = ScriptedTransport::new();
    t.push(Scripted::ReplyWith(
        200,
        vec![("Metadata-Flavor", "Google".into())],
        b"computeMetadata/".to_vec(),
    ))
    .push(Scripted::ReplyWith(
        200,
        vec![("Metadata-Flavor", "Google".into())],
        token_json("ya29.adc").into_bytes(),
    ))
    .reply(200, encrypt_ok());
    let p = anykms_gcp::GcpProviderBuilder::from_env_with(move |k| match k {
        "HOME" | "APPDATA" | "CLOUDSDK_CONFIG" => Some(home.clone()),
        _ => None,
    })
    .unwrap()
    .http_transport(t.clone())
    .max_response_bytes(1024 * 1024)
    .build()
    .unwrap();
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].uri, "http://169.254.169.254/");
    assert_eq!(seen[0].timeout, Some(METADATA_TIMEOUT));
    assert_eq!(seen[1].timeout, Some(METADATA_TIMEOUT));
    assert_kms(&seen[2], "ya29.adc");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn authorized_user_refresh_through_the_injected_transport() {
    let t = ScriptedTransport::new();
    t.reply(200, token_json("ya29.user"))
        .reply(200, encrypt_ok());
    let creds = Credentials::from_json(
        json!({"type": "authorized_user", "client_id": "c", "client_secret": "S3CRET",
            "refresh_token": "R3FRESH", "quota_project_id": "qp"})
        .to_string(),
    );
    let p = provider(&t, creds);
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].uri, "https://oauth2.googleapis.com/token");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].timeout, None);
    assert_eq!(seen[0].limit, 64 * 1024);
    let body = String::from_utf8(seen[0].body.clone()).unwrap();
    assert!(body.contains("grant_type=refresh_token"), "{body}");
    assert!(body.contains("refresh_token=R3FRESH"), "{body}");
    assert_kms(&seen[1], "ya29.user");
    assert_eq!(seen[1].headers.get("x-goog-user-project").unwrap(), "qp");
}

#[tokio::test]
async fn external_account_sts_and_impersonation_through_the_injected_transport() {
    let dir = std::env::temp_dir().join(format!("anykms-gcp-scripted-wif-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let subject = dir.join("subject");
    std::fs::write(&subject, "eyJ.subject.token").unwrap();
    let f = json!({
        "type": "external_account",
        "audience": "//iam.googleapis.com/pool",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "service_account_impersonation_url":
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/ci@p.iam.gserviceaccount.com:generateAccessToken",
        "credential_source": {"file": subject},
    });
    let wif = dir.join("wif.json");
    std::fs::write(&wif, f.to_string()).unwrap();

    let t = ScriptedTransport::new();
    t.reply(200, token_json("ya29.federated"))
        .reply(
            200,
            json!({"accessToken": "ya29.sa", "expireTime": "2099-01-01T00:00:00Z"}).to_string(),
        )
        .reply(200, encrypt_ok());
    let p = provider(&t, Credentials::external_account_file(&wif));
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].uri, "https://sts.googleapis.com/v1/token");
    let body = String::from_utf8(seen[0].body.clone()).unwrap();
    assert!(body.contains("subject_token=eyJ.subject.token"), "{body}");
    assert_eq!(
        seen[1].uri,
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/ci@p.iam.gserviceaccount.com:generateAccessToken"
    );
    assert_eq!(
        seen[1].headers.get("authorization").unwrap(),
        "Bearer ya29.federated"
    );
    assert!(seen[1].headers.get("authorization").unwrap().is_sensitive());
    for r in &seen[..2] {
        assert_eq!(r.timeout, None, "{r:?}");
        assert_eq!(r.limit, 64 * 1024, "{r:?}");
    }
    assert_kms(&seen[2], "ya29.sa");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn impersonated_credentials_through_the_injected_transport() {
    let t = ScriptedTransport::new();
    t.reply(
        200,
        json!({"accessToken": "ya29.imp", "expireTime": "2099-01-01T00:00:00Z"}).to_string(),
    )
    .reply(200, encrypt_ok());
    let p = provider(
        &t,
        Credentials::impersonated(
            Credentials::static_token("ya29.src"),
            "a@p.iam.gserviceaccount.com",
        ),
    );
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(
        seen[0].uri,
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a@p.iam.gserviceaccount.com:generateAccessToken"
    );
    assert_eq!(
        seen[0].headers.get("authorization").unwrap(),
        "Bearer ya29.src"
    );
    assert_kms(&seen[1], "ya29.imp");
}

#[tokio::test]
async fn an_oversized_body_from_a_misbehaving_transport_is_rejected() {
    let t = ScriptedTransport::new();
    t.push(Scripted::Oversized(200, vec![b'x'; 1024 * 1024 + 1]));
    let p = provider(&t, Credentials::static_token("ya29.x"));
    let e = encrypt(&p).await.unwrap_err();
    assert!(
        e.to_string().contains("response exceeds the maximum size"),
        "{e}"
    );
}
