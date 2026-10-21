//! The AWS backend and its credential sources over an injected [`ScriptedTransport`]: no
//! network, no reqwest. IMDS, the container endpoint and STS web identity all go through the one
//! transport the provider was given; the link-local endpoints carry the short per-request
//! timeout; KMS requests carry the configured response limit.

mod support;

use std::path::PathBuf;
use std::time::Duration;

use anykms_aws::AwsProvider;
use anykms_aws::credentials::{ContainerCredentials, ImdsCredentials, WebIdentityCredentials};
use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck};
use anykms_testkit::{Scripted, ScriptedTransport, SeenRequest};
use serde_json::json;
use support::*;

const FUTURE: &str = "2999-01-01T00:00:00Z";
/// Twice `LOCAL_TIMEOUT` (1 s): the per-request timeout of the link-local credential endpoints.
const LOCAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("anykms-aws-scripted-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn creds_json(key: &str, token: &str) -> String {
    json!({
        "Code": "Success", "AccessKeyId": key, "SecretAccessKey": "S", "Token": token,
        "Expiration": FUTURE
    })
    .to_string()
}

fn encrypt_ok() -> String {
    json!({"CiphertextBlob": b64(b"b")}).to_string()
}

fn provider(
    t: &ScriptedTransport,
    source: impl anykms_aws::CredentialSource + 'static,
) -> AwsProvider {
    AwsProvider::builder()
        .credentials(source)
        .http_transport(t.clone())
        .max_response_bytes(128 * 1024)
        .build()
        .unwrap()
}

async fn encrypt(p: &AwsProvider) -> anykms_core::Result<()> {
    p.aead_key(uri(SYM))?
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"x", b"")
        .await
        .map(drop)
}

/// The KMS request: signed with `key`, carrying `token`, the configured limit, no per-request
/// timeout, to the derived regional endpoint.
fn assert_kms(r: &SeenRequest, key: &str, token: &str) {
    assert_eq!(r.uri, "https://kms.us-east-1.amazonaws.com/", "{r:?}");
    assert_eq!(r.limit, 128 * 1024, "{r:?}");
    assert_eq!(r.timeout, None, "{r:?}");
    assert_eq!(
        r.headers.get("x-amz-target").unwrap(),
        "TrentService.Encrypt"
    );
    let auth = r.headers.get("authorization").unwrap();
    assert!(auth.is_sensitive());
    assert!(
        auth.to_str()
            .unwrap()
            .contains(&format!("Credential={key}/")),
        "{auth:?}"
    );
    assert_eq!(r.headers.get("x-amz-security-token").unwrap(), token);
}

#[tokio::test]
async fn imds_through_the_injected_transport() {
    let t = ScriptedTransport::new();
    t.push(Scripted::Reply(200, b"IMDSTOKEN".to_vec()))
        .push(Scripted::Reply(200, b"my-role\n".to_vec()))
        .reply(200, creds_json("ASIAIMDS", "T-IMDS"))
        .reply(200, encrypt_ok());
    let p = provider(&t, ImdsCredentials::from_env_with(|_| None));
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert_eq!(seen[0].uri, "http://169.254.169.254/latest/api/token");
    assert_eq!(seen[0].method, "PUT");
    assert_eq!(seen[0].limit, 4096);
    assert_eq!(
        seen[1].uri,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    );
    assert_eq!(
        seen[1].headers.get("x-aws-ec2-metadata-token").unwrap(),
        "IMDSTOKEN"
    );
    assert!(
        seen[1]
            .headers
            .get("x-aws-ec2-metadata-token")
            .unwrap()
            .is_sensitive()
    );
    assert_eq!(
        seen[2].uri,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role"
    );
    assert_eq!(seen[2].limit, 64 * 1024);
    for r in &seen[..3] {
        assert_eq!(r.timeout, Some(LOCAL_REQUEST_TIMEOUT), "{r:?}");
    }
    assert_kms(&seen[3], "ASIAIMDS", "T-IMDS");

    // An unreachable metadata service is `Unavailable`, whatever the transport said.
    let t = ScriptedTransport::new();
    t.push(Scripted::Fail(
        anykms_aws::anykms_http::SendError::TlsRejected {
            reason: "TLS certificate rejected: unknown issuer",
            source: "x".into(),
        },
    ));
    let p = provider(&t, ImdsCredentials::from_env_with(|_| None));
    let e = encrypt(&p).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert!(
        e.to_string()
            .contains("instance metadata service unreachable"),
        "{e}"
    );
}

#[tokio::test]
async fn container_endpoint_through_the_injected_transport() {
    let dir = tmp("container");
    let token_file = dir.join("token");
    std::fs::write(&token_file, "PODTOKEN\n").unwrap();
    let tf = token_file.display().to_string();

    // The link-local ECS endpoint: relative URI, fast timeout.
    let t = ScriptedTransport::new();
    t.reply(200, creds_json("ASIAECS", "T-ECS"))
        .reply(200, encrypt_ok());
    let src = ContainerCredentials::from_env_with(|k| {
        (k == "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").then(|| "/v2/credentials/abc".to_owned())
    });
    let p = provider(&t, src);
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].uri, "http://169.254.170.2/v2/credentials/abc");
    assert_eq!(seen[0].timeout, Some(LOCAL_REQUEST_TIMEOUT));
    assert_eq!(seen[0].limit, 64 * 1024);
    assert!(seen[0].headers.get("authorization").is_none());
    assert_kms(&seen[1], "ASIAECS", "T-ECS");

    // An HTTPS endpoint (EKS Pod Identity): the transport's own timeout, the token file's token.
    let t = ScriptedTransport::new();
    t.reply(200, creds_json("ASIAPOD", "T-POD"))
        .reply(200, encrypt_ok());
    let src = ContainerCredentials::from_env_with(move |k| match k {
        "AWS_CONTAINER_CREDENTIALS_FULL_URI" => Some("https://creds.example/creds".to_owned()),
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" => Some(tf.clone()),
        _ => None,
    });
    let p = provider(&t, src);
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen[0].uri, "https://creds.example/creds");
    assert_eq!(seen[0].timeout, None);
    assert_eq!(seen[0].headers.get("authorization").unwrap(), "PODTOKEN");
    assert!(seen[0].headers.get("authorization").unwrap().is_sensitive());
    assert_kms(&seen[1], "ASIAPOD", "T-POD");

    // A refusal is `Unauthenticated`; a transport failure is `Unavailable`.
    let t = ScriptedTransport::new();
    t.reply(401, "{}");
    let src = ContainerCredentials::from_env_with(|k| {
        (k == "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").then(|| "/creds".to_owned())
    });
    let e = encrypt(&provider(&t, src)).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated, "{e}");
    let t = ScriptedTransport::new();
    t.push(Scripted::Fail(anykms_aws::anykms_http::SendError::Other(
        "down".into(),
    )));
    let src = ContainerCredentials::from_env_with(|k| {
        (k == "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").then(|| "/creds".to_owned())
    });
    let e = encrypt(&provider(&t, src)).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert!(
        e.to_string()
            .contains("container credentials endpoint unreachable"),
        "{e}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn sts_web_identity_through_the_injected_transport() {
    let dir = tmp("sts");
    std::fs::write(dir.join("jwt"), "eyJ.WEBID.sig\n").unwrap();
    let t = ScriptedTransport::new();
    t.reply(
        200,
        "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>\
         <AccessKeyId>ASIASTS</AccessKeyId><SecretAccessKey>S</SecretAccessKey>\
         <SessionToken>T-STS</SessionToken><Expiration>2999-01-01T00:00:00Z</Expiration>\
         </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>",
    )
    .reply(200, encrypt_ok());
    let src = WebIdentityCredentials::new(dir.join("jwt"), "arn:aws:iam::111122223333:role/app")
        .region("eu-west-1");
    let p = provider(&t, src);
    encrypt(&p).await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].uri, "https://sts.eu-west-1.amazonaws.com/");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].timeout, None);
    assert_eq!(seen[0].limit, 64 * 1024);
    let body = String::from_utf8(seen[0].body.clone()).unwrap();
    assert!(body.contains("Action=AssumeRoleWithWebIdentity"), "{body}");
    assert!(body.contains("WebIdentityToken=eyJ.WEBID.sig"), "{body}");
    assert_kms(&seen[1], "ASIASTS", "T-STS");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn an_oversized_kms_body_from_a_misbehaving_transport_is_rejected() {
    let t = ScriptedTransport::new();
    t.push(Scripted::Oversized(200, vec![b'x'; 128 * 1024 + 1]));
    let p = provider(
        &t,
        anykms_aws::credentials::StaticCredentials::new(anykms_aws::Credentials::new(
            "AKIA", "S", None,
        )),
    );
    let e = encrypt(&p).await.unwrap_err();
    assert!(
        e.to_string().contains("response exceeds the maximum size"),
        "{e}"
    );
}
