//! Credential sources against mock endpoints: IMDSv2, container (ECS / EKS Pod Identity), STS
//! web identity, static keys in shared profiles, and the default chain, each through a
//! provider so the KMS request shows which credentials were used.

mod support;

use std::path::PathBuf;

use anykms_aws::AwsProvider;
use anykms_aws::credentials::{
    ContainerCredentials, DefaultChain, EnvCredentials, ImdsCredentials, ProfileCredentials,
    WebIdentityCredentials,
};
use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck};
use serde_json::json;
use support::*;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FUTURE: &str = "2999-01-01T00:00:00Z";

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("anykms-aws-creds-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A KMS mock answering Encrypt, and a provider using `source` against it.
async fn kms_with(
    source: impl anykms_aws::CredentialSource + 'static,
) -> (MockServer, AwsProvider) {
    let kms = MockServer::start().await;
    on(
        &kms,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    let p = AwsProvider::builder()
        .credentials(source)
        .endpoint_url(kms.uri())
        .allow_loopback_http()
        .build()
        .unwrap();
    (kms, p)
}

async fn encrypt(p: &AwsProvider) -> anykms_core::Result<()> {
    p.aead_key(uri(SYM))?
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"x", b"")
        .await
        .map(drop)
}

async fn used_key(kms: &MockServer) -> (String, Option<String>) {
    let r = kms.received_requests().await.unwrap().pop().unwrap();
    let auth = r.headers["authorization"].to_str().unwrap().to_owned();
    let akid = auth
        .split("Credential=")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    let tok = r
        .headers
        .get("x-amz-security-token")
        .map(|v| v.to_str().unwrap().to_owned());
    (akid, tok)
}

#[tokio::test]
async fn imds_v2() {
    let imds = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/latest/api/token"))
        .and(header("x-aws-ec2-metadata-token-ttl-seconds", "21600"))
        .respond_with(ResponseTemplate::new(200).set_body_string("IMDSTOKEN"))
        .mount(&imds)
        .await;
    Mock::given(method("GET"))
        .and(path("/latest/meta-data/iam/security-credentials/"))
        .and(header("x-aws-ec2-metadata-token", "IMDSTOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_string("my-role\n"))
        .mount(&imds)
        .await;
    Mock::given(method("GET"))
        .and(path("/latest/meta-data/iam/security-credentials/my-role"))
        .and(header("x-aws-ec2-metadata-token", "IMDSTOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code": "Success", "AccessKeyId": "ASIAIMDS", "SecretAccessKey": "S", "Token": "T-IMDS", "Expiration": FUTURE
        })))
        .mount(&imds)
        .await;
    let (kms, p) = kms_with(ImdsCredentials::from_env_with(|_| None).endpoint(imds.uri())).await;
    encrypt(&p).await.unwrap();
    encrypt(&p).await.unwrap();
    assert_eq!(
        used_key(&kms).await,
        ("ASIAIMDS".into(), Some("T-IMDS".into()))
    );
    // Cached: one token, one role list, one credential fetch.
    assert_eq!(imds.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn imds_without_role_or_endpoint() {
    let imds = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).set_body_string("T"))
        .mount(&imds)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&imds)
        .await;
    let (_, p) = kms_with(ImdsCredentials::from_env_with(|_| None).endpoint(imds.uri())).await;
    assert_eq!(
        encrypt(&p).await.unwrap_err().kind(),
        ErrorKind::Configuration
    );
    // IMDSv1 is never tried: a refused token is not followed by a GET.
    let imds = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&imds)
        .await;
    let (_, p) = kms_with(ImdsCredentials::from_env_with(|_| None).endpoint(imds.uri())).await;
    assert!(encrypt(&p).await.is_err());
    assert_eq!(imds.received_requests().await.unwrap().len(), 1);
    // Unreachable.
    let (_, p) =
        kms_with(ImdsCredentials::from_env_with(|_| None).endpoint("http://127.0.0.1:9")).await;
    let e = encrypt(&p).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
}

#[tokio::test]
async fn container_full_uri_with_token_file() {
    let ep = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/creds"))
        .and(header("authorization", "PODTOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "AccessKeyId": "ASIAPOD", "SecretAccessKey": "S", "Token": "T-POD", "Expiration": FUTURE
        })))
        .mount(&ep)
        .await;
    let dir = tmp("container");
    let token_file = dir.join("token");
    std::fs::write(&token_file, "PODTOKEN\n").unwrap();
    let full = format!("{}/creds", ep.uri());
    let tf = token_file.display().to_string();
    let src = ContainerCredentials::from_env_with(move |k| match k {
        "AWS_CONTAINER_CREDENTIALS_FULL_URI" => Some(full.clone()),
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" => Some(tf.clone()),
        _ => None,
    });
    let (kms, p) = kms_with(src).await;
    encrypt(&p).await.unwrap();
    assert_eq!(
        used_key(&kms).await,
        ("ASIAPOD".into(), Some("T-POD".into()))
    );

    // A wrong token: Unauthenticated.
    let ep2 = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&ep2)
        .await;
    let full = format!("{}/creds", ep2.uri());
    let src = ContainerCredentials::from_env_with(move |k| {
        (k == "AWS_CONTAINER_CREDENTIALS_FULL_URI").then(|| full.clone())
    });
    let (_, p) = kms_with(src).await;
    assert_eq!(
        encrypt(&p).await.unwrap_err().kind(),
        ErrorKind::Unauthenticated
    );
    // A host outside the allowlist: Configuration, no request.
    let src = ContainerCredentials::from_env_with(|k| {
        (k == "AWS_CONTAINER_CREDENTIALS_FULL_URI").then(|| "http://192.0.2.1/creds".to_owned())
    });
    let (_, p) = kms_with(src).await;
    assert_eq!(
        encrypt(&p).await.unwrap_err().kind(),
        ErrorKind::Configuration
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sts_web_identity() {
    let sts = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
        .and(body_string_contains(
            "RoleArn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fapp",
        ))
        .and(body_string_contains("WebIdentityToken=JWT.TOKEN"))
        .and(body_string_contains("RoleSessionName=sess"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>\
             <AccessKeyId>ASIASTS</AccessKeyId><SecretAccessKey>S</SecretAccessKey>\
             <SessionToken>T-STS</SessionToken><Expiration>{FUTURE}</Expiration>\
             </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
        )))
        .mount(&sts)
        .await;
    let dir = tmp("sts");
    std::fs::write(dir.join("jwt"), "JWT.TOKEN\n").unwrap();
    let (tf, ep) = (dir.join("jwt").display().to_string(), sts.uri());
    let src = WebIdentityCredentials::from_env_with(move |k| match k {
        "AWS_WEB_IDENTITY_TOKEN_FILE" => Some(tf.clone()),
        "AWS_ROLE_ARN" => Some("arn:aws:iam::111122223333:role/app".into()),
        "AWS_ROLE_SESSION_NAME" => Some("sess".into()),
        "AWS_ENDPOINT_URL_STS" => Some(ep.clone()),
        _ => None,
    })
    .unwrap();
    let (kms, p) = kms_with(src).await;
    encrypt(&p).await.unwrap();
    assert_eq!(
        used_key(&kms).await,
        ("ASIASTS".into(), Some("T-STS".into()))
    );

    // A rejected token.
    let sts2 = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            "<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>Incorrect token audience</Message></Error></ErrorResponse>",
        ))
        .mount(&sts2)
        .await;
    let src = WebIdentityCredentials::new(dir.join("jwt"), "arn:aws:iam::111122223333:role/app")
        .endpoint(sts2.uri());
    let (_, p) = kms_with(src).await;
    let e = encrypt(&p).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated);
    assert_eq!(e.detail().unwrap().code(), Some("InvalidIdentityToken"));
    // P1-2: a missing token file is a rotation race (`Unavailable`); a directory, an empty
    // file or a non-UTF-8 file is a deployment error (`Configuration`). The message names the
    // file.
    std::fs::create_dir_all(dir.join("adir")).unwrap();
    std::fs::write(dir.join("empty"), b"  \n").unwrap();
    std::fs::write(dir.join("binary"), [0xff, 0xfe]).unwrap();
    for (file, kind) in [
        ("nope", ErrorKind::Unavailable),
        ("adir", ErrorKind::Configuration),
        ("empty", ErrorKind::Configuration),
        ("binary", ErrorKind::Configuration),
    ] {
        let src = WebIdentityCredentials::new(dir.join(file), "arn:aws:iam::111122223333:role/app")
            .endpoint(sts.uri());
        let (_, p) = kms_with(src).await;
        let e = encrypt(&p).await.unwrap_err();
        assert_eq!(e.kind(), kind, "{file}: {e}");
        assert!(e.to_string().contains(file), "{file}: {e}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn profile_static_keys_and_sdk_only_settings() {
    let dir = tmp("profile");
    std::fs::write(
        dir.join("config"),
        "[profile proc]\ncredential_process = /bin/false\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("credentials"),
        "[default]\naws_access_key_id = AKIAFILE\naws_secret_access_key = S\n",
    )
    .unwrap();
    // A profile that needs the AWS SDK fails before any request, naming the feature; the command
    // is never run.
    let src = ProfileCredentials::named("proc")
        .config_file(dir.join("config"))
        .credentials_file(dir.join("credentials"));
    let (kms, p) = kms_with(src).await;
    let e = encrypt(&p).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert!(e.to_string().contains("sdk-credentials"), "{e}");
    assert!(kms.received_requests().await.unwrap().is_empty());
    // The chain: no environment keys, AWS_PROFILE unset, a default profile in the file.
    let (c, cr) = (
        dir.join("config").display().to_string(),
        dir.join("credentials").display().to_string(),
    );
    let chain = DefaultChain::from_env_with(move |k| match k {
        "AWS_CONFIG_FILE" => Some(c.clone()),
        "AWS_SHARED_CREDENTIALS_FILE" => Some(cr.clone()),
        "AWS_EC2_METADATA_DISABLED" => Some("true".into()),
        _ => None,
    });
    let (kms, p) = kms_with(chain).await;
    encrypt(&p).await.unwrap();
    assert_eq!(used_key(&kms).await.0, "AKIAFILE");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn chain_order_and_nothing_found() {
    // Environment keys win.
    let chain = DefaultChain::from_env_with(|k| match k {
        "AWS_ACCESS_KEY_ID" => Some("AKIAENV".into()),
        "AWS_SECRET_ACCESS_KEY" => Some("S".into()),
        "AWS_SESSION_TOKEN" => Some("T-ENV".into()),
        "AWS_ROLE_ARN" => Some("arn:aws:iam::1:role/r".into()),
        _ => None,
    });
    let (kms, p) = kms_with(chain).await;
    encrypt(&p).await.unwrap();
    assert_eq!(
        used_key(&kms).await,
        ("AKIAENV".into(), Some("T-ENV".into()))
    );
    // Nothing configured, IMDS disabled: Configuration, no request anywhere.
    let chain = DefaultChain::from_env_with(|k| match k {
        "AWS_EC2_METADATA_DISABLED" => Some("true".into()),
        "HOME" => Some("/nonexistent-anykms-home".into()),
        _ => None,
    });
    let (kms, p) = kms_with(chain).await;
    let e = encrypt(&p).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert!(e.to_string().contains("no AWS credentials found"), "{e}");
    assert_eq!(kms.received_requests().await.unwrap().len(), 0);
    // IMDS unreachable as the last resort: Configuration as well.
    let chain = DefaultChain::from_env_with(|k| match k {
        "AWS_EC2_METADATA_SERVICE_ENDPOINT" => Some("http://127.0.0.1:9".into()),
        "HOME" => Some("/nonexistent-anykms-home".into()),
        _ => None,
    });
    let (_, p) = kms_with(chain).await;
    assert_eq!(
        encrypt(&p).await.unwrap_err().kind(),
        ErrorKind::Configuration
    );
    // An explicitly named, missing profile is reported, not skipped.
    let chain = DefaultChain::from_env_with(|k| match k {
        "AWS_PROFILE" => Some("missing".into()),
        "HOME" => Some("/nonexistent-anykms-home".into()),
        _ => None,
    });
    let (_, p) = kms_with(chain).await;
    let e = encrypt(&p).await.unwrap_err();
    assert!(e.to_string().contains("\"missing\""), "{e}");
    // Half-set environment keys.
    let (_, p) = kms_with(EnvCredentials::from_env_with(|k| {
        (k == "AWS_ACCESS_KEY_ID").then(|| "A".into())
    }))
    .await;
    assert_eq!(
        encrypt(&p).await.unwrap_err().kind(),
        ErrorKind::Configuration
    );
}

/// `SdkCredentials` maps an AWS SDK credentials provider: its credentials sign the KMS request,
/// its expiry drives the refetch, and its errors keep their kind with no KMS request.
#[cfg(feature = "sdk-credentials")]
mod sdk {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use anykms_aws::credentials::SdkCredentials;
    use aws_credential_types::provider::error::CredentialsError;
    use aws_credential_types::provider::{ProvideCredentials, future};

    use super::*;

    /// What a [`Counting`] provider answers.
    type Make = fn() -> Result<aws_credential_types::Credentials, CredentialsError>;

    /// Answers with `make()`, counting calls.
    #[derive(Debug)]
    struct Counting {
        calls: Arc<AtomicUsize>,
        make: Make,
    }

    impl ProvideCredentials for Counting {
        fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            future::ProvideCredentials::ready((self.make)())
        }
    }

    fn counting(make: Make) -> (SdkCredentials, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let src = SdkCredentials::new(Counting {
            calls: calls.clone(),
            make,
        });
        (src, calls)
    }

    #[tokio::test]
    async fn sdk_credentials_sign_and_are_cached() {
        let (src, calls) = counting(|| {
            Ok(aws_credential_types::Credentials::new(
                "AKIASDK",
                "S",
                Some("T-SDK".into()),
                None,
                "test",
            ))
        });
        let (kms, p) = kms_with(src).await;
        encrypt(&p).await.unwrap();
        encrypt(&p).await.unwrap();
        assert_eq!(
            used_key(&kms).await,
            ("AKIASDK".into(), Some("T-SDK".into()))
        );
        // No expiry: fetched once.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sdk_expiry_drives_the_refetch() {
        let (src, calls) = counting(|| {
            Ok(aws_credential_types::Credentials::new(
                "AKIASDK",
                "S",
                None,
                Some(SystemTime::now() + Duration::from_millis(200)),
                "test",
            ))
        });
        let (_kms, p) = kms_with(src).await;
        encrypt(&p).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        encrypt(&p).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sdk_errors_keep_their_kind() {
        let cases: [(Make, ErrorKind); 4] = [
            (
                || Err(CredentialsError::not_loaded("no profile")),
                ErrorKind::Configuration,
            ),
            (
                || Err(CredentialsError::invalid_configuration("bad")),
                ErrorKind::Configuration,
            ),
            (
                || Err(CredentialsError::provider_timed_out(Duration::from_secs(1))),
                ErrorKind::Timeout,
            ),
            (
                || Err(CredentialsError::provider_error("sts said no")),
                ErrorKind::Unavailable,
            ),
        ];
        for (make, kind) in cases {
            let (src, _) = counting(make);
            let (kms, p) = kms_with(src).await;
            let e = encrypt(&p).await.unwrap_err();
            assert_eq!(e.kind(), kind, "{e}");
            assert!(std::error::Error::source(&e).is_some(), "{e}");
            assert!(kms.received_requests().await.unwrap().is_empty());
        }
    }
}
