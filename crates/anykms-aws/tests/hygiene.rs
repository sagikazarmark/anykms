//! Captures every log line at TRACE (reqwest, hyper and rustls included) while running operations
//! whose requests and responses carry marker secrets, and asserts the markers never appear in logs
//! or errors (`Display`, `Debug`, every `source()`).
//!
//! Markers: plaintext, AAD and its hex, a native context value, a data key, messages and
//! MAC input, the secret access key, session tokens (static and refreshed), a grant token and a
//! web identity token. Covered: every operation, server errors echoing input, the refresh-once
//! retry, STS web identity, an undecodable response, a transport error and (feature
//! `sdk-credentials`) credentials from an AWS SDK provider, failing ones included. It also pins the span
//! schema shared by the HTTP backends (D3, through `anykms-testkit`): the request span
//! `anykms.aws` and the credential span `anykms.aws.token` declare exactly the shared fields, and
//! no other `anykms.aws.*` span exists. A second test formats every public configuration and
//! credential type (P1-1). Run with `--features tracing`.
//!
//! The capture is the thread's subscriber (`anykms_testkit::capture`); this binary installs no
//! global subscriber.

#![cfg(feature = "tracing")]

mod support;

use std::fmt::Write as _;

use anykms_aws::credentials::{SourceContext, WebIdentityCredentials};
use anykms_aws::{
    AwsProvider, CredentialSource, Credentials, EncryptionContext, EncryptionContextAead,
    GrantTokens,
};
use anykms_core::prelude::*;
use anykms_core::{
    BoxFuture, Ciphertext, DataKeySpec, Digest, KeyUri, KeyVersion, MacAlgorithm, OpenOptions,
    Provider, SignatureAlgorithm, Tag,
};
use serde_json::json;
use support::*;
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PT: &str = "HYGIENEPLAINTEXT0123456789";
const AAD: &str = "HYGIENEAAD0123456789";
const CTX: &str = "HYGIENECTXVALUE0123456789";
const DEK: &[u8; 32] = b"HYGIENEDATAKEY0123456789abcdefgh";
const MSG: &str = "HYGIENEMESSAGE0123456789";
const SECRET: &str = "HYGIENESECRETKEY0123456789";
const TOKEN: &str = "HYGIENESESSIONTOKEN0123456789";
const NEW_TOKEN: &str = "HYGIENENEWTOKEN0123456789";
const GRANT: &str = "HYGIENEGRANTTOKEN0123456789";
const JWT: &str = "HYGIENEJWT0123456789";

fn markers() -> Vec<String> {
    use base64::Engine as _;
    let std = base64::engine::general_purpose::STANDARD;
    vec![
        PT.into(),
        AAD.into(),
        AAD.bytes().fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        }),
        std.encode(PT),
        CTX.into(),
        String::from_utf8(DEK.to_vec()).unwrap(),
        std.encode(DEK),
        MSG.into(),
        std.encode(MSG),
        SECRET.into(),
        TOKEN.into(),
        NEW_TOKEN.into(),
        GRANT.into(),
        JWT.into(),
    ]
}

fn render(e: &anykms_core::Error) -> String {
    let mut out = format!("{e}\n{e:?}\n");
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        writeln!(out, "{s}\n{s:?}").unwrap();
        src = s.source();
    }
    out
}

/// Hands out `TOKEN` until invalidated by a rejection, then `NEW_TOKEN`.
#[derive(Debug, Default)]
struct Rotating(std::sync::atomic::AtomicUsize);

impl CredentialSource for Rotating {
    fn kind(&self) -> &'static str {
        "rotating"
    }
    fn credentials<'a>(
        &'a self,
        _: &'a SourceContext,
    ) -> BoxFuture<'a, anykms_core::Result<Credentials>> {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let t = if n == 0 { TOKEN } else { NEW_TOKEN };
        Box::pin(async move {
            Ok(Credentials::new(
                format!("AKIA{n}"),
                SECRET,
                Some(t.to_owned()),
            ))
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn trace_output_and_errors_never_contain_secrets() {
    let capture = anykms_testkit::capture();

    let server = MockServer::start().await;
    describe_all(&server).await;
    use base64::Engine as _;
    let std = base64::engine::general_purpose::STANDARD;
    // The first request with the original token is rejected (refresh-once path).
    Mock::given(method("POST"))
        .and(header("x-amz-security-token", TOKEN))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            json!({"__type": "ExpiredTokenException", "message": format!("token {TOKEN} expired")}),
        ))
        .mount(&server)
        .await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"blob")}),
    )
    .await;
    on(
        &server,
        "Decrypt",
        None,
        200,
        json!({"Plaintext": std.encode(PT)}),
    )
    .await;
    // ReEncrypt fails echoing the input.
    on(
        &server,
        "ReEncrypt",
        None,
        400,
        json!({"__type": "InvalidCiphertextException", "message": format!("bad {PT} {AAD} {CTX}")}),
    )
    .await;
    on(
        &server,
        "GenerateDataKey",
        None,
        200,
        json!({"CiphertextBlob": b64(b"w"), "Plaintext": std.encode(DEK)}),
    )
    .await;
    on(
        &server,
        "Sign",
        None,
        200,
        json!({"KeyId": EC, "Signature": b64(b"sig")}),
    )
    .await;
    on(
        &server,
        "Verify",
        None,
        400,
        json!({"__type": "KMSInvalidSignatureException", "message": MSG}),
    )
    .await;
    on(
        &server,
        "GenerateMac",
        None,
        200,
        json!({"KeyId": HMAC, "Mac": b64([1u8; 32])}),
    )
    .await;
    on(
        &server,
        "VerifyMac",
        None,
        200,
        json!({"KeyId": HMAC, "MacValid": false}),
    )
    .await;

    let p = builder(&server)
        .credentials(Rotating::default())
        .build()
        .unwrap();
    let opts = OpenOptions::new().with_extension(GrantTokens::new([GRANT]).unwrap());
    let key = |a: &str| -> KeyUri { uri(a).parse().unwrap() };
    let mut errors = Vec::new();

    let aead = p.aead(&key(SYM), &opts).unwrap();
    let ct = aead.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap();
    aead.decrypt(&ct, AAD.as_bytes()).await.unwrap();
    errors.push(aead.rewrap(&ct, AAD.as_bytes()).await.unwrap_err());
    aead.generate_data_key(DataKeySpec::Aes256, AAD.as_bytes())
        .await
        .unwrap();
    let ctx = EncryptionContext::new().with("tenant", CTX);
    aead.encrypt_with_context(PT.as_bytes(), &ctx)
        .await
        .unwrap();
    errors.push(aead.rewrap_with_context(&ct, &ctx, &ctx).await.unwrap_err());
    errors.push(aead.encrypt(&[0; 4097], AAD.as_bytes()).await.unwrap_err());

    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let s = p.digest_signer(&key(EC), alg, &opts).unwrap();
    let d = Digest::sha256(MSG.as_bytes());
    let sig = s.sign_digest(&d).await.unwrap();
    errors.push(s.verify_digest(&d, &sig).await.unwrap_err());
    let mac = p.mac(&key(HMAC), MacAlgorithm::HmacSha256, &opts).unwrap();
    let tag = mac.mac(MSG.as_bytes()).await.unwrap();
    errors.push(mac.verify_mac(MSG.as_bytes(), &tag).await.unwrap_err());
    let foreign = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::new(OTHER)),
        vec![1u8; 32],
    );
    errors.push(mac.verify_mac(MSG.as_bytes(), &foreign).await.unwrap_err());

    // Undecodable and transport failures.
    let bad = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("{{\"Plaintext\": \"{PT}!!\"}}")),
        )
        .mount(&bad)
        .await;
    let pb = builder(&bad).build().unwrap();
    let k = pb
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(anykms_core::KeyTypeCheck::TrustCaller);
    errors.push(
        k.decrypt(&Ciphertext::from_bytes(b"c".to_vec()), AAD.as_bytes())
            .await
            .unwrap_err(),
    );
    let down = AwsProvider::builder()
        .endpoint_url("http://127.0.0.1:9")
        .allow_loopback_http()
        .credentials(Rotating::default())
        .build()
        .unwrap();
    let k = down
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(anykms_core::KeyTypeCheck::TrustCaller);
    errors.push(k.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap_err());

    // STS web identity, rejected with the token echoed.
    let sts = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_string(format!(
            "<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>{JWT}</Message></Error></ErrorResponse>"
        )))
        .mount(&sts)
        .await;
    let dir = std::env::temp_dir().join(format!("anykms-aws-hygiene-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("jwt"), JWT).unwrap();
    let wi = builder(&server)
        .credentials(
            WebIdentityCredentials::new(dir.join("jwt"), "arn:aws:iam::111122223333:role/r")
                .endpoint(sts.uri()),
        )
        .build()
        .unwrap();
    let k = wi.aead_key(uri(SYM)).unwrap();
    errors.push(k.encrypt(PT.as_bytes(), b"").await.unwrap_err());
    std::fs::remove_dir_all(&dir).unwrap();

    let mut all = capture.text();
    assert!(all.contains("anykms.aws"), "spans were not recorded");
    assert!(all.contains("request_id"), "{all}");
    assert!(all.contains("resource=\"aws-kms://arn:"), "{all}");
    assert!(
        all.contains("code=\"KMSInvalidSignatureException\""),
        "{all}"
    );
    assert!(all.contains(&format!("key_version=\"{EC}\"")), "{all}");
    // The span schema shared by the HTTP backends (D3), exactly.
    anykms_testkit::assert_request_schema(capture.spans(), "aws");
    anykms_testkit::assert_token_schema(capture.spans(), "aws");
    // A successful request records its request id (P1-9 filter).
    let ok = capture
        .spans()
        .named("anykms.aws")
        .into_iter()
        .find(|s| s.value("outcome") == Some("ok") && s.value("op") == Some("encrypt"))
        .expect("a successful encrypt span");
    assert!(ok.value("request_id").is_some(), "{ok:?}");
    assert_eq!(ok.value("http_status"), Some("200"), "{ok:?}");
    for e in &errors {
        all.push_str(&render(e));
        if let Some(r) = e.resource() {
            assert!(r.starts_with("aws-kms://arn:"), "{r}");
        }
    }
    writeln!(all, "{p:?}\n{opts:?}\n{aead:?}\n{s:?}\n{mac:?}\n{ctx:?}").unwrap();
    for m in markers() {
        assert!(!all.contains(&m), "marker {m} leaked:\n{all}");
    }
}

/// P1-1: no public configuration, builder or credential type prints a proxy's userinfo, a
/// secret access key, a session token, or anything but the origin of a configured URL.
#[test]
fn debug_output_redacts_proxies_secrets_and_tokens() {
    use anykms_aws::AwsProviderBuilder;
    use anykms_aws::anykms_http::ReqwestTransport;
    use anykms_aws::credentials::{
        ContainerCredentials, DefaultChain, EnvCredentials, ImdsCredentials, ProfileCredentials,
        StaticCredentials,
    };
    const USER: &str = "PROXYUSER";
    const PASS: &str = "PROXYPASS";
    const QUERY: &str = "URLQUERYSECRET";
    let with_userinfo = |host: &str| format!("https://{USER}:{PASS}@{host}/p?q={QUERY}");
    // Proxies live on the transport: its builder redacts the URL's userinfo and query.
    let proxy = || {
        ReqwestTransport::builder().proxy(Some(format!(
            "http://{USER}:{PASS}@proxy.example:3128/?t={QUERY}"
        )))
    };
    let transport = || proxy().require_roots(false).build().unwrap();
    let secrets = [USER, PASS, QUERY, SECRET, TOKEN, JWT, GRANT];
    let env = |k: &str| -> Option<String> {
        match k {
            "AWS_ACCESS_KEY_ID" => Some("AKIAHYGIENE".into()),
            "AWS_SECRET_ACCESS_KEY" => Some(SECRET.into()),
            "AWS_SESSION_TOKEN" => Some(TOKEN.into()),
            "AWS_CONTAINER_CREDENTIALS_FULL_URI" => Some("https://creds.example/x".into()),
            "AWS_CONTAINER_AUTHORIZATION_TOKEN" => Some(JWT.into()),
            "AWS_ENDPOINT_URL_KMS" => Some("https://kms.example/".into()),
            _ => None,
        }
    };
    let creds = || Credentials::new("AKIAHYGIENE", SECRET, Some(TOKEN.into()));
    let check = |v: &dyn std::fmt::Debug| anykms_testkit::assert_debug_redacts(v, &secrets);

    check(&proxy());
    check(&transport());
    check(
        &AwsProvider::builder()
            .http_transport(transport())
            .endpoint("eu-west-1", with_userinfo("vpce.example"))
            .endpoint_url(with_userinfo("kms.example"))
            .credentials(StaticCredentials::new(creds())),
    );
    let from_env = AwsProviderBuilder::from_env_with(env).unwrap();
    check(&from_env);
    check(&from_env.http_transport(transport()).build().unwrap());
    check(
        &AwsProvider::builder()
            .http_transport(transport())
            .endpoint_url("https://kms.example/base")
            .credentials(StaticCredentials::new(creds()))
            .build()
            .unwrap(),
    );
    check(&creds());
    check(&StaticCredentials::new(creds()));
    check(&EnvCredentials::from_env_with(env));
    check(&DefaultChain::from_env_with(env));
    check(&ContainerCredentials::from_env_with(env));
    check(&ProfileCredentials::from_env_with(env));
    #[cfg(feature = "sdk-credentials")]
    check(&anykms_aws::credentials::SdkCredentials::new(
        aws_credential_types::Credentials::new(
            "AKIDHYGIENE",
            SECRET,
            Some(TOKEN.into()),
            None,
            "test",
        ),
    ));
    check(
        &ImdsCredentials::from_env_with(env)
            .endpoint(format!("http://{USER}:{PASS}@169.254.169.254/?q={QUERY}")),
    );
    check(
        &WebIdentityCredentials::new("/var/run/token", "arn:aws:iam::111122223333:role/r")
            .endpoint(with_userinfo("sts.example")),
    );
    check(&GrantTokens::new([GRANT]).unwrap());
}

/// The `sdk-credentials` bridge at TRACE: credentials from an AWS SDK provider (marker secret and
/// session token) sign real requests, and a failing SDK provider's error is rendered with its
/// source chain; neither the logs nor the errors contain the markers. The credential fetch runs
/// inside the shared token span.
#[cfg(feature = "sdk-credentials")]
#[tokio::test(flavor = "current_thread")]
async fn sdk_credentials_never_appear_in_trace_output_or_errors() {
    use anykms_aws::credentials::SdkCredentials;
    use anykms_core::KeyTypeCheck;
    use aws_credential_types::provider::error::CredentialsError;
    use aws_credential_types::provider::{ProvideCredentials, future};

    const SDK_SECRET: &str = "HYGIENESDKSECRET0123456789";
    const SDK_TOKEN: &str = "HYGIENESDKTOKEN0123456789";

    #[derive(Debug)]
    struct Failing;
    impl ProvideCredentials for Failing {
        fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            future::ProvideCredentials::ready(Err(CredentialsError::provider_error(
                "the role cannot be assumed",
            )))
        }
    }

    let capture = anykms_testkit::capture();
    let server = MockServer::start().await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    let provider = |src: SdkCredentials| {
        AwsProvider::builder()
            .credentials(src)
            .endpoint_url(server.uri())
            .allow_loopback_http()
            .build()
            .unwrap()
    };
    let ok = provider(SdkCredentials::new(aws_credential_types::Credentials::new(
        "AKIASDKHYGIENE",
        SDK_SECRET,
        Some(SDK_TOKEN.into()),
        None,
        "test",
    )));
    let k = ok
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    for _ in 0..2 {
        k.encrypt(PT.as_bytes(), b"").await.unwrap();
    }
    let failing = provider(SdkCredentials::new(Failing));
    let e = failing
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(PT.as_bytes(), b"")
        .await
        .unwrap_err();

    // The SDK's credentials did sign the requests.
    let sent = server.received_requests().await.unwrap();
    assert_eq!(sent.len(), 2);
    for r in &sent {
        assert_eq!(r.headers["x-amz-security-token"], SDK_TOKEN);
    }
    assert_eq!(e.kind(), anykms_core::ErrorKind::Unavailable, "{e}");

    let mut all = capture.text();
    assert!(all.contains("anykms.aws"), "spans were not recorded");
    anykms_testkit::assert_token_schema(capture.spans(), "aws");
    all.push_str(&render(&e));
    writeln!(all, "{ok:?}\n{k:?}\n{failing:?}").unwrap();
    for m in [SDK_SECRET, SDK_TOKEN, PT] {
        assert!(!all.contains(m), "marker {m} leaked:\n{all}");
    }
}
