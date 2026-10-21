//! Wiremock tests: the exact request of every operation, response handling, every error-mapping
//! row, transport behavior (redirects, timeouts, oversized and malformed responses), the
//! refresh-once and clock-skew rules, versions, the extension and RSA key wrapping.

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use anykms_aws::{AwsProvider, EncryptionContext, EncryptionContextAead, GrantTokens};
use anykms_core::prelude::*;
use anykms_core::{
    Ciphertext, DataKeySpec, Digest, ErrorKind, KeyTypeCheck, KeyUri, KeyVersion, MacAlgorithm,
    OpenOptions, Preflight, Provider, Registry, RetryLayer, Signature, SignatureAlgorithm, Tag,
    instant_sleep,
};
use serde_json::{Value, json};
use support::*;
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn key(s: &str) -> KeyUri {
    uri(s).parse().unwrap()
}

#[tokio::test]
async fn aead_requests_and_aad_encoding() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(&server, "Encrypt", None, 200, json!({"CiphertextBlob": b64(b"blob"), "KeyId": SYM, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})).await;
    on(
        &server,
        "Decrypt",
        None,
        200,
        json!({"Plaintext": b64(b"pt"), "KeyId": SYM, "KeyMaterialId": "ab"}),
    )
    .await;
    let k = provider(&server).aead_key(uri(SYM)).unwrap();

    let ct = k.encrypt(b"pt", b"users/42").await.unwrap();
    assert_eq!(ct.as_bytes(), b"blob");
    assert_eq!(&*k.decrypt(&ct, b"users/42").await.unwrap(), b"pt");
    k.encrypt(b"pt", b"").await.unwrap();
    k.decrypt(&ct, b"").await.unwrap();
    assert_eq!(k.ciphertext_version(&ct).unwrap(), None);

    let enc = bodies(&server, "Encrypt").await;
    assert_eq!(
        enc[0],
        json!({"KeyId": SYM, "Plaintext": b64(b"pt"), "EncryptionContext": {"associatedData": "75736572732f3432"}})
    );
    // Empty AAD: no EncryptionContext at all.
    assert_eq!(enc[1], json!({"KeyId": SYM, "Plaintext": b64(b"pt")}));
    let dec = bodies(&server, "Decrypt").await;
    // Decrypt always names the key.
    assert_eq!(
        dec[0],
        json!({"KeyId": SYM, "CiphertextBlob": b64(b"blob"), "EncryptionContext": {"associatedData": "75736572732f3432"}})
    );
    assert_eq!(
        dec[1],
        json!({"KeyId": SYM, "CiphertextBlob": b64(b"blob")})
    );
    // One DescribeKey for the key-type check, cached.
    assert_eq!(bodies(&server, "DescribeKey").await.len(), 1);

    // The signed request.
    let reqs = server.received_requests().await.unwrap();
    let r = reqs
        .iter()
        .find(|r| r.headers["x-amz-target"] == "TrentService.Encrypt")
        .unwrap();
    let auth = r.headers["authorization"].to_str().unwrap();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
        "{auth}"
    );
    assert!(auth.contains("/us-east-1/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature="), "{auth}");
    assert_eq!(r.headers["content-type"], "application/x-amz-json-1.1");
    assert!(r.headers.get("x-amz-security-token").is_none());
}

#[tokio::test]
async fn local_limits_send_nothing() {
    let server = MockServer::start().await;
    let p = provider(&server);
    let k = p.aead_key(uri(SYM)).unwrap();
    for (pt, aad) in [
        (&b""[..], &b""[..]),
        (&[0u8; 4097][..], &b""[..]),
        (b"x", &[0u8; 3073][..]),
    ] {
        let e = k.encrypt(pt, aad).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{e}");
        assert_eq!(e.resource(), Some(uri(SYM).as_str()));
    }
    let e = k
        .decrypt(&Ciphertext::from_bytes(vec![]), b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed);
    let e = k
        .decrypt(&Ciphertext::from_bytes(vec![0; 6145]), b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed);
    let ed = p.ed25519_key(uri(ED)).unwrap();
    assert_eq!(
        ed.sign_message(b"").await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        ed.sign_message(&[0; 4097]).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    let mac = p.mac_key(uri(HMAC), MacAlgorithm::HmacSha256).unwrap();
    assert_eq!(
        mac.mac(&[0; 4097]).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        mac.mac(b"").await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    let ds = p
        .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let e = ds.sign_digest(&Digest::sha384(b"m")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert_eq!(count(&server).await, 0);
}

/// The AAD cap is inclusive: exactly `MAX_AAD_BYTES` goes out as a 6144-character context value.
/// It binds the operations that produce a ciphertext; `Decrypt` sends a longer AAD (R-50).
#[tokio::test]
async fn aad_at_the_cap_is_sent() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"KeyId": SYM, "CiphertextBlob": b64(b"blob")}),
    )
    .await;
    on(
        &server,
        "Decrypt",
        None,
        200,
        json!({"Plaintext": b64(b"x"), "KeyId": SYM}),
    )
    .await;
    let k = provider(&server).aead_key(uri(SYM)).unwrap();
    let aad = vec![7u8; anykms_aws::MAX_AAD_BYTES];
    assert_eq!(aad.len(), 3072);
    k.encrypt(b"x", &aad).await.unwrap();
    let enc = bodies(&server, "Encrypt").await;
    assert_eq!(
        enc[0]["EncryptionContext"]["associatedData"],
        json!("07".repeat(3072))
    );
    let over = [7u8; 3073];
    let ct = Ciphertext::from_bytes(b"blob".to_vec());
    let before = count(&server).await;
    for e in [
        k.encrypt(b"x", &over).await.unwrap_err(),
        k.rewrap(&ct, &over).await.unwrap_err(),
        k.generate_data_key(DataKeySpec::Aes256, &over)
            .await
            .unwrap_err(),
        k.generate_wrapped_data_key(DataKeySpec::Aes256, &over)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    }
    assert_eq!(count(&server).await, before);
    // A ciphertext written under a raised cap still decrypts.
    assert_eq!(&*k.decrypt(&ct, &over).await.unwrap(), b"x");
    assert_eq!(
        bodies(&server, "Decrypt").await[0]["EncryptionContext"]["associatedData"],
        json!("07".repeat(3073))
    );
}

#[tokio::test]
async fn rewrap_and_data_keys() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "ReEncrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"new"), "KeyId": SYM, "SourceKeyId": SYM}),
    )
    .await;
    on(
        &server,
        "GenerateDataKey",
        None,
        200,
        json!({"CiphertextBlob": b64(b"wrapped"), "Plaintext": b64([7u8; 32]), "KeyId": SYM}),
    )
    .await;
    on(
        &server,
        "GenerateDataKeyWithoutPlaintext",
        None,
        200,
        json!({"CiphertextBlob": b64(b"wrapped2"), "KeyId": SYM}),
    )
    .await;
    let k = provider(&server).aead_key(uri(SYM)).unwrap();
    let ct = k
        .rewrap(&Ciphertext::from_bytes(b"old".to_vec()), b"a")
        .await
        .unwrap();
    assert_eq!(ct.as_bytes(), b"new");
    assert_eq!(
        bodies(&server, "ReEncrypt").await[0],
        json!({
            "CiphertextBlob": b64(b"old"),
            "SourceKeyId": SYM,
            "DestinationKeyId": SYM,
            "SourceEncryptionContext": {"associatedData": "61"},
            "DestinationEncryptionContext": {"associatedData": "61"},
        })
    );
    let dk = k
        .generate_data_key(DataKeySpec::Aes256, b"a")
        .await
        .unwrap();
    assert_eq!(dk.plaintext(), &[7u8; 32]);
    assert_eq!(dk.ciphertext().as_bytes(), b"wrapped");
    assert_eq!(
        bodies(&server, "GenerateDataKey").await[0],
        json!({"KeyId": SYM, "KeySpec": "AES_256", "EncryptionContext": {"associatedData": "61"}})
    );
    let w = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    assert_eq!(w.as_bytes(), b"wrapped2");
    assert_eq!(
        bodies(&server, "GenerateDataKeyWithoutPlaintext").await[0],
        json!({"KeyId": SYM, "KeySpec": "AES_256"})
    );
}

#[tokio::test]
async fn wrong_data_key_length_is_backend() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "GenerateDataKey",
        None,
        200,
        json!({"CiphertextBlob": b64(b"w"), "Plaintext": b64([7u8; 16]), "KeyId": SYM}),
    )
    .await;
    let k = provider(&server).aead_key(uri(SYM)).unwrap();
    let e = k
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend);
}

#[tokio::test]
async fn key_type_check() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    let p = provider(&server);
    // An ECC key opened as AEAD.
    let e = p
        .aead_key(uri(EC))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    assert_eq!(e.operation(), anykms_core::Operation::Encrypt);
    // A P-256 key opened for RSA-PSS, an HMAC key for another size.
    let e = p
        .digest_signing_key(uri(EC), SignatureAlgorithm::RsaPssSha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"m"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    let e = p
        .mac_key(uri(HMAC), MacAlgorithm::HmacSha512)
        .unwrap()
        .mac(b"m")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    // Ed25519 is message-only.
    let e = p
        .digest_signing_key(uri(ED), SignatureAlgorithm::Ed25519)
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    // Only DescribeKey requests were made.
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.headers["x-amz-target"] == "TrentService.DescribeKey")
    );

    // TrustCaller skips DescribeKey.
    let server = MockServer::start().await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    let k = provider(&server)
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    k.encrypt(b"x", b"").await.unwrap();
    assert_eq!(
        bodies(&server, "DescribeKey").await,
        [] as [serde_json::Value; 0]
    );
}

#[tokio::test]
async fn digest_signing_and_versions() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Sign",
        None,
        200,
        json!({"KeyId": EC, "Signature": b64(b"sig"), "SigningAlgorithm": "ECDSA_SHA_256"}),
    )
    .await;
    on(
        &server,
        "Verify",
        None,
        200,
        json!({"KeyId": EC, "SignatureValid": true, "SigningAlgorithm": "ECDSA_SHA_256"}),
    )
    .await;
    let k = provider(&server)
        .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let d = Digest::sha256(b"msg");
    let sig = k.sign_digest(&d).await.unwrap();
    assert_eq!(sig.as_bytes(), b"sig");
    assert_eq!(sig.key_version().unwrap().as_str(), EC);
    assert_eq!(
        bodies(&server, "Sign").await[0],
        json!({"KeyId": EC, "Message": b64(d.as_bytes()), "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256"})
    );
    k.verify_digest(&d, &sig).await.unwrap();
    assert_eq!(
        bodies(&server, "Verify").await[0],
        json!({"KeyId": EC, "Message": b64(d.as_bytes()), "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256", "Signature": b64(b"sig")})
    );
    let before = count(&server).await;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    // Another key's ARN: VerificationFailed, no request.
    let foreign = Signature::from_parts(alg, Some(KeyVersion::new(OTHER)), b"sig".to_vec());
    assert_eq!(
        k.verify_digest(&d, &foreign).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    // A malformed version, an alias ARN, another algorithm: InvalidArgument, never a URI parse
    // error (A3(c): input versions are not configuration).
    for v in [Some(KeyVersion::new("1")), Some(KeyVersion::new(ALIAS))] {
        let s = Signature::from_parts(alg, v, b"sig".to_vec());
        let e = k.verify_digest(&d, &s).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        assert_eq!(e.operation(), anykms_core::Operation::Verify);
    }
    let s = Signature::from_parts(
        SignatureAlgorithm::RsaPssSha256,
        Some(KeyVersion::new(EC)),
        b"sig".to_vec(),
    );
    assert_eq!(
        k.verify_digest(&d, &s).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(count(&server).await, before);
    // No version: verified with the handle's key.
    let unversioned = Signature::from_parts(alg, None, b"sig".to_vec());
    k.verify_digest(&d, &unversioned).await.unwrap();
    assert_eq!(bodies(&server, "Verify").await[1]["KeyId"], EC);
}

#[tokio::test]
async fn verification_failures() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Verify",
        Some(json!({"Signature": b64(b"bad")})),
        400,
        json!({"__type": "KMSInvalidSignatureException"}),
    )
    .await;
    on(
        &server,
        "Verify",
        Some(json!({"Signature": b64(b"false")})),
        200,
        json!({"KeyId": EC, "SignatureValid": false}),
    )
    .await;
    let k = provider(&server)
        .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let d = Digest::sha256(b"msg");
    for s in [&b"bad"[..], b"false"] {
        let sig = Signature::from_parts(
            SignatureAlgorithm::EcdsaP256Sha256,
            Some(KeyVersion::new(EC)),
            s.to_vec(),
        );
        let e = k.verify_digest(&d, &sig).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{e}");
    }
}

#[tokio::test]
async fn alias_resolution_follows_responses() {
    let server = MockServer::start().await;
    describe(
        &server,
        ALIAS,
        "ECC_NIST_P256",
        "SIGN_VERIFY",
        json!({"Arn": EC, "SigningAlgorithms": ["ECDSA_SHA_256"]}),
    )
    .await;
    on(
        &server,
        "Sign",
        None,
        200,
        json!({"KeyId": OTHER, "Signature": b64(b"sig")}),
    )
    .await;
    on(
        &server,
        "Verify",
        None,
        200,
        json!({"KeyId": OTHER, "SignatureValid": true}),
    )
    .await;
    describe(
        &server,
        EC,
        "ECC_NIST_P256",
        "SIGN_VERIFY",
        json!({"SigningAlgorithms": ["ECDSA_SHA_256"]}),
    )
    .await;
    on(&server, "GetPublicKey", None, 200, json!({"KeyId": EC, "PublicKey": b64(b"spki"), "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"})).await;
    let k = provider(&server)
        .digest_signing_key(uri(ALIAS), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    // public_key_version with the alias target from DescribeKey: the state check describes the
    // key ARN that GetPublicKey then fetches, never the alias again.
    let pk = k.public_key_version(&KeyVersion::new(EC)).await.unwrap();
    assert_eq!(pk.key_version().unwrap().as_str(), EC);
    assert_eq!(bodies(&server, "GetPublicKey").await[0]["KeyId"], EC);
    let described: Vec<Value> = bodies(&server, "DescribeKey").await;
    assert_eq!(described.len(), 2);
    assert_eq!(described[0]["KeyId"], ALIAS);
    assert_eq!(described[1]["KeyId"], EC);
    // public_key: the alias is described (resolving it), and the key it names is fetched.
    let pk = k.public_key().await.unwrap();
    assert_eq!(pk.key_version().unwrap().as_str(), EC);
    assert_eq!(bodies(&server, "DescribeKey").await[2]["KeyId"], ALIAS);
    assert_eq!(bodies(&server, "GetPublicKey").await[1]["KeyId"], EC);
    // The alias was repointed: Sign answers with another key; it becomes the resolved key.
    let d = Digest::sha256(b"m");
    let sig = k.sign_digest(&d).await.unwrap();
    assert_eq!(sig.key_version().unwrap().as_str(), OTHER);
    assert_eq!(bodies(&server, "Sign").await[0]["KeyId"], ALIAS);
    k.verify_digest(&d, &sig).await.unwrap();
    assert_eq!(bodies(&server, "Verify").await[0]["KeyId"], OTHER);
    // The old key's ARN is no longer accepted.
    let old = Signature::from_parts(
        SignatureAlgorithm::EcdsaP256Sha256,
        Some(KeyVersion::new(EC)),
        b"sig".to_vec(),
    );
    assert_eq!(
        k.verify_digest(&d, &old).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
}

#[tokio::test]
async fn a_key_uri_response_naming_another_key_is_backend() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Sign",
        None,
        200,
        json!({"KeyId": OTHER, "Signature": b64(b"sig")}),
    )
    .await;
    let k = provider(&server)
        .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    assert_eq!(
        k.sign_digest(&Digest::sha256(b"m"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Backend
    );
}

/// An alias resolves only to keys of its own partition, region and account: a response naming
/// another account's key is refused, from `DescribeKey` and from a data-plane `KeyId`.
#[tokio::test]
async fn an_alias_response_naming_another_account_is_backend() {
    const FOREIGN: &str =
        "arn:aws:kms:us-east-1:444455556666:key/22222222-2222-2222-2222-222222222222";
    const FOREIGN_REGION: &str =
        "arn:aws:kms:eu-west-1:111122223333:key/22222222-2222-2222-2222-222222222222";
    for arn in [FOREIGN, FOREIGN_REGION] {
        // DescribeKey.
        let server = MockServer::start().await;
        describe(
            &server,
            ALIAS,
            "ECC_NIST_P256",
            "SIGN_VERIFY",
            json!({"Arn": arn, "SigningAlgorithms": ["ECDSA_SHA_256"]}),
        )
        .await;
        let k = provider(&server)
            .digest_signing_key(uri(ALIAS), SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap();
        let e = k.sign_digest(&Digest::sha256(b"m")).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Backend, "{arn}");
        assert_eq!(bodies(&server, "Sign").await.len(), 0);
        // A Sign response under TrustCaller.
        let server = MockServer::start().await;
        on(
            &server,
            "Sign",
            None,
            200,
            json!({"KeyId": arn, "Signature": b64(b"sig")}),
        )
        .await;
        let k = provider(&server)
            .digest_signing_key(uri(ALIAS), SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap()
            .with_key_type_check(anykms_core::KeyTypeCheck::TrustCaller);
        let e = k.sign_digest(&Digest::sha256(b"m")).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Backend, "{arn}");
    }
}

/// Every handle runs its key-type check on demand and returns its AWS metadata.
#[tokio::test]
async fn every_handle_verifies_with_describe() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    let p = provider(&server);
    p.aead_key(uri(SYM)).unwrap().preflight().await.unwrap();
    p.key_wrap_key(uri(RSA_WRAP))
        .unwrap()
        .preflight()
        .await
        .unwrap();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    p.digest_signing_key(uri(EC), alg)
        .unwrap()
        .preflight()
        .await
        .unwrap();
    p.ed25519_key(uri(ED)).unwrap().preflight().await.unwrap();
    let mac = p.mac_key(uri(HMAC), MacAlgorithm::HmacSha256).unwrap();
    mac.preflight().await.unwrap();
    assert_eq!(
        mac.describe()
            .await
            .unwrap()
            .backend_info::<anykms_aws::AwsKeyInfo>()
            .unwrap()
            .clone()
            .arn,
        HMAC
    );
    let e = p.ed25519_key(uri(EC)).unwrap().preflight().await;
    assert_eq!(e.unwrap_err().kind(), ErrorKind::KeyMismatch);
    let e = p.key_wrap_key(uri(EC)).unwrap().preflight().await;
    assert_eq!(e.unwrap_err().kind(), ErrorKind::KeyMismatch);
    let e = p
        .mac_key(uri(HMAC), MacAlgorithm::HmacSha512)
        .unwrap()
        .preflight()
        .await;
    assert_eq!(e.unwrap_err().kind(), ErrorKind::KeyMismatch);
    let e = p
        .digest_signing_key(uri(SYM), alg)
        .unwrap()
        .preflight()
        .await;
    assert_eq!(e.unwrap_err().kind(), ErrorKind::KeyMismatch);
    // Preflight checks the type even under TrustCaller, labelled Describe.
    let e = p
        .key_wrap_key(uri(EC))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .preflight()
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::KeyMismatch, anykms_core::Operation::Describe)
    );
    let e = p
        .digest_signing_key(uri(SYM), alg)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .preflight()
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::KeyMismatch, anykms_core::Operation::Describe)
    );
    let e = p
        .aead(
            &key(EC),
            &OpenOptions::new().with_key_type_check(KeyTypeCheck::TrustCaller),
        )
        .unwrap()
        .preflight()
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::KeyMismatch, anykms_core::Operation::Describe)
    );
}

/// COR-1: preflight refuses a key that is not enabled (a fresh `DescribeKey`), for every typed
/// handle and the opaque handles, under either key-type check, labelled `Describe`.
#[tokio::test]
async fn preflight_refuses_unusable_keys() {
    for (state, kind) in [
        ("Disabled", ErrorKind::KeyStateInvalid),
        ("PendingDeletion", ErrorKind::KeyStateInvalid),
        ("Creating", ErrorKind::Unavailable),
    ] {
        let server = MockServer::start().await;
        describe(
            &server,
            SYM,
            "SYMMETRIC_DEFAULT",
            "ENCRYPT_DECRYPT",
            json!({"EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"], "KeyState": state}),
        )
        .await;
        describe(
            &server,
            RSA_WRAP,
            "RSA_2048",
            "ENCRYPT_DECRYPT",
            json!({"EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"], "KeyState": state}),
        )
        .await;
        describe(
            &server,
            EC,
            "ECC_NIST_P256",
            "SIGN_VERIFY",
            json!({"SigningAlgorithms": ["ECDSA_SHA_256"], "KeyState": state}),
        )
        .await;
        describe(
            &server,
            ED,
            "ECC_NIST_EDWARDS25519",
            "SIGN_VERIFY",
            json!({"SigningAlgorithms": ["ED25519_SHA_512"], "KeyState": state}),
        )
        .await;
        describe(
            &server,
            HMAC,
            "HMAC_256",
            "GENERATE_VERIFY_MAC",
            json!({"MacAlgorithms": ["HMAC_SHA_256"], "KeyState": state}),
        )
        .await;
        let p = provider(&server);
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        for check in [KeyTypeCheck::Describe, KeyTypeCheck::TrustCaller] {
            let opts = OpenOptions::new().with_key_type_check(check);
            let results = [
                p.aead_key(uri(SYM))
                    .unwrap()
                    .with_key_type_check(check)
                    .preflight()
                    .await,
                p.key_wrap_key(uri(RSA_WRAP))
                    .unwrap()
                    .with_key_type_check(check)
                    .preflight()
                    .await,
                p.key_wrap_key(uri(SYM))
                    .unwrap()
                    .with_key_type_check(check)
                    .preflight()
                    .await,
                p.digest_signing_key(uri(EC), alg)
                    .unwrap()
                    .with_key_type_check(check)
                    .preflight()
                    .await,
                p.ed25519_key(uri(ED))
                    .unwrap()
                    .with_key_type_check(check)
                    .preflight()
                    .await,
                p.mac_key(uri(HMAC), MacAlgorithm::HmacSha256)
                    .unwrap()
                    .with_key_type_check(check)
                    .preflight()
                    .await,
                p.aead(&key(SYM), &opts).unwrap().preflight().await,
                p.key_wrap(&key(RSA_WRAP), &opts).unwrap().preflight().await,
                p.digest_signer(&key(EC), alg, &opts)
                    .unwrap()
                    .preflight()
                    .await,
                p.mac(&key(HMAC), MacAlgorithm::HmacSha256, &opts)
                    .unwrap()
                    .preflight()
                    .await,
            ];
            for (i, r) in results.into_iter().enumerate() {
                let e = r.unwrap_err();
                assert_eq!(
                    (e.kind(), e.operation()),
                    (kind, anykms_core::Operation::Describe),
                    "{state} {check:?} #{i}: {e}"
                );
                assert_eq!(e.is_retryable(), kind == ErrorKind::Unavailable, "{state}");
            }
        }
    }
}

/// SEC-1: an RSA KEK checks the key state before every local wrap. AWS serves `GetPublicKey`
/// for a disabled key, so without the check a cold process would wrap to it.
#[tokio::test]
async fn rsa_key_wrap_refuses_unusable_keys() {
    let pk = json!({"KeyId": RSA_WRAP, "PublicKey": RSA_SPKI_B64, "KeySpec": "RSA_2048", "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"]});
    let rsa =
        |state: &str| json!({"EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"], "KeyState": state});

    // (a) Cold: the key is already disabled before the first wrap. No GetPublicKey is sent.
    for (state, kind) in [
        ("Disabled", ErrorKind::KeyStateInvalid),
        ("PendingDeletion", ErrorKind::KeyStateInvalid),
        ("Creating", ErrorKind::Unavailable),
    ] {
        let server = MockServer::start().await;
        describe(&server, RSA_WRAP, "RSA_2048", "ENCRYPT_DECRYPT", rsa(state)).await;
        on(&server, "GetPublicKey", None, 200, pk.clone()).await;
        let p = provider(&server);
        let typed = p.key_wrap_key(uri(RSA_WRAP)).unwrap();
        let opaque = p.key_wrap(&key(RSA_WRAP), &OpenOptions::new()).unwrap();
        for e in [
            typed.wrap_key(&[5u8; 32]).await.unwrap_err(),
            opaque.wrap_key(&[5u8; 32]).await.unwrap_err(),
        ] {
            assert_eq!(
                (e.kind(), e.operation()),
                (kind, anykms_core::Operation::WrapKey),
                "{state}: {e}"
            );
            assert_eq!(e.is_retryable(), kind == ErrorKind::Unavailable, "{state}");
        }
        assert!(bodies(&server, "GetPublicKey").await.is_empty(), "{state}");
        assert!(bodies(&server, "Encrypt").await.is_empty(), "{state}");
    }

    // (b) Warm: a wrap with the key enabled pins its public key; once the key is disabled (or
    // pending deletion) and `describe` refreshes the metadata, the next wrap is refused.
    for state in ["Disabled", "PendingDeletion"] {
        let server = MockServer::start().await;
        describe(
            &server,
            RSA_WRAP,
            "RSA_2048",
            "ENCRYPT_DECRYPT",
            rsa("Enabled"),
        )
        .await;
        on(&server, "GetPublicKey", None, 200, pk.clone()).await;
        let p = provider(&server);
        let kek = p.key_wrap(&key(RSA_WRAP), &OpenOptions::new()).unwrap();
        kek.wrap_key(&[5u8; 32]).await.unwrap();
        server.reset().await;
        describe(&server, RSA_WRAP, "RSA_2048", "ENCRYPT_DECRYPT", rsa(state)).await;
        on(&server, "GetPublicKey", None, 200, pk.clone()).await;
        kek.describe().await.unwrap();
        let e = kek.wrap_key(&[5u8; 32]).await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::KeyStateInvalid, anykms_core::Operation::WrapKey),
            "{state}"
        );
        assert!(e.is_config_error(), "{state}");
        // The typed handle shares the provider's metadata cache.
        let e = p
            .key_wrap_key(uri(RSA_WRAP))
            .unwrap()
            .wrap_key(&[5u8; 32])
            .await;
        assert_eq!(e.unwrap_err().kind(), ErrorKind::KeyStateInvalid, "{state}");
        assert!(bodies(&server, "GetPublicKey").await.is_empty(), "{state}");
    }
}

#[tokio::test]
async fn ed25519_and_rsa_signing() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Sign",
        Some(json!({"KeyId": ED})),
        200,
        json!({"KeyId": ED, "Signature": b64([1u8; 64])}),
    )
    .await;
    on(
        &server,
        "Sign",
        Some(json!({"KeyId": RSA_SIGN})),
        200,
        json!({"KeyId": RSA_SIGN, "Signature": b64([2u8; 256])}),
    )
    .await;
    on(
        &server,
        "Verify",
        None,
        200,
        json!({"KeyId": ED, "SignatureValid": true}),
    )
    .await;
    let p = provider(&server);
    let ed = p.ed25519_key(uri(ED)).unwrap();
    let sig = ed.sign_message(b"hello").await.unwrap();
    assert_eq!(
        bodies(&server, "Sign").await[0],
        json!({"KeyId": ED, "Message": b64(b"hello"), "MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512"})
    );
    ed.verify_message(b"hello", &sig).await.unwrap();
    // Another key's ARN as a public-key version: UnknownKeyVersion before any request.
    let before = count(&server).await;
    assert_eq!(
        ed.public_key_version(&KeyVersion::new(OTHER))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::UnknownKeyVersion
    );
    assert_eq!(count(&server).await, before);
    let rsa = p
        .digest_signing_key(uri(RSA_SIGN), SignatureAlgorithm::RsaPkcs1v15Sha256)
        .unwrap();
    rsa.sign_digest(&Digest::sha256(b"m")).await.unwrap();
    assert_eq!(
        bodies(&server, "Sign").await[1]["SigningAlgorithm"],
        "RSASSA_PKCS1_V1_5_SHA_256"
    );
}

#[tokio::test]
async fn mac_requests() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "GenerateMac",
        None,
        200,
        json!({"KeyId": HMAC, "Mac": b64([9u8; 32]), "MacAlgorithm": "HMAC_SHA_256"}),
    )
    .await;
    on(
        &server,
        "VerifyMac",
        Some(json!({"Mac": b64([9u8; 32])})),
        200,
        json!({"KeyId": HMAC, "MacValid": true}),
    )
    .await;
    on(
        &server,
        "VerifyMac",
        Some(json!({"Mac": b64([8u8; 32])})),
        400,
        json!({"__type": "KMSInvalidMacException", "message": "The MAC is not valid."}),
    )
    .await;
    let k = provider(&server)
        .mac_key(uri(HMAC), MacAlgorithm::HmacSha256)
        .unwrap();
    let tag = k.mac(b"data").await.unwrap();
    assert_eq!(tag.key_version().unwrap().as_str(), HMAC);
    assert_eq!(
        bodies(&server, "GenerateMac").await[0],
        json!({"KeyId": HMAC, "Message": b64(b"data"), "MacAlgorithm": "HMAC_SHA_256"})
    );
    k.verify_mac(b"data", &tag).await.unwrap();
    assert_eq!(
        bodies(&server, "VerifyMac").await[0],
        json!({"KeyId": HMAC, "Message": b64(b"data"), "MacAlgorithm": "HMAC_SHA_256", "Mac": b64([9u8; 32])})
    );
    let bad = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::new(HMAC)),
        vec![8u8; 32],
    );
    let e = k.verify_mac(b"data", &bad).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::VerificationFailed);
    assert_eq!(
        e.detail().unwrap().server_message,
        Some(anykms_core::ServerMessage::Known(
            "The MAC is not valid.".into()
        ))
    );
    let before = count(&server).await;
    let short = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::new(HMAC)),
        vec![9u8; 31],
    );
    assert_eq!(
        k.verify_mac(b"data", &short).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    let foreign = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::new(OTHER)),
        vec![9u8; 32],
    );
    assert_eq!(
        k.verify_mac(b"data", &foreign).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    let malformed = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::new("1")),
        vec![9u8; 32],
    );
    let e = k.verify_mac(b"data", &malformed).await.unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (
            ErrorKind::InvalidArgument,
            anykms_core::Operation::VerifyMac
        )
    );
    assert_eq!(count(&server).await, before);
    let none = Tag::from_parts(MacAlgorithm::HmacSha256, None, vec![9u8; 32]);
    k.verify_mac(b"data", &none).await.unwrap();
}

#[tokio::test]
async fn public_keys_and_describe() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(&server, "GetPublicKey", None, 200, json!({"KeyId": EC, "PublicKey": b64(b"spki"), "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["ECDSA_SHA_256"]})).await;
    let p = provider(&server);
    let k = p
        .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let pk = k.public_key().await.unwrap();
    assert_eq!(pk.spki_der(), b"spki");
    assert_eq!(pk.key_type(), anykms_core::AsymmetricKeyType::EcP256);
    assert_eq!(pk.key_version().unwrap().as_str(), EC);
    // §3.1(f): DescribeKey, uncached, then GetPublicKey, for the same key.
    assert_eq!(bodies(&server, "DescribeKey").await.len(), 1);
    assert_eq!(
        k.public_key_version(&KeyVersion::new(EC)).await.unwrap(),
        pk
    );
    assert_eq!(bodies(&server, "DescribeKey").await.len(), 2);
    assert_eq!(bodies(&server, "GetPublicKey").await.len(), 2);
    for d in bodies(&server, "DescribeKey").await {
        assert_eq!(d["KeyId"], EC);
    }
    let before = count(&server).await;
    assert_eq!(
        k.public_key_version(&KeyVersion::new(OTHER))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::UnknownKeyVersion
    );
    // Malformed: InvalidArgument (labeled PublicKey, never ParseUri).
    for v in ["", "1", "../1", ALIAS] {
        let e = k.public_key_version(&KeyVersion::new(v)).await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (
                ErrorKind::InvalidArgument,
                anykms_core::Operation::PublicKey
            ),
            "{v}"
        );
    }
    assert_eq!(count(&server).await, before);

    let info = k.describe().await.unwrap();
    assert_eq!(info.backend_key_type(), "ECC_NIST_P256");
    assert_eq!(
        info.signature_algorithms(),
        &[SignatureAlgorithm::EcdsaP256Sha256]
    );
    assert_eq!(info.primary_version().unwrap().as_str(), EC);
    let aws = k
        .describe()
        .await
        .unwrap()
        .backend_info::<anykms_aws::AwsKeyInfo>()
        .unwrap()
        .clone();
    assert_eq!(aws.account, ACCOUNT);
    // Describe through the provider never runs the check.
    let d = p.describe(&key(HMAC), &OpenOptions::new()).unwrap();
    assert_eq!(
        d.describe().await.unwrap().mac_algorithm(),
        Some(MacAlgorithm::HmacSha256)
    );
}

#[tokio::test]
async fn rsa_key_wrap() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(&server, "GetPublicKey", None, 200, json!({"KeyId": RSA_WRAP, "PublicKey": RSA_SPKI_B64, "KeySpec": "RSA_2048", "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"]})).await;
    on(
        &server,
        "Decrypt",
        None,
        200,
        json!({"KeyId": RSA_WRAP, "Plaintext": b64([5u8; 32])}),
    )
    .await;
    on(
        &server,
        "ReEncrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"re")}),
    )
    .await;
    let p = provider(&server);
    let kek = p.key_wrap(&key(RSA_WRAP), &OpenOptions::new()).unwrap();
    let wrapped = kek.wrap_key(&[5u8; 32]).await.unwrap();
    assert_eq!(wrapped.len(), 256);
    // Wrapped locally: no Encrypt request; the public key is fetched once.
    kek.wrap_key(&[6u8; 32]).await.unwrap();
    assert_eq!(
        bodies(&server, "Encrypt").await,
        [] as [serde_json::Value; 0]
    );
    assert_eq!(bodies(&server, "GetPublicKey").await.len(), 1);
    // The wrap is real RSA-OAEP-SHA-256 under the key.
    let pk8 = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/rsa-2048.pk8"
    ))
    .unwrap();
    let priv_key = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(&pk8).unwrap();
    let oaep = aws_lc_rs::rsa::OaepPrivateDecryptingKey::new(priv_key).unwrap();
    let mut out = vec![0u8; 256];
    let pt = oaep
        .decrypt(
            &aws_lc_rs::rsa::OAEP_SHA256_MGF1SHA256,
            wrapped.as_bytes(),
            &mut out,
            None,
        )
        .unwrap();
    assert_eq!(pt, &[5u8; 32]);
    // Unwrap through Decrypt with the algorithm.
    assert_eq!(&*kek.unwrap_key(&wrapped).await.unwrap(), &[5u8; 32]);
    // A3(d): key-wrap errors name the key-wrap operations.
    let e = kek
        .unwrap_key(&Ciphertext::from_bytes(Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::DecryptFailed, anykms_core::Operation::UnwrapKey)
    );
    let e = p
        .key_wrap(&key(EC), &OpenOptions::new())
        .unwrap()
        .wrap_key(&[5u8; 32])
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::KeyMismatch, anykms_core::Operation::WrapKey)
    );
    assert_eq!(
        bodies(&server, "Decrypt").await[0],
        json!({"KeyId": RSA_WRAP, "CiphertextBlob": b64(wrapped.as_bytes()), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"})
    );
    kek.rewrap(&wrapped, b"").await.unwrap();
    let re = &bodies(&server, "ReEncrypt").await[0];
    assert_eq!(re["SourceEncryptionAlgorithm"], "RSAES_OAEP_SHA_256");
    assert_eq!(re["DestinationEncryptionAlgorithm"], "RSAES_OAEP_SHA_256");
    assert_eq!(re["DestinationKeyId"], RSA_WRAP);
    assert!(
        kek.describe()
            .await
            .unwrap()
            .capabilities()
            .contains(anykms_core::Capabilities::KEY_WRAP)
    );

    // A symmetric KEK wraps with Encrypt and no context.
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"w")}),
    )
    .await;
    let sym = p.key_wrap(&key(SYM), &OpenOptions::new()).unwrap();
    sym.wrap_key(&[1u8; 32]).await.unwrap();
    assert_eq!(
        bodies(&server, "Encrypt").await[0],
        json!({"KeyId": SYM, "Plaintext": b64([1u8; 32])})
    );
    // A signing key is not a KEK.
    let e = p
        .key_wrap(&key(EC), &OpenOptions::new())
        .unwrap()
        .wrap_key(&[1u8; 32])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    // The opaque handle refuses rewrap AAD.
    assert_eq!(
        sym.rewrap(&wrapped, b"x").await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
}

#[tokio::test]
async fn grant_tokens_go_on_every_request() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    let p = provider(&server);
    let opts = OpenOptions::new().with_extension(GrantTokens::new(["GT1", "GT2"]).unwrap());
    let k = p.aead(&key(SYM), &opts).unwrap();
    k.encrypt(b"x", b"").await.unwrap();
    assert_eq!(
        bodies(&server, "DescribeKey").await[0]["GrantTokens"],
        json!(["GT1", "GT2"])
    );
    assert_eq!(
        bodies(&server, "Encrypt").await[0]["GrantTokens"],
        json!(["GT1", "GT2"])
    );
    assert!(!format!("{opts:?}").contains("GT1"));
}

#[tokio::test]
async fn encryption_context_extension_is_layered() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    // The first Encrypt fails with a retryable error, the second succeeds.
    Mock::given(method("POST"))
        .and(header("x-amz-target", "TrentService.Encrypt"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"__type": "KMSInternalException"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    on(
        &server,
        "Decrypt",
        None,
        200,
        json!({"Plaintext": b64(b"pt")}),
    )
    .await;
    on(
        &server,
        "ReEncrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"c")}),
    )
    .await;
    on(
        &server,
        "GenerateDataKey",
        None,
        200,
        json!({"CiphertextBlob": b64(b"w"), "Plaintext": b64([1u8; 32])}),
    )
    .await;
    let registry = Registry::builder()
        .provider(provider(&server))
        .layer(RetryLayer::new(instant_sleep()))
        .build()
        .unwrap();
    let k = registry.aead(uri(SYM)).unwrap();
    let ctx = EncryptionContext::new().with("tenant", "t1");
    let ct = k.encrypt_with_context(b"pt", &ctx).await.unwrap();
    assert_eq!(
        bodies(&server, "Encrypt").await.len(),
        2,
        "retried by the layer"
    );
    assert_eq!(
        bodies(&server, "Encrypt").await[1]["EncryptionContext"],
        json!({"tenant": "t1"})
    );
    assert_eq!(&*k.decrypt_with_context(&ct, &ctx).await.unwrap(), b"pt");
    let to = EncryptionContext::new().with("tenant", "t2");
    k.rewrap_with_context(&ct, &ctx, &to).await.unwrap();
    let re = &bodies(&server, "ReEncrypt").await[0];
    assert_eq!(re["SourceEncryptionContext"], json!({"tenant": "t1"}));
    assert_eq!(re["DestinationEncryptionContext"], json!({"tenant": "t2"}));
    k.generate_data_key_with_context(DataKeySpec::Aes256, &ctx)
        .await
        .unwrap();
    // The reserved key is refused before any request.
    let before = count(&server).await;
    let bad = EncryptionContext::new().with("associatedData", "x");
    assert_eq!(
        k.encrypt_with_context(b"pt", &bad)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(count(&server).await, before);
    // Through the concrete handle too.
    let concrete = provider(&server).aead_key(uri(SYM)).unwrap();
    concrete.encrypt_with_context(b"pt", &ctx).await.unwrap();
}

/// One row per error-mapping entry of docs/cloud/aws.md §7.
#[tokio::test]
async fn error_mapping_table() {
    let rows: &[(u16, Option<&str>, ErrorKind)] = &[
        (400, Some("NotFoundException"), ErrorKind::NotFound),
        (
            400,
            Some("InvalidCiphertextException"),
            ErrorKind::DecryptFailed,
        ),
        (400, Some("IncorrectKeyException"), ErrorKind::DecryptFailed),
        (
            400,
            Some("KMSInvalidSignatureException"),
            ErrorKind::VerificationFailed,
        ),
        (
            400,
            Some("KMSInvalidMacException"),
            ErrorKind::VerificationFailed,
        ),
        (400, Some("DisabledException"), ErrorKind::KeyStateInvalid),
        (
            400,
            Some("KMSInvalidStateException"),
            ErrorKind::KeyStateInvalid,
        ),
        (500, Some("KeyUnavailableException"), ErrorKind::Unavailable),
        (
            400,
            Some("CustomKeyStoreInvalidStateException"),
            ErrorKind::Unavailable,
        ),
        (
            400,
            Some("XksProxyUriUnreachableException"),
            ErrorKind::Unavailable,
        ),
        (
            400,
            Some("XksProxyInvalidResponseException"),
            ErrorKind::Unavailable,
        ),
        (
            400,
            Some("CloudHsmClusterNotActiveException"),
            ErrorKind::Unavailable,
        ),
        (
            400,
            Some("InvalidKeyUsageException"),
            ErrorKind::KeyMismatch,
        ),
        (400, Some("ValidationException"), ErrorKind::InvalidArgument),
        (400, Some("ValidationError"), ErrorKind::InvalidArgument),
        (
            413,
            Some("RequestEntityTooLargeException"),
            ErrorKind::InvalidArgument,
        ),
        (
            400,
            Some("UnsupportedOperationException"),
            ErrorKind::Unsupported,
        ),
        (
            400,
            Some("InvalidGrantTokenException"),
            ErrorKind::Configuration,
        ),
        (400, Some("InvalidArnException"), ErrorKind::Configuration),
        (
            400,
            Some("UnknownOperationException"),
            ErrorKind::Configuration,
        ),
        (403, Some("OptInRequired"), ErrorKind::Configuration),
        (
            400,
            Some("AccessDeniedException"),
            ErrorKind::PermissionDenied,
        ),
        (
            400,
            Some("UnrecognizedClientException"),
            ErrorKind::Unauthenticated,
        ),
        (
            403,
            Some("InvalidClientTokenId"),
            ErrorKind::Unauthenticated,
        ),
        (
            400,
            Some("ExpiredTokenException"),
            ErrorKind::Unauthenticated,
        ),
        (
            400,
            Some("InvalidSignatureException"),
            ErrorKind::Unauthenticated,
        ),
        (400, Some("IncompleteSignature"), ErrorKind::Unauthenticated),
        (
            403,
            Some("MissingAuthenticationToken"),
            ErrorKind::Unauthenticated,
        ),
        (401, Some("NotAuthorized"), ErrorKind::Unauthenticated),
        (400, Some("ThrottlingException"), ErrorKind::Throttled),
        (400, Some("LimitExceededException"), ErrorKind::Backend),
        (500, Some("KMSInternalException"), ErrorKind::Unavailable),
        (
            500,
            Some("DependencyTimeoutException"),
            ErrorKind::Unavailable,
        ),
        (500, Some("InternalFailure"), ErrorKind::Unavailable),
        (503, Some("ServiceUnavailable"), ErrorKind::Unavailable),
        (408, Some("RequestTimeoutException"), ErrorKind::Unavailable),
        (502, None, ErrorKind::Unavailable),
        (504, None, ErrorKind::Unavailable),
        (403, None, ErrorKind::PermissionDenied),
        (404, None, ErrorKind::NotFound),
        (429, None, ErrorKind::Throttled),
        (400, Some("SomethingNewException"), ErrorKind::Backend),
        (418, None, ErrorKind::Backend),
    ];
    for (status, code, want) in rows {
        let server = MockServer::start().await;
        let mut body = json!({"message": "Key 'arn:aws:kms:SECRETECHO' message"});
        if let Some(c) = code {
            body["__type"] = Value::String(format!("com.amazonaws.kms#{c}"));
        }
        on(&server, "Encrypt", None, *status, body).await;
        let k = provider(&server)
            .aead_key(uri(SYM))
            .unwrap()
            .with_key_type_check(KeyTypeCheck::TrustCaller);
        let e = k.encrypt(b"x", b"").await.unwrap_err();
        assert_eq!(e.kind(), *want, "{status} {code:?}: {e}");
        assert_eq!(e.resource(), Some(uri(SYM).as_str()));
        let d = e.detail().unwrap();
        assert_eq!(d.http_status, Some(*status));
        assert_eq!(d.code(), *code);
        assert_eq!(d.request_id(), Some("req-0001"));
        let all = format!("{e} {e:?}");
        assert!(!all.contains("SECRETECHO"), "{all}");
        if *code == Some("IncorrectKeyException") {
            assert!(e.to_string().contains("EnvelopeKeyring"), "{e}");
        }
    }
}

/// Every error response recorded from real AWS KMS by the A0 probe (us-east-1, 2026-10-07;
/// `scripts/probe-aws.sh`), with the account and key ids rewritten to the fixtures and the request
/// ids replaced. Classification does not depend on the operation, so each body answers `Encrypt`.
#[tokio::test]
async fn recorded_aws_error_responses() {
    use anykms_core::ServerMessage;
    // (probe file, kind, server message kept verbatim)
    let want: &[(&str, ErrorKind, Option<&str>)] = &[
        ("access-denied", ErrorKind::PermissionDenied, None),
        ("clock-skew-30min-behind", ErrorKind::Unavailable, None),
        (
            "context-over-limit",
            ErrorKind::InvalidArgument,
            Some("Invalid EncryptionContext"),
        ),
        (
            "decrypt-other-key",
            ErrorKind::DecryptFailed,
            Some(
                "The key ID in the request does not identify a CMK that can perform this operation.",
            ),
        ),
        ("decrypt-tampered", ErrorKind::DecryptFailed, None),
        ("decrypt-wrong-context", ErrorKind::DecryptFailed, None),
        (
            "encrypt-4097",
            ErrorKind::InvalidArgument,
            Some(
                "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length less than or equal to 4096",
            ),
        ),
        ("encrypt-disabled", ErrorKind::KeyStateInvalid, None),
        (
            "encrypt-empty",
            ErrorKind::InvalidArgument,
            Some(
                "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length greater than or equal to 1",
            ),
        ),
        ("encrypt-pending-deletion", ErrorKind::KeyStateInvalid, None),
        (
            "generate-mac-4097",
            ErrorKind::InvalidArgument,
            Some(
                "1 validation error detected: Value at 'message' failed to satisfy constraint: Member must have length less than or equal to 4096",
            ),
        ),
        (
            "generate-mac-empty",
            ErrorKind::InvalidArgument,
            Some(
                "1 validation error detected: Value at 'message' failed to satisfy constraint: Member must have length greater than or equal to 1",
            ),
        ),
        ("invalid-arn", ErrorKind::Configuration, None),
        ("invalid-key-usage", ErrorKind::KeyMismatch, None),
        (
            "invalid-signature",
            ErrorKind::Unauthenticated,
            Some(
                "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.",
            ),
        ),
        ("malformed-json", ErrorKind::Backend, None),
        ("not-found", ErrorKind::NotFound, None),
        (
            "rsa-with-context",
            ErrorKind::InvalidArgument,
            Some(
                "EncryptionContext is not supported when encrypting/decrypting with asymmetric CMKs.",
            ),
        ),
        ("sign-disabled", ErrorKind::KeyStateInvalid, None),
        (
            "sign-ed25519-raw-4097",
            ErrorKind::InvalidArgument,
            Some(
                "1 validation error detected: Value at 'message' failed to satisfy constraint: Member must have length less than or equal to 4096",
            ),
        ),
        (
            "sign-ed25519-raw-empty",
            ErrorKind::InvalidArgument,
            Some(
                "1 validation error detected: Value at 'message' failed to satisfy constraint: Member must have length greater than or equal to 1",
            ),
        ),
        ("unknown-operation", ErrorKind::Configuration, None),
        (
            "unrecognized-client",
            ErrorKind::Unauthenticated,
            Some("The security token included in the request is invalid."),
        ),
        ("unsupported-operation", ErrorKind::Unsupported, None),
        ("verify-bad-signature", ErrorKind::VerificationFailed, None),
        ("verify-mac-bad", ErrorKind::VerificationFailed, None),
    ];
    let recorded: Vec<Value> =
        serde_json::from_str(include_str!("data/aws-errors-2026-10-07.json")).unwrap();
    assert_eq!(recorded.len(), want.len());
    for r in &recorded {
        let name = r["name"].as_str().unwrap();
        let (_, kind, pinned) = want.iter().find(|w| w.0 == name).expect(name);
        let status = u16::try_from(r["status"].as_u64().unwrap()).unwrap();
        let rid = r["headers"]["x-amzn-requestid"].as_str().unwrap();
        // Real AWS sends no x-amzn-ErrorType header: the type is only in the body.
        assert!(r["headers"].get("x-amzn-errortype").is_none(), "{name}");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("content-type", "application/x-amz-json-1.1")
                    .insert_header("x-amzn-requestid", rid)
                    .set_body_json(&r["body"]),
            )
            .mount(&server)
            .await;
        let k = provider(&server)
            .aead_key(uri(SYM))
            .unwrap()
            .with_key_type_check(KeyTypeCheck::TrustCaller);
        let e = k.encrypt(b"x", b"").await.unwrap_err();
        assert_eq!(e.kind(), *kind, "{name}: {e}");
        let d = e.detail().unwrap();
        assert_eq!(d.http_status, Some(status), "{name}");
        assert_eq!(d.code(), r["body"]["__type"].as_str(), "{name}");
        assert_eq!(d.request_id(), Some(rid), "{name}");
        let message = r["body"]
            .get("message")
            .or_else(|| r["body"].get("Message"))
            .and_then(Value::as_str);
        match (message, pinned) {
            (None, _) => assert_eq!(d.server_message, None, "{name}"),
            (Some(_), Some(p)) => {
                assert_eq!(
                    d.server_message,
                    Some(ServerMessage::Known((*p).into())),
                    "{name}"
                );
            }
            (Some(m), None) => {
                assert!(
                    matches!(d.server_message, Some(ServerMessage::Redacted { .. })),
                    "{name}"
                );
                // Messages that echo ARNs, accounts or timestamps never surface.
                let all = format!("{e} {e:?}");
                assert!(!all.contains(m), "{name}: {all}");
            }
        }
        if name == "decrypt-other-key" {
            assert!(e.to_string().contains("EnvelopeKeyring"), "{e}");
        }
    }
}

#[tokio::test]
async fn error_type_header_wins_and_throttling_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header(
                    "x-amzn-ErrorType",
                    "ThrottlingException:http://internal.amazon.com/coral/com.amazonaws.kms/",
                )
                .insert_header("Retry-After", "3")
                .set_body_string("{}"),
        )
        .mount(&server)
        .await;
    let k = provider(&server)
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Throttled);
    assert_eq!(e.retry_after(), Some(Duration::from_secs(3)));
    assert_eq!(e.detail().unwrap().code(), Some("ThrottlingException"));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let other = MockServer::start().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/", other.uri()).as_str()),
        )
        .mount(&server)
        .await;
    let k = provider(&server)
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert_eq!(count(&other).await, 0);
}

#[tokio::test]
async fn malformed_oversized_and_slow_responses() {
    let server = MockServer::start().await;
    on(&server, "Encrypt", None, 200, json!({"NoBlob": 1})).await;
    on(
        &server,
        "Decrypt",
        None,
        200,
        json!({"Plaintext": "!!!not base64"}),
    )
    .await;
    let k = provider(&server)
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Backend
    );
    let e = k
        .decrypt(&Ciphertext::from_bytes(b"c".to_vec()), b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend);
    assert!(!format!("{e:?}").contains("not base64"));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(64 * 1024 + 1)))
        .mount(&server)
        .await;
    let p = builder(&server)
        .max_response_bytes(64 * 1024)
        .build()
        .unwrap();
    let k = p
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Backend
    );

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let p = builder(&server)
        .request_timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let k = p
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Timeout
    );

    // Nothing listening.
    let p = AwsProvider::builder()
        .endpoint_url("http://127.0.0.1:9")
        .allow_loopback_http()
        .credentials(anykms_aws::credentials::StaticCredentials::new(
            anykms_aws::Credentials::new("A", "S", None),
        ))
        .build()
        .unwrap();
    let k = p
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Unavailable
    );
}

#[tokio::test]
async fn expired_credentials_are_refreshed_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-amz-security-token", "TOKEN1"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"__type": "ExpiredTokenException", "message": "The security token included in the request is expired"})))
        .mount(&server)
        .await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    let src = counting(false);
    let p = builder(&server)
        .credentials_arc(src.clone())
        .build()
        .unwrap();
    let k = p
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    k.encrypt(b"x", b"").await.unwrap();
    assert_eq!(src.fetches.load(Ordering::SeqCst), 2);
    assert_eq!(count(&server).await, 2);
    let reqs = server.received_requests().await.unwrap();
    assert!(
        reqs[1].headers["authorization"]
            .to_str()
            .unwrap()
            .contains("Credential=AKID2/")
    );

    // Credentials that do not change: no retry, Unauthenticated.
    let server = MockServer::start().await;
    on(
        &server,
        "Encrypt",
        None,
        400,
        json!({"__type": "UnrecognizedClientException"}),
    )
    .await;
    let src = counting(true);
    let p = builder(&server)
        .credentials_arc(src.clone())
        .build()
        .unwrap();
    let k = p
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Unauthenticated
    );
    assert_eq!(count(&server).await, 1);
    // Rejected again with new credentials: only one retry.
    let server = MockServer::start().await;
    on(
        &server,
        "Encrypt",
        None,
        400,
        json!({"__type": "ExpiredTokenException"}),
    )
    .await;
    let p = builder(&server)
        .credentials_arc(counting(false))
        .build()
        .unwrap();
    let k = p
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Unauthenticated
    );
    assert_eq!(count(&server).await, 2);
}

#[tokio::test]
async fn clock_skew_is_recorded_and_retryable() {
    let server = MockServer::start().await;
    let ahead = std::time::SystemTime::now() + Duration::from_secs(3600);
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Date", httpdate::fmt_http_date(ahead).as_str())
                .set_body_json(json!({"__type": "InvalidSignatureException", "message": "Signature expired: 20260101T000000Z is now earlier than 20260101T001000Z (20260101T010000Z - 5 min.)"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    let k = provider(&server)
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable);
    assert!(e.is_retryable());
    assert_eq!(count(&server).await, 1, "no retry inside the backend");
    k.encrypt(b"x", b"").await.unwrap();
    let reqs = server.received_requests().await.unwrap();
    let date = reqs[1].headers["x-amz-date"].to_str().unwrap().to_owned();
    let expect = httpdate::fmt_http_date(ahead);
    // The second request is signed with the server's clock (same hour as `ahead`).
    let hour = |d: &str| d[9..11].to_owned();
    let ahead_hour = expect[17..19].to_owned();
    assert_eq!(hour(&date), ahead_hour, "{date} vs {expect}");
}

#[tokio::test]
async fn session_tokens_are_signed() {
    let server = MockServer::start().await;
    on(
        &server,
        "Encrypt",
        None,
        200,
        json!({"CiphertextBlob": b64(b"b")}),
    )
    .await;
    let p = builder(&server)
        .credentials_arc(counting(true))
        .build()
        .unwrap();
    let k = p
        .aead_key(uri(SYM))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    k.encrypt(b"x", b"").await.unwrap();
    let r = &server.received_requests().await.unwrap()[0];
    assert_eq!(r.headers["x-amz-security-token"], "TOKEN1");
    assert!(
        r.headers["authorization"].to_str().unwrap().contains(
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
        )
    );
}

#[tokio::test]
async fn open_policy() {
    let server = MockServer::start().await;
    let p = builder(&server)
        .allowed_accounts(["444455556666"])
        .build()
        .unwrap();
    let e = p.aead_key(uri(SYM)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert_eq!(e.resource(), Some(uri(SYM).as_str()));
    let p = builder(&server)
        .allowed_regions(["eu-west-1"])
        .build()
        .unwrap();
    assert_eq!(
        p.aead_key(uri(SYM)).unwrap_err().kind(),
        ErrorKind::Configuration
    );
    // A3(c): a malformed URI is configuration, labeled ParseUri.
    let e = p.aead_key("aws-kms://alias/x").unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::Configuration, anykms_core::Operation::ParseUri)
    );
    // Derived, per-region and global endpoints.
    let p = AwsProvider::builder()
        .fips(true)
        .endpoint(
            "eu-west-1",
            "https://vpce-1.kms.eu-west-1.vpce.amazonaws.com",
        )
        .build()
        .unwrap();
    assert_eq!(
        p.__endpoint(&uri(SYM)).unwrap(),
        "https://kms-fips.us-east-1.amazonaws.com/"
    );
    assert_eq!(
        p.__endpoint("aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/a")
            .unwrap(),
        "https://vpce-1.kms.eu-west-1.vpce.amazonaws.com/"
    );
    assert_eq!(
        p.aead_key("aws-kms://arn:aws-iso:kms:us-iso-east-1:111122223333:alias/a")
            .unwrap_err()
            .kind(),
        ErrorKind::Configuration
    );
    // http:// needs the opt-in; building does no I/O.
    assert!(
        AwsProvider::builder()
            .endpoint_url("http://127.0.0.1:1")
            .build()
            .is_err()
    );
    assert!(
        AwsProvider::builder()
            .allowed_accounts(["1"])
            .build()
            .is_err()
    );
    // Labels that are not regions never reach endpoint derivation.
    for bad in [
        "aws-kms://arn:aws:kms:s3:111122223333:alias/a",
        "aws-kms://arn:aws:kms:a1:111122223333:alias/a",
    ] {
        assert_eq!(
            p.aead_key(bad).unwrap_err().kind(),
            ErrorKind::Configuration
        );
        assert!(p.__endpoint(bad).is_err());
    }
    assert_eq!(p.schemes(), &[anykms_aws::SCHEME]);
    assert_eq!(p.schemes(), &["aws-kms"]);
    assert_eq!(p.name(), "aws");
}

#[tokio::test]
async fn registry_opens_every_handle_kind() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Sign",
        None,
        200,
        json!({"KeyId": EC, "Signature": b64(b"s")}),
    )
    .await;
    let r = Registry::builder()
        .provider(provider(&server))
        .build()
        .unwrap();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    r.digest_signer(uri(EC), alg)
        .unwrap()
        .sign_digest(&Digest::sha256(b"m"))
        .await
        .unwrap();
    r.digest_verifier(uri(EC), alg).unwrap();
    r.public_keys(uri(EC), alg).unwrap();
    r.message_signer(uri(ED), SignatureAlgorithm::Ed25519)
        .unwrap();
    r.message_verifier(uri(ED), SignatureAlgorithm::Ed25519)
        .unwrap();
    r.mac(uri(HMAC), MacAlgorithm::HmacSha256).unwrap();
    r.data_keys(uri(SYM)).unwrap();
    r.key_wrap(uri(SYM)).unwrap();
    r.describe(uri(SYM)).unwrap();
    let a = r.aead(uri(SYM)).unwrap();
    assert!(a.supports_rewrap() && a.supports_data_keys() && a.supports_wrapped_data_keys());
    assert!(a.downcast_ref::<anykms_aws::AwsAeadKey>().is_some());
    assert_eq!(
        r.digest_signer(uri(ED), SignatureAlgorithm::Ed25519)
            .unwrap_err()
            .kind(),
        ErrorKind::KeyMismatch
    );
}

/// P1-6: every open-time error after the URI is parsed names the key.
#[test]
fn open_errors_name_the_key() {
    let p = AwsProvider::builder()
        .credentials(anykms_aws::credentials::StaticCredentials::new(
            anykms_aws::Credentials::new("a", "s", None),
        ))
        .allowed_accounts(["999999999999"])
        .build()
        .unwrap();
    let opts = OpenOptions::new();
    let ed = SignatureAlgorithm::Ed25519;
    let ec = SignatureAlgorithm::EcdsaP256Sha256;
    let errors = [
        p.digest_signer(&key(ED), ed, &opts).unwrap_err(),
        p.digest_verifier(&key(ED), ed, &opts).unwrap_err(),
        p.message_signer(&key(EC), ec, &opts).unwrap_err(),
        p.message_verifier(&key(EC), ec, &opts).unwrap_err(),
        p.digest_signing_key(uri(EC), ed).unwrap_err(),
        p.aead(&key(SYM), &opts).unwrap_err(),
    ];
    for e in errors {
        let r = e.resource().unwrap_or_else(|| panic!("no resource: {e:?}"));
        assert!(r.starts_with("aws-kms://arn:aws:kms:"), "{r}");
    }
}

/// P1-4: versions from input never drop the cached key metadata. 100 forged versions through
/// verify, `verify_mac` and `public_key_version` cause no `DescribeKey`; the server refusing the
/// handle's own version (from input) does not either, nor does `InvalidArgument`. A `NotFound`
/// for a request of the handle's own key does.
#[tokio::test]
async fn forged_versions_never_drop_cached_metadata() {
    let server = MockServer::start().await;
    describe_all(&server).await;
    let not_found = json!({"__type": "NotFoundException", "message": "Key not found"});
    for target in ["Verify", "GetPublicKey", "VerifyMac"] {
        on(&server, target, None, 400, not_found.clone()).await;
    }
    on(
        &server,
        "Sign",
        None,
        400,
        json!({"__type": "ValidationException", "message": "bad"}),
    )
    .await;
    let p = provider(&server);
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let k = p.digest_signing_key(uri(EC), alg).unwrap();
    let mac = p.mac_key(uri(HMAC), MacAlgorithm::HmacSha256).unwrap();
    let d = Digest::sha256(b"msg");

    // The metadata is cached once per key.
    k.describe().await.unwrap();
    mac.describe().await.unwrap();
    let base = bodies(&server, "DescribeKey").await.len();
    assert_eq!(base, 2);
    for i in 0..100 {
        let forged = KeyVersion::new(format!(
            "arn:aws:kms:us-east-1:{ACCOUNT}:key/00000000-0000-0000-0000-{i:012}"
        ));
        let sig = Signature::from_parts(alg, Some(forged.clone()), b"sig".to_vec());
        assert!(k.verify_digest(&d, &sig).await.is_err());
        assert!(k.public_key_version(&forged).await.is_err());
        let tag = Tag::from_parts(MacAlgorithm::HmacSha256, Some(forged), vec![1; 32]);
        assert!(mac.verify_mac(b"m", &tag).await.is_err());
    }
    assert_eq!(
        bodies(&server, "DescribeKey").await.len(),
        base,
        "a forged version caused a DescribeKey"
    );
    // The handle's own version, from input, refused by the server.
    let own = Signature::from_parts(alg, Some(KeyVersion::new(EC)), b"sig".to_vec());
    assert_eq!(
        k.verify_digest(&d, &own).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        k.public_key_version(&KeyVersion::new(EC))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    let tag = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::new(HMAC)),
        vec![1; 32],
    );
    assert!(mac.verify_mac(b"m", &tag).await.is_err());
    // InvalidArgument from a request for the handle's key.
    assert_eq!(
        k.sign_digest(&d).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    // Only public_key_version(EC)'s own uncached state check (§3.1(f)) described the key: the
    // cached metadata was not dropped (a drop would add a DescribeKey for Sign).
    assert_eq!(
        bodies(&server, "DescribeKey").await.len(),
        base + 1,
        "a version from input dropped the cached metadata"
    );

    // The handle's own key not found: the metadata is dropped and described again.
    assert_eq!(
        k.public_key().await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(bodies(&server, "DescribeKey").await.len(), base + 2);
    assert!(k.sign_digest(&d).await.is_err());
    assert_eq!(bodies(&server, "DescribeKey").await.len(), base + 3);
}

/// §3.1(f): a disabled key's public key is refused although AWS would serve it; transient
/// states are retryable; a refused `DescribeKey` fails closed. No `GetPublicKey` is sent then.
#[tokio::test]
async fn public_keys_of_unusable_keys_are_refused() {
    for (state, kind) in [
        ("Disabled", ErrorKind::KeyStateInvalid),
        ("PendingDeletion", ErrorKind::KeyStateInvalid),
        ("PendingImport", ErrorKind::KeyStateInvalid),
        ("Creating", ErrorKind::Unavailable),
        ("Updating", ErrorKind::Unavailable),
        ("Unavailable", ErrorKind::Unavailable),
    ] {
        let server = MockServer::start().await;
        describe(
            &server,
            EC,
            "ECC_NIST_P256",
            "SIGN_VERIFY",
            json!({"SigningAlgorithms": ["ECDSA_SHA_256"], "KeyState": state}),
        )
        .await;
        on(&server, "GetPublicKey", None, 200, json!({"KeyId": EC, "PublicKey": b64(b"spki"), "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"})).await;
        for check in [KeyTypeCheck::Describe, KeyTypeCheck::TrustCaller] {
            let k = provider(&server)
                .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
                .unwrap()
                .with_key_type_check(check);
            let e = k.public_key().await.unwrap_err();
            assert_eq!(e.kind(), kind, "{state}");
            assert!(
                e.is_retryable() == (kind == ErrorKind::Unavailable),
                "{state}"
            );
            let e = k
                .public_key_version(&KeyVersion::new(EC))
                .await
                .unwrap_err();
            assert_eq!(e.kind(), kind, "{state}");
            if kind == ErrorKind::KeyStateInvalid {
                assert!(e.is_config_error(), "{state}");
            }
        }
        assert!(bodies(&server, "GetPublicKey").await.is_empty(), "{state}");
    }

    // A3(b): a write with the key the handle chose, disabled: KeyStateInvalid, a config error.
    let server = MockServer::start().await;
    describe_all(&server).await;
    on(
        &server,
        "Sign",
        None,
        400,
        json!({"__type": "DisabledException", "message": "disabled"}),
    )
    .await;
    let e = provider(&server)
        .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"m"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
    assert!(e.is_config_error() && !e.is_caller_error());

    // Without kms:DescribeKey the public key is not served (fail closed).
    let server = MockServer::start().await;
    on(
        &server,
        "DescribeKey",
        None,
        400,
        json!({"__type": "AccessDeniedException", "message": "denied"}),
    )
    .await;
    on(&server, "GetPublicKey", None, 200, json!({"KeyId": EC, "PublicKey": b64(b"spki"), "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"})).await;
    let k = provider(&server)
        .digest_signing_key(uri(EC), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.public_key().await.unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        k.public_key_version(&KeyVersion::new(EC))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        bodies(&server, "GetPublicKey").await,
        [] as [serde_json::Value; 0]
    );
}

/// R-34: concurrent first uses of a key, through handles opened separately from one provider,
/// share one `DescribeKey` and its result, a failure included.
#[tokio::test]
async fn concurrent_metadata_misses_share_one_describe_key() {
    let meta = json!({"KeyMetadata": {
        "Arn": SYM, "KeyId": SYM.rsplit('/').next().unwrap(), "AWSAccountId": ACCOUNT,
        "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled",
        "CreationDate": 1_700_000_000.0, "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
    }});
    for (status, body) in [
        (200, meta),
        (500, json!({"__type": "KMSInternalException"})),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("x-amz-target", "TrentService.DescribeKey"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(body)
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&server)
            .await;
        on(&server, "Encrypt", None, 200, json!({"CiphertextBlob": b64(b"blob"), "KeyId": SYM, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})).await;
        let p = provider(&server);
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let k = p.aead_key(uri(SYM)).unwrap();
                tokio::spawn(async move { k.encrypt(b"pt", b"aad").await })
            })
            .collect();
        for t in tasks {
            match t.await.unwrap() {
                Ok(ct) => assert_eq!(ct.as_bytes(), b"blob"),
                Err(e) => {
                    assert_eq!(status, 500);
                    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
                    assert_eq!(e.operation(), anykms_core::Operation::Encrypt);
                    assert_eq!(e.resource(), Some(uri(SYM).as_str()));
                }
            }
        }
        assert_eq!(bodies(&server, "DescribeKey").await.len(), 1, "{status}");
        let encrypts = if status == 200 { 20 } else { 0 };
        assert_eq!(bodies(&server, "Encrypt").await.len(), encrypts);
    }
}

/// R-39: a typed opener's URI parse error names the key (the URI without its query string), as
/// the registry's does.
#[tokio::test]
async fn typed_open_parse_errors_name_the_uri() {
    let server = MockServer::start().await;
    let p = provider(&server);
    let e = p
        .aead_key("aws-kms://arn:aws:kms:us-east-1:111122223333:bucket/k?x=1")
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::Configuration, anykms_core::Operation::ParseUri),
        "{e}"
    );
    assert_eq!(
        e.resource(),
        Some("aws-kms://arn:aws:kms:us-east-1:111122223333:bucket/k")
    );
}
