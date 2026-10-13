//! End to end against the in-process fake Cloud KMS server (`tests/common/fake.rs`): real request
//! and response shapes, CRC32C fields, real crypto. Open → encrypt → decrypt → sign → verify →
//! MAC, rotation, version states, key-type checks, RSA key wrapping, describe, error paths and
//! every credential type that can run without Google.

mod common;

use std::sync::Arc;

use anykms_core::prelude::*;
use anykms_core::{
    Capabilities, Ciphertext, DataKeySpec, Digest, ErrorKind, KeyTypeCheck, KeyUri, KeyVersion,
    MacAlgorithm, OpenOptions, Preflight, Provider, Registry, Signature, SignatureAlgorithm, Tag,
};
use anykms_gcp::{AuthEndpoints, Credentials, GcpProvider};
use common::fake::{self, FakeKms};
use common::{provider, uri, vuri};

fn key_uri(s: &str) -> KeyUri {
    s.parse().unwrap()
}

#[tokio::test]
async fn aead_roundtrip_rotation_and_used_primary() {
    let fake = FakeKms::start().await;
    let name = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let p = provider(&fake);
    let k = p.aead_key(uri(&name)).unwrap();
    for (pt, aad) in [
        (&b"hello"[..], &b""[..]),
        (b"x", b"users/42"),
        (&[7u8; 65536], b"a"),
    ] {
        let ct = k.encrypt(pt, aad).await.unwrap();
        assert_eq!(&*k.decrypt(&ct, aad).await.unwrap(), pt);
        assert_eq!(k.ciphertext_version(&ct).unwrap(), None);
    }
    let ct = k.encrypt(b"secret", b"ctx").await.unwrap();
    // Wrong AAD, tampering, truncation: DecryptFailed.
    let e = k.decrypt(&ct, b"other").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{e}");
    assert_eq!(e.resource(), Some(uri(&name).as_str()));
    let mut bad = ct.as_bytes().to_vec();
    *bad.last_mut().unwrap() ^= 1;
    let e = k
        .decrypt(&Ciphertext::from_bytes(bad), b"ctx")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed);
    let e = k
        .decrypt(&Ciphertext::from_bytes(Vec::new()), b"ctx")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed);
    // Another key cannot decrypt it.
    let other = p
        .aead_key(uri(&fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION")))
        .unwrap();
    assert_eq!(
        other.decrypt(&ct, b"ctx").await.unwrap_err().kind(),
        ErrorKind::DecryptFailed
    );
    // used_primary: true, then false after a rotation; new ciphertexts use the new primary.
    let info = k.decrypt_with_info(&ct, b"ctx").await.unwrap();
    assert_eq!(info.used_primary(), Some(true));
    assert_eq!(info.key_version(), None);
    fake.rotate(&name);
    let info = k.decrypt_with_info(&ct, b"ctx").await.unwrap();
    assert_eq!(info.used_primary(), Some(false));
    assert_eq!(info.plaintext(), b"secret");
    let ct2 = k.encrypt(b"secret", b"ctx").await.unwrap();
    assert_eq!(
        k.decrypt_with_info(&ct2, b"ctx")
            .await
            .unwrap()
            .used_primary(),
        Some(true)
    );
    // Over 64 KiB: InvalidArgument before any request.
    let before = fake.requests();
    let e = k.encrypt(&[0; 65537], b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert_eq!(fake.requests(), before);
}

/// A3: a disabled version taken from the input (the ciphertext's) is `KeyVersionUnusable`, a
/// caller error; the version the handle chose (the primary version encrypt uses) is
/// `KeyStateInvalid`, a config error.
#[tokio::test]
async fn disabled_versions_by_origin() {
    let fake = FakeKms::start().await;
    let name = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let k = provider(&fake).aead_key(uri(&name)).unwrap();
    let old = k.encrypt(b"old", b"").await.unwrap();
    fake.rotate(&name);
    fake.set_state(&name, 1, "DISABLED");
    let e = k.decrypt(&old, b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    assert!(
        e.is_caller_error(),
        "old data on a disabled version is a caller error"
    );
    let new = k.encrypt(b"new", b"").await.unwrap();
    assert_eq!(&*k.decrypt(&new, b"").await.unwrap(), b"new");
    // A disabled primary: encrypt fails, as a config error.
    fake.set_state(&name, 2, "DISABLED");
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    assert!(e.is_config_error());
    // A pending version carries a retry hint.
    fake.set_state(&name, 2, "PENDING_GENERATION");
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
    assert!(e.retry_hint().is_some());
    assert!(matches!(e.class(), anykms_core::ErrorClass::Hinted(_)));
}

const SIGNING: &[(&str, SignatureAlgorithm)] = &[
    ("EC_SIGN_P256_SHA256", SignatureAlgorithm::EcdsaP256Sha256),
    ("EC_SIGN_P384_SHA384", SignatureAlgorithm::EcdsaP384Sha384),
    ("RSA_SIGN_PSS_2048_SHA256", SignatureAlgorithm::RsaPssSha256),
    (
        "RSA_SIGN_PKCS1_2048_SHA256",
        SignatureAlgorithm::RsaPkcs1v15Sha256,
    ),
    ("RSA_SIGN_PSS_4096_SHA512", SignatureAlgorithm::RsaPssSha512),
];

#[tokio::test]
async fn digest_signing_with_local_verification() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    for &(gcp_alg, alg) in SIGNING {
        let name = fake.create_key(gcp_alg);
        let k = p.digest_signing_key(vuri(&name, 1), alg).unwrap();
        let d = Digest::compute(alg.hash().unwrap(), b"release.tar.gz");
        let sig = k.sign_digest(&d).await.unwrap();
        assert_eq!(sig.key_version(), Some(&KeyVersion::from_u64(1)));
        assert_eq!(sig.algorithm(), alg);
        let verify_calls = fake.calls("POST asymmetricSign");
        k.verify_digest(&d, &sig).await.unwrap();
        assert_eq!(
            fake.calls("POST asymmetricSign"),
            verify_calls,
            "verify is local"
        );
        let other = Digest::compute(alg.hash().unwrap(), b"other");
        assert_eq!(
            k.verify_digest(&other, &sig).await.unwrap_err().kind(),
            ErrorKind::VerificationFailed,
            "{gcp_alg}"
        );
        let pk = k.public_key().await.unwrap();
        assert_eq!(pk.key_version(), Some(&KeyVersion::from_u64(1)));
        assert!(alg.is_compatible_with(&pk.key_type()));
        // The signature verifies with the recipes' verifier too.
        anykms_recipes::LocalVerifier::new(pk, alg)
            .unwrap()
            .verify_digest(&d, &sig)
            .await
            .unwrap();
        // A missing version: UnknownKeyVersion (verifying with it: VerificationFailed);
        // unversioned or malformed: InvalidArgument.
        let e = k
            .public_key_version(&KeyVersion::from_u64(9))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion, "{e}");
        let unknown =
            Signature::from_parts(alg, Some(KeyVersion::from_u64(9)), sig.as_bytes().to_vec());
        assert_eq!(
            k.verify_digest(&d, &unknown).await.unwrap_err().kind(),
            ErrorKind::VerificationFailed
        );
        let unversioned = Signature::from_parts(alg, None, sig.as_bytes().to_vec());
        assert_eq!(
            k.verify_digest(&d, &unversioned).await.unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
        let malformed =
            Signature::from_parts(alg, Some(KeyVersion::new("abc")), sig.as_bytes().to_vec());
        assert_eq!(
            k.verify_digest(&d, &malformed).await.unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
    }
}

#[tokio::test]
async fn signing_versions_rotation_and_disable() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let name = fake.create_key("EC_SIGN_P256_SHA256");
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let v1 = p.digest_signing_key(vuri(&name, 1), alg).unwrap();
    let d = Digest::sha256(b"m");
    let s1 = v1.sign_digest(&d).await.unwrap();
    fake.rotate(&name);
    let v2 = p.digest_signing_key(vuri(&name, 2), alg).unwrap();
    let s2 = v2.sign_digest(&d).await.unwrap();
    assert_eq!(s2.key_version(), Some(&KeyVersion::from_u64(2)));
    // Either handle verifies either version's signatures; the old handle keeps signing with v1.
    v1.verify_digest(&d, &s2).await.unwrap();
    v2.verify_digest(&d, &s1).await.unwrap();
    assert_eq!(
        v1.sign_digest(&d).await.unwrap().key_version(),
        Some(&KeyVersion::from_u64(1))
    );
    // A signature relabeled with the other version fails.
    let relabeled =
        Signature::from_parts(alg, Some(KeyVersion::from_u64(2)), s1.as_bytes().to_vec());
    assert_eq!(
        v1.verify_digest(&d, &relabeled).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    fake.set_state(&name, 1, "DISABLED");
    // The handle's own (pinned) version: KeyStateInvalid, public_key() included.
    let e = v1.sign_digest(&d).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    assert!(e.is_config_error());
    let e = v1.public_key().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    // A version from the input: KeyVersionUnusable.
    let e = v2.verify_digest(&d, &s1).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable);
    assert!(e.is_caller_error());
    let e = v2
        .public_key_version(&KeyVersion::from_u64(1))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    v2.verify_digest(&d, &s2).await.unwrap();
}

#[tokio::test]
async fn ed25519_and_mac() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let name = fake.create_key("EC_SIGN_ED25519");
    let k = p.ed25519_key(vuri(&name, 1)).unwrap();
    let sig = k.sign_message(b"hello").await.unwrap();
    k.verify_message(b"hello", &sig).await.unwrap();
    assert_eq!(
        k.verify_message(b"hellO", &sig).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    assert_eq!(
        k.sign_message(&[0; 65537]).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );

    for (gcp_alg, alg) in [
        ("HMAC_SHA256", MacAlgorithm::HmacSha256),
        ("HMAC_SHA384", MacAlgorithm::HmacSha384),
        ("HMAC_SHA512", MacAlgorithm::HmacSha512),
    ] {
        let name = fake.create_key(gcp_alg);
        let m = p.mac_key(vuri(&name, 1), alg).unwrap();
        let tag = m.mac(b"token-42").await.unwrap();
        assert_eq!(tag.as_bytes().len(), alg.tag_len());
        assert_eq!(tag.key_version(), Some(&KeyVersion::from_u64(1)));
        let before = fake.calls("POST macVerify");
        m.verify_mac(b"token-42", &tag).await.unwrap();
        assert_eq!(
            fake.calls("POST macVerify"),
            before + 1,
            "MAC verify is server-side"
        );
        assert_eq!(
            m.verify_mac(b"token-43", &tag).await.unwrap_err().kind(),
            ErrorKind::VerificationFailed
        );
        // Rotation: the tag names its version, which the server verifies with.
        fake.rotate(&name);
        let m2 = p.mac_key(vuri(&name, 2), alg).unwrap();
        m2.verify_mac(b"token-42", &tag).await.unwrap();
        let t2 = m2.mac(b"token-42").await.unwrap();
        assert_ne!(t2.as_bytes(), tag.as_bytes());
        // Local checks before any request.
        let before = fake.requests();
        let wrong_len = Tag::from_parts(alg, Some(KeyVersion::from_u64(1)), vec![0; 3]);
        assert_eq!(
            m.verify_mac(b"x", &wrong_len).await.unwrap_err().kind(),
            ErrorKind::VerificationFailed
        );
        let unversioned = Tag::from_parts(alg, None, tag.as_bytes().to_vec());
        assert_eq!(
            m.verify_mac(b"x", &unversioned).await.unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(fake.requests(), before);
    }
}

#[tokio::test]
async fn key_type_checks() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let aead = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let p256 = fake.create_key("EC_SIGN_P256_SHA256");
    let pss = fake.create_key("RSA_SIGN_PSS_2048_SHA256");
    let hmac = fake.create_key("HMAC_SHA256");
    let d = Digest::sha256(b"m");
    let mismatch = |r: anykms_core::Result<Signature>| {
        assert_eq!(r.unwrap_err().kind(), ErrorKind::KeyMismatch);
    };
    // An AEAD key version opened as a signer.
    mismatch(
        p.digest_signing_key(vuri(&aead, 1), SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap()
            .sign_digest(&d)
            .await,
    );
    // P-256 asserted as P-384.
    mismatch(
        p.digest_signing_key(vuri(&p256, 1), SignatureAlgorithm::EcdsaP384Sha384)
            .unwrap()
            .sign_digest(&Digest::sha384(b"m"))
            .await,
    );
    // PSS asserted as PKCS#1 (the server cannot catch this).
    mismatch(
        p.digest_signing_key(vuri(&pss, 1), SignatureAlgorithm::RsaPkcs1v15Sha256)
            .unwrap()
            .sign_digest(&d)
            .await,
    );
    // A signing key as AEAD, an HMAC key with another algorithm.
    let e = p
        .aead_key(uri(&p256))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
    let e = p
        .mac_key(vuri(&hmac, 1), MacAlgorithm::HmacSha512)
        .unwrap()
        .mac(b"x")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    // The check is cached: one getPublicKey for many signatures.
    let k = p
        .digest_signing_key(vuri(&p256, 1), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    k.preflight().await.unwrap();
    let before = fake.calls("GET publicKey");
    for _ in 0..3 {
        k.sign_digest(&d).await.unwrap();
    }
    assert_eq!(fake.calls("GET publicKey"), before);
    // TrustCaller skips it: a PSS key asserted as PKCS#1 then signs (mislabeled).
    let trusted = p
        .digest_signing_key(vuri(&pss, 1), SignatureAlgorithm::RsaPkcs1v15Sha256)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let sig = trusted.sign_digest(&d).await.unwrap();
    assert_eq!(
        trusted.verify_digest(&d, &sig).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
}

#[tokio::test]
async fn rsa_key_wrapping_and_envelopes() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let name = fake.create_key("RSA_DECRYPT_OAEP_2048_SHA256");
    let kek = p
        .key_wrap(&key_uri(&vuri(&name, 1)), &OpenOptions::new())
        .unwrap();
    let wrapped = kek.wrap_key(&[9; 32]).await.unwrap();
    assert_eq!(wrapped.len(), 256);
    assert_eq!(&*kek.unwrap_key(&wrapped).await.unwrap(), &[9; 32]);
    let mut bad = wrapped.as_bytes().to_vec();
    bad[10] ^= 1;
    assert_eq!(
        kek.unwrap_key(&Ciphertext::from_bytes(bad))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DecryptFailed
    );
    let info = kek.describe().await.unwrap();
    assert!(info.capabilities().contains(Capabilities::KEY_WRAP));
    assert_eq!(info.primary_version(), None);
    // Envelopes over both kinds of KEK.
    let aead = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    for kek in [
        p.key_wrap(&key_uri(&vuri(&name, 1)), &OpenOptions::new())
            .unwrap(),
        p.key_wrap(&key_uri(&uri(&aead)), &OpenOptions::new())
            .unwrap(),
    ] {
        let env = anykms_recipes::EnvelopeAead::new("kek", kek).unwrap();
        let ct = env.encrypt(&[1; 100_000], b"row-7").await.unwrap();
        assert_eq!(&*env.decrypt(&ct, b"row-7").await.unwrap(), &[1; 100_000]);
    }
    // A signing key version is not a KEK.
    let p256 = fake.create_key("EC_SIGN_P256_SHA256");
    let e = p
        .key_wrap(&key_uri(&vuri(&p256, 1)), &OpenOptions::new())
        .unwrap()
        .wrap_key(&[1; 32])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
}

/// Q10: only OAEP-SHA-256 versions wrap or unwrap; anything else is `KeyMismatch` before any
/// `asymmetricDecrypt`.
#[tokio::test]
async fn rsa_key_wrapping_checks_the_algorithm_on_unwrap() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let blob = Ciphertext::from_bytes(vec![1; 256]);
    let sha1 = fake.create_key("RSA_DECRYPT_OAEP_2048_SHA1");
    let p256 = fake.create_key("EC_SIGN_P256_SHA256");
    for name in [&sha1, &p256] {
        let kek = p.key_wrap_key(vuri(name, 1)).unwrap();
        let e = kek.unwrap_key(&blob).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{name}: {e}");
        assert_eq!(e.resource(), Some(vuri(name, 1).as_str()));
        assert_eq!(
            kek.wrap_key(&[1; 32]).await.unwrap_err().kind(),
            ErrorKind::KeyMismatch
        );
        assert_eq!(
            kek.preflight().await.unwrap_err().kind(),
            ErrorKind::KeyMismatch
        );
        // Through the registry path too.
        let e = p
            .key_wrap(&key_uri(&vuri(name, 1)), &OpenOptions::new())
            .unwrap()
            .unwrap_key(&blob)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    }
    let e = p
        .key_wrap_key(vuri(&sha1, 1))
        .unwrap()
        .unwrap_key(&blob)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("SHA256"), "{e}");
    assert_eq!(fake.calls("POST asymmetricDecrypt"), 0);
    // `key_type_check` reaches the RSA handle: TrustCaller skips the check on unwrap.
    let trusting = OpenOptions::new().with_key_type_check(KeyTypeCheck::TrustCaller);
    let e = p
        .key_wrap(&key_uri(&vuri(&sha1, 1)), &trusting)
        .unwrap()
        .unwrap_key(&blob)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{e}");
    assert_eq!(fake.calls("POST asymmetricDecrypt"), 1);
    // The check is cached: one getPublicKey for many unwraps.
    let good = fake.create_key("RSA_DECRYPT_OAEP_2048_SHA256");
    let kek = p.key_wrap_key(vuri(&good, 1)).unwrap();
    let w = kek.wrap_key(&[3; 32]).await.unwrap();
    let before = fake.calls("GET publicKey");
    for _ in 0..3 {
        assert_eq!(&*kek.unwrap_key(&w).await.unwrap(), &[3; 32]);
    }
    assert!(fake.calls("GET publicKey") - before <= 1);
    // Over-long and empty blobs never reach the server.
    let before = fake.requests();
    for bad in [vec![0; 513], Vec::new()] {
        assert_eq!(
            kek.unwrap_key(&Ciphertext::from_bytes(bad))
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DecryptFailed
        );
    }
    assert_eq!(fake.requests(), before);
}

#[tokio::test]
async fn describe_and_not_native_parts() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let name = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    fake.rotate(&name);
    fake.set_state(&name, 1, "DESTROY_SCHEDULED");
    let reg = Registry::builder().provider(p.clone()).build().unwrap();
    let k = reg.aead(uri(&name)).unwrap();
    let info = k.describe().await.unwrap();
    assert_eq!(info.backend_key_type(), "GOOGLE_SYMMETRIC_ENCRYPTION");
    assert_eq!(info.state(), None);
    assert_eq!(info.primary_version(), Some(&KeyVersion::from_u64(2)));
    assert_eq!(info.versions().len(), 2);
    assert!(!info.capabilities().contains(Capabilities::REWRAP));
    // Rewrap and data keys: Unsupported, before any request.
    assert!(!k.supports_rewrap() && !k.supports_data_keys());
    let ct = k.encrypt(b"x", b"").await.unwrap();
    let before = fake.requests();
    assert_eq!(
        k.rewrap(&ct, b"").await.unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        k.generate_data_key(DataKeySpec::Aes256, b"")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        reg.data_keys(uri(&name)).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(fake.requests(), before);
    // The GCP view.
    let g = p
        .aead_key(uri(&name))
        .unwrap()
        .describe()
        .await
        .unwrap()
        .backend_info::<anykms_gcp::GcpKeyInfo>()
        .unwrap()
        .clone();
    assert_eq!(g.purpose(), "ENCRYPT_DECRYPT");
    assert_eq!(g.protection_level(), Some("SOFTWARE"));
    assert_eq!(g.versions()[0].state(), "DESTROY_SCHEDULED");
    // Signing keys: no primary; a versioned describe names that version's algorithm.
    let s = fake.create_key("RSA_SIGN_PKCS1_4096_SHA512");
    let info = reg.describe(vuri(&s, 1)).unwrap().describe().await.unwrap();
    assert_eq!(info.primary_version(), None);
    assert_eq!(
        info.signature_algorithms(),
        &[SignatureAlgorithm::RsaPkcs1v15Sha512]
    );
    assert!(info.capabilities().contains(Capabilities::VERIFY));
    // The typed describe-only handle (it has no encrypt, sign or MAC methods).
    let d = p.describe_key(vuri(&s, 1)).unwrap();
    assert_eq!(
        d.describe()
            .await
            .unwrap()
            .backend_info::<anykms_gcp::GcpKeyInfo>()
            .unwrap()
            .clone()
            .purpose(),
        "ASYMMETRIC_SIGN"
    );
    assert_eq!(d.describe().await.unwrap(), info);
    // Through the registry, the signer verifies its own signatures.
    let signer = reg
        .digest_signer(vuri(&s, 1), SignatureAlgorithm::RsaPkcs1v15Sha512)
        .unwrap();
    let d = Digest::sha512(b"m");
    let sig = signer.sign_digest(&d).await.unwrap();
    signer.verify_digest(&d, &sig).await.unwrap();
}

#[tokio::test]
async fn error_paths() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let name = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    // Missing key.
    let missing = format!("{}/cryptoKeys/nope", FakeKms::RING);
    let e = p
        .aead_key(uri(&missing))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    assert_eq!(e.resource(), Some(uri(&missing).as_str()));
    // Throttled, with Retry-After.
    fake.throttle(&name, true);
    let e = p
        .aead_key(uri(&name))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Throttled);
    assert_eq!(e.retry_after(), Some(std::time::Duration::from_secs(1)));
    fake.throttle(&name, false);
    // Denied credentials.
    let denied = common::builder(&fake)
        .credentials(Credentials::static_token(fake::DENIED_TOKEN))
        .build()
        .unwrap();
    let e = denied
        .aead_key(uri(&name))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    // Unknown credentials (a static token cannot be refreshed: no retry).
    let unknown = common::builder(&fake)
        .credentials(Credentials::static_token("ya29.unknown"))
        .build()
        .unwrap();
    let before = fake.requests();
    let e = unknown
        .aead_key(uri(&name))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated);
    assert_eq!(fake.requests(), before + 1);
    // Allowlist.
    let e = p
        .aead_key("gcp-kms://projects/other-project/locations/global/keyRings/r/cryptoKeys/k")
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    // Nothing listening: Unavailable.
    let closed = GcpProvider::builder()
        .credentials(Credentials::none())
        .endpoint(anykms_gcp::Endpoint::custom("http://127.0.0.1:9"))
        .allow_loopback_http()
        .build()
        .unwrap();
    let e = closed
        .aead_key(uri(&name))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
}

/// A provider whose tokens come from the fake's token endpoints.
fn with_creds(fake: &FakeKms, creds: Credentials) -> GcpProvider {
    common::builder(fake)
        .credentials(creds)
        .auth_endpoints(AuthEndpoints::custom(&fake.uri()).unwrap())
        .build()
        .unwrap()
}

async fn roundtrip(p: &GcpProvider, name: &str) {
    let k = p.aead_key(uri(name)).unwrap();
    let ct = k.encrypt(b"via credentials", b"").await.unwrap();
    assert_eq!(&*k.decrypt(&ct, b"").await.unwrap(), b"via credentials");
}

fn temp_file(tag: &str, contents: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("anykms-gcp-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(tag);
    std::fs::write(&p, contents).unwrap();
    p
}

#[tokio::test]
async fn credentials_end_to_end() {
    let fake = FakeKms::start().await;
    let name = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let origin = fake.uri();

    // Metadata server.
    let p = with_creds(&fake, Credentials::metadata_server());
    roundtrip(&p, &name).await;

    // authorized_user (refresh token).
    let au = serde_json::json!({
        "type": "authorized_user", "client_id": "cid", "client_secret": "csecret",
        "refresh_token": fake::REFRESH_TOKEN, "quota_project_id": "fake-project",
    });
    roundtrip(
        &with_creds(&fake, Credentials::from_json(au.to_string())),
        &name,
    )
    .await;

    // external_account: a file subject token, STS, then impersonation.
    let subject = temp_file("subject", fake::SUBJECT_TOKEN);
    let ea = serde_json::json!({
        "type": "external_account",
        "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/gh",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": format!("{origin}/v1/token"),
        "service_account_impersonation_url": format!(
            "{origin}/v1/projects/-/serviceAccounts/ci@fake-project.iam.gserviceaccount.com:generateAccessToken"
        ),
        "credential_source": {"file": subject},
    });
    let f = temp_file("external.json", &ea.to_string());
    roundtrip(
        &with_creds(&fake, Credentials::external_account_file(&f)),
        &name,
    )
    .await;

    // external_account: a URL subject token in a JSON field, no impersonation.
    let ea = serde_json::json!({
        "type": "external_account",
        "audience": "aud",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": format!("{origin}/v1/token"),
        "credential_source": {
            "url": format!("{origin}/subject"),
            "headers": {"Metadata": "True"},
            "format": {"type": "json", "subject_token_field_name": "value"},
        },
    });
    let subject_server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::path("/subject"))
        .and(wiremock::matchers::header("Metadata", "True"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"value": fake::SUBJECT_TOKEN})),
        )
        .mount(&subject_server)
        .await;
    let mut ea = ea;
    ea["credential_source"]["url"] = format!("{}/subject", subject_server.uri()).into();
    roundtrip(
        &with_creds(&fake, Credentials::from_json(ea.to_string())),
        &name,
    )
    .await;

    // impersonated_service_account over an authorized_user source.
    let imp = serde_json::json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": format!(
            "{origin}/v1/projects/-/serviceAccounts/app@fake-project.iam.gserviceaccount.com:generateAccessToken"
        ),
        "source_credentials": {
            "type": "authorized_user", "client_id": "cid", "client_secret": "s",
            "refresh_token": fake::REFRESH_TOKEN,
        },
        "delegates": ["delegate@fake-project.iam.gserviceaccount.com"],
    });
    roundtrip(
        &with_creds(&fake, Credentials::from_json(imp.to_string())),
        &name,
    )
    .await;

    // Credentials::impersonated over the metadata server.
    roundtrip(
        &with_creds(
            &fake,
            Credentials::impersonated(
                Credentials::metadata_server(),
                "app@fake-project.iam.gserviceaccount.com",
            ),
        ),
        &name,
    )
    .await;

    // service_account: a self-signed JWT.
    let sa = service_account_json();
    roundtrip(&with_creds(&fake, Credentials::from_json(sa)), &name).await;

    // A planted credential file naming another host is refused.
    let planted = serde_json::json!({
        "type": "external_account", "audience": "a",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://attacker.example/v1/token",
        "credential_source": {"file": subject},
    });
    let e = with_creds(&fake, Credentials::from_json(planted.to_string()))
        .aead_key(uri(&name))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
}

/// A `service_account` JSON with a fresh RSA key.
pub fn service_account_json() -> String {
    use aws_lc_rs::encoding::AsDer as _;
    let kp = aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let der: aws_lc_rs::encoding::Pkcs8V1Der<'_> = kp.as_der().unwrap();
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for c in b.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(c).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    serde_json::json!({
        "type": "service_account", "project_id": "fake-project", "private_key_id": "kid1",
        "private_key": pem, "client_email": "app@fake-project.iam.gserviceaccount.com",
        "client_id": "1", "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string()
}

#[tokio::test]
async fn refreshes_once_after_401() {
    let fake = FakeKms::start().await;
    let name = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let p = with_creds(&fake, Credentials::metadata_server());
    roundtrip(&p, &name).await;
    // The server forgets the issued token: the client refreshes once and succeeds.
    fake.revoke_token("ya29.issued-1");
    let before = fake.calls("GET token");
    roundtrip(&p, &name).await;
    assert_eq!(fake.calls("GET token"), before + 1);
}

#[tokio::test]
async fn registry_and_typed_handles_agree() {
    let fake = FakeKms::start().await;
    let p = Arc::new(provider(&fake));
    let name = fake.create_key("EC_SIGN_P384_SHA384");
    let reg = Registry::builder().provider(p.clone()).build().unwrap();
    let alg = SignatureAlgorithm::EcdsaP384Sha384;
    let s = reg.digest_signer(vuri(&name, 1), alg).unwrap();
    let d = Digest::sha384(b"m");
    let sig = s.sign_digest(&d).await.unwrap();
    let typed = p.digest_signing_key(vuri(&name, 1), alg).unwrap();
    typed.verify_digest(&d, &sig).await.unwrap();
    let pk = reg.public_keys(vuri(&name, 1), alg).unwrap();
    assert_eq!(
        pk.public_key().await.unwrap(),
        typed.public_key().await.unwrap()
    );
    // Versioned AEAD and unversioned signing URIs fail to open.
    assert_eq!(
        reg.aead(vuri(&name, 1)).unwrap_err().kind(),
        ErrorKind::KeyMismatch
    );
    assert_eq!(
        reg.digest_signer(uri(&name), alg).unwrap_err().kind(),
        ErrorKind::KeyMismatch
    );
    let _ = Provider::name(&*p);
}

/// The fake server corrupts one success-response field at a time, for every operation: a bad
/// CRC32C or a missing `verified*` flag is `Unavailable`, another key's `name` is `Backend`.
#[tokio::test]
async fn corrupted_responses_are_refused_on_every_operation() {
    use serde_json::{Value, json};
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let aead = p
        .aead_key(uri(&fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION")))
        .unwrap();
    let ct = aead.encrypt(b"pt", b"ad").await.unwrap();
    let ec = p
        .digest_signing_key(
            vuri(&fake.create_key("EC_SIGN_P256_SHA256"), 1),
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .unwrap();
    let ed = p
        .ed25519_key(vuri(&fake.create_key("EC_SIGN_ED25519"), 1))
        .unwrap();
    let mac = p
        .mac_key(
            vuri(&fake.create_key("HMAC_SHA256"), 1),
            MacAlgorithm::HmacSha256,
        )
        .unwrap();
    let tag = mac.mac(b"d").await.unwrap();
    let kek = p
        .key_wrap_key(vuri(&fake.create_key("RSA_DECRYPT_OAEP_2048_SHA256"), 1))
        .unwrap();
    let wrapped = kek.wrap_key(&[4; 32]).await.unwrap();
    let other = "projects/fake-project/locations/global/keyRings/test/cryptoKeys/other";
    let other_v = format!("{other}/cryptoKeyVersions/1");

    let unavailable = ErrorKind::Unavailable;
    let backend = ErrorKind::Backend;
    let cases: Vec<(&str, &str, Value, ErrorKind)> = vec![
        ("POST encrypt", "ciphertextCrc32c", json!("1"), unavailable),
        ("POST encrypt", "ciphertextCrc32c", Value::Null, unavailable),
        (
            "POST encrypt",
            "verifiedPlaintextCrc32c",
            json!(false),
            unavailable,
        ),
        (
            "POST encrypt",
            "verifiedAdditionalAuthenticatedDataCrc32c",
            Value::Null,
            unavailable,
        ),
        ("POST encrypt", "name", json!(other_v), backend),
        ("POST decrypt", "plaintextCrc32c", json!("1"), unavailable),
        ("POST decrypt", "plaintextCrc32c", Value::Null, unavailable),
        (
            "POST asymmetricSign",
            "signatureCrc32c",
            json!("1"),
            unavailable,
        ),
        (
            "POST asymmetricSign",
            "verifiedDigestCrc32c",
            json!(false),
            unavailable,
        ),
        (
            "POST asymmetricSign",
            "verifiedDataCrc32c",
            json!(false),
            unavailable,
        ),
        ("POST asymmetricSign", "name", json!(other_v), backend),
        ("POST macSign", "macCrc32c", json!("1"), unavailable),
        (
            "POST macSign",
            "verifiedDataCrc32c",
            json!(false),
            unavailable,
        ),
        ("POST macSign", "name", json!(other_v), backend),
        (
            "POST macVerify",
            "verifiedDataCrc32c",
            json!(false),
            unavailable,
        ),
        (
            "POST macVerify",
            "verifiedMacCrc32c",
            json!(false),
            unavailable,
        ),
        (
            "POST macVerify",
            "verifiedSuccessIntegrity",
            json!(false),
            unavailable,
        ),
        ("POST macVerify", "name", json!(other_v), backend),
        ("GET publicKey", "pemCrc32c", json!("1"), unavailable),
        ("GET publicKey", "name", json!(other_v), backend),
        (
            "POST asymmetricDecrypt",
            "verifiedCiphertextCrc32c",
            json!(false),
            unavailable,
        ),
        (
            "POST asymmetricDecrypt",
            "plaintextCrc32c",
            json!("1"),
            unavailable,
        ),
        ("GET k0", "name", json!(other), backend),
    ];
    for (call, field, value, want) in cases {
        fake.tamper(call, field, value.clone());
        let r: anykms_core::Result<()> = match call {
            "POST encrypt" => aead.encrypt(b"pt", b"ad").await.map(drop),
            "POST decrypt" => aead.decrypt(&ct, b"ad").await.map(drop),
            "POST asymmetricSign" if field == "verifiedDataCrc32c" => {
                ed.sign_message(b"m").await.map(drop)
            }
            "POST asymmetricSign" => ec.sign_digest(&Digest::sha256(b"m")).await.map(drop),
            "POST macSign" => mac.mac(b"d").await.map(drop),
            "POST macVerify" => mac.verify_mac(b"d", &tag).await,
            "GET publicKey" => ec.public_key().await.map(drop),
            "POST asymmetricDecrypt" => kek.unwrap_key(&wrapped).await.map(drop),
            // cryptoKeys.get of the AEAD key (`k0`, the first key created).
            _ => aead.describe().await.map(drop),
        };
        fake.clear_tamper();
        let e = r.expect_err(&format!("{call} {field}={value}"));
        assert_eq!(e.kind(), want, "{call} {field}={value}: {e}");
    }
    // Untampered, everything works again.
    aead.decrypt(&ct, b"ad").await.unwrap();
    mac.verify_mac(b"d", &tag).await.unwrap();
    assert_eq!(&*kek.unwrap_key(&wrapped).await.unwrap(), &[4; 32]);
}

/// P1-4 and P1-13: 100 distinct forged versions through verify, `public_key_version` and MAC
/// verification never drop the handle's key-type check; with the public-key cache on, each
/// forged version costs one version-state lookup (no `getPublicKey`), and a repeat costs none
/// (the negative cache). A3: verifying with a forged version is `VerificationFailed`, its public
/// key `UnknownKeyVersion`.
#[tokio::test]
async fn forged_versions_do_not_flush_the_checks() {
    let fake = FakeKms::start().await;
    let ec = fake.create_key("EC_SIGN_P256_SHA256");
    let hm = fake.create_key("HMAC_SHA256");
    let p = common::builder(&fake)
        .public_key_ttl(std::time::Duration::from_secs(60))
        .build()
        .unwrap();
    let s = p
        .digest_signing_key(vuri(&ec, 1), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let m = p.mac_key(vuri(&hm, 1), MacAlgorithm::HmacSha256).unwrap();
    let d = Digest::sha256(b"m");
    let sig = s.sign_digest(&d).await.unwrap();
    let tag = m.mac(b"m").await.unwrap();
    let keys = fake.calls("GET publicKey");
    assert_eq!(keys, 1, "the key-type check");
    let before = fake.requests();
    for v in 1000..1100u64 {
        let forged = Signature::from_parts(
            SignatureAlgorithm::EcdsaP256Sha256,
            Some(KeyVersion::from_u64(v)),
            sig.as_bytes().to_vec(),
        );
        let e = s.verify_digest(&d, &forged).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{e}");
        // Remembered: no second request for the same version.
        let e = s
            .public_key_version(&KeyVersion::from_u64(v))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion, "{e}");
        assert!(e.is_caller_error());
        let forged = Tag::from_parts(
            MacAlgorithm::HmacSha256,
            Some(KeyVersion::from_u64(v)),
            tag.as_bytes().to_vec(),
        );
        let e = m.verify_mac(b"m", &forged).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{e}");
    }
    assert_eq!(fake.calls("GET publicKey"), keys);
    assert_eq!(
        fake.requests(),
        before + 200,
        "one version-state lookup and one macVerify each"
    );
    // The checks still stand: signing and MACing make no check request.
    let before = fake.requests();
    s.sign_digest(&d).await.unwrap();
    m.mac(b"m").await.unwrap();
    assert_eq!(fake.requests(), before + 2);
    // A real version still verifies (the negative cache is per version).
    s.verify_digest(&d, &sig).await.unwrap();
}

/// P1-13: without the public-key cache (`public_key_ttl(ZERO)`), nothing is remembered: each
/// verification of a forged version asks again.
#[tokio::test]
async fn without_the_public_key_cache_unknown_versions_are_not_remembered() {
    let fake = FakeKms::start().await;
    let ec = fake.create_key("EC_SIGN_P256_SHA256");
    let s = provider(&fake)
        .digest_signing_key(vuri(&ec, 1), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let d = Digest::sha256(b"m");
    let sig = s.sign_digest(&d).await.unwrap();
    let forged = Signature::from_parts(
        SignatureAlgorithm::EcdsaP256Sha256,
        Some(KeyVersion::from_u64(7)),
        sig.as_bytes().to_vec(),
    );
    let before = fake.calls("GET 7");
    for _ in 0..2 {
        s.verify_digest(&d, &forged).await.unwrap_err();
    }
    assert_eq!(fake.calls("GET 7"), before + 2);
}

/// P1-7: a custom source goes through the token cache: asked once while its token is valid,
/// and told about a 401 (the cache forwards `invalidate`).
#[tokio::test]
async fn custom_sources_are_cached() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct Src {
        calls: AtomicUsize,
        rotated: AtomicBool,
    }
    impl anykms_gcp::CredentialSource for Src {
        fn token(
            &self,
        ) -> anykms_core::BoxFuture<'_, anykms_core::Result<Option<anykms_gcp::Token>>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let t = if self.rotated.load(Ordering::SeqCst) {
                fake::TOKEN
            } else {
                "ya29.custom-old"
            };
            let at = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
            Box::pin(async move { Ok(Some(anykms_gcp::Token::new(t, Some(at)))) })
        }
        fn invalidate(&self, rejected: &anykms_gcp::Token) {
            if rejected.expose() == "ya29.custom-old" {
                self.rotated.store(true, Ordering::SeqCst);
            }
        }
    }

    let fake = FakeKms::start().await;
    fake.accept_token("ya29.custom-old");
    let name = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let src = Arc::new(Src::default());
    let p = common::builder(&fake)
        .credentials(Credentials::custom(src.clone()))
        .build()
        .unwrap();
    roundtrip(&p, &name).await;
    roundtrip(&p, &name).await;
    assert_eq!(src.calls.load(Ordering::SeqCst), 1, "cached while valid");
    // The server stops accepting the token: the cache drops it, forwards the 401 to the source
    // and asks it again once.
    fake.revoke_token("ya29.custom-old");
    roundtrip(&p, &name).await;
    assert!(src.rotated.load(Ordering::SeqCst));
    assert_eq!(src.calls.load(Ordering::SeqCst), 2);
}

/// §3.1(f): the public key of a version that is not enabled is refused even where the server
/// would serve it: the version-state lookup runs before `getPublicKey`. The handle's own version
/// is `KeyStateInvalid` (`public_key()`, signing's key-type check, RSA wrap), an input version
/// `KeyVersionUnusable` (`public_key_version`, verification).
#[tokio::test]
async fn public_keys_of_disabled_versions_are_refused() {
    let fake = FakeKms::start().await;
    fake.serve_disabled_public_keys(true);
    let p = provider(&fake);
    let ec = fake.create_key("EC_SIGN_P256_SHA256");
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let s1 = p.digest_signing_key(vuri(&ec, 1), alg).unwrap();
    let d = Digest::sha256(b"m");
    let sig = s1.sign_digest(&d).await.unwrap();
    fake.rotate(&ec);
    let s2 = p.digest_signing_key(vuri(&ec, 2), alg).unwrap();
    s2.verify_digest(&d, &sig).await.unwrap();
    fake.set_state(&ec, 1, "DISABLED");
    let keys = fake.calls("GET publicKey");
    let e = s1.public_key().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    assert!(e.is_config_error());
    let e = s1.preflight().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    let e = s2
        .public_key_version(&KeyVersion::from_u64(1))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    assert!(e.is_caller_error());
    let e = s2.verify_digest(&d, &sig).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    assert_eq!(
        fake.calls("GET publicKey"),
        keys,
        "no public key was fetched"
    );
    // A pending version: the same kinds, with the retry hint.
    fake.set_state(&ec, 1, "PENDING_GENERATION");
    let e = s1.public_key().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
    assert!(e.retry_hint().is_some());
    // RSA key wrapping: wrap and public_key() on a disabled pinned version.
    let rsa = fake.create_key("RSA_DECRYPT_OAEP_2048_SHA256");
    let kek = p.key_wrap_key(vuri(&rsa, 1)).unwrap();
    kek.wrap_key(&[1; 32]).await.unwrap();
    fake.set_state(&rsa, 1, "DISABLED");
    let e = kek.wrap_key(&[1; 32]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    assert_eq!(e.operation(), anykms_core::Operation::WrapKey);
    let e = kek.public_key().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    // Enabled again: served.
    fake.set_state(&ec, 1, "ENABLED");
    s1.public_key().await.unwrap();
    s2.verify_digest(&d, &sig).await.unwrap();
}

/// §3.1(f), round-2 security notes: without `cloudkms.cryptoKeyVersions.get`, public keys fail
/// closed (`PermissionDenied`, no `getPublicKey`).
#[tokio::test]
async fn the_version_state_lookup_fails_closed() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let ec = fake.create_key("EC_SIGN_P256_SHA256");
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let s = p.digest_signing_key(vuri(&ec, 1), alg).unwrap();
    let d = Digest::sha256(b"m");
    let sig = s.sign_digest(&d).await.unwrap();
    fake.deny_version_get(true);
    let keys = fake.calls("GET publicKey");
    for e in [
        s.public_key().await.unwrap_err(),
        s.public_key_version(&KeyVersion::from_u64(1))
            .await
            .unwrap_err(),
        s.verify_digest(&d, &sig).await.unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    }
    assert_eq!(fake.calls("GET publicKey"), keys);
}

/// The version-state lookup of an input version is negative-cached (one lookup per TTL for a
/// disabled version) and never drops the handle's checks; the handle's own version is not
/// negative-cached, and a pending version (hinted) is not remembered.
#[tokio::test]
async fn refused_input_versions_are_remembered() {
    let fake = FakeKms::start().await;
    let ec = fake.create_key("EC_SIGN_P256_SHA256");
    let p = common::builder(&fake)
        .public_key_ttl(std::time::Duration::from_secs(60))
        .build()
        .unwrap();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    // Signed through another provider, so `p` has not cached version 1's public key.
    let s1 = provider(&fake)
        .digest_signing_key(vuri(&ec, 1), alg)
        .unwrap();
    let d = Digest::sha256(b"m");
    let sig = s1.sign_digest(&d).await.unwrap();
    fake.rotate(&ec);
    let s2 = p.digest_signing_key(vuri(&ec, 2), alg).unwrap();
    s2.sign_digest(&d).await.unwrap();
    fake.set_state(&ec, 1, "DISABLED");
    let before = fake.calls("GET 1");
    for _ in 0..3 {
        let e = s2.verify_digest(&d, &sig).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    }
    assert_eq!(fake.calls("GET 1"), before + 1, "remembered");
    // The checks stand: signing makes no check request.
    let requests = fake.requests();
    s2.sign_digest(&d).await.unwrap();
    assert_eq!(fake.requests(), requests + 1);
    // Pending (hinted): asked again each time.
    let v3 = fake.rotate(&ec);
    fake.set_state(&ec, v3, "PENDING_GENERATION");
    let what = format!("GET {v3}");
    let before = fake.calls(&what);
    for _ in 0..2 {
        let e = s2
            .public_key_version(&KeyVersion::from_u64(v3))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable);
        assert!(e.retry_hint().is_some());
    }
    assert_eq!(fake.calls(&what), before + 2);
}

/// An RSA KEK serves only its pinned version's public key: a key wrapped offline to another
/// version could not be unwrapped through the handle, so `public_key_version` refuses any other
/// version with `UnknownKeyVersion` before any request.
#[tokio::test]
async fn rsa_kek_serves_only_its_pinned_public_key() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let rsa = fake.create_key("RSA_DECRYPT_OAEP_2048_SHA256");
    fake.rotate(&rsa);
    let kek = p.key_wrap_key(vuri(&rsa, 1)).unwrap();
    let before = fake.requests();
    for v in ["2", "3"] {
        let e = kek
            .public_key_version(&KeyVersion::new(v))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion, "{v}: {e}");
        assert_eq!(e.operation(), anykms_core::Operation::PublicKey, "{e}");
        assert!(e.is_caller_error());
    }
    assert_eq!(fake.requests(), before, "refused before any request");
    // The pinned version itself is served, and is the key wrap_key uses.
    let pinned = kek
        .public_key_version(&KeyVersion::from_u64(1))
        .await
        .unwrap();
    assert_eq!(pinned, kek.public_key().await.unwrap());
}

/// Preflight refusals are labelled `Describe`, through the typed handles and the registry alike.
#[tokio::test]
async fn preflight_refusals_are_labelled_describe() {
    let fake = FakeKms::start().await;
    let p = provider(&fake);
    let p256 = fake.create_key("EC_SIGN_P256_SHA256");
    let hmac = fake.create_key("HMAC_SHA256");
    let check = |e: anykms_core::Error| {
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
        assert_eq!(e.operation(), anykms_core::Operation::Describe, "{e}");
    };
    // A signing key as AEAD, a signing version as a KEK, P-256 as P-384, HMAC as SHA-512.
    check(
        p.aead_key(uri(&p256))
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    check(
        p.key_wrap_key(vuri(&p256, 1))
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    let p384 = SignatureAlgorithm::EcdsaP384Sha384;
    check(
        p.digest_signing_key(vuri(&p256, 1), p384)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    check(
        p.mac_key(vuri(&hmac, 1), MacAlgorithm::HmacSha512)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    let opts = OpenOptions::new();
    check(
        p.aead(&key_uri(&uri(&p256)), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    check(
        p.key_wrap(&key_uri(&vuri(&p256, 1)), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
}
