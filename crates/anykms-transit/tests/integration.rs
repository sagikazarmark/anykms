//! Transit-specific integration cases against the compose servers (`scripts/dev-up.sh --sealed
//! --tls`).
//!
//! A libtest-mimic harness (`harness = false`): each case's prerequisite (a reachable server, the
//! dev TLS CA) is probed up front. A case whose prerequisite is missing is reported as **ignored**
//! with kind `skip` and the reason, never as passed, unless `ANYKMS_REQUIRE_FIXTURE=1` (CI), which
//! makes it fail.

mod common;

use std::future::Future;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck, KeyUri};
use anykms_transit::{Flavor, ServerConfig, TransitProvider};
use common::TransitFixture;
use libtest_mimic::{Arguments, Trial};
use serde_json::json;
use tokio::runtime::Runtime;

fn require() -> bool {
    std::env::var("ANYKMS_REQUIRE_FIXTURE").is_ok_and(|v| v == "1")
}

/// A prerequisite: its value when available, or why not.
type Prereq<P> = Result<P, String>;

/// One case: run when its prerequisite is available; otherwise ignored (kind `skip`), or failed
/// under `ANYKMS_REQUIRE_FIXTURE=1`.
fn case<P, F, Fut>(name: &str, rt: &Arc<Runtime>, prereq: &Prereq<P>, body: F) -> Trial
where
    P: Clone + Send + 'static,
    F: FnOnce(P) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    match prereq {
        Ok(p) => {
            let (p, rt) = (p.clone(), rt.clone());
            Trial::test(name, move || {
                rt.block_on(body(p));
                Ok(())
            })
        }
        Err(reason) if require() => {
            let reason = reason.clone();
            Trial::test(name, move || {
                Err(
                    format!("prerequisite unavailable and ANYKMS_REQUIRE_FIXTURE=1: {reason}")
                        .into(),
                )
            })
        }
        Err(reason) => {
            let reason = reason.clone();
            Trial::test(
                name,
                move || Err(format!("not run (skip): {reason}").into()),
            )
            .with_ignored_flag(true)
            .with_kind("skip")
        }
    }
}

fn main() -> ExitCode {
    let args = Arguments::from_args();
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );
    let vault: Prereq<Arc<TransitFixture>> = rt
        .block_on(TransitFixture::connect("vault", Flavor::Vault))
        .map(Arc::new);
    let openbao: Prereq<Arc<TransitFixture>> = rt
        .block_on(TransitFixture::connect("openbao", Flavor::OpenBao))
        .map(Arc::new);
    let sealed_addr =
        std::env::var("ANYKMS_SEALED_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8210".into());
    let sealed: Prereq<String> = if rt.block_on(reachable(&sealed_addr)) {
        Ok(sealed_addr)
    } else {
        Err(format!(
            "sealed server {sealed_addr} unreachable (scripts/dev-up.sh --sealed)"
        ))
    };
    let tls = |port: u16, dir: &str| -> Prereq<(String, Vec<u8>)> {
        let addr = format!("https://127.0.0.1:{port}");
        let ca_path = format!(
            "{}/../../.dev/tls/{dir}/vault-ca.pem",
            env!("CARGO_MANIFEST_DIR")
        );
        let ca = std::fs::read(&ca_path)
            .map_err(|_| format!("{ca_path} missing (scripts/dev-up.sh --tls)"))?;
        if !rt.block_on(reachable(&addr)) {
            return Err(format!(
                "TLS server {addr} unreachable (scripts/dev-up.sh --tls)"
            ));
        }
        Ok((addr, ca))
    };
    let tls_vault = tls(8201, "vault");
    let tls_openbao = tls(8301, "openbao");

    let trials = vec![
        case(
            "sealed_server_is_unavailable",
            &rt,
            &sealed,
            sealed_server_is_unavailable,
        ),
        case("tls_vault", &rt, &tls_vault, |(addr, ca)| {
            tls_case(Flavor::Vault, addr, ca)
        }),
        case("tls_openbao", &rt, &tls_openbao, |(addr, ca)| {
            tls_case(Flavor::OpenBao, addr, ca)
        }),
        case("upsert_vault", &rt, &vault, upsert_case),
        case("upsert_openbao", &rt, &openbao, upsert_case),
        case(
            "openbao_unknown_namespace_is_configuration",
            &rt,
            &openbao,
            openbao_unknown_namespace_is_configuration,
        ),
        case(
            "vault_ce_ignores_namespaces",
            &rt,
            &vault,
            vault_ce_ignores_namespaces,
        ),
        case(
            "openbao_datakey_binds_aad_and_vault_refuses",
            &rt,
            &openbao,
            openbao_datakey_binds_aad_and_vault_refuses,
        ),
        case(
            "sign_verify_hmac_errors_vault",
            &rt,
            &vault,
            sign_verify_hmac_errors,
        ),
        case(
            "sign_verify_hmac_errors_openbao",
            &rt,
            &openbao,
            sign_verify_hmac_errors,
        ),
        case("jwt_login_vault", &rt, &vault, jwt_login),
        case("jwt_login_openbao", &rt, &openbao, jwt_login),
    ];
    libtest_mimic::run(&args, trials).exit_code()
}

/// `Login::jwt` against a real server: a JWT auth mount trusting a transit ECDSA key, a JWT
/// signed with that key, and a provider that logs in with it and uses the resulting token.
async fn jwt_login(fx: Arc<TransitFixture>) {
    use base64::Engine as _;
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64 = base64::engine::general_purpose::STANDARD;
    let post = reqwest::Method::POST;
    let mount = format!("jwt-anykms-{}", std::process::id());

    let signer = fx.create("ecdsa-p256").await.unwrap();
    let info = fx
        .admin
        .req(
            reqwest::Method::GET,
            &format!("transit/keys/{signer}"),
            None,
        )
        .await
        .unwrap();
    let pem = info["data"]["keys"]["1"]["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let _ = fx
        .admin
        .req(reqwest::Method::DELETE, &format!("sys/auth/{mount}"), None)
        .await;
    fx.admin
        .req(
            post.clone(),
            &format!("sys/auth/{mount}"),
            Some(json!({"type": "jwt"})),
        )
        .await
        .unwrap();
    fx.admin
        .req(
            post.clone(),
            &format!("auth/{mount}/config"),
            Some(json!({"jwt_validation_pubkeys": [pem]})),
        )
        .await
        .unwrap();
    fx.admin
        .req(
            post.clone(),
            &format!("auth/{mount}/role/anykms"),
            Some(json!({
                "role_type": "jwt",
                "bound_audiences": ["anykms-test"],
                "user_claim": "sub",
                "token_policies": ["anykms-conformance"],
                "token_ttl": "10m",
            })),
        )
        .await
        .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let input = format!(
        "{}.{}",
        b64url.encode(br#"{"alg":"ES256","typ":"JWT"}"#),
        b64url.encode(
            json!({"sub": "anykms", "aud": "anykms-test", "iat": now, "nbf": now - 5, "exp": now + 600})
                .to_string()
        ),
    );
    let sig = fx
        .admin
        .req(
            post.clone(),
            &format!("transit/sign/{signer}"),
            Some(json!({
                "input": b64.encode(&input),
                "hash_algorithm": "sha2-256",
                "marshaling_algorithm": "jws",
            })),
        )
        .await
        .unwrap();
    let sig = sig["data"]["signature"].as_str().unwrap();
    let jwt = format!("{input}.{}", sig.rsplit(':').next().unwrap());
    let dir = std::env::temp_dir().join(format!("anykms-jwt-login-{}", fx.name));
    std::fs::create_dir_all(&dir).unwrap();
    let jwt_file = dir.join(format!("jwt-{}", std::process::id()));
    std::fs::write(&jwt_file, &jwt).unwrap();

    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(&fx.admin.addr, fx.flavor)
                .allow_loopback_http()
                .login(anykms_transit::Login::jwt("anykms", &jwt_file).mount(&mount)),
        )
        .build()
        .unwrap();
    let name = fx.create("aes256-gcm96").await.unwrap();
    let k = p.aead_key(fx.uri(&name)).unwrap();
    let ct = k.encrypt(b"logged in", b"").await.unwrap();
    assert_eq!(&*k.decrypt(&ct, b"").await.unwrap(), b"logged in");

    // A role the mount does not have: the login is refused.
    let wrong = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(&fx.admin.addr, fx.flavor)
                .allow_loopback_http()
                .login(anykms_transit::Login::jwt("nope", &jwt_file).mount(&mount)),
        )
        .build()
        .unwrap();
    let e = wrong
        .aead_key(fx.uri(&name))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert!(!format!("{e:?}").contains(&jwt), "{e:?}");

    fx.admin
        .req(reqwest::Method::DELETE, &format!("sys/auth/{mount}"), None)
        .await
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

async fn reachable(addr: &str) -> bool {
    let url = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(url))
        .await
        .is_ok_and(|r| r.is_ok())
}

fn key(name: &str) -> KeyUri {
    format!("hashivault:///transit/keys/{name}")
        .parse()
        .unwrap()
}

async fn sealed_server_is_unavailable(addr: String) {
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(addr, Flavor::Vault)
                .token("root")
                .allow_loopback_http(),
        )
        .build()
        .unwrap();
    let k = p
        .aead_key(key("sealed-key"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert!(e.is_retryable());
    assert_eq!(e.detail().and_then(|d| d.http_status), Some(503));
}

async fn tls_case(flavor: Flavor, addr: String, ca: Vec<u8>) {
    // Set up a key with the root token over the verified TLS connection itself.
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(&addr, flavor)
                .token("root")
                .ca_pem(ca.clone()),
        )
        .build()
        .unwrap();
    // Encrypting to a missing key would upsert on this fresh dev server; create the key first by
    // way of a typed handle without type check is not possible, so mount + create via HTTP.
    let admin = reqwest::Client::builder()
        .use_preconfigured_tls(
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut r = rustls::RootCertStore::empty();
                use rustls_pki_types::pem::PemObject;
                for c in rustls_pki_types::CertificateDer::pem_slice_iter(&ca) {
                    r.add(c.unwrap()).unwrap();
                }
                r
            })
            .with_no_client_auth(),
        )
        .build()
        .unwrap();
    let _ = admin
        .post(format!("{addr}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", "root")
        .json(&json!({"type":"transit"}))
        .send()
        .await;
    admin
        .post(format!("{addr}/v1/transit/keys/tls-key"))
        .header("X-Vault-Token", "root")
        .json(&json!({"type":"aes256-gcm96"}))
        .send()
        .await
        .unwrap();
    let k = p.aead_key(key("tls-key")).unwrap();
    let ct = k
        .encrypt(b"over tls", b"a")
        .await
        .expect("encrypt over verified TLS");
    assert_eq!(&*k.decrypt(&ct, b"a").await.unwrap(), b"over tls");

    // System roots do not trust the dev CA: the handshake fails, nothing is sent, and the
    // failure is a (non-retryable) configuration error naming the reason.
    let untrusted = TransitProvider::builder()
        .server("default", ServerConfig::new(&addr, flavor).token("root"))
        .build();
    if let Ok(untrusted) = untrusted {
        let e = untrusted
            .aead_key(key("tls-key"))
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        assert!(
            e.to_string()
                .contains("TLS certificate rejected: unknown issuer"),
            "{e}"
        );
    }
}

/// Pins the missing-key behaviors (verified on Vault 2.1 and OpenBao 2.7):
/// - default key-type check: the `GET keys/<name>` is a 404 → `NotFound`;
/// - `TrustCaller` with a token that lacks `create` (the recommended policy): the server's
///   existence check demands `create` → 403 `PermissionDenied`, with or without `disable_upsert`;
/// - `TrustCaller` with a token that holds `create`, on a `disable_upsert` mount → 400 "encryption
///   key not found" → `NotFound`.
async fn upsert_case(fx: Arc<TransitFixture>) {
    let flavor = fx.flavor;
    let missing = key(&format!("upsert-missing-{}", std::process::id()));
    let k = fx.provider.aead_key(&missing).unwrap();
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    let k = k.with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    let root = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(&fx.admin.addr, flavor)
                .token(fx.admin.root.clone())
                .allow_loopback_http(),
        )
        .build()
        .unwrap();
    let k = root
        .aead_key(&missing)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::NotFound
    );

    let _ = fx
        .admin
        .req(
            reqwest::Method::POST,
            "sys/mounts/transit-upsert",
            Some(json!({"type": "transit"})),
        )
        .await;
    fx.admin
        .req(
            reqwest::Method::PUT,
            "sys/policies/acl/anykms-upsert",
            Some(json!({"policy": "path \"transit-upsert/encrypt/*\" { capabilities = [\"update\"] }"})),
        )
        .await
        .unwrap();
    let tok = fx
        .admin
        .req(
            reqwest::Method::POST,
            "auth/token/create",
            Some(json!({"policies": ["anykms-upsert"], "ttl": "10m", "no_default_policy": true})),
        )
        .await
        .unwrap();
    let token = tok["auth"]["client_token"].as_str().unwrap().to_owned();
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(&fx.admin.addr, flavor)
                .token(token)
                .allow_loopback_http(),
        )
        .build()
        .unwrap();
    let uri: KeyUri = format!(
        "hashivault:///transit-upsert/keys/upsert-missing-{}",
        std::process::id()
    )
    .parse()
    .unwrap();
    let k = p
        .aead_key(&uri)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
}

async fn openbao_unknown_namespace_is_configuration(fx: Arc<TransitFixture>) {
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(&fx.admin.addr, Flavor::OpenBao)
                .token("root")
                .namespace("no-such-ns")
                .allow_loopback_http(),
        )
        .build()
        .unwrap();
    let e = p
        .aead_key(key("aes"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
}

async fn vault_ce_ignores_namespaces(fx: Arc<TransitFixture>) {
    // Documented behavior: Vault CE silently ignores X-Vault-Namespace and serves the root
    // namespace. Pinned so a future change is noticed.
    let name = fx.create("aes256-gcm96").await.unwrap();
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(&fx.admin.addr, Flavor::Vault)
                .token(fx.data_token.clone())
                .namespace("no-such-ns")
                .allow_loopback_http(),
        )
        .build()
        .unwrap();
    assert!(
        p.aead_key(key(&name))
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .is_ok()
    );
}

/// OpenBao binds AAD to data keys from 2.5 (the conformance fixture's gate: 2.4.4 lacks it,
/// 2.7.1 has it). Older servers return the key but warn about `associated_data`, which fails
/// closed as `Unsupported`.
async fn openbao_datakey_binds_aad_and_vault_refuses(fx: Arc<TransitFixture>) {
    let name = fx.create("aes256-gcm96").await.unwrap();
    let k = fx.provider.aead_key(key(&name)).unwrap();
    let res = k
        .generate_data_key(anykms_core::DataKeySpec::Aes256, b"ctx")
        .await;
    if !fx.openbao_at_least(2, 5) {
        let e = res.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        return;
    }
    let dk = res.unwrap();
    assert_eq!(
        &*k.decrypt(dk.ciphertext(), b"ctx").await.unwrap(),
        dk.plaintext()
    );
    assert_eq!(
        k.decrypt(dk.ciphertext(), b"").await.unwrap_err().kind(),
        ErrorKind::DecryptFailed
    );
}

/// Missing signing/HMAC keys are `NotFound` (with the replica-lag retry hint) even without the
/// key-type check, and structurally malformed signatures and tags are `VerificationFailed`, not
/// `Backend`. Pins the server messages in `src/errors.rs`.
async fn sign_verify_hmac_errors(fx: Arc<TransitFixture>) {
    use anykms_core::{
        Digest, HashAlgorithm, KeyVersion, MacAlgorithm, Signature, SignatureAlgorithm, Tag,
    };
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let digest = Digest::new(HashAlgorithm::Sha256, &[7u8; 32]).unwrap();
    let missing = key(&format!("missing-{}", std::process::id()));
    let not_found = |e: anykms_core::Error| {
        assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
        assert!(e.retry_hint().is_some(), "{e:?}");
    };
    let sk = fx
        .provider
        .digest_signing_key(&missing, alg)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    not_found(sk.sign_digest(&digest).await.unwrap_err());
    let sig = Signature::from_parts(alg, Some(KeyVersion::from_u64(1)), vec![0x30, 0x00]);
    not_found(sk.verify_digest(&digest, &sig).await.unwrap_err());
    let mk = fx
        .provider
        .mac_key(&missing, MacAlgorithm::HmacSha256)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    not_found(mk.mac(b"x").await.unwrap_err());

    // "supplied signature is invalid": bytes that are not a DER ECDSA signature.
    let ec = fx.create("ecdsa-p256").await.unwrap();
    let sk = fx.provider.digest_signing_key(key(&ec), alg).unwrap();
    for bytes in [vec![0u8; 3], vec![0x30, 0x00]] {
        let sig = Signature::from_parts(alg, Some(KeyVersion::from_u64(1)), bytes);
        let e = sk.verify_digest(&digest, &sig).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{e}");
    }
    // "invalid signature: version is too new".
    let good = sk.sign_digest(&digest).await.unwrap();
    let future = Signature::from_parts(alg, Some(KeyVersion::from_u64(9)), good.as_bytes());
    let e = sk.verify_digest(&digest, &future).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{e}");

    // "invalid HMAC: version is too new".
    let hm = fx.create("hmac").await.unwrap();
    let mk = fx
        .provider
        .mac_key(key(&hm), MacAlgorithm::HmacSha256)
        .unwrap();
    let tag = mk.mac(b"x").await.unwrap();
    let future = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::from_u64(9)),
        tag.as_bytes(),
    );
    let e = mk.verify_mac(b"x", &future).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{e}");
}
