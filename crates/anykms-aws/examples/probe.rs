//! The A0 live probe (docs/cloud/aws.md §14): records the AWS KMS behaviors the backend pins,
//! as raw responses, into a directory of JSON files. Run it through `scripts/probe-aws.sh`.
//!
//! It creates throwaway keys (tagged `anykms-probe`) and schedules them for deletion (7 days)
//! at the end. Needs credentials of the default chain allowed to `kms:CreateKey`,
//! `kms:TagResource`, `kms:CreateAlias`/`DeleteAlias`, `kms:DisableKey`,
//! `kms:ScheduleKeyDeletion`, `kms:RotateKeyOnDemand` and the data-plane actions.
//!
//! Environment: `ANYKMS_PROBE_REGION` (else `AWS_REGION`), `ANYKMS_PROBE_OUT` (output
//! directory), `ANYKMS_PROBE_ENDPOINT` (an emulator, with `http://` loopback allowed), optional
//! `ANYKMS_PROBE_DENIED_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` for the AccessDenied case.

use std::path::PathBuf;

use anykms_aws::__test::Admin;
use anykms_aws::credentials::StaticCredentials;
use anykms_aws::{AwsProvider, AwsProviderBuilder, Credentials};
use base64::Engine as _;
use serde_json::{Value, json};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

struct Probe {
    admin: Admin,
    endpoint: String,
    region: String,
    out: PathBuf,
    keys: Vec<String>,
}

impl Probe {
    /// Sends one request and records it as `<name>.json`: request, status, headers, body.
    async fn record(&self, name: &str, target: &'static str, body: Value) -> (u16, Value) {
        self.record_with(&self.admin, name, target, body).await
    }

    async fn record_with(
        &self,
        admin: &Admin,
        name: &str,
        target: &'static str,
        body: Value,
    ) -> (u16, Value) {
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, headers, resp) = match admin
            .raw(&self.endpoint, &self.region, target, &bytes)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let v = json!({"target": target, "transport_error": e.to_string()});
                std::fs::write(
                    self.out.join(format!("{name}.json")),
                    serde_json::to_vec_pretty(&v).unwrap(),
                )
                .unwrap();
                return (0, Value::Null);
            }
        };
        let parsed: Value = serde_json::from_slice(&resp)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&resp)}));
        let keep = [
            "x-amzn-requestid",
            "x-amzn-errortype",
            "retry-after",
            "content-type",
            "date",
            "x-amzn-query-error",
        ];
        let headers: serde_json::Map<String, Value> = headers
            .into_iter()
            .filter(|(k, _)| keep.contains(&k.as_str()))
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
        // Plaintexts and data keys in responses are probe values, not secrets.
        let v = json!({"target": target, "request": body, "status": status, "headers": headers, "body": parsed});
        std::fs::write(
            self.out.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&v).unwrap(),
        )
        .unwrap();
        println!(
            "{name}: {status} {}",
            parsed.get("__type").and_then(Value::as_str).unwrap_or("")
        );
        (status, parsed)
    }

    async fn create(&mut self, spec: &str, usage: &str) -> String {
        let (_, r) = self
            .record(
                &format!("create-{spec}-{usage}").to_lowercase(),
                "CreateKey",
                json!({"KeySpec": spec, "KeyUsage": usage, "Description": "anykms A0 probe", "Tags": [{"TagKey": "anykms-probe", "TagValue": "1"}]}),
            )
            .await;
        let arn = r["KeyMetadata"]["Arn"]
            .as_str()
            .expect("CreateKey failed; see its JSON")
            .to_owned();
        self.keys.push(arn.clone());
        arn
    }
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() {
    let region = env("ANYKMS_PROBE_REGION")
        .or_else(|| env("AWS_REGION"))
        .expect("ANYKMS_PROBE_REGION or AWS_REGION");
    let out = PathBuf::from(env("ANYKMS_PROBE_OUT").unwrap_or_else(|| "aws-probe".into()));
    std::fs::create_dir_all(&out).unwrap();
    let (builder, endpoint) = match env("ANYKMS_PROBE_ENDPOINT") {
        Some(e) => (
            AwsProviderBuilder::from_env()
                .unwrap()
                .endpoint_url(&e)
                .allow_loopback_http(),
            e,
        ),
        None => (
            AwsProviderBuilder::from_env().unwrap(),
            format!("https://kms.{region}.amazonaws.com/"),
        ),
    };
    let provider = builder.build().unwrap();
    let mut p = Probe {
        admin: provider.__admin(),
        endpoint: endpoint.clone(),
        region: region.clone(),
        out,
        keys: Vec::new(),
    };

    let sym = p.create("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT").await;
    let sym2 = p.create("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT").await;
    let ec = p.create("ECC_NIST_P256", "SIGN_VERIFY").await;
    let ed = p.create("ECC_NIST_EDWARDS25519", "SIGN_VERIFY").await;
    let hmac = p.create("HMAC_256", "GENERATE_VERIFY_MAC").await;
    let rsa = p.create("RSA_2048", "ENCRYPT_DECRYPT").await;
    let account = sym.split(':').nth(4).unwrap().to_owned();
    for (n, k) in [
        ("symmetric", &sym),
        ("ecc", &ec),
        ("ed25519", &ed),
        ("hmac", &hmac),
        ("rsa-encrypt", &rsa),
    ] {
        p.record(&format!("describe-{n}"), "DescribeKey", json!({"KeyId": k}))
            .await;
    }

    // 1. The encryption-context size limit: the largest single value accepted (binary search).
    let (mut lo, mut hi) = (1usize, 65_536usize);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let body = json!({"KeyId": sym, "Plaintext": B64.encode(b"x"), "EncryptionContext": {"associatedData": "a".repeat(mid)}});
        let bytes = serde_json::to_vec(&body).unwrap();
        let (status, _, _) = p
            .admin
            .raw(&endpoint, &region, "Encrypt", &bytes)
            .await
            .unwrap();
        if status == 200 {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    std::fs::write(
        p.out.join("context-limit.json"),
        serde_json::to_vec_pretty(&json!({"largest_associated_data_value_chars": lo})).unwrap(),
    )
    .unwrap();
    println!("context limit: largest accepted associatedData value = {lo} chars");
    p.record("context-over-limit", "Encrypt", json!({"KeyId": sym, "Plaintext": B64.encode(b"x"), "EncryptionContext": {"associatedData": "a".repeat(lo + 1)}})).await;

    // 2. KeyId formats through an alias.
    let alias = format!("alias/anykms-probe-{}", std::process::id());
    p.record(
        "create-alias",
        "CreateAlias",
        json!({"AliasName": alias, "TargetKeyId": ec}),
    )
    .await;
    let alias_arn = format!("arn:aws:kms:{region}:{account}:{alias}");
    let digest = B64.encode([7u8; 32]);
    let (_, sig) = p.record("sign-via-alias", "Sign", json!({"KeyId": alias_arn, "Message": digest, "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256"})).await;
    p.record(
        "get-public-key-via-alias",
        "GetPublicKey",
        json!({"KeyId": alias_arn}),
    )
    .await;
    p.record("delete-alias", "DeleteAlias", json!({"AliasName": alias}))
        .await;
    let mac_alias = format!("alias/anykms-probe-mac-{}", std::process::id());
    p.record(
        "create-mac-alias",
        "CreateAlias",
        json!({"AliasName": mac_alias, "TargetKeyId": hmac}),
    )
    .await;
    let (_, mac) = p.record("generate-mac-via-alias", "GenerateMac", json!({"KeyId": format!("arn:aws:kms:{region}:{account}:{mac_alias}"), "Message": B64.encode(b"m"), "MacAlgorithm": "HMAC_SHA_256"})).await;
    p.record(
        "delete-mac-alias",
        "DeleteAlias",
        json!({"AliasName": mac_alias}),
    )
    .await;

    // 3. Verification failures: exception or SignatureValid=false?
    let mut bad_sig = B64
        .decode(sig["Signature"].as_str().unwrap_or("AAAA"))
        .unwrap_or_default();
    if let Some(b) = bad_sig.last_mut() {
        *b ^= 1;
    }
    p.record("verify-bad-signature", "Verify", json!({"KeyId": ec, "Message": digest, "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256", "Signature": B64.encode(&bad_sig)})).await;
    let mut bad_mac = B64
        .decode(mac["Mac"].as_str().unwrap_or("AAAA"))
        .unwrap_or_default();
    if let Some(b) = bad_mac.last_mut() {
        *b ^= 1;
    }
    p.record("verify-mac-bad", "VerifyMac", json!({"KeyId": hmac, "Message": B64.encode(b"m"), "MacAlgorithm": "HMAC_SHA_256", "Mac": B64.encode(&bad_mac)})).await;

    // 4. Input limits.
    p.record(
        "encrypt-empty",
        "Encrypt",
        json!({"KeyId": sym, "Plaintext": ""}),
    )
    .await;
    p.record(
        "encrypt-4097",
        "Encrypt",
        json!({"KeyId": sym, "Plaintext": B64.encode([1u8; 4097])}),
    )
    .await;
    p.record("sign-ed25519-raw-4096", "Sign", json!({"KeyId": ed, "Message": B64.encode([1u8; 4096]), "MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512"})).await;
    p.record("sign-ed25519-raw-4097", "Sign", json!({"KeyId": ed, "Message": B64.encode([1u8; 4097]), "MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512"})).await;
    p.record("sign-ed25519-raw-empty", "Sign", json!({"KeyId": ed, "Message": "", "MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512"})).await;
    p.record(
        "generate-mac-4097",
        "GenerateMac",
        json!({"KeyId": hmac, "Message": B64.encode([1u8; 4097]), "MacAlgorithm": "HMAC_SHA_256"}),
    )
    .await;
    p.record(
        "generate-mac-empty",
        "GenerateMac",
        json!({"KeyId": hmac, "Message": "", "MacAlgorithm": "HMAC_SHA_256"}),
    )
    .await;

    // 5. Every error of the mapping table that a probe can provoke.
    let (_, ct) = p.record("encrypt-ok", "Encrypt", json!({"KeyId": sym, "Plaintext": B64.encode(b"x"), "EncryptionContext": {"associatedData": "61"}})).await;
    let blob = ct["CiphertextBlob"].as_str().unwrap_or("").to_owned();
    p.record(
        "decrypt-ok",
        "Decrypt",
        json!({"KeyId": sym, "CiphertextBlob": blob, "EncryptionContext": {"associatedData": "61"}}),
    )
    .await;
    p.record(
        "decrypt-wrong-context",
        "Decrypt",
        json!({"KeyId": sym, "CiphertextBlob": blob, "EncryptionContext": {"associatedData": "62"}}),
    )
    .await;
    p.record(
        "decrypt-other-key",
        "Decrypt",
        json!({"KeyId": sym2, "CiphertextBlob": blob, "EncryptionContext": {"associatedData": "61"}}),
    )
    .await;
    let mut tampered = B64.decode(&blob).unwrap_or_default();
    if let Some(b) = tampered.last_mut() {
        *b ^= 1;
    }
    p.record("decrypt-tampered", "Decrypt", json!({"KeyId": sym, "CiphertextBlob": B64.encode(&tampered), "EncryptionContext": {"associatedData": "61"}})).await;
    p.record("reencrypt", "ReEncrypt", json!({"CiphertextBlob": blob, "SourceKeyId": sym, "DestinationKeyId": sym, "SourceEncryptionContext": {"associatedData": "61"}, "DestinationEncryptionContext": {"associatedData": "61"}})).await;
    let missing =
        format!("arn:aws:kms:{region}:{account}:key/00000000-0000-0000-0000-000000000000");
    p.record(
        "not-found",
        "Encrypt",
        json!({"KeyId": missing, "Plaintext": B64.encode(b"x")}),
    )
    .await;
    p.record("invalid-key-usage", "Sign", json!({"KeyId": sym, "Message": digest, "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256"})).await;
    p.record(
        "invalid-arn",
        "Encrypt",
        json!({"KeyId": "arn:aws:kms:nowhere", "Plaintext": B64.encode(b"x")}),
    )
    .await;
    p.record(
        "invalid-grant-token",
        "Encrypt",
        json!({"KeyId": sym, "Plaintext": B64.encode(b"x"), "GrantTokens": ["not-a-grant-token"]}),
    )
    .await;
    p.record(
        "unsupported-operation",
        "RotateKeyOnDemand",
        json!({"KeyId": ec}),
    )
    .await;
    p.record("unknown-operation", "NoSuchOperation", json!({}))
        .await;
    p.record("malformed-json", "Encrypt", json!("not an object"))
        .await;
    p.record("rsa-oaep-sha256", "Encrypt", json!({"KeyId": rsa, "Plaintext": B64.encode([3u8; 32]), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"})).await;
    p.record("rsa-with-context", "Encrypt", json!({"KeyId": rsa, "Plaintext": B64.encode([3u8; 32]), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256", "EncryptionContext": {"a": "b"}})).await;
    p.record("ed25519-ph-digest", "Sign", json!({"KeyId": ed, "Message": B64.encode([1u8; 64]), "MessageType": "DIGEST", "SigningAlgorithm": "ED25519_PH_SHA_512"})).await;

    // Disabled and pending-deletion keys.
    p.record("disable", "DisableKey", json!({"KeyId": sym2}))
        .await;
    p.record(
        "encrypt-disabled",
        "Encrypt",
        json!({"KeyId": sym2, "Plaintext": B64.encode(b"x")}),
    )
    .await;
    p.record("sign-disabled-setup", "DisableKey", json!({"KeyId": ed}))
        .await;
    p.record("sign-disabled", "Sign", json!({"KeyId": ed, "Message": B64.encode(b"m"), "MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512"})).await;
    p.record(
        "schedule-deletion-sym2",
        "ScheduleKeyDeletion",
        json!({"KeyId": sym2, "PendingWindowInDays": 7}),
    )
    .await;
    p.record(
        "encrypt-pending-deletion",
        "Encrypt",
        json!({"KeyId": sym2, "Plaintext": B64.encode(b"x")}),
    )
    .await;
    p.keys.retain(|k| *k != sym2);

    // Credentials: unknown access key, wrong secret, clock skew.
    let bogus = AwsProvider::builder()
        .credentials(StaticCredentials::new(Credentials::new(
            "AKIAAAAAAAAAAAAAAAAA",
            "wrongsecret",
            None,
        )))
        .endpoint_url(&endpoint)
        .allow_loopback_http()
        .build()
        .unwrap()
        .__admin();
    p.record_with(
        &bogus,
        "unrecognized-client",
        "Encrypt",
        json!({"KeyId": sym, "Plaintext": B64.encode(b"x")}),
    )
    .await;
    if let (Some(id), Some(_)) = (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY")) {
        let wrong = AwsProvider::builder()
            .credentials(StaticCredentials::new(Credentials::new(
                id,
                "wrong-secret",
                env("AWS_SESSION_TOKEN"),
            )))
            .endpoint_url(&endpoint)
            .allow_loopback_http()
            .build()
            .unwrap()
            .__admin();
        p.record_with(
            &wrong,
            "invalid-signature",
            "Encrypt",
            json!({"KeyId": sym, "Plaintext": B64.encode(b"x")}),
        )
        .await;
    }
    p.admin.set_clock_offset(-30 * 60 * 1000);
    p.record(
        "clock-skew-30min-behind",
        "Encrypt",
        json!({"KeyId": sym, "Plaintext": B64.encode(b"x")}),
    )
    .await;
    p.admin.set_clock_offset(0);
    if let (Some(id), Some(secret)) = (
        env("ANYKMS_PROBE_DENIED_ACCESS_KEY_ID"),
        env("ANYKMS_PROBE_DENIED_SECRET_ACCESS_KEY"),
    ) {
        let denied = AwsProvider::builder()
            .credentials(StaticCredentials::new(Credentials::new(
                id,
                secret,
                env("ANYKMS_PROBE_DENIED_SESSION_TOKEN"),
            )))
            .endpoint_url(&endpoint)
            .allow_loopback_http()
            .build()
            .unwrap()
            .__admin();
        p.record_with(
            &denied,
            "access-denied",
            "Encrypt",
            json!({"KeyId": sym, "Plaintext": B64.encode(b"x")}),
        )
        .await;
    }

    // Clean up: every probe key is scheduled for deletion.
    for k in std::mem::take(&mut p.keys) {
        let _ = p
            .admin
            .call(
                &endpoint,
                &region,
                "ScheduleKeyDeletion",
                &json!({"KeyId": k, "PendingWindowInDays": 7}),
            )
            .await;
    }
    println!("recorded into {}", p.out.display());
}
