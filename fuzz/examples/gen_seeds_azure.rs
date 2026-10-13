//! Writes the committed seed corpora of the Azure targets under `fuzz/seeds/<target>/`
//! (`azure_framing`, `azure_response`, `azure_uri`). Regenerate (from `fuzz/`) with:
//!
//! ```sh
//! cargo run --example gen_seeds_azure
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anykms_azure::framing::{self, FrameAlg};

const V: &str = "0123456789abcdef0123456789abcdef";

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

fn main() {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "seeds".to_owned()),
    );

    // azure_framing: one frame per algorithm.
    let dir = root.join("azure_framing");
    write(
        &dir,
        "rsa-oaep-256",
        &framing::encode(FrameAlg::RsaOaep256, V, &[0x5a; 256]).unwrap(),
    );
    write(
        &dir,
        "a256gcm",
        &framing::encode_gcm(V, &[1; 12], b"ciphertext", &[2; 16]).unwrap(),
    );
    write(
        &dir,
        "a256kw",
        &framing::encode(FrameAlg::A256Kw, V, &[3; 40]).unwrap(),
    );

    // azure_response: the fuzz input is (status: u16, which: u8, body) as arbitrary decodes
    // it; the seeds are bodies only, which reach the targets with whatever prefix arbitrary
    // takes from them.
    let dir = root.join("azure_response");
    let kid = format!("https://kv1.vault.azure.net/keys/k/{V}");
    for (name, body) in [
        (
            "bundle-ec",
            format!(
                r#"{{"key":{{"kid":"{kid}","kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","key_ops":["sign","verify"]}},"attributes":{{"enabled":true,"created":1700000000}},"tags":{{"a":"b"}}}}"#
            ),
        ),
        (
            "bundle-oct",
            format!(
                r#"{{"key":{{"kid":"{kid}","kty":"oct-HSM","key_ops":["encrypt","decrypt"]}},"attributes":{{"enabled":false,"nbf":1,"exp":2}}}}"#
            ),
        ),
        (
            "sign",
            format!(r#"{{"kid":"{kid}","value":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}}"#),
        ),
        (
            "encrypt",
            format!(r#"{{"kid":"{kid}","value":"Q1Q","iv":"AQEBAQEBAQEBAQEB","tag":"AgICAgICAgICAgICAgICAg"}}"#),
        ),
        ("verify", r#"{"value":true}"#.to_owned()),
        (
            "error",
            r#"{"error":{"code":"Forbidden","message":"x","innererror":{"code":"ForbiddenByRbac"}}}"#
                .to_owned(),
        ),
        (
            "token",
            r#"{"token_type":"Bearer","expires_in":3599,"access_token":"eyJ0"}"#.to_owned(),
        ),
        (
            "token-error",
            r#"{"error":"invalid_client","error_description":"AADSTS7000215","error_codes":[7000215]}"#
                .to_owned(),
        ),
    ] {
        write(&dir, name, body.as_bytes());
    }

    // azure_uri: the target prepends "azure-kv:".
    let dir = root.join("azure_uri");
    for (name, s) in [
        ("vault", "//contoso.vault.azure.net/keys/app-kek".to_owned()),
        ("pinned", format!("//hsm1.managedhsm.azure.net/keys/k/{V}")),
        ("test-host", "//localhost:8443/keys/k".to_owned()),
        ("kid", format!("https://kv1.vault.azure.cn/keys/k/{V}")),
    ] {
        write(&dir, name, s.as_bytes());
    }
}
