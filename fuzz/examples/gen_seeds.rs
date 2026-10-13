//! Writes the committed seed corpora under `fuzz/seeds/<target>/`.
//!
//! Without seeds, `envelope_parse` and the decode half of `core_values` rarely get past the
//! 3-byte magic (`AKE`, `AKS`/`AKT`). The seeds are real encodings produced by the crates' own
//! APIs. Regenerate (from `fuzz/`) with:
//!
//! ```sh
//! cargo run --example gen_seeds
//! ```
//!
//! Key material is random, so regenerating changes the bytes but not the structure.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use anykms_core::encoding::{encode_signature, encode_tag};
use anykms_core::{Aead, KeyVersion, MacAlgorithm, Signature, SignatureAlgorithm, Tag};
use anykms_local::LocalKeyset;
use anykms_recipes::{Envelope, EnvelopeAead};

/// Local keys never suspend, so their futures complete on the first poll.
fn ready<T>(f: impl Future<Output = T>) -> T {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("local future suspended"),
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

/// Hex strings of `"envelope": "<hex>"` entries in the committed test vectors.
fn vector_envelopes(json: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = json;
    let mut n = 0;
    while let Some(i) = rest.find("\"envelope\": \"") {
        rest = &rest[i + 13..];
        let end = rest.find('"').unwrap();
        let hex = &rest[..end];
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        out.push((format!("vector-{n:02}"), bytes));
        n += 1;
        rest = &rest[end..];
    }
    out
}

fn main() {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "seeds".to_owned()),
    );
    let ks = LocalKeyset::builder().aead("kek").build();
    let kek = ks.aead_key("kek");

    // envelope_parse: real envelopes, the committed vectors, and a transit-style slot.
    let dir = root.join("envelope_parse");
    let long_id = "k".repeat(255);
    for (name, kek_id, pt) in [
        ("local-empty", "app-kek", &b""[..]),
        ("local-short", "app-kek", b"hello"),
        ("local-no-kek-id", "", b"payload"),
        ("local-long-kek-id", long_id.as_str(), b"payload"),
        ("local-1k", "app-kek", &[0x5a; 1024][..]),
    ] {
        let env = EnvelopeAead::new(kek_id, (&kek).into_key_wrap()).unwrap();
        let ct = ready(env.encrypt(pt, b"row-1")).unwrap();
        write(&dir, name, ct.as_bytes());
    }
    let ct = ready(
        EnvelopeAead::new("app-kek", (&kek).into_key_wrap())
            .unwrap()
            .encrypt(b"x", b""),
    )
    .unwrap();
    let parsed = Envelope::parse(ct.as_bytes()).unwrap();
    let slot = b"vault:v3:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2";
    let mut transit = ct.as_bytes()[..49].to_vec();
    transit.push(7);
    transit.extend_from_slice(b"app-kek");
    transit.extend_from_slice(&(slot.len() as u16).to_be_bytes());
    transit.extend_from_slice(slot);
    transit.extend_from_slice(parsed.payload());
    Envelope::parse(&transit).unwrap();
    write(&dir, "transit-slot", &transit);
    let vectors = include_str!("../../crates/anykms-recipes/tests/vectors/envelope_v1.json");
    for (name, bytes) in vector_envelopes(vectors) {
        write(&dir, &name, &bytes);
    }

    // core_values: input is (selector u8, rest); the rest feeds Digest::new and both decoders.
    let dir = root.join("core_values");
    for (i, alg) in SignatureAlgorithm::ALL.iter().copied().enumerate() {
        for (vname, version) in [
            ("v1", Some(KeyVersion::from(1))),
            ("v12", Some(KeyVersion::from(12))),
            ("unversioned", None),
            (
                "opaque",
                Some(KeyVersion::new("0123456789abcdef0123456789abcdef")),
            ),
        ] {
            let sig = Signature::from_parts(alg, version, vec![0x30, 0x44, 0x02, 0x20, 0xab]);
            let mut seed = vec![i as u8];
            seed.extend_from_slice(&encode_signature(&sig).unwrap());
            write(&dir, &format!("sig-{}-{vname}", alg.as_str()), &seed);
        }
    }
    for (i, alg) in MacAlgorithm::ALL.iter().copied().enumerate() {
        for (vname, version) in [("v1", Some(KeyVersion::from(1))), ("unversioned", None)] {
            let tag = Tag::from_parts(alg, version, vec![0x11; alg.tag_len()]);
            let mut seed = vec![i as u8];
            seed.extend_from_slice(&encode_tag(&tag).unwrap());
            write(&dir, &format!("tag-{}-{vname}", alg.as_str()), &seed);
        }
    }
    for (sel, len) in [(0u8, 32usize), (1, 48), (2, 64)] {
        let mut seed = vec![sel];
        seed.extend(std::iter::repeat_n(0x42, len));
        write(&dir, &format!("digest-{len}"), &seed);
    }

    // local_framing: real local ciphertexts, before and after rotation.
    let dir = root.join("local_framing");
    for (name, pt) in [("v1-empty", &b""[..]), ("v1-short", b"hello")] {
        write(&dir, name, ready(kek.encrypt(pt, b"")).unwrap().as_bytes());
    }
    ks.rotate("kek").unwrap();
    for _ in 0..10 {
        ks.rotate("kek").unwrap();
    }
    write(
        &dir,
        "v12-short",
        ready(kek.encrypt(b"hello", b"aad")).unwrap().as_bytes(),
    );

    // transit_success: input is [which, body]; which % 6 = encrypt/rewrap, decrypt, datakey,
    // sign, verify, hmac, and which / 6 picks the algorithm. Bodies as transit returns them.
    let dir = root.join("transit_success");
    let wrap = |data: &str| {
        format!(
            r#"{{"request_id":"7d5b6c0e-0000-0000-0000-000000000000","lease_id":"","renewable":false,"lease_duration":0,"data":{data},"wrap_info":null,"warnings":null,"auth":null}}"#
        )
    };
    let ct = r#""vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==""#;
    let p256 = format!(
        "vault:v3:{}",
        b64([
            &[0x30u8, 0x44, 0x02, 0x20][..],
            &[0x11; 32],
            &[0x02, 0x20],
            &[0x22; 32]
        ]
        .concat())
    );
    let ed_sig = format!("vault:v2:{}", b64([0x33u8; 64]));
    let hmac = format!("vault:v1:{}", b64([0x44u8; 32]));
    let dek = b64([0x55u8; 32]);
    let ed_which = 3 + 6 * alg_index(SignatureAlgorithm::Ed25519);
    for (name, which, data) in [
        (
            "encrypt",
            0u8,
            format!(r#"{{"ciphertext":{ct},"key_version":1}}"#),
        ),
        ("decrypt", 1, r#"{"plaintext":"aGVsbG8="}"#.to_owned()),
        (
            "datakey",
            2,
            format!(r#"{{"plaintext":"{dek}","ciphertext":{ct},"key_version":1}}"#),
        ),
        (
            "sign-p256",
            3 + 6 * alg_index(SignatureAlgorithm::EcdsaP256Sha256),
            format!(r#"{{"signature":"{p256}","key_version":3}}"#),
        ),
        (
            "sign-ed25519",
            ed_which,
            format!(r#"{{"signature":"{ed_sig}","key_version":2}}"#),
        ),
        ("verify", 4, r#"{"valid":true}"#.to_owned()),
        ("hmac", 5, format!(r#"{{"hmac":"{hmac}","key_version":1}}"#)),
    ] {
        let mut seed = vec![which];
        seed.extend_from_slice(wrap(&data).as_bytes());
        write(&dir, name, &seed);
    }
}

/// Standard, padded base64 (as transit returns it).
fn b64(data: impl AsRef<[u8]>) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.as_ref().chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn alg_index(alg: SignatureAlgorithm) -> u8 {
    SignatureAlgorithm::ALL
        .iter()
        .position(|a| *a == alg)
        .unwrap() as u8
}
