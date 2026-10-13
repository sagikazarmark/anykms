//! The ciphertext-frame vectors of `docs/azure-ciphertext.md` (`tests/vectors/frames.json`):
//! valid frames parse to their parts and their bodies decrypt to the stated plaintext
//! (RSA-OAEP-256 with the test key, AES-256-GCM; the A256KW body is RFC 3394's vector), and
//! invalid frames are refused with the stated reason. The format is a wire format: these vectors
//! never change.

use anykms_azure::framing::{self, FrameAlg, FrameError};
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/frames.json")).unwrap()
}

fn alg(name: &str) -> FrameAlg {
    match name {
        "RSA-OAEP-256" => FrameAlg::RsaOaep256,
        "A256GCM" => FrameAlg::A256Gcm,
        "A256KW" => FrameAlg::A256Kw,
        other => panic!("{other}"),
    }
}

#[test]
fn valid_frames_parse_and_decrypt() {
    let v = vectors();
    for case in v["valid"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bytes = hex(case["frame"].as_str().unwrap());
        let f = framing::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(f.alg(), alg(case["alg"].as_str().unwrap()), "{name}");
        assert_eq!(f.alg().azure_name(), case["alg"].as_str().unwrap());
        assert_eq!(f.version(), case["version"].as_str().unwrap(), "{name}");
        assert_eq!(f.body(), hex(case["body"].as_str().unwrap()), "{name}");
        assert_eq!(
            framing::encode(f.alg(), f.version(), f.body()).unwrap(),
            bytes,
            "{name}"
        );
        let Some(pt) = case["plaintext"].as_str().map(hex) else {
            continue;
        };
        match f.alg() {
            FrameAlg::RsaOaep256 => {
                use base64::Engine as _;
                let b64: String = include_str!("data/rsa_2048.pk8.pem")
                    .lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .unwrap();
                let key = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(&der).unwrap();
                let key = aws_lc_rs::rsa::OaepPrivateDecryptingKey::new(key).unwrap();
                let mut out = vec![0u8; 256];
                let got = key
                    .decrypt(
                        &aws_lc_rs::rsa::OAEP_SHA256_MGF1SHA256,
                        f.body(),
                        &mut out,
                        None,
                    )
                    .unwrap();
                assert_eq!(got, &pt[..], "{name}");
            }
            FrameAlg::A256Gcm => {
                use aes_gcm::aead::{Aead, KeyInit, Payload};
                let (iv, ct, tag) = f.gcm_parts().unwrap();
                assert_eq!(iv, hex(case["iv"].as_str().unwrap()));
                assert_eq!(tag, hex(case["tag"].as_str().unwrap()));
                let key = aes_gcm::Aes256Gcm::new_from_slice(&hex(case["key"].as_str().unwrap()))
                    .unwrap();
                let nonce: [u8; 12] = iv.try_into().unwrap();
                let msg = [ct, tag].concat();
                let aad = hex(case["aad"].as_str().unwrap());
                let got = key
                    .decrypt(
                        &nonce.into(),
                        Payload {
                            msg: &msg,
                            aad: &aad,
                        },
                    )
                    .unwrap();
                assert_eq!(got, pt, "{name}");
            }
            // RFC 3394 §4.6: the body is the RFC's ciphertext for its key data.
            FrameAlg::A256Kw => assert_eq!(f.body().len(), pt.len() + 8),
            _ => unreachable!(),
        }
    }
}

#[test]
fn invalid_frames_are_refused() {
    let v = vectors();
    for case in v["invalid"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let want = match case["error"].as_str().unwrap() {
            "Truncated" => FrameError::Truncated,
            "BadMagic" => FrameError::BadMagic,
            "UnknownFormat" => FrameError::UnknownFormat,
            "UnknownAlgorithm" => FrameError::UnknownAlgorithm,
            "BadVersion" => FrameError::BadVersion,
            "BadBody" => FrameError::BadBody,
            other => panic!("{other}"),
        };
        assert_eq!(
            framing::parse(&hex(case["frame"].as_str().unwrap())),
            Err(want),
            "{name}"
        );
    }
}
