//! `rsa_oaep_sha256_encrypt` against fixed keys (tests/vectors, made with OpenSSL):
//! - `rsa_oaep_2048.pk8.pem` / `.spki.pem`: a 2048-bit test key pair (test use only);
//! - `rsa_oaep_2048_openssl.hex`: `OpenSSL pkeyutl -encrypt` of `MSG` under that key with
//!   `rsa_padding_mode:oaep`, `rsa_oaep_md:sha256`, `rsa_mgf1_md:sha256`, which pins the
//!   decrypters below to the parameters the cloud KMSs use;
//! - `rsa_1024.spki.pem`, `ec_p256.spki.pem`: keys that must be refused.
//!
//! Whichever backend the features select encrypts; RustCrypto (always a dev-dependency) and, with
//! `rsa-aws-lc-rs`, AWS-LC decrypt, so each backend's output is checked by an independent
//! decrypter.

use anykms_core::{ErrorKind, Operation};
use anykms_recipes::{pem_to_der, rsa_oaep_sha256_encrypt};
use rsa::pkcs8::DecodePrivateKey as _;

const MSG: &[u8] = b"anykms rsa-oaep-sha256 vector";

fn spki(name: &str) -> Vec<u8> {
    let pem = std::fs::read_to_string(format!(
        "{}/tests/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    pem_to_der(&pem).unwrap()
}

fn private_pkcs8_der() -> Vec<u8> {
    use base64::Engine as _;
    let pem = include_str!("vectors/rsa_oaep_2048.pk8.pem");
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

fn decrypt_rustcrypto(ct: &[u8]) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::from_pkcs8_der(&private_pkcs8_der()).unwrap();
    key.decrypt(rsa::Oaep::<sha2::Sha256>::new(), ct).unwrap()
}

#[cfg(feature = "rsa-aws-lc-rs")]
fn decrypt_aws_lc(ct: &[u8]) -> Vec<u8> {
    use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey};
    let key = PrivateDecryptingKey::from_pkcs8(&private_pkcs8_der()).unwrap();
    let key = OaepPrivateDecryptingKey::new(key).unwrap();
    let mut out = vec![0u8; key.key_size_bytes()];
    key.decrypt(&OAEP_SHA256_MGF1SHA256, ct, &mut out, None)
        .unwrap()
        .to_vec()
}

#[test]
fn openssl_vector_decrypts_with_the_test_decrypters() {
    let ct = hex::decode(include_str!("vectors/rsa_oaep_2048_openssl.hex").trim()).unwrap();
    assert_eq!(decrypt_rustcrypto(&ct), MSG);
    #[cfg(feature = "rsa-aws-lc-rs")]
    assert_eq!(decrypt_aws_lc(&ct), MSG);
}

#[cfg(any(feature = "rsa-aws-lc-rs", feature = "rsa-rustcrypto"))]
mod with_backend {
    use super::*;

    #[test]
    fn round_trip() {
        let key = spki("rsa_oaep_2048.spki.pem");
        for msg in [&b""[..], MSG, &[0x42; 32][..], &[7u8; 256 - 66][..]] {
            let ct = rsa_oaep_sha256_encrypt(&key, msg).unwrap();
            assert_eq!(ct.len(), 256);
            assert_eq!(decrypt_rustcrypto(&ct), msg);
            #[cfg(feature = "rsa-aws-lc-rs")]
            assert_eq!(decrypt_aws_lc(&ct), msg);
        }
    }

    #[test]
    fn randomized() {
        let key = spki("rsa_oaep_2048.spki.pem");
        let a = rsa_oaep_sha256_encrypt(&key, MSG).unwrap();
        let b = rsa_oaep_sha256_encrypt(&key, MSG).unwrap();
        assert_ne!(a, b);
    }
}

#[test]
fn message_too_long() {
    let key = spki("rsa_oaep_2048.spki.pem");
    let err = rsa_oaep_sha256_encrypt(&key, &[0u8; 256 - 65]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert_eq!(err.operation(), Operation::Encrypt);
}

#[test]
fn refuses_small_and_non_rsa_keys() {
    for name in ["rsa_1024.spki.pem", "ec_p256.spki.pem"] {
        let err = rsa_oaep_sha256_encrypt(&spki(name), MSG).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KeyMismatch, "{name}");
        assert_eq!(err.operation(), Operation::Encrypt);
    }
    let err = rsa_oaep_sha256_encrypt(b"not der", MSG).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
}

#[cfg(not(any(feature = "rsa-aws-lc-rs", feature = "rsa-rustcrypto")))]
#[test]
fn unsupported_without_backend() {
    let err = rsa_oaep_sha256_encrypt(&spki("rsa_oaep_2048.spki.pem"), MSG).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}
