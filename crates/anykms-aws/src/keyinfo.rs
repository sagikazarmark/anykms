//! `DescribeKey` metadata: [`AwsKeyInfo`], the portable [`KeyInfo`] view and the key-type check.

use anykms_core::{
    AsymmetricKeyType, Capabilities, Error, ErrorKind, KeyInfo, KeyState, KeyVersion,
    KeyVersionInfo, MacAlgorithm, Operation, Result, SignatureAlgorithm,
};
use serde::Deserialize;

use crate::BACKEND;

/// AWS's description of a key (`DescribeKey`'s `KeyMetadata`), with every field anykms reads.
/// Algorithm lists are verbatim (including algorithms anykms does not map).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AwsKeyInfo {
    /// The key ARN.
    pub arn: String,
    /// The key id.
    pub key_id: String,
    /// The account.
    pub account: String,
    /// `SYMMETRIC_DEFAULT`, `RSA_2048`, `ECC_NIST_P256`, `HMAC_256`, ...
    pub key_spec: String,
    /// `ENCRYPT_DECRYPT`, `SIGN_VERIFY`, `GENERATE_VERIFY_MAC`, `KEY_AGREEMENT`.
    pub key_usage: String,
    /// `Enabled`, `Disabled`, `PendingDeletion`, `PendingImport`, `Creating`, ...
    pub key_state: String,
    /// Encryption algorithms.
    pub encryption_algorithms: Vec<String>,
    /// Signing algorithms.
    pub signing_algorithms: Vec<String>,
    /// MAC algorithms.
    pub mac_algorithms: Vec<String>,
    /// `AWS_KMS`, `EXTERNAL`, `AWS_CLOUDHSM`, `EXTERNAL_KEY_STORE`.
    pub origin: Option<String>,
    /// `CUSTOMER` or `AWS`.
    pub key_manager: Option<String>,
    /// Whether this is a multi-Region key.
    pub multi_region: Option<bool>,
    /// The custom key store, if any.
    pub custom_key_store_id: Option<String>,
    /// The current key material (symmetric keys).
    pub current_key_material_id: Option<String>,
    /// Creation time, seconds since the epoch.
    pub creation_date: Option<u64>,
    /// Scheduled deletion time, seconds since the epoch.
    pub deletion_date: Option<u64>,
    /// Expiry of imported key material, seconds since the epoch.
    pub valid_to: Option<u64>,
}

/// The wire form of `DescribeKey`'s `KeyMetadata` (kept private so that [`AwsKeyInfo`] does not
/// promise a public `Deserialize`).
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawKeyMetadata {
    arn: String,
    key_id: String,
    #[serde(rename = "AWSAccountId", default)]
    account: String,
    #[serde(default)]
    key_spec: String,
    #[serde(default)]
    key_usage: String,
    #[serde(default)]
    key_state: String,
    #[serde(default)]
    encryption_algorithms: Vec<String>,
    #[serde(default)]
    signing_algorithms: Vec<String>,
    #[serde(default)]
    mac_algorithms: Vec<String>,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    key_manager: Option<String>,
    #[serde(default)]
    multi_region: Option<bool>,
    #[serde(default)]
    custom_key_store_id: Option<String>,
    #[serde(default)]
    current_key_material_id: Option<String>,
    #[serde(default, deserialize_with = "epoch")]
    creation_date: Option<u64>,
    #[serde(default, deserialize_with = "epoch")]
    deletion_date: Option<u64>,
    #[serde(default, deserialize_with = "epoch")]
    valid_to: Option<u64>,
}

impl From<RawKeyMetadata> for AwsKeyInfo {
    fn from(r: RawKeyMetadata) -> Self {
        AwsKeyInfo {
            arn: r.arn,
            key_id: r.key_id,
            account: r.account,
            key_spec: r.key_spec,
            key_usage: r.key_usage,
            key_state: r.key_state,
            encryption_algorithms: r.encryption_algorithms,
            signing_algorithms: r.signing_algorithms,
            mac_algorithms: r.mac_algorithms,
            origin: r.origin,
            key_manager: r.key_manager,
            multi_region: r.multi_region,
            custom_key_store_id: r.custom_key_store_id,
            current_key_material_id: r.current_key_material_id,
            creation_date: r.creation_date,
            deletion_date: r.deletion_date,
            valid_to: r.valid_to,
        }
    }
}

fn epoch<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<u64>, D::Error> {
    Ok(Option::<f64>::deserialize(d)?.and_then(crate::time::epoch_number))
}

/// What a key spec is, for anykms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Spec {
    Symmetric,
    Asymmetric(AsymmetricKeyType),
    Hmac(MacAlgorithm),
    Other,
}

pub(crate) fn spec(key_spec: &str) -> Spec {
    match key_spec {
        "SYMMETRIC_DEFAULT" => Spec::Symmetric,
        "ECC_NIST_P256" => Spec::Asymmetric(AsymmetricKeyType::EcP256),
        "ECC_NIST_P384" => Spec::Asymmetric(AsymmetricKeyType::EcP384),
        "ECC_NIST_P521" => Spec::Asymmetric(AsymmetricKeyType::EcP521),
        "ECC_NIST_EDWARDS25519" => Spec::Asymmetric(AsymmetricKeyType::Ed25519),
        "RSA_2048" => Spec::Asymmetric(AsymmetricKeyType::Rsa { bits: 2048 }),
        "RSA_3072" => Spec::Asymmetric(AsymmetricKeyType::Rsa { bits: 3072 }),
        "RSA_4096" => Spec::Asymmetric(AsymmetricKeyType::Rsa { bits: 4096 }),
        "HMAC_256" => Spec::Hmac(MacAlgorithm::HmacSha256),
        "HMAC_384" => Spec::Hmac(MacAlgorithm::HmacSha384),
        "HMAC_512" => Spec::Hmac(MacAlgorithm::HmacSha512),
        _ => Spec::Other,
    }
}

/// AWS's signing algorithm name for `alg`.
pub(crate) fn aws_signing_alg(alg: SignatureAlgorithm) -> Option<&'static str> {
    use SignatureAlgorithm as S;
    Some(match alg {
        S::EcdsaP256Sha256 => "ECDSA_SHA_256",
        S::EcdsaP384Sha384 => "ECDSA_SHA_384",
        S::EcdsaP521Sha512 => "ECDSA_SHA_512",
        S::RsaPssSha256 => "RSASSA_PSS_SHA_256",
        S::RsaPssSha384 => "RSASSA_PSS_SHA_384",
        S::RsaPssSha512 => "RSASSA_PSS_SHA_512",
        S::RsaPkcs1v15Sha256 => "RSASSA_PKCS1_V1_5_SHA_256",
        S::RsaPkcs1v15Sha384 => "RSASSA_PKCS1_V1_5_SHA_384",
        S::RsaPkcs1v15Sha512 => "RSASSA_PKCS1_V1_5_SHA_512",
        S::Ed25519 => "ED25519_SHA_512",
        _ => return None,
    })
}

/// The anykms algorithm of an AWS signing algorithm name.
pub(crate) fn from_aws_signing_alg(name: &str) -> Option<SignatureAlgorithm> {
    SignatureAlgorithm::ALL
        .iter()
        .copied()
        .find(|a| aws_signing_alg(*a) == Some(name))
}

/// AWS's MAC algorithm name.
pub(crate) fn aws_mac_alg(alg: MacAlgorithm) -> Option<&'static str> {
    Some(match alg {
        MacAlgorithm::HmacSha256 => "HMAC_SHA_256",
        MacAlgorithm::HmacSha384 => "HMAC_SHA_384",
        MacAlgorithm::HmacSha512 => "HMAC_SHA_512",
        _ => return None,
    })
}

/// The RSA-OAEP algorithm anykms uses (SHA-1 OAEP is never used).
pub(crate) const RSA_OAEP: &str = "RSAES_OAEP_SHA_256";

fn mismatch(m: &'static str) -> Error {
    Error::new(ErrorKind::KeyMismatch, BACKEND, Operation::Open, m)
}

impl AwsKeyInfo {
    /// Parses a `DescribeKey` response body.
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(rename = "KeyMetadata")]
            key_metadata: RawKeyMetadata,
        }
        serde_json::from_slice::<Resp>(body)
            .ok()
            .map(|r| AwsKeyInfo::from(r.key_metadata))
            .filter(|k| crate::uri::is_key_arn(&k.arn))
            .ok_or_else(|| {
                crate::errors::unusable_response(
                    Operation::Describe,
                    Some(200),
                    "unexpected key metadata format",
                )
            })
    }

    pub(crate) fn spec(&self) -> Spec {
        spec(&self.key_spec)
    }

    /// The portable view.
    pub fn to_key_info(&self) -> KeyInfo {
        let usage = self.key_usage.as_str();
        let caps = match (self.spec(), usage) {
            (Spec::Symmetric, "ENCRYPT_DECRYPT") => {
                Capabilities::AEAD
                    | Capabilities::REWRAP
                    | Capabilities::DATA_KEYS
                    | Capabilities::KEY_WRAP
            }
            (Spec::Asymmetric(AsymmetricKeyType::Rsa { .. }), "ENCRYPT_DECRYPT")
                if self.encryption_algorithms.iter().any(|a| a == RSA_OAEP) =>
            {
                Capabilities::KEY_WRAP | Capabilities::REWRAP | Capabilities::PUBLIC_KEY
            }
            (Spec::Asymmetric(_), "SIGN_VERIFY") => {
                Capabilities::SIGN | Capabilities::VERIFY | Capabilities::PUBLIC_KEY
            }
            (Spec::Hmac(_), "GENERATE_VERIFY_MAC") => Capabilities::MAC,
            _ => Capabilities::NONE,
        };
        let state = match self.key_state.as_str() {
            "Enabled" => KeyState::Enabled,
            "Disabled" => KeyState::Disabled,
            "PendingDeletion" => KeyState::PendingDeletion,
            other => KeyState::Unknown(other.to_owned()),
        };
        let mut info = KeyInfo::new(self.key_spec.clone(), caps)
            .with_signature_algorithms(
                self.signing_algorithms
                    .iter()
                    .filter_map(|a| from_aws_signing_alg(a))
                    .collect(),
            )
            .with_mac_algorithm(match self.spec() {
                Spec::Hmac(m) => Some(m),
                _ => None,
            })
            .with_state(Some(state.clone()));
        // One version, the key ARN: a key's versions are its ARN (signatures, tags and public
        // keys carry it). Symmetric keys list it but name no primary version: their ciphertexts
        // reveal none, and rotation changes key material inside the same ARN.
        let v = KeyVersion::new(self.arn.as_str());
        if !matches!(self.spec(), Spec::Symmetric) {
            info = info.with_primary_version(Some(v.clone()));
        }
        info.with_versions(vec![
            KeyVersionInfo::new(v, state).with_created_at(self.creation_date),
        ])
        .with_backend_info(self.clone())
    }

    /// The key-type check of an AEAD handle.
    pub(crate) fn check_aead(&self) -> Result<()> {
        if self.spec() == Spec::Symmetric && self.key_usage == "ENCRYPT_DECRYPT" {
            Ok(())
        } else {
            Err(mismatch(
                "the AWS key is not a symmetric encryption key (SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT)",
            ))
        }
    }

    /// The key-type check of a signing handle for `alg`.
    pub(crate) fn check_signing(&self, alg: SignatureAlgorithm) -> Result<()> {
        let Spec::Asymmetric(t) = self.spec() else {
            return Err(mismatch("the AWS key is not an asymmetric signing key"));
        };
        if self.key_usage != "SIGN_VERIFY" {
            return Err(mismatch("the AWS key's usage is not SIGN_VERIFY"));
        }
        if !alg.is_compatible_with(&t) {
            return Err(mismatch(
                "the AWS key's type does not match the signature algorithm",
            ));
        }
        let name =
            aws_signing_alg(alg).ok_or_else(|| mismatch("unsupported signature algorithm"))?;
        if !self.signing_algorithms.iter().any(|a| a == name) {
            return Err(mismatch(
                "the AWS key does not allow this signing algorithm",
            ));
        }
        Ok(())
    }

    /// The key-type check of a MAC handle for `alg`.
    pub(crate) fn check_mac(&self, alg: MacAlgorithm) -> Result<()> {
        if self.spec() != Spec::Hmac(alg) || self.key_usage != "GENERATE_VERIFY_MAC" {
            return Err(mismatch(
                "the AWS key is not an HMAC key for this algorithm",
            ));
        }
        let name = aws_mac_alg(alg).ok_or_else(|| mismatch("unsupported MAC algorithm"))?;
        if !self.mac_algorithms.is_empty() && !self.mac_algorithms.iter().any(|a| a == name) {
            return Err(mismatch("the AWS key does not allow this MAC algorithm"));
        }
        Ok(())
    }

    /// The key-type check of an RSA-OAEP key-wrapping handle.
    pub(crate) fn check_rsa_wrap(&self) -> Result<()> {
        match self.spec() {
            Spec::Asymmetric(AsymmetricKeyType::Rsa { .. })
                if self.key_usage == "ENCRYPT_DECRYPT" => {}
            _ => return Err(mismatch("the AWS key is not an RSA encryption key")),
        }
        if !self.encryption_algorithms.iter().any(|a| a == RSA_OAEP) {
            return Err(mismatch(
                "the AWS key does not allow RSAES_OAEP_SHA_256 (SHA-1 OAEP is not used)",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/4cc22e1e-aa03-4374-81d2-b45946154992";

    fn info(spec: &str, usage: &str, extra: &str) -> AwsKeyInfo {
        AwsKeyInfo::parse(
            format!(
                r#"{{"KeyMetadata":{{"Arn":"{ARN}","KeyId":"k","AWSAccountId":"111122223333","KeySpec":"{spec}","KeyUsage":"{usage}","KeyState":"Enabled","CreationDate":1791246089.5,"NewField":1{extra}}}}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn maps_and_checks() {
        let sym = info(
            "SYMMETRIC_DEFAULT",
            "ENCRYPT_DECRYPT",
            r#","EncryptionAlgorithms":["SYMMETRIC_DEFAULT"]"#,
        );
        assert!(sym.check_aead().is_ok());
        let ki = sym.to_key_info();
        assert!(
            ki.capabilities()
                .contains(Capabilities::AEAD | Capabilities::KEY_WRAP)
        );
        assert!(ki.primary_version().is_none());
        assert_eq!(ki.state(), Some(&KeyState::Enabled));
        assert_eq!(sym.creation_date, Some(1_791_246_089));

        let ec = info(
            "ECC_NIST_P256",
            "SIGN_VERIFY",
            r#","SigningAlgorithms":["ECDSA_SHA_256"]"#,
        );
        assert!(
            ec.check_signing(SignatureAlgorithm::EcdsaP256Sha256)
                .is_ok()
        );
        assert!(
            ec.check_signing(SignatureAlgorithm::EcdsaP384Sha384)
                .is_err()
        );
        assert!(ec.check_aead().is_err());
        let ki = ec.to_key_info();
        assert_eq!(
            ki.signature_algorithms(),
            &[SignatureAlgorithm::EcdsaP256Sha256]
        );
        assert_eq!(ki.primary_version().unwrap().as_str(), ARN);
        assert_eq!(ki.versions()[0].created_at(), Some(1_791_246_089));

        let rsa = info(
            "RSA_2048",
            "SIGN_VERIFY",
            r#","SigningAlgorithms":["RSASSA_PSS_SHA_256","RSASSA_PKCS1_V1_5_SHA_512","SM2DSA"]"#,
        );
        assert!(rsa.check_signing(SignatureAlgorithm::RsaPssSha256).is_ok());
        assert!(rsa.check_signing(SignatureAlgorithm::RsaPssSha384).is_err());
        assert_eq!(rsa.to_key_info().signature_algorithms().len(), 2);

        let ed = info(
            "ECC_NIST_EDWARDS25519",
            "SIGN_VERIFY",
            r#","SigningAlgorithms":["ED25519_SHA_512","ED25519_PH_SHA_512"]"#,
        );
        assert!(ed.check_signing(SignatureAlgorithm::Ed25519).is_ok());
        assert!(
            ed.check_signing(SignatureAlgorithm::EcdsaP256Sha256)
                .is_err()
        );

        let mac = info(
            "HMAC_384",
            "GENERATE_VERIFY_MAC",
            r#","MacAlgorithms":["HMAC_SHA_384"]"#,
        );
        assert!(mac.check_mac(MacAlgorithm::HmacSha384).is_ok());
        assert!(mac.check_mac(MacAlgorithm::HmacSha256).is_err());
        assert_eq!(
            mac.to_key_info().mac_algorithm(),
            Some(MacAlgorithm::HmacSha384)
        );

        let wrap = info(
            "RSA_3072",
            "ENCRYPT_DECRYPT",
            r#","EncryptionAlgorithms":["RSAES_OAEP_SHA_1","RSAES_OAEP_SHA_256"]"#,
        );
        assert!(wrap.check_rsa_wrap().is_ok());
        assert!(
            wrap.to_key_info()
                .capabilities()
                .contains(Capabilities::KEY_WRAP)
        );
        let sha1 = info(
            "RSA_3072",
            "ENCRYPT_DECRYPT",
            r#","EncryptionAlgorithms":["RSAES_OAEP_SHA_1"]"#,
        );
        assert!(sha1.check_rsa_wrap().is_err());

        let other = info("ECC_SECG_P256K1", "SIGN_VERIFY", "");
        assert!(
            other
                .check_signing(SignatureAlgorithm::EcdsaP256Sha256)
                .is_err()
        );
        assert!(other.to_key_info().capabilities().is_empty());
        let mut pending = info("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "");
        pending.key_state = "PendingImport".into();
        assert_eq!(
            pending.to_key_info().state(),
            Some(&KeyState::Unknown("PendingImport".into()))
        );
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            &b"{}"[..],
            br#"{"KeyMetadata":{"Arn":"x","KeyId":"k"}}"#,
            b"nope",
        ] {
            assert_eq!(
                AwsKeyInfo::parse(bad).unwrap_err().kind(),
                ErrorKind::Backend
            );
        }
    }

    #[test]
    fn algorithm_names_round_trip() {
        for a in SignatureAlgorithm::ALL {
            if let Some(n) = aws_signing_alg(*a) {
                assert_eq!(from_aws_signing_alg(n), Some(*a));
            }
        }
    }
}
