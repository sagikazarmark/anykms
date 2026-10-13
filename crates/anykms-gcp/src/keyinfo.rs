//! Key metadata (`cryptoKeys.get` plus `cryptoKeyVersions.list`) and the algorithm mapping.

use anykms_core::{
    AsymmetricKeyType, Capabilities, KeyInfo, KeyState, KeyVersion, KeyVersionInfo, MacAlgorithm,
    SignatureAlgorithm,
};
use serde::Deserialize;

/// What a Cloud KMS `CryptoKeyVersionAlgorithm` is to anykms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alg {
    /// `GOOGLE_SYMMETRIC_ENCRYPTION`, `EXTERNAL_SYMMETRIC_ENCRYPTION`.
    Aead,
    /// A signing algorithm, with the key type its public key must have.
    Sign(SignatureAlgorithm, AsymmetricKeyType),
    Mac(MacAlgorithm),
    /// `RSA_DECRYPT_OAEP_<bits>_SHA256`: a key-wrapping key (local wrap, server unwrap).
    OaepSha256(u32),
    /// Known to Cloud KMS but not mapped; `true` when core plans the variant (secp256k1,
    /// HMAC-SHA224).
    Unmapped {
        planned: bool,
    },
}

/// Maps a `CryptoKeyVersionAlgorithm` name.
pub(crate) fn map_algorithm(name: &str) -> Alg {
    use AsymmetricKeyType as T;
    use SignatureAlgorithm as S;
    let rsa = |a, bits| Alg::Sign(a, T::Rsa { bits });
    match name {
        "GOOGLE_SYMMETRIC_ENCRYPTION" | "EXTERNAL_SYMMETRIC_ENCRYPTION" => Alg::Aead,
        "EC_SIGN_P256_SHA256" => Alg::Sign(S::EcdsaP256Sha256, T::EcP256),
        "EC_SIGN_P384_SHA384" => Alg::Sign(S::EcdsaP384Sha384, T::EcP384),
        "EC_SIGN_ED25519" => Alg::Sign(S::Ed25519, T::Ed25519),
        "RSA_SIGN_PSS_2048_SHA256" => rsa(S::RsaPssSha256, 2048),
        "RSA_SIGN_PSS_3072_SHA256" => rsa(S::RsaPssSha256, 3072),
        "RSA_SIGN_PSS_4096_SHA256" => rsa(S::RsaPssSha256, 4096),
        "RSA_SIGN_PSS_4096_SHA512" => rsa(S::RsaPssSha512, 4096),
        "RSA_SIGN_PKCS1_2048_SHA256" => rsa(S::RsaPkcs1v15Sha256, 2048),
        "RSA_SIGN_PKCS1_3072_SHA256" => rsa(S::RsaPkcs1v15Sha256, 3072),
        "RSA_SIGN_PKCS1_4096_SHA256" => rsa(S::RsaPkcs1v15Sha256, 4096),
        "RSA_SIGN_PKCS1_4096_SHA512" => rsa(S::RsaPkcs1v15Sha512, 4096),
        "HMAC_SHA256" => Alg::Mac(MacAlgorithm::HmacSha256),
        "HMAC_SHA384" => Alg::Mac(MacAlgorithm::HmacSha384),
        "HMAC_SHA512" => Alg::Mac(MacAlgorithm::HmacSha512),
        "RSA_DECRYPT_OAEP_2048_SHA256" => Alg::OaepSha256(2048),
        "RSA_DECRYPT_OAEP_3072_SHA256" => Alg::OaepSha256(3072),
        "RSA_DECRYPT_OAEP_4096_SHA256" => Alg::OaepSha256(4096),
        "EC_SIGN_SECP256K1_SHA256" | "HMAC_SHA224" => Alg::Unmapped { planned: true },
        _ => Alg::Unmapped { planned: false },
    }
}

/// `CryptoKeyVersion` (the fields used).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionJson {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) state: String,
    #[serde(default)]
    pub(crate) protection_level: String,
    #[serde(default)]
    pub(crate) algorithm: String,
    #[serde(default)]
    pub(crate) create_time: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionTemplateJson {
    #[serde(default)]
    pub(crate) protection_level: String,
    #[serde(default)]
    pub(crate) algorithm: String,
}

/// `CryptoKey` (the fields used).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyJson {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) purpose: String,
    #[serde(default)]
    pub(crate) primary: Option<VersionJson>,
    #[serde(default)]
    pub(crate) version_template: Option<VersionTemplateJson>,
    #[serde(default)]
    pub(crate) rotation_period: Option<String>,
    #[serde(default)]
    pub(crate) next_rotation_time: Option<String>,
    #[serde(default)]
    pub(crate) destroy_scheduled_duration: Option<String>,
    #[serde(default)]
    pub(crate) import_only: bool,
}

/// `ListCryptoKeyVersionsResponse`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListJson {
    #[serde(default)]
    pub(crate) crypto_key_versions: Vec<VersionJson>,
    #[serde(default)]
    pub(crate) next_page_token: Option<String>,
}

/// One key version as Cloud KMS reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GcpVersionInfo {
    version: u64,
    state: String,
    algorithm: String,
    protection_level: String,
    created_at: Option<u64>,
}

impl GcpVersionInfo {
    pub(crate) fn from_json(v: &VersionJson) -> Option<Self> {
        let n = v.name.rsplit_once("/cryptoKeyVersions/")?.1;
        Some(Self {
            version: crate::uri::parse_version(n)?,
            state: v.state.clone(),
            algorithm: v.algorithm.clone(),
            protection_level: v.protection_level.clone(),
            created_at: v
                .create_time
                .as_deref()
                .and_then(crate::auth::parse_rfc3339),
        })
    }

    /// The version number.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The state (`ENABLED`, `DISABLED`, `DESTROY_SCHEDULED`, `DESTROYED`,
    /// `PENDING_GENERATION`, ...).
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The `CryptoKeyVersionAlgorithm` (`GOOGLE_SYMMETRIC_ENCRYPTION`, `EC_SIGN_P256_SHA256`, ...).
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The protection level (`SOFTWARE`, `HSM`, `EXTERNAL`, `EXTERNAL_VPC`).
    pub fn protection_level(&self) -> &str {
        &self.protection_level
    }

    /// The creation time, in seconds since the Unix epoch.
    pub fn created_at(&self) -> Option<u64> {
        self.created_at
    }

    fn to_portable(&self) -> KeyVersionInfo {
        // Versions of one key may differ in algorithm (a new version gets the key's template).
        let (sig, mac) = match map_algorithm(&self.algorithm) {
            Alg::Sign(a, _) => (Some(a), None),
            Alg::Mac(m) => (None, Some(m)),
            _ => (None, None),
        };
        KeyVersionInfo::new(KeyVersion::from_u64(self.version), map_state(&self.state))
            .with_created_at(self.created_at)
            .with_signature_algorithm(sig)
            .with_mac_algorithm(mac)
    }
}

/// A Cloud KMS version state as a portable [`KeyState`].
pub(crate) fn map_state(s: &str) -> KeyState {
    match s {
        "ENABLED" => KeyState::Enabled,
        "DISABLED" => KeyState::Disabled,
        "DESTROY_SCHEDULED" => KeyState::PendingDeletion,
        "DESTROYED" => KeyState::Destroyed,
        other => KeyState::Unknown(other.to_owned()),
    }
}

/// A Cloud KMS key's metadata, with the fields the portable [`KeyInfo`] has no place for.
/// Attached to the `KeyInfo` every GCP handle's `describe()` and `preflight()` return
/// ([`KeyInfo::backend_info`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GcpKeyInfo {
    name: String,
    purpose: String,
    protection_level: Option<String>,
    template_algorithm: Option<String>,
    primary: Option<u64>,
    versions: Vec<GcpVersionInfo>,
    rotation_period: Option<String>,
    next_rotation_time: Option<String>,
    destroy_scheduled_duration: Option<String>,
    import_only: bool,
    /// The version the handle's URI names, if any.
    requested_version: Option<u64>,
}

impl GcpKeyInfo {
    pub(crate) fn new(key: KeyJson, versions: Vec<VersionJson>, requested: Option<u64>) -> Self {
        let mut versions: Vec<GcpVersionInfo> = versions
            .iter()
            .filter_map(GcpVersionInfo::from_json)
            .collect();
        versions.sort_by_key(|v| v.version);
        let primary = key
            .primary
            .as_ref()
            .and_then(GcpVersionInfo::from_json)
            .map(|v| v.version);
        let (protection_level, template_algorithm) = match key.version_template {
            Some(t) => (
                Some(t.protection_level).filter(|s| !s.is_empty()),
                Some(t.algorithm).filter(|s| !s.is_empty()),
            ),
            None => (None, None),
        };
        Self {
            name: key.name,
            purpose: key.purpose,
            protection_level,
            template_algorithm,
            primary,
            versions,
            rotation_period: key.rotation_period,
            next_rotation_time: key.next_rotation_time,
            destroy_scheduled_duration: key.destroy_scheduled_duration,
            import_only: key.import_only,
            requested_version: requested,
        }
    }

    /// The key's resource name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The purpose (`ENCRYPT_DECRYPT`, `ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`, `MAC`,
    /// `RAW_ENCRYPT_DECRYPT`).
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// The protection level of new versions (`versionTemplate.protectionLevel`).
    pub fn protection_level(&self) -> Option<&str> {
        self.protection_level.as_deref()
    }

    /// The algorithm of new versions (`versionTemplate.algorithm`).
    pub fn template_algorithm(&self) -> Option<&str> {
        self.template_algorithm.as_deref()
    }

    /// The primary version (`ENCRYPT_DECRYPT` keys only).
    pub fn primary(&self) -> Option<u64> {
        self.primary
    }

    /// Every version, in ascending order.
    pub fn versions(&self) -> &[GcpVersionInfo] {
        &self.versions
    }

    /// The automatic rotation period (`"7776000s"`), if set.
    pub fn rotation_period(&self) -> Option<&str> {
        self.rotation_period.as_deref()
    }

    /// The next automatic rotation (RFC 3339), if set.
    pub fn next_rotation_time(&self) -> Option<&str> {
        self.next_rotation_time.as_deref()
    }

    /// How long versions stay `DESTROY_SCHEDULED` before they are destroyed (`"86400s"`).
    pub fn destroy_scheduled_duration(&self) -> Option<&str> {
        self.destroy_scheduled_duration.as_deref()
    }

    /// Whether the key accepts only imported versions.
    pub fn import_only(&self) -> bool {
        self.import_only
    }

    /// The algorithm that identifies the key: the version the URI names, else the primary's,
    /// else the version template's.
    pub fn algorithm(&self) -> Option<&str> {
        let by_version = |n: u64| {
            self.versions
                .iter()
                .find(|v| v.version == n)
                .map(|v| v.algorithm.as_str())
        };
        self.requested_version
            .and_then(by_version)
            .or_else(|| self.primary.and_then(by_version))
            .or(self.template_algorithm.as_deref())
    }

    /// The portable view.
    ///
    /// - capabilities: `ENCRYPT_DECRYPT` → `AEAD | KEY_WRAP` (never `REWRAP` or `DATA_KEYS`: not
    ///   native); `ASYMMETRIC_SIGN` → `SIGN | VERIFY | PUBLIC_KEY` (`VERIFY` is local
    ///   verification by the handle); `MAC` → `MAC`; `ASYMMETRIC_DECRYPT` with an OAEP-SHA-256
    ///   algorithm → `KEY_WRAP | PUBLIC_KEY`; anything else → none.
    /// - state: `None` (Cloud KMS has no key-level state); per-version states in `versions()`.
    /// - primary version: `ENCRYPT_DECRYPT` keys only.
    pub fn to_key_info(&self) -> KeyInfo {
        let alg = self.algorithm().unwrap_or("");
        let mapped = map_algorithm(alg);
        let caps = match (self.purpose.as_str(), mapped) {
            ("ENCRYPT_DECRYPT", _) => Capabilities::AEAD | Capabilities::KEY_WRAP,
            ("ASYMMETRIC_SIGN", Alg::Sign(..)) => {
                Capabilities::SIGN | Capabilities::VERIFY | Capabilities::PUBLIC_KEY
            }
            ("MAC", Alg::Mac(_)) => Capabilities::MAC,
            ("ASYMMETRIC_DECRYPT", Alg::OaepSha256(_)) => {
                Capabilities::KEY_WRAP | Capabilities::PUBLIC_KEY
            }
            _ => Capabilities::NONE,
        };
        let sigs = match mapped {
            Alg::Sign(a, _) if self.purpose == "ASYMMETRIC_SIGN" => vec![a],
            _ => Vec::new(),
        };
        let mac = match mapped {
            Alg::Mac(m) if self.purpose == "MAC" => Some(m),
            _ => None,
        };
        let primary = (self.purpose == "ENCRYPT_DECRYPT")
            .then_some(self.primary)
            .flatten()
            .map(KeyVersion::from_u64);
        KeyInfo::new(alg, caps)
            .with_signature_algorithms(sigs)
            .with_mac_algorithm(mac)
            .with_state(None)
            .with_primary_version(primary)
            .with_versions(self.versions.iter().map(|v| v.to_portable()).collect())
            .with_backend_info(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u64, state: &str, alg: &str) -> VersionJson {
        VersionJson {
            name: format!("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/{n}"),
            state: state.into(),
            protection_level: "SOFTWARE".into(),
            algorithm: alg.into(),
            create_time: Some("2024-01-01T00:00:00Z".into()),
        }
    }

    #[test]
    fn aead_key_info() {
        let key = KeyJson {
            name: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
            purpose: "ENCRYPT_DECRYPT".into(),
            primary: Some(v(2, "ENABLED", "GOOGLE_SYMMETRIC_ENCRYPTION")),
            version_template: Some(VersionTemplateJson {
                protection_level: "HSM".into(),
                algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION".into(),
            }),
            ..Default::default()
        };
        let versions = vec![
            v(2, "ENABLED", "GOOGLE_SYMMETRIC_ENCRYPTION"),
            v(1, "DESTROY_SCHEDULED", "GOOGLE_SYMMETRIC_ENCRYPTION"),
            v(3, "PENDING_GENERATION", "GOOGLE_SYMMETRIC_ENCRYPTION"),
        ];
        let g = GcpKeyInfo::new(key, versions, None);
        assert_eq!(g.primary(), Some(2));
        assert_eq!(g.protection_level(), Some("HSM"));
        let i = g.to_key_info();
        assert_eq!(i.backend_key_type(), "GOOGLE_SYMMETRIC_ENCRYPTION");
        assert!(
            i.capabilities()
                .contains(Capabilities::AEAD | Capabilities::KEY_WRAP)
        );
        assert!(!i.capabilities().contains(Capabilities::REWRAP));
        assert!(!i.capabilities().contains(Capabilities::DATA_KEYS));
        assert_eq!(i.state(), None);
        assert_eq!(i.primary_version().unwrap().as_str(), "2");
        let states: Vec<_> = i.versions().iter().map(|v| v.state().clone()).collect();
        assert_eq!(
            states,
            vec![
                KeyState::PendingDeletion,
                KeyState::Enabled,
                KeyState::Unknown("PENDING_GENERATION".into())
            ]
        );
        assert_eq!(i.versions()[0].created_at(), Some(1_704_067_200));
    }

    #[test]
    fn signing_and_mac_key_info() {
        let key = KeyJson {
            name: "k".into(),
            purpose: "ASYMMETRIC_SIGN".into(),
            version_template: Some(VersionTemplateJson {
                protection_level: "SOFTWARE".into(),
                algorithm: "EC_SIGN_P384_SHA384".into(),
            }),
            ..Default::default()
        };
        let g = GcpKeyInfo::new(key, vec![v(1, "ENABLED", "EC_SIGN_P256_SHA256")], Some(1));
        let i = g.to_key_info();
        assert_eq!(i.backend_key_type(), "EC_SIGN_P256_SHA256");
        assert_eq!(
            i.signature_algorithms(),
            &[SignatureAlgorithm::EcdsaP256Sha256]
        );
        assert!(i.capabilities().contains(Capabilities::VERIFY));
        assert_eq!(i.primary_version(), None);

        let key = KeyJson {
            purpose: "MAC".into(),
            version_template: Some(VersionTemplateJson {
                protection_level: "SOFTWARE".into(),
                algorithm: "HMAC_SHA512".into(),
            }),
            ..Default::default()
        };
        let i = GcpKeyInfo::new(key, vec![], None).to_key_info();
        assert_eq!(i.mac_algorithm(), Some(MacAlgorithm::HmacSha512));
        assert_eq!(i.capabilities(), Capabilities::MAC);

        let key = KeyJson {
            purpose: "RAW_ENCRYPT_DECRYPT".into(),
            ..Default::default()
        };
        assert_eq!(
            GcpKeyInfo::new(key, vec![], None)
                .to_key_info()
                .capabilities(),
            Capabilities::NONE
        );
    }

    #[test]
    fn version_algorithms() {
        let sig = GcpVersionInfo::from_json(&v(1, "ENABLED", "EC_SIGN_P384_SHA384"))
            .unwrap()
            .to_portable();
        assert_eq!(
            sig.signature_algorithm(),
            Some(SignatureAlgorithm::EcdsaP384Sha384)
        );
        assert_eq!(sig.mac_algorithm(), None);
        let mac = GcpVersionInfo::from_json(&v(2, "ENABLED", "HMAC_SHA512"))
            .unwrap()
            .to_portable();
        assert_eq!(mac.mac_algorithm(), Some(MacAlgorithm::HmacSha512));
        assert_eq!(mac.signature_algorithm(), None);
        let aead = GcpVersionInfo::from_json(&v(3, "ENABLED", "GOOGLE_SYMMETRIC_ENCRYPTION"))
            .unwrap()
            .to_portable();
        assert_eq!(
            (aead.signature_algorithm(), aead.mac_algorithm()),
            (None, None)
        );
    }

    #[test]
    fn algorithms() {
        assert_eq!(
            map_algorithm("RSA_SIGN_PSS_4096_SHA512"),
            Alg::Sign(
                SignatureAlgorithm::RsaPssSha512,
                AsymmetricKeyType::Rsa { bits: 4096 }
            )
        );
        assert_eq!(
            map_algorithm("HMAC_SHA224"),
            Alg::Unmapped { planned: true }
        );
        assert_eq!(map_algorithm("HMAC_SHA1"), Alg::Unmapped { planned: false });
        assert_eq!(
            map_algorithm("RSA_SIGN_RAW_PKCS1_2048"),
            Alg::Unmapped { planned: false }
        );
        assert_eq!(
            map_algorithm("RSA_DECRYPT_OAEP_2048_SHA1"),
            Alg::Unmapped { planned: false }
        );
        assert_eq!(
            map_algorithm("RSA_DECRYPT_OAEP_3072_SHA256"),
            Alg::OaepSha256(3072)
        );
    }
}
