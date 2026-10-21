//! Parsing of `GET <mount>/keys/<name>`.

use std::collections::BTreeMap;
use std::time::Duration;

use anykms_core::{
    AsymmetricKeyType, Capabilities, Error, ErrorKind, KeyInfo, KeyState, KeyVersion,
    KeyVersionInfo, Operation, Result, SignatureAlgorithm,
};
use serde::Deserialize;

use crate::BACKEND;

/// Transit key types anykms understands.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransitKeyType {
    Aes128Gcm96,
    Aes256Gcm96,
    Chacha20Poly1305,
    XChacha20Poly1305,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
    Rsa(u32),
    Hmac,
    /// Any other type (e.g. Enterprise-only types).
    Other(String),
}

impl TransitKeyType {
    /// Parses the server's `type` field.
    pub fn parse(s: &str) -> Self {
        match s {
            "aes128-gcm96" => Self::Aes128Gcm96,
            "aes256-gcm96" => Self::Aes256Gcm96,
            "chacha20-poly1305" => Self::Chacha20Poly1305,
            "xchacha20-poly1305" => Self::XChacha20Poly1305,
            "ecdsa-p256" => Self::EcdsaP256,
            "ecdsa-p384" => Self::EcdsaP384,
            "ecdsa-p521" => Self::EcdsaP521,
            "ed25519" => Self::Ed25519,
            "hmac" => Self::Hmac,
            s => match s.strip_prefix("rsa-").and_then(|b| b.parse().ok()) {
                Some(bits) => Self::Rsa(bits),
                None => Self::Other(s.to_owned()),
            },
        }
    }

    /// Whether the type is an AEAD cipher usable for `Aead`/`DataKeys`/`Rewrap`.
    pub fn is_aead(&self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm96
                | Self::Aes256Gcm96
                | Self::Chacha20Poly1305
                | Self::XChacha20Poly1305
        )
    }

    /// The asymmetric key type, for signing keys.
    pub fn asymmetric(&self) -> Option<AsymmetricKeyType> {
        Some(match self {
            Self::EcdsaP256 => AsymmetricKeyType::EcP256,
            Self::EcdsaP384 => AsymmetricKeyType::EcP384,
            Self::EcdsaP521 => AsymmetricKeyType::EcP521,
            Self::Ed25519 => AsymmetricKeyType::Ed25519,
            Self::Rsa(bits) => AsymmetricKeyType::Rsa { bits: *bits },
            _ => return None,
        })
    }

    /// Signature algorithms anykms supports for this type.
    pub fn signature_algorithms(&self) -> Vec<SignatureAlgorithm> {
        match self.asymmetric() {
            Some(t) => SignatureAlgorithm::ALL
                .iter()
                .copied()
                .filter(|a| a.is_compatible_with(&t))
                .collect(),
            None => Vec::new(),
        }
    }
}

/// Transit-specific key metadata (not portable; see [`KeyInfo`] for the portable view): the
/// server's key read (`GET <mount>/keys/<name>`), as returned. Fields the server omits read as
/// zero, `false` or empty.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitKeyInfo {
    /// Native type string (`type`, e.g. `aes256-gcm96`).
    pub key_type: String,
    /// Parsed type.
    pub parsed_type: TransitKeyType,
    /// The newest version (`latest_version`): the one encryption and signing use unless
    /// `min_encryption_version` says otherwise.
    pub latest_version: u64,
    /// The oldest version the server still decrypts or verifies with
    /// (`min_decryption_version`).
    pub min_decryption_version: u64,
    /// The version encryption uses (`min_encryption_version`); `0` means the latest.
    pub min_encryption_version: u64,
    /// The oldest version whose key material the server still holds (`min_available_version`);
    /// older versions were trimmed. `0` where nothing was trimmed.
    pub min_available_version: u64,
    /// Whether the key derives per-request keys from a context (`derived`). anykms refuses
    /// derived keys with `Unsupported`.
    pub derived: bool,
    /// Whether the key may be deleted (`deletion_allowed`).
    pub deletion_allowed: bool,
    /// Whether the key material may be exported (`exportable`).
    pub exportable: bool,
    /// OpenBao soft-delete state (`soft_deleted`; always `false` on Vault). A soft-deleted key
    /// refuses every operation; the portable state is then
    /// [`KeyState::PendingDeletion`](anykms_core::KeyState::PendingDeletion).
    pub soft_deleted: bool,
    /// The automatic rotation period (`auto_rotate_period`); `None` when rotation is manual.
    pub auto_rotate_period: Option<Duration>,
    /// Version → creation time (Unix seconds) where known. Versions below the minimum decryption
    /// version are omitted by the server; HMAC keys report none.
    pub versions: BTreeMap<u64, Option<u64>>,
    /// Version → PEM public key, for asymmetric keys. Raw server metadata: the server still lists
    /// the public keys of a soft-deleted key here. For a key that is usable, read public keys
    /// through the handle (`public_key()`, `public_key_version()`), which refuses a soft-deleted
    /// key.
    pub public_keys: BTreeMap<u64, String>,
}

#[derive(Deserialize)]
struct Envelope {
    data: Raw,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(rename = "type")]
    key_type: String,
    #[serde(default)]
    latest_version: u64,
    #[serde(default)]
    min_decryption_version: u64,
    #[serde(default)]
    min_encryption_version: u64,
    #[serde(default)]
    min_available_version: u64,
    #[serde(default)]
    derived: bool,
    #[serde(default)]
    deletion_allowed: bool,
    #[serde(default)]
    exportable: bool,
    #[serde(default)]
    soft_deleted: bool,
    #[serde(default)]
    auto_rotate_period: Option<serde_json::Value>,
    #[serde(default)]
    keys: Option<BTreeMap<String, serde_json::Value>>,
}

/// Parses an RFC 3339 timestamp (`2026-10-03T19:33:42.29Z`, `...+02:00`) into Unix seconds.
/// Returns `None` for anything malformed or out of range; never panics.
pub(crate) fn rfc3339_to_unix(s: &str) -> Option<u64> {
    fn num(s: &str, len: usize) -> Option<i64> {
        (s.len() == len && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    }
    let (date, rest) = s.split_once(['T', 't'])?;
    let mut d = date.split('-');
    let (y, m, day) = (num(d.next()?, 4)?, num(d.next()?, 2)?, num(d.next()?, 2)?);
    if d.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    // Split off the zone: `Z` or `±HH:MM`.
    let (time, offset_secs) = if let Some(t) = rest.strip_suffix(['Z', 'z']) {
        (t, 0)
    } else {
        let i = rest.rfind(['+', '-'])?;
        let (t, z) = rest.split_at(i);
        let sign = if z.starts_with('-') { -1 } else { 1 };
        let (oh, om) = z[1..].split_once(':')?;
        let (oh, om) = (num(oh, 2)?, num(om, 2)?);
        if oh > 23 || om > 59 {
            return None;
        }
        (t, sign * (oh * 3600 + om * 60))
    };
    let time = match time.split_once('.') {
        Some((t, frac)) if !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit()) => t,
        Some(_) => return None,
        None => time,
    };
    let mut t = time.split(':');
    let (hh, mm, ss) = (num(t.next()?, 2)?, num(t.next()?, 2)?, num(t.next()?, 2)?);
    if t.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant); all values are small, so no overflow is possible.
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss - offset_secs).ok()
}

impl TransitKeyInfo {
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        let env: Envelope = serde_json::from_slice(body).map_err(|_| {
            Error::new(
                ErrorKind::Backend,
                BACKEND,
                Operation::Describe,
                "unexpected key metadata format",
            )
        })?;
        let r = env.data;
        let mut versions = BTreeMap::new();
        let mut public_keys = BTreeMap::new();
        for (k, v) in r.keys.unwrap_or_default() {
            let Ok(ver) = k.parse::<u64>() else { continue };
            match v {
                serde_json::Value::Number(n) => {
                    versions.insert(ver, n.as_u64());
                }
                serde_json::Value::Object(o) => {
                    let created = o
                        .get("creation_time")
                        .and_then(|t| t.as_str())
                        .and_then(rfc3339_to_unix);
                    versions.insert(ver, created);
                    if let Some(pk) = o
                        .get("public_key")
                        .and_then(|p| p.as_str())
                        .filter(|p| !p.is_empty())
                    {
                        public_keys.insert(ver, pk.to_owned());
                    }
                }
                _ => {
                    versions.insert(ver, None);
                }
            }
        }
        let auto_rotate_period = match r.auto_rotate_period {
            Some(serde_json::Value::Number(n)) => {
                n.as_u64().filter(|s| *s > 0).map(Duration::from_secs)
            }
            _ => None,
        };
        Ok(Self {
            parsed_type: TransitKeyType::parse(&r.key_type),
            key_type: r.key_type,
            latest_version: r.latest_version,
            min_decryption_version: r.min_decryption_version,
            min_encryption_version: r.min_encryption_version,
            min_available_version: r.min_available_version,
            derived: r.derived,
            deletion_allowed: r.deletion_allowed,
            exportable: r.exportable,
            soft_deleted: r.soft_deleted,
            auto_rotate_period,
            versions,
            public_keys,
        })
    }

    /// The portable view.
    pub fn to_key_info(&self) -> KeyInfo {
        let t = &self.parsed_type;
        // DATA_KEYS without AAD binding on Vault (see the `Capabilities` docs); KEY_WRAP through
        // empty-AAD encryption (`Provider::key_wrap`).
        let caps = if t.is_aead() {
            Capabilities::AEAD
                | Capabilities::REWRAP
                | Capabilities::DATA_KEYS
                | Capabilities::KEY_WRAP
        } else if *t == TransitKeyType::Hmac {
            Capabilities::MAC
        } else if t.asymmetric().is_some() {
            Capabilities::SIGN | Capabilities::VERIFY | Capabilities::PUBLIC_KEY
        } else {
            Capabilities::NONE
        };
        let state = if self.soft_deleted {
            KeyState::PendingDeletion
        } else {
            KeyState::Enabled
        };
        let versions = self
            .versions
            .iter()
            .map(|(v, created)| {
                KeyVersionInfo::new(KeyVersion::from_u64(*v), state.clone())
                    .with_created_at(*created)
            })
            .collect();
        KeyInfo::new(self.key_type.clone(), caps)
            .with_state(Some(state))
            .with_signature_algorithms(t.signature_algorithms())
            .with_primary_version(
                (self.latest_version > 0).then(|| KeyVersion::from_u64(self.latest_version)),
            )
            .with_versions(versions)
            .with_backend_info(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_symmetric_and_asymmetric() {
        let sym = br#"{"data":{"type":"aes256-gcm96","latest_version":2,"min_decryption_version":2,"keys":{"2":1791056022},"derived":false}}"#;
        let i = TransitKeyInfo::parse(sym).unwrap();
        assert!(i.parsed_type.is_aead());
        assert_eq!(i.versions.get(&2), Some(&Some(1_791_056_022)));
        let asym = br#"{"data":{"type":"ecdsa-p256","latest_version":1,"keys":{"1":{"creation_time":"2026-10-03T19:33:42.291260574Z","name":"P-256","public_key":"PEM"}}}}"#;
        let i = TransitKeyInfo::parse(asym).unwrap();
        assert_eq!(i.public_keys.get(&1).map(String::as_str), Some("PEM"));
        assert_eq!(i.versions.get(&1), Some(&Some(1_791_056_022)));
        let hmac = br#"{"data":{"type":"hmac","latest_version":1,"keys":null}}"#;
        assert!(TransitKeyInfo::parse(hmac).unwrap().versions.is_empty());
        assert_eq!(TransitKeyType::parse("rsa-3072"), TransitKeyType::Rsa(3072));
    }

    #[test]
    fn rfc3339() {
        let z = Some(1_791_056_022);
        assert_eq!(rfc3339_to_unix("2026-10-03T19:33:42.291260574Z"), z);
        assert_eq!(rfc3339_to_unix("2026-10-03T19:33:42Z"), z);
        assert_eq!(rfc3339_to_unix("2026-10-03T21:33:42+02:00"), z);
        assert_eq!(rfc3339_to_unix("2026-10-03T14:33:42.5-05:00"), z);
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        for bad in [
            "2026-13-45T99:99:99Z",
            "2026-10-03T9223372036854775807:00:00Z",
            "99999999999-01-01T00:00:00Z",
            "2026-10-03T19:33:42",
            "2026-10-03T19:33:42.Z",
            "2026-10-03 19:33:42Z",
            "1969-12-31T23:59:59Z",
            "",
        ] {
            assert_eq!(rfc3339_to_unix(bad), None, "{bad}");
        }
        assert_eq!(
            TransitKeyType::parse("rsa-2048")
                .signature_algorithms()
                .len(),
            6
        );
    }
}
