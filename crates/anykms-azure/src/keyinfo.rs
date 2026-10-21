//! Key bundles (`GET /keys/<name>[/<version>]`), version lists, JWK → SubjectPublicKeyInfo, and
//! the portable and Azure-specific metadata views.

use std::collections::BTreeMap;

use anykms_core::{
    AsymmetricKeyType, Capabilities, KeyInfo, KeyState, KeyVersion, KeyVersionInfo, PublicKey,
    SignatureAlgorithm,
};
use base64::Engine as _;
use serde::Deserialize;

use crate::config::VaultKind;
use crate::uri::AzureKeyRef;

/// base64url, padding optional on decode, none on encode (Key Vault's encoding).
pub(crate) const B64URL: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// A Key Vault key type (`kty`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AzureKeyType {
    /// `RSA` (software-protected).
    Rsa,
    /// `RSA-HSM`.
    RsaHsm,
    /// `EC` (software-protected).
    Ec,
    /// `EC-HSM`.
    EcHsm,
    /// `oct` (software symmetric; not used by anykms).
    Oct,
    /// `oct-HSM` (Managed HSM; Premium vaults in preview).
    OctHsm,
    /// Any other type (e.g. `AKP`), verbatim.
    Other(String),
}

impl AzureKeyType {
    /// Parses `kty`.
    pub fn parse(s: &str) -> Self {
        match s {
            "RSA" => Self::Rsa,
            "RSA-HSM" => Self::RsaHsm,
            "EC" => Self::Ec,
            "EC-HSM" => Self::EcHsm,
            "oct" => Self::Oct,
            "oct-HSM" => Self::OctHsm,
            o => Self::Other(o.to_owned()),
        }
    }

    /// The `kty` string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rsa => "RSA",
            Self::RsaHsm => "RSA-HSM",
            Self::Ec => "EC",
            Self::EcHsm => "EC-HSM",
            Self::Oct => "oct",
            Self::OctHsm => "oct-HSM",
            Self::Other(s) => s,
        }
    }

    /// RSA or RSA-HSM.
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa | Self::RsaHsm)
    }

    /// EC or EC-HSM.
    pub fn is_ec(&self) -> bool {
        matches!(self, Self::Ec | Self::EcHsm)
    }
}

/// One version of a key, from `GET /keys/<name>/versions`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzureVersionInfo {
    /// The version (lowercase).
    pub version: String,
    /// `attributes.enabled`.
    pub enabled: Option<bool>,
    /// `attributes.nbf` (Unix seconds).
    pub not_before: Option<u64>,
    /// `attributes.exp` (Unix seconds).
    pub expires: Option<u64>,
    /// `attributes.created` (Unix seconds).
    pub created: Option<u64>,
    /// `attributes.updated` (Unix seconds).
    pub updated: Option<u64>,
}

/// Azure-specific key metadata (not portable; [`KeyInfo`] is the portable view). Returned by the
/// handles' `describe()` and `preflight()`, attached to the portable `KeyInfo`
/// ([`KeyInfo::backend_info`](anykms_core::KeyInfo::backend_info)).
///
/// Tag values are not exposed (they may hold operator metadata); only their names.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzureKeyInfo {
    /// The key identifier of the version described (`kid`).
    pub key_id: String,
    /// That version (lowercase).
    pub version: String,
    /// `kty`.
    pub key_type: AzureKeyType,
    /// `crv` for EC keys.
    pub curve: Option<String>,
    /// The RSA modulus size in bits.
    pub rsa_bits: Option<u32>,
    /// `key_ops`, verbatim (`None` when the server sent none).
    pub key_ops: Option<Vec<String>>,
    /// `attributes.enabled`.
    pub enabled: Option<bool>,
    /// `attributes.nbf` (Unix seconds).
    pub not_before: Option<u64>,
    /// `attributes.exp` (Unix seconds).
    pub expires: Option<u64>,
    /// `attributes.created` (Unix seconds).
    pub created: Option<u64>,
    /// `attributes.updated` (Unix seconds).
    pub updated: Option<u64>,
    /// `attributes.recoveryLevel`.
    pub recovery_level: Option<String>,
    /// `attributes.recoverableDays`.
    pub recoverable_days: Option<u32>,
    /// `attributes.exportable`.
    pub exportable: Option<bool>,
    /// `attributes.hsmPlatform`.
    pub hsm_platform: Option<String>,
    /// `managed`: the key backs a certificate.
    pub managed: bool,
    /// The names of the key's tags.
    pub tag_names: Vec<String>,
    /// A vault or a Managed HSM.
    pub vault_kind: VaultKind,
    /// Every version, from `/versions` (paged; see `versions_truncated`). Empty when only one
    /// version was read.
    pub versions: Vec<AzureVersionInfo>,
    /// The version list stopped after the page limit (10 pages).
    pub versions_truncated: bool,
    /// The key's current version (versionless `GET`) when the URI pins an older one; `None`
    /// when the described version is the current one. The portable view takes the primary
    /// version from it (what an unversioned write would use); the state is the described
    /// version's.
    pub current: Option<AzureVersionInfo>,
}

#[derive(Deserialize)]
struct RawJwk {
    kid: String,
    kty: String,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawAttrs {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    updated: Option<i64>,
    #[serde(default, rename = "recoveryLevel")]
    recovery_level: Option<String>,
    #[serde(default, rename = "recoverableDays")]
    recoverable_days: Option<i64>,
    #[serde(default)]
    exportable: Option<bool>,
    #[serde(default, rename = "hsmPlatform")]
    hsm_platform: Option<String>,
}

#[derive(Deserialize)]
struct RawBundle {
    key: RawJwk,
    #[serde(default)]
    attributes: Option<RawAttrs>,
    #[serde(default)]
    tags: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    managed: Option<bool>,
}

fn ts(v: Option<i64>) -> Option<u64> {
    v.and_then(|t| u64::try_from(t).ok())
}

/// A parsed key bundle: one version of a key.
#[derive(Clone, Debug)]
pub(crate) struct KeyBundle {
    pub(crate) info: AzureKeyInfo,
    /// The public key (RSA and EC P-256/384/521 only), validated.
    pub(crate) public: Option<PublicKey>,
}

/// Why a bundle could not be used.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BundleError {
    /// Not a key bundle (malformed JSON, `kid` not a key identifier, bad JWK).
    Malformed,
}

impl KeyBundle {
    /// Parses a key bundle from `host` (a vault or MHSM).
    pub(crate) fn parse(body: &[u8], vault_kind: VaultKind) -> Result<Self, BundleError> {
        let raw: RawBundle = serde_json::from_slice(body).map_err(|_| BundleError::Malformed)?;
        let kid = AzureKeyRef::from_key_id(&raw.key.kid).map_err(|_| BundleError::Malformed)?;
        let version = kid.version().ok_or(BundleError::Malformed)?.to_owned();
        let key_type = AzureKeyType::parse(&raw.key.kty);
        let (public, rsa_bits) = if key_type.is_rsa() {
            let n = raw.key.n.as_deref().ok_or(BundleError::Malformed)?;
            let e = raw.key.e.as_deref().ok_or(BundleError::Malformed)?;
            let (der, bits) = rsa_spki(n, e).ok_or(BundleError::Malformed)?;
            let pk = PublicKey::new(
                AsymmetricKeyType::Rsa { bits },
                der,
                Some(KeyVersion::new(version.as_str())),
            );
            (Some(pk), Some(bits))
        } else if key_type.is_ec() {
            let crv = raw.key.crv.as_deref().ok_or(BundleError::Malformed)?;
            let pk = match crv {
                "P-256" | "P-384" | "P-521" => {
                    let x = raw.key.x.as_deref().ok_or(BundleError::Malformed)?;
                    let y = raw.key.y.as_deref().ok_or(BundleError::Malformed)?;
                    let (t, der) = ec_spki(crv, x, y).ok_or(BundleError::Malformed)?;
                    Some(PublicKey::new(
                        t,
                        der,
                        Some(KeyVersion::new(version.as_str())),
                    ))
                }
                // P-256K and others: no portable key type; the key-type check refuses them.
                _ => None,
            };
            (pk, None)
        } else {
            (None, None)
        };
        let a = raw.attributes.unwrap_or_default();
        let mut tag_names: Vec<String> = raw
            .tags
            .map(|t| t.into_keys().collect())
            .unwrap_or_default();
        tag_names.sort();
        Ok(Self {
            info: AzureKeyInfo {
                key_id: raw.key.kid.clone(),
                version,
                key_type,
                curve: raw.key.crv.clone(),
                rsa_bits,
                key_ops: raw.key.key_ops.clone(),
                enabled: a.enabled,
                not_before: ts(a.nbf),
                expires: ts(a.exp),
                created: ts(a.created),
                updated: ts(a.updated),
                recovery_level: a.recovery_level,
                recoverable_days: a.recoverable_days.and_then(|d| u32::try_from(d).ok()),
                exportable: a.exportable,
                hsm_platform: a.hsm_platform,
                managed: raw.managed.unwrap_or(false),
                tag_names,
                vault_kind,
                versions: Vec::new(),
                versions_truncated: false,
                current: None,
            },
            public,
        })
    }

    /// Whether `key_ops` allows `op` (`sign`, `wrapKey`, ...). A bundle without `key_ops`
    /// allows everything.
    pub(crate) fn allows(&self, op: &str) -> bool {
        self.info
            .key_ops
            .as_ref()
            .is_none_or(|ops| ops.iter().any(|o| o == op))
    }
}

impl AzureKeyInfo {
    fn state_of(enabled: Option<bool>, nbf: Option<u64>, exp: Option<u64>) -> Option<KeyState> {
        let now = anykms_core::time::unix_now().as_secs();
        match enabled? {
            false => Some(KeyState::Disabled),
            true if nbf.is_some_and(|n| n > now) => {
                Some(KeyState::Unknown("not-yet-valid".to_owned()))
            }
            true if exp.is_some_and(|e| e <= now) => Some(KeyState::Unknown("expired".to_owned())),
            true => Some(KeyState::Enabled),
        }
    }

    /// The state of the described version (`Enabled`, `Disabled`, or `Unknown("not-yet-valid")`
    /// / `Unknown("expired")` outside the activation window).
    pub fn state(&self) -> Option<KeyState> {
        Self::state_of(self.enabled, self.not_before, self.expires)
    }

    fn public_key_type(&self) -> Option<AsymmetricKeyType> {
        if self.key_type.is_rsa() {
            return self.rsa_bits.map(|bits| AsymmetricKeyType::Rsa { bits });
        }
        if self.key_type.is_ec() {
            return match self.curve.as_deref() {
                Some("P-256") => Some(AsymmetricKeyType::EcP256),
                Some("P-384") => Some(AsymmetricKeyType::EcP384),
                Some("P-521") => Some(AsymmetricKeyType::EcP521),
                _ => None,
            };
        }
        None
    }

    fn allows(&self, op: &str) -> bool {
        self.key_ops
            .as_ref()
            .is_none_or(|ops| ops.iter().any(|o| o == op))
    }

    /// The capabilities anykms opens for this key, from `kty` and `key_ops`.
    pub fn capabilities(&self) -> Capabilities {
        let mut c = Capabilities::NONE;
        let supported_asym = self.public_key_type().is_some_and(|t| match t {
            AsymmetricKeyType::Rsa { bits } => bits >= anykms_recipes::MIN_RSA_BITS,
            _ => true,
        });
        if supported_asym {
            c |= Capabilities::PUBLIC_KEY;
            if self.allows("sign") {
                c |= Capabilities::SIGN;
            }
            if self.allows("verify") {
                c |= Capabilities::VERIFY;
            }
            if self.key_type.is_rsa() && self.allows("wrapKey") && self.allows("unwrapKey") {
                c |= Capabilities::KEY_WRAP;
            }
        }
        if self.key_type == AzureKeyType::OctHsm && self.vault_kind == VaultKind::ManagedHsm {
            if self.allows("encrypt") && self.allows("decrypt") {
                c |= Capabilities::AEAD | Capabilities::DATA_KEYS;
            }
            if self.allows("wrapKey") && self.allows("unwrapKey") {
                c |= Capabilities::KEY_WRAP;
            }
            #[cfg(feature = "mhsm-hmac")]
            if self.allows("sign") && self.allows("verify") {
                c |= Capabilities::MAC;
            }
        }
        c
    }

    /// `kty` plus size or curve (`RSA-HSM 3072`, `EC P-256`, `oct-HSM`).
    pub fn backend_key_type(&self) -> String {
        match (&self.rsa_bits, &self.curve) {
            (Some(b), _) => format!("{} {b}", self.key_type.as_str()),
            (None, Some(c)) if self.key_type.is_ec() => format!("{} {c}", self.key_type.as_str()),
            _ => self.key_type.as_str().to_owned(),
        }
    }

    /// This version as a version-list entry.
    pub(crate) fn version_info(&self) -> AzureVersionInfo {
        AzureVersionInfo {
            version: self.version.clone(),
            enabled: self.enabled,
            not_before: self.not_before,
            expires: self.expires,
            created: self.created,
            updated: self.updated,
        }
    }

    /// The portable view: capabilities, signature algorithms and state of the described version
    /// (for a URI that pins a version, the pinned version: the one the handle uses), the primary
    /// version (the current version, also when the URI pins an older one: see
    /// [`current`](Self::current)), and the version list.
    ///
    /// `oct-HSM` keys report [`Capabilities::MAC`] (with `mhsm-hmac`) but no MAC algorithm: an
    /// HMAC key is not bound to one `HS*` algorithm.
    pub fn to_key_info(&self) -> KeyInfo {
        let algs = self
            .public_key_type()
            .map(|t| {
                SignatureAlgorithm::ALL
                    .iter()
                    .copied()
                    .filter(|a| a.is_compatible_with(&t) && !a.is_message_signing())
                    .collect()
            })
            .unwrap_or_default();
        let versions = self
            .versions
            .iter()
            .map(|v| {
                KeyVersionInfo::new(
                    KeyVersion::new(v.version.as_str()),
                    Self::state_of(v.enabled, v.not_before, v.expires)
                        .unwrap_or(KeyState::Unknown("unknown".to_owned())),
                )
                .with_created_at(v.created)
            })
            .collect();
        KeyInfo::new(self.backend_key_type(), self.capabilities())
            .with_signature_algorithms(algs)
            .with_state(self.state())
            .with_primary_version(Some(KeyVersion::new(
                self.current
                    .as_ref()
                    .map_or(self.version.as_str(), |c| c.version.as_str()),
            )))
            .with_versions(versions)
            .with_backend_info(self.clone())
    }
}

#[derive(Deserialize)]
struct RawItem {
    kid: String,
    #[serde(default)]
    attributes: Option<RawAttrs>,
}

#[derive(Deserialize)]
struct RawPage {
    #[serde(default)]
    value: Vec<RawItem>,
    #[serde(default, rename = "nextLink")]
    next_link: Option<String>,
}

/// One page of `GET /keys/<name>/versions`: the versions of key `name` (items for other keys or
/// malformed ids are refused: `None`), and the next link.
pub(crate) fn parse_versions_page(
    body: &[u8],
    name: &str,
) -> Option<(Vec<AzureVersionInfo>, Option<String>)> {
    let page: RawPage = serde_json::from_slice(body).ok()?;
    let mut out = Vec::with_capacity(page.value.len());
    for item in page.value {
        let kid = AzureKeyRef::from_key_id(&item.kid).ok()?;
        if !kid.name().eq_ignore_ascii_case(name) {
            return None;
        }
        let a = item.attributes.unwrap_or_default();
        out.push(AzureVersionInfo {
            version: kid.version()?.to_owned(),
            enabled: a.enabled,
            not_before: ts(a.nbf),
            expires: ts(a.exp),
            created: ts(a.created),
            updated: ts(a.updated),
        });
    }
    Some((out, page.next_link.filter(|l| !l.is_empty())))
}

// ---------------------------------------------------------------------------------------------
// JWK -> SubjectPublicKeyInfo DER

#[allow(
    clippy::cast_possible_truncation,
    reason = "each branch bounds `len` to its width; callers' content is under 64 KiB (RSA moduli are at most 2048 bytes, EC points 133)"
)]
fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    push_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// A DER INTEGER from big-endian unsigned bytes (leading zeros stripped, a 0x00 added when the
/// high bit is set).
fn uint(bytes: &[u8]) -> Option<Vec<u8>> {
    let first = bytes.iter().position(|&b| b != 0)?;
    let b = &bytes[first..];
    let mut content = Vec::with_capacity(b.len() + 1);
    if b[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(b);
    Some(tlv(0x02, &content))
}

/// RSA: `SEQUENCE { SEQUENCE { rsaEncryption, NULL }, BIT STRING { SEQUENCE { n, e } } }` and
/// the exact modulus size in bits. Moduli above 16384 bits are refused.
pub(crate) fn rsa_spki(n_b64: &str, e_b64: &str) -> Option<(Vec<u8>, u32)> {
    let n = B64URL.decode(n_b64).ok()?;
    let e = B64URL.decode(e_b64).ok()?;
    let n_trim = &n[n.iter().position(|&b| b != 0)?..];
    if n_trim.len() > 2048 || e.len() > 8 {
        return None;
    }
    let bits = (u32::try_from(n_trim.len()).ok()? - 1) * 8 + (8 - n_trim[0].leading_zeros());
    let mut rsa_key = uint(n_trim)?;
    rsa_key.extend_from_slice(&uint(&e)?);
    let rsa_key = tlv(0x30, &rsa_key);
    let mut bit_string = Vec::with_capacity(rsa_key.len() + 1);
    bit_string.push(0);
    bit_string.extend_from_slice(&rsa_key);
    // AlgorithmIdentifier { 1.2.840.113549.1.1.1, NULL }
    let mut body = vec![
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    body.extend_from_slice(&tlv(0x03, &bit_string));
    let der = tlv(0x30, &body);
    // Cross-check with the independent parser in anykms-recipes.
    match anykms_recipes::spki_key_type(&der).ok()? {
        AsymmetricKeyType::Rsa { bits: b } if b == bits => Some((der, bits)),
        _ => None,
    }
}

/// EC P-256/384/521: the uncompressed point, checked to be on the curve, in an SPKI.
pub(crate) fn ec_spki(crv: &str, x_b64: &str, y_b64: &str) -> Option<(AsymmetricKeyType, Vec<u8>)> {
    let (t, len, curve_oid): (_, usize, &[u8]) = match crv {
        "P-256" => (
            AsymmetricKeyType::EcP256,
            32,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        ),
        "P-384" => (
            AsymmetricKeyType::EcP384,
            48,
            &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
        ),
        "P-521" => (
            AsymmetricKeyType::EcP521,
            66,
            &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
        ),
        _ => return None,
    };
    let x = B64URL.decode(x_b64).ok()?;
    let y = B64URL.decode(y_b64).ok()?;
    // Coordinates are fixed-size (RFC 7518 §6.2.1.2); tolerate missing leading zeros.
    let pad = |c: &[u8]| -> Option<Vec<u8>> {
        if c.len() > len {
            return None;
        }
        let mut v = vec![0u8; len - c.len()];
        v.extend_from_slice(c);
        Some(v)
    };
    let mut point = Vec::with_capacity(1 + 2 * len);
    point.push(0x04);
    point.extend_from_slice(&pad(&x)?);
    point.extend_from_slice(&pad(&y)?);
    let on_curve = match t {
        AsymmetricKeyType::EcP256 => p256::PublicKey::from_sec1_bytes(&point).is_ok(),
        AsymmetricKeyType::EcP384 => p384::PublicKey::from_sec1_bytes(&point).is_ok(),
        AsymmetricKeyType::EcP521 => p521::PublicKey::from_sec1_bytes(&point).is_ok(),
        _ => false,
    };
    if !on_curve {
        return None;
    }
    // AlgorithmIdentifier { id-ecPublicKey, curve }
    let mut alg = vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    alg.extend_from_slice(curve_oid);
    let mut bit_string = Vec::with_capacity(point.len() + 1);
    bit_string.push(0);
    bit_string.extend_from_slice(&point);
    let mut body = tlv(0x30, &alg);
    body.extend_from_slice(&tlv(0x03, &bit_string));
    Some((t, tlv(0x30, &body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "0123456789abcdef0123456789abcdef";

    /// The P-256 test key of RFC 7515 A.3.
    const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    pub(crate) fn ec_bundle(ops: &str) -> String {
        format!(
            r#"{{"key":{{"kid":"https://kv1.vault.azure.net/keys/sig/{V}","kty":"EC","crv":"P-256","x":"{X}","y":"{Y}","key_ops":{ops}}},"attributes":{{"enabled":true,"created":1700000000,"updated":1700000001,"recoveryLevel":"Recoverable+Purgeable","recoverableDays":90,"exportable":false}},"tags":{{"owner":"secret-value"}}}}"#
        )
    }

    #[test]
    fn ec_bundle_parses() {
        let b = KeyBundle::parse(
            ec_bundle(r#"["sign","verify"]"#).as_bytes(),
            VaultKind::Vault,
        )
        .unwrap();
        assert_eq!(b.info.version, V);
        assert_eq!(b.info.key_type, AzureKeyType::Ec);
        assert_eq!(b.info.tag_names, ["owner"]);
        assert!(!format!("{:?}", b.info).contains("secret-value"));
        let pk = b.public.as_ref().unwrap();
        assert_eq!(pk.key_type(), AsymmetricKeyType::EcP256);
        assert_eq!(
            anykms_recipes::spki_key_type(pk.spki_der()).unwrap(),
            AsymmetricKeyType::EcP256
        );
        assert_eq!(pk.key_version().unwrap().as_str(), V);
        let ki = b.info.to_key_info();
        assert_eq!(ki.backend_key_type(), "EC P-256");
        assert_eq!(
            ki.capabilities(),
            Capabilities::SIGN | Capabilities::VERIFY | Capabilities::PUBLIC_KEY
        );
        assert_eq!(
            ki.signature_algorithms(),
            &[SignatureAlgorithm::EcdsaP256Sha256]
        );
        assert_eq!(ki.state(), Some(&KeyState::Enabled));
        assert_eq!(ki.primary_version().unwrap().as_str(), V);
        // Verify-only key_ops.
        let b = KeyBundle::parse(ec_bundle(r#"["verify"]"#).as_bytes(), VaultKind::Vault).unwrap();
        assert!(!b.allows("sign"));
        assert!(!b.info.capabilities().contains(Capabilities::SIGN));
    }

    #[test]
    fn off_curve_and_malformed_are_refused() {
        let off = format!(
            r#"{{"key":{{"kid":"https://kv1.vault.azure.net/keys/sig/{V}","kty":"EC","crv":"P-256","x":"{X}","y":"{X}"}}}}"#
        );
        assert!(KeyBundle::parse(off.as_bytes(), VaultKind::Vault).is_err());
        for bad in [
            "{}".to_owned(),
            r#"{"key":{"kid":"https://kv1.vault.azure.net/keys/sig","kty":"EC"}}"#.to_owned(),
            format!(
                r#"{{"key":{{"kid":"http://kv1.vault.azure.net/keys/sig/{V}","kty":"oct-HSM"}}}}"#
            ),
            format!(
                r#"{{"key":{{"kid":"https://kv1.vault.azure.net/keys/sig/{V}","kty":"RSA","n":"AQAB"}}}}"#
            ),
            format!(
                r#"{{"key":{{"kid":"https://kv1.vault.azure.net/keys/sig/{V}","kty":"EC","crv":"P-256","x":"{X}"}}}}"#
            ),
        ] {
            assert!(
                KeyBundle::parse(bad.as_bytes(), VaultKind::Vault).is_err(),
                "{bad}"
            );
        }
        // P-256K parses but has no portable public key or capability.
        let k = format!(
            r#"{{"key":{{"kid":"https://kv1.vault.azure.net/keys/sig/{V}","kty":"EC","crv":"P-256K","x":"{X}","y":"{Y}"}}}}"#
        );
        let b = KeyBundle::parse(k.as_bytes(), VaultKind::Vault).unwrap();
        assert!(b.public.is_none());
        assert_eq!(b.info.capabilities(), Capabilities::NONE);
    }

    #[test]
    fn rsa_spki_matches_openssl() {
        // The RSA-2048 public key of tests/data/rsa_2048.spki.pem, inline so that the packaged
        // crate (which ships no tests/) still compiles its unit tests.
        let pem = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4XG4IROnbAVlQ4sURfc6
F5K5eYqMX9qUWF1JPMe8cTsC+S36+N7dR1wq/XY3o49fZtypAt6FWzrvDTPxxCqe
jTu9B0ES5liP6UkG0MKVcQgbEcMVBPnEhKiuui+HUxgISx5HkvjQQQZwvh+sHbCe
1Ss7GEEkp1jzBGzzlYpJOzjH/sU+tptgH46TK6tJk5v2nQ4roZqAKsicWW0+JQmZ
4CUMrCm1Z/esiKVxFIQ2EHWAs+lAaZqZZXT49pzgaXsfv8++PPKC9BjOftPdQsrz
E7K5HuWCECqQ/g+ek/j2OMOmOueGy7yWrfnsPsskPFtfeSj2wuOxi+mAAdldl9wj
bQIDAQAB
-----END PUBLIC KEY-----
";
        let der = anykms_recipes::pem_to_der(pem).unwrap();
        // Extract n and e with the DER layout of a 2048-bit key with e = 65537.
        let n = &der[der.len() - 5 - 256..der.len() - 5];
        let e = &der[der.len() - 3..];
        assert_eq!(e, [1, 0, 1]);
        let (built, bits) = rsa_spki(&B64URL.encode(n), &B64URL.encode(e)).unwrap();
        assert_eq!(bits, 2048);
        assert_eq!(built, der);
        // A leading zero byte in `n` is tolerated.
        let mut padded = vec![0u8];
        padded.extend_from_slice(n);
        assert_eq!(
            rsa_spki(&B64URL.encode(&padded), &B64URL.encode(e))
                .unwrap()
                .0,
            der
        );
        assert!(rsa_spki("", "AQAB").is_none());
        assert!(rsa_spki("!!", "AQAB").is_none());
    }

    #[test]
    fn states_and_versions() {
        let now = anykms_core::time::unix_now().as_secs();
        assert_eq!(
            AzureKeyInfo::state_of(Some(false), None, None),
            Some(KeyState::Disabled)
        );
        assert_eq!(
            AzureKeyInfo::state_of(Some(true), Some(now + 100), None),
            Some(KeyState::Unknown("not-yet-valid".into()))
        );
        assert_eq!(
            AzureKeyInfo::state_of(Some(true), None, Some(now - 1)),
            Some(KeyState::Unknown("expired".into()))
        );
        assert_eq!(AzureKeyInfo::state_of(None, None, None), None);
        let page = format!(
            r#"{{"value":[{{"kid":"https://kv1.vault.azure.net/keys/Sig/{V}","attributes":{{"enabled":false,"created":5}}}}],"nextLink":"https://kv1.vault.azure.net/keys/sig/versions?api-version=2025-07-01&$skiptoken=abc"}}"#
        );
        let (vs, next) = parse_versions_page(page.as_bytes(), "sig").unwrap();
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].enabled, Some(false));
        assert!(next.unwrap().contains("skiptoken"));
        assert!(parse_versions_page(page.as_bytes(), "other").is_none());
        assert_eq!(
            parse_versions_page(br#"{"value":[],"nextLink":null}"#, "x"),
            Some((vec![], None))
        );
    }

    /// A pinned handle reports its pinned version's state; the primary version stays the
    /// current version (what an unversioned write uses).
    #[test]
    fn pinned_state_is_the_pinned_versions() {
        const CUR: &str = "fedcba9876543210fedcba9876543210";
        let pinned = |enabled: bool| {
            let b = ec_bundle(r#"["sign","verify"]"#)
                .replace(r#""enabled":true"#, &format!(r#""enabled":{enabled}"#));
            KeyBundle::parse(b.as_bytes(), VaultKind::Vault)
                .unwrap()
                .info
        };
        let current = |enabled: bool| AzureVersionInfo {
            version: CUR.to_owned(),
            enabled: Some(enabled),
            not_before: None,
            expires: None,
            created: None,
            updated: None,
        };
        for (pin_on, cur_on, want) in [
            (true, false, KeyState::Enabled),
            (false, true, KeyState::Disabled),
            (true, true, KeyState::Enabled),
        ] {
            let mut info = pinned(pin_on);
            info.current = Some(current(cur_on));
            let ki = info.to_key_info();
            assert_eq!(ki.state(), Some(&want), "{pin_on} {cur_on}");
            assert_eq!(ki.primary_version().unwrap().as_str(), CUR);
        }
        // Unversioned (the described version is the current one): unchanged.
        for (on, want) in [(true, KeyState::Enabled), (false, KeyState::Disabled)] {
            let ki = pinned(on).to_key_info();
            assert_eq!(ki.state(), Some(&want));
            assert_eq!(ki.primary_version().unwrap().as_str(), V);
        }
    }
}
