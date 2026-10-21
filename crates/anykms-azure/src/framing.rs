//! The anykms ciphertext frame for Azure (a wire format: `docs/azure-ciphertext.md`).
//!
//! Azure returns raw RSA-OAEP and AES key-wrap output, and AES-GCM's IV and tag separately; no
//! key version is embedded. anykms stores them framed:
//!
//! ```text
//! "AZK" | format 0x01 | alg | vlen | version[vlen] | body
//! alg  0x01 RSA-OAEP-256   body = ct (exactly the modulus size; checked against the key on unwrap)
//!      0x02 A256GCM        body = iv[12] | ct | tag[16]
//!      0x03 A256KW         body = ct (input + 8)
//! vlen = 1..=64, version = [0-9a-z] (32 hex characters today)
//! ```
//!
//! The frame is not authenticated by itself: a tampered version selects another key version
//! (which fails to decrypt), a tampered algorithm is refused before any request. Other Azure
//! tools need the frame stripped: [`parse`] gives the parts.

/// The magic prefix.
pub const MAGIC: &[u8; 3] = b"AZK";
/// The only format version.
pub const FORMAT_V1: u8 = 0x01;
/// The longest version a frame carries.
pub const MAX_VERSION_LEN: usize = 64;
/// AES-GCM IV length in the frame.
pub const GCM_IV_LEN: usize = 12;
/// AES-GCM tag length in the frame.
pub const GCM_TAG_LEN: usize = 16;

const HEADER_LEN: usize = 6;

/// The algorithm of a framed ciphertext.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameAlg {
    /// `RSA-OAEP-256` (`wrapkey`): RSA-OAEP with SHA-256 and MGF1-SHA-256.
    RsaOaep256,
    /// `A256GCM` (`encrypt`, Managed HSM).
    A256Gcm,
    /// `A256KW` (`wrapkey`, Managed HSM): RFC 3394 AES key wrap.
    A256Kw,
}

impl FrameAlg {
    /// The frame's algorithm byte.
    pub fn code(&self) -> u8 {
        match self {
            Self::RsaOaep256 => 0x01,
            Self::A256Gcm => 0x02,
            Self::A256Kw => 0x03,
        }
    }

    /// The algorithm for a frame byte.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::RsaOaep256),
            0x02 => Some(Self::A256Gcm),
            0x03 => Some(Self::A256Kw),
            _ => None,
        }
    }

    /// Azure's `alg` name.
    pub fn azure_name(&self) -> &'static str {
        match self {
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::A256Gcm => "A256GCM",
            Self::A256Kw => "A256KW",
        }
    }
}

/// Why bytes are not a valid frame.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Shorter than a header, or a body shorter than the algorithm needs.
    Truncated,
    /// Not starting with `AZK`.
    BadMagic,
    /// An unknown format byte.
    UnknownFormat,
    /// An unknown algorithm byte.
    UnknownAlgorithm,
    /// A version length of 0 or above [`MAX_VERSION_LEN`], or characters outside `[0-9a-z]`.
    BadVersion,
    /// A body whose size the algorithm rules out (A256KW not a multiple of 8, ...).
    BadBody,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated Azure ciphertext frame",
            Self::BadMagic => "not an anykms Azure ciphertext frame",
            Self::UnknownFormat => "unknown Azure ciphertext frame format",
            Self::UnknownAlgorithm => "unknown Azure ciphertext frame algorithm",
            Self::BadVersion => "invalid key version in Azure ciphertext frame",
            Self::BadBody => "invalid Azure ciphertext frame body",
        })
    }
}

impl std::error::Error for FrameError {}

/// A parsed frame, borrowing the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    alg: FrameAlg,
    version: &'a str,
    body: &'a [u8],
}

impl<'a> Frame<'a> {
    /// The algorithm.
    pub fn alg(&self) -> FrameAlg {
        self.alg
    }

    /// The key version that produced the ciphertext.
    pub fn version(&self) -> &'a str {
        self.version
    }

    /// The body: what Azure returned (for A256GCM, `iv | ct | tag`).
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// For A256GCM, `(iv, ciphertext, tag)`; `None` for other algorithms.
    pub fn gcm_parts(&self) -> Option<(&'a [u8], &'a [u8], &'a [u8])> {
        if self.alg != FrameAlg::A256Gcm {
            return None;
        }
        let (iv, rest) = self.body.split_at(GCM_IV_LEN);
        let (ct, tag) = rest.split_at(rest.len() - GCM_TAG_LEN);
        Some((iv, ct, tag))
    }
}

fn version_ok(v: &[u8]) -> bool {
    (1..=MAX_VERSION_LEN).contains(&v.len())
        && v.iter()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

/// Parses a frame.
pub fn parse(bytes: &[u8]) -> Result<Frame<'_>, FrameError> {
    if bytes.len() < HEADER_LEN {
        return Err(if bytes.starts_with(&MAGIC[..bytes.len().min(3)]) {
            FrameError::Truncated
        } else {
            FrameError::BadMagic
        });
    }
    if &bytes[..3] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    if bytes[3] != FORMAT_V1 {
        return Err(FrameError::UnknownFormat);
    }
    let alg = FrameAlg::from_code(bytes[4]).ok_or(FrameError::UnknownAlgorithm)?;
    let vlen = bytes[5] as usize;
    let rest = &bytes[HEADER_LEN..];
    if vlen == 0 || vlen > MAX_VERSION_LEN {
        return Err(FrameError::BadVersion);
    }
    if rest.len() < vlen {
        return Err(FrameError::Truncated);
    }
    let (v, body) = rest.split_at(vlen);
    if !version_ok(v) {
        return Err(FrameError::BadVersion);
    }
    let version = std::str::from_utf8(v).map_err(|_| FrameError::BadVersion)?;
    match alg {
        FrameAlg::RsaOaep256 if body.is_empty() => return Err(FrameError::Truncated),
        // An empty GCM ciphertext (empty plaintext) is representable.
        FrameAlg::A256Gcm if body.len() < GCM_IV_LEN + GCM_TAG_LEN => {
            return Err(FrameError::Truncated);
        }
        FrameAlg::A256Kw if body.len() < 24 => return Err(FrameError::Truncated),
        FrameAlg::A256Kw if body.len() % 8 != 0 => return Err(FrameError::BadBody),
        _ => {}
    }
    Ok(Frame { alg, version, body })
}

/// Frames `body` (for A256GCM, `iv | ct | tag`) produced by key version `version`.
pub fn encode(alg: FrameAlg, version: &str, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    if !version_ok(version.as_bytes()) {
        return Err(FrameError::BadVersion);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + version.len() + body.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_V1);
    out.push(alg.code());
    out.push(u8::try_from(version.len()).map_err(|_| FrameError::BadVersion)?);
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(body);
    // Round-trip check: the body must satisfy the algorithm's size rules.
    parse(&out)?;
    Ok(out)
}

/// Frames an A256GCM result.
pub fn encode_gcm(version: &str, iv: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>, FrameError> {
    if iv.len() != GCM_IV_LEN || tag.len() != GCM_TAG_LEN {
        return Err(FrameError::BadBody);
    }
    let mut body = Vec::with_capacity(iv.len() + ct.len() + tag.len());
    body.extend_from_slice(iv);
    body.extend_from_slice(ct);
    body.extend_from_slice(tag);
    encode(FrameAlg::A256Gcm, version, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn round_trip() {
        let f = encode(FrameAlg::RsaOaep256, V, &[7u8; 256]).unwrap();
        assert_eq!(&f[..6], b"AZK\x01\x01\x20");
        assert_eq!(f.len(), 6 + 32 + 256);
        let p = parse(&f).unwrap();
        assert_eq!(p.alg(), FrameAlg::RsaOaep256);
        assert_eq!(p.version(), V);
        assert_eq!(p.body(), &[7u8; 256][..]);
        assert_eq!(p.gcm_parts(), None);

        let g = encode_gcm(V, &[1; 12], b"ct", &[2; 16]).unwrap();
        let (iv, ct, tag) = parse(&g).unwrap().gcm_parts().unwrap();
        assert_eq!((iv, ct, tag), (&[1u8; 12][..], &b"ct"[..], &[2u8; 16][..]));
        // An empty GCM ciphertext is representable.
        assert!(encode_gcm(V, &[1; 12], b"", &[2; 16]).is_ok());

        let k = encode(FrameAlg::A256Kw, V, &[3; 40]).unwrap();
        assert_eq!(parse(&k).unwrap().alg(), FrameAlg::A256Kw);
    }

    #[test]
    fn rejects() {
        assert_eq!(parse(b""), Err(FrameError::Truncated));
        assert_eq!(parse(b"AZ"), Err(FrameError::Truncated));
        assert_eq!(parse(b"vault:v1:abc"), Err(FrameError::BadMagic));
        assert_eq!(parse(b"AZK\x02\x01\x01a1"), Err(FrameError::UnknownFormat));
        assert_eq!(
            parse(b"AZK\x01\x09\x01a1"),
            Err(FrameError::UnknownAlgorithm)
        );
        assert_eq!(parse(b"AZK\x01\x01\x00x"), Err(FrameError::BadVersion));
        assert_eq!(parse(b"AZK\x01\x01\x41x"), Err(FrameError::BadVersion));
        assert_eq!(parse(b"AZK\x01\x01\x02A1x"), Err(FrameError::BadVersion));
        assert_eq!(parse(b"AZK\x01\x01\x05ab"), Err(FrameError::Truncated));
        assert_eq!(parse(b"AZK\x01\x01\x01a"), Err(FrameError::Truncated));
        assert_eq!(
            parse(&[b"AZK\x01\x02\x01a".as_slice(), &[0; 27]].concat()),
            Err(FrameError::Truncated)
        );
        assert_eq!(
            parse(&[b"AZK\x01\x03\x01a".as_slice(), &[0; 25]].concat()),
            Err(FrameError::BadBody)
        );
        assert_eq!(
            encode(FrameAlg::RsaOaep256, "", b"x"),
            Err(FrameError::BadVersion)
        );
        assert_eq!(
            encode(FrameAlg::RsaOaep256, &"a".repeat(65), b"x"),
            Err(FrameError::BadVersion)
        );
        assert_eq!(
            encode_gcm(V, &[0; 11], b"", &[0; 16]),
            Err(FrameError::BadBody)
        );
        // A version of 64 characters is the maximum.
        assert!(encode(FrameAlg::RsaOaep256, &"a".repeat(64), b"x").is_ok());
    }
}
