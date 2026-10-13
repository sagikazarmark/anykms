//! ECDSA signature conversion between ASN.1 DER (`SEQUENCE { INTEGER r, INTEGER s }`) and the
//! fixed-width `r || s` form used by JOSE (JWS) and some KMS APIs.

use anykms_core::{Error, ErrorKind, Operation, Result, Signature, SignatureAlgorithm};

const BACKEND: &str = "recipes";

fn err(m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, Operation::Verify, m)
}

/// Largest supported scalar size in bytes (P-521). Bounds every DER length to one length byte,
/// which is all the encoder and decoder support.
pub const MAX_SCALAR_LEN: usize = 66;

fn check_scalar_len(scalar_len: usize) -> Result<()> {
    if scalar_len == 0 || scalar_len > MAX_SCALAR_LEN {
        return Err(err("unsupported ECDSA scalar length"));
    }
    Ok(())
}

/// Scalar size in bytes for an ECDSA algorithm (`None` for non-ECDSA algorithms).
pub fn ecdsa_scalar_len(alg: SignatureAlgorithm) -> Option<usize> {
    match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => Some(32),
        SignatureAlgorithm::EcdsaP384Sha384 => Some(48),
        SignatureAlgorithm::EcdsaP521Sha512 => Some(66),
        _ => None,
    }
}

fn read_len(input: &[u8]) -> Result<(usize, &[u8])> {
    let (&first, rest) = input
        .split_first()
        .ok_or_else(|| err("truncated DER length"))?;
    if first < 0x80 {
        return Ok((first as usize, rest));
    }
    // Long form: only one length byte is ever needed for ECDSA signatures (max ~139 bytes).
    if first != 0x81 {
        return Err(err("unsupported DER length encoding"));
    }
    let (&len, rest) = rest
        .split_first()
        .ok_or_else(|| err("truncated DER length"))?;
    if len < 0x80 {
        return Err(err("non-minimal DER length"));
    }
    Ok((len as usize, rest))
}

fn read_integer(input: &[u8], scalar_len: usize) -> Result<(&[u8], &[u8])> {
    let (&tag, rest) = input
        .split_first()
        .ok_or_else(|| err("truncated DER integer"))?;
    if tag != 0x02 {
        return Err(err("expected DER INTEGER"));
    }
    let (len, rest) = read_len(rest)?;
    if len == 0 || rest.len() < len {
        return Err(err("truncated DER integer"));
    }
    let (int, rest) = rest.split_at(len);
    if int[0] & 0x80 != 0 {
        return Err(err("negative DER integer"));
    }
    if int.len() > 1 && int[0] == 0 && int[1] & 0x80 == 0 {
        return Err(err("non-minimal DER integer"));
    }
    let int = if int[0] == 0 && int.len() > 1 {
        &int[1..]
    } else {
        int
    };
    if int.len() > scalar_len {
        return Err(err("DER integer too large for curve"));
    }
    Ok((int, rest))
}

/// Converts a DER ECDSA signature to fixed-width `r || s` with `scalar_len`-byte halves.
/// `scalar_len` must be in `1..=`[`MAX_SCALAR_LEN`] (`InvalidArgument` otherwise).
pub fn der_to_fixed(der: &[u8], scalar_len: usize) -> Result<Vec<u8>> {
    check_scalar_len(scalar_len)?;
    let (&tag, rest) = der.split_first().ok_or_else(|| err("empty signature"))?;
    if tag != 0x30 {
        return Err(err("expected DER SEQUENCE"));
    }
    let (len, body) = read_len(rest)?;
    if body.len() != len {
        return Err(err("DER SEQUENCE length mismatch"));
    }
    let (r, rest) = read_integer(body, scalar_len)?;
    let (s, rest) = read_integer(rest, scalar_len)?;
    if !rest.is_empty() {
        return Err(err("trailing data in DER signature"));
    }
    let mut out = vec![0u8; scalar_len * 2];
    out[scalar_len - r.len()..scalar_len].copy_from_slice(r);
    out[2 * scalar_len - s.len()..].copy_from_slice(s);
    Ok(out)
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        // `check_scalar_len` bounds every length to at most 2 * (2 + MAX_SCALAR_LEN + 1) = 138.
        assert!(len <= 0xff, "DER length exceeds one length byte");
        out.push(0x81);
        out.push(len as u8);
    }
}

fn push_integer(out: &mut Vec<u8>, bytes: &[u8]) {
    let first_nonzero = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let int = &bytes[first_nonzero..];
    let pad = int[0] & 0x80 != 0;
    out.push(0x02);
    push_len(out, int.len() + pad as usize);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(int);
}

/// Converts a fixed-width `r || s` ECDSA signature to DER. `scalar_len` must be in
/// `1..=`[`MAX_SCALAR_LEN`] (`InvalidArgument` otherwise).
pub fn fixed_to_der(fixed: &[u8], scalar_len: usize) -> Result<Vec<u8>> {
    check_scalar_len(scalar_len)?;
    if fixed.len() != 2 * scalar_len {
        return Err(err("fixed-width signature has the wrong length"));
    }
    let (r, s) = fixed.split_at(scalar_len);
    let mut body = Vec::with_capacity(2 * scalar_len + 8);
    push_integer(&mut body, r);
    push_integer(&mut body, s);
    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(0x30);
    push_len(&mut out, body.len());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Converts an ECDSA [`Signature`] (DER) to fixed-width `r || s`, e.g. for a JWS.
pub fn signature_to_fixed(sig: &Signature) -> Result<Vec<u8>> {
    let n = ecdsa_scalar_len(sig.algorithm()).ok_or_else(|| err("not an ECDSA signature"))?;
    der_to_fixed(sig.as_bytes(), n)
}

/// Builds an ECDSA [`Signature`] from fixed-width `r || s`.
pub fn signature_from_fixed(
    alg: SignatureAlgorithm,
    key_version: Option<anykms_core::KeyVersion>,
    fixed: &[u8],
) -> Result<Signature> {
    let n = ecdsa_scalar_len(alg).ok_or_else(|| err("not an ECDSA algorithm"))?;
    Ok(Signature::from_parts(
        alg,
        key_version,
        fixed_to_der(fixed, n)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_sizes() {
        for n in [32usize, 48, 66] {
            for pattern in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let mut fixed = vec![pattern; 2 * n];
                fixed[0] = pattern & 0x01; // P-521 top byte is at most 1
                fixed[n] = 0;
                fixed[n + 1] = pattern;
                let der = fixed_to_der(&fixed, n).unwrap();
                assert_eq!(
                    der_to_fixed(&der, n).unwrap(),
                    fixed,
                    "n={n} p={pattern:#x}"
                );
            }
        }
    }

    #[test]
    fn p521_uses_long_form_length() {
        let fixed = vec![0x01u8; 132];
        let der = fixed_to_der(&fixed, 66).unwrap();
        assert_eq!(&der[..2], &[0x30, 0x81]);
        assert_eq!(der_to_fixed(&der, 66).unwrap(), fixed);
    }

    #[test]
    fn rejects_unsupported_scalar_len() {
        // 128-byte halves would need a two-byte DER length (0x82); the encoder used to emit a
        // truncated 0x81 length instead.
        for n in [0usize, MAX_SCALAR_LEN + 1, 128, 200] {
            let fixed = vec![0xffu8; 2 * n];
            let e = fixed_to_der(&fixed, n).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "n={n}");
            assert!(der_to_fixed(&[0x30, 0x00], n).is_err(), "n={n}");
        }
        // The largest supported size still round-trips with all-ones halves (maximum length).
        let fixed = vec![0xffu8; 2 * MAX_SCALAR_LEN];
        let der = fixed_to_der(&fixed, MAX_SCALAR_LEN).unwrap();
        assert_eq!(der_to_fixed(&der, MAX_SCALAR_LEN).unwrap(), fixed);
    }

    #[test]
    fn rejects_non_minimal_and_trailing() {
        assert!(der_to_fixed(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00], 32).is_err());
        assert!(der_to_fixed(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01], 32).is_err());
        assert!(der_to_fixed(&[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01], 32).is_err());
        assert!(der_to_fixed(&[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], 32).is_err());
    }
}
