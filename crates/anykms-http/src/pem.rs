//! PEM decoding into zeroizing buffers.

use anykms_core::{Error, ErrorKind, Operation, Result};
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

fn config_err(backend: &'static str, m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, backend, Operation::Configure, m)
}

/// Decodes the first private key in `pem` (PKCS#8, PKCS#1 or SEC1). Unlike rustls-pki-types'
/// PEM reader, every intermediate buffer (base64 text, DER) is zeroizing; the DER moves into the
/// returned key, which rustls wipes after loading it. Encrypted keys are refused. Errors are
/// `Configuration` with fixed messages (never the contents).
pub fn private_key_from_pem(backend: &'static str, pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    use base64::Engine as _;
    use rustls_pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    let bad = || config_err(backend, "cannot parse the client key PEM");
    let encrypted = || config_err(backend, "encrypted client keys are not supported");
    let mut lines = pem
        .split(|&b| b == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|l| !l.is_empty());
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix(b"-----BEGIN ")
            .and_then(|l| l.strip_suffix(b"-----"))
        else {
            continue;
        };
        let make: fn(Vec<u8>) -> PrivateKeyDer<'static> = match label {
            b"PRIVATE KEY" => |d| PrivatePkcs8KeyDer::from(d).into(),
            b"RSA PRIVATE KEY" => |d| PrivatePkcs1KeyDer::from(d).into(),
            b"EC PRIVATE KEY" => |d| PrivateSec1KeyDer::from(d).into(),
            b"ENCRYPTED PRIVATE KEY" => return Err(encrypted()),
            // Anything else (certificates, EC PARAMETERS, ...) is skipped.
            _ => continue,
        };
        let mut b64 = Zeroizing::new(Vec::with_capacity(pem.len()));
        let mut ended = false;
        for line in lines.by_ref() {
            if let Some(end) = line
                .strip_prefix(b"-----END ")
                .and_then(|l| l.strip_suffix(b"-----"))
            {
                if end != label {
                    return Err(bad());
                }
                ended = true;
                break;
            }
            if line.contains(&b':') {
                // RFC 1421 headers (`Proc-Type: 4,ENCRYPTED`): a legacy encrypted key.
                return Err(encrypted());
            }
            b64.extend_from_slice(line);
        }
        if !ended {
            return Err(bad());
        }
        let mut der = Zeroizing::new(vec![0u8; b64.len() / 4 * 3 + 3]);
        let n = base64::engine::general_purpose::STANDARD
            .decode_slice(&b64[..], &mut der[..])
            .map_err(|_| bad())?;
        der.truncate(n);
        // Moves the allocation out; the emptied Zeroizing has nothing left to wipe.
        return Ok(make(std::mem::take(&mut *der)));
    }
    Err(bad())
}
