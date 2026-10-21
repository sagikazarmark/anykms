//! Zeroizing buffers that grow without leaving unwiped copies behind.
//!
//! `Vec` growth reallocates and frees the old allocation without wiping it, so a `Zeroizing<Vec>`
//! that grows in place leaks its earlier contents to the allocator. These helpers grow into a
//! fresh zeroizing buffer instead and let the old one be wiped on drop.

use std::io;

use zeroize::Zeroizing;

/// Appends `data`, growing into a fresh zeroizing buffer (at least doubling, capped at `limit`)
/// when the capacity is exhausted. Returns `false`, leaving `buf` unchanged, if the result would
/// exceed `limit`.
pub fn extend(buf: &mut Zeroizing<Vec<u8>>, data: &[u8], limit: usize) -> bool {
    let need = match buf.len().checked_add(data.len()) {
        Some(n) if n <= limit => n,
        _ => return false,
    };
    if need > buf.capacity() {
        let cap = buf.capacity().saturating_mul(2).clamp(need, limit);
        let mut bigger = Zeroizing::new(Vec::with_capacity(cap));
        bigger.extend_from_slice(buf);
        *buf = bigger;
    }
    buf.extend_from_slice(data);
    true
}

/// An [`io::Write`] sink over a zeroizing buffer that grows through [`extend`], for serializing
/// secret-bearing request bodies.
#[derive(Debug)]
pub struct Writer(pub Zeroizing<Vec<u8>>);

impl io::Write for Writer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if extend(&mut self.0, data, usize::MAX) {
            Ok(data.len())
        } else {
            Err(io::ErrorKind::OutOfMemory.into())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serializes `value` as JSON into a zeroizing buffer (starting at `capacity`, growing through
/// [`extend`]), for request bodies that carry plaintext, keys or credentials. Size `capacity` for
/// the expected body (e.g. the base64 length of the plaintext plus the field names) so it rarely
/// grows.
pub fn json_body<T: serde::Serialize + ?Sized>(
    value: &T,
    capacity: usize,
) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    let mut w = Writer(Zeroizing::new(Vec::with_capacity(capacity)));
    serde_json::to_writer(&mut w, value)?;
    Ok(w.0)
}

/// Reads a small secret file (such as a TLS private key or a credentials file) into a zeroizing
/// buffer, failing with `InvalidData` if it is larger than `limit`.
pub fn read_file(path: &std::path::Path, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let hint = file.metadata().map_or(0, |m| m.len());
    let mut buf = Zeroizing::new(Vec::with_capacity(
        usize::try_from(hint).unwrap_or(limit).min(limit),
    ));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let n = file.read(&mut chunk[..])?;
        if n == 0 {
            return Ok(buf);
        }
        if !extend(&mut buf, &chunk[..n], limit) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
        }
    }
}

/// The kind of a failure to read a **token file** (a projected or rotated token: web identity,
/// container token, federated or subject token, a Vault token or JWT): `NotFound` is
/// `Unavailable` (a rotation race: the next attempt may find the new file); everything else is
/// `Configuration` (`EACCES`, `ENOTDIR`, `EISDIR`, too large, not UTF-8, empty, control
/// characters: a deployment error that retrying cannot fix).
///
/// Files that *select* a credential source (an ADC JSON file, an AWS profile) are not token
/// files: any failure to read them is `Configuration`.
pub fn token_file_error_kind(e: &io::Error) -> anykms_core::ErrorKind {
    match e.kind() {
        io::ErrorKind::NotFound => anykms_core::ErrorKind::Unavailable,
        _ => anykms_core::ErrorKind::Configuration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_file_errors() {
        use anykms_core::ErrorKind;
        let kind = |k: io::ErrorKind| token_file_error_kind(&io::Error::from(k));
        assert_eq!(kind(io::ErrorKind::NotFound), ErrorKind::Unavailable);
        for k in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidData,
            io::ErrorKind::Other,
        ] {
            assert_eq!(kind(k), ErrorKind::Configuration, "{k:?}");
        }
        // A directory where the file should be.
        let e = read_file(&std::env::temp_dir(), 16).unwrap_err();
        assert_eq!(token_file_error_kind(&e), ErrorKind::Configuration, "{e:?}");
    }

    #[test]
    fn extend_grows_and_caps() {
        let mut b = Zeroizing::new(Vec::with_capacity(4));
        assert!(extend(&mut b, b"abc", 10));
        assert_eq!(b.capacity(), 4);
        assert!(extend(&mut b, b"de", 10));
        // Doubled, within the limit.
        assert_eq!(&b[..], b"abcde");
        assert!(b.capacity() >= 5 && b.capacity() <= 10);
        assert!(extend(&mut b, b"fghij", 10));
        assert_eq!(&b[..], b"abcdefghij");
        assert!(b.capacity() <= 10, "{}", b.capacity());
        assert!(!extend(&mut b, b"k", 10));
        assert_eq!(&b[..], b"abcdefghij");
    }

    #[test]
    fn writer_serializes_beyond_the_hint() {
        let mut w = Writer(Zeroizing::new(Vec::with_capacity(1)));
        serde_json::to_writer(&mut w, &serde_json::json!({"k": "v".repeat(1000)})).unwrap();
        assert_eq!(w.0.len(), 1008);
    }

    #[test]
    fn json_body_serializes() {
        let b = json_body(&serde_json::json!({"plaintext": "AAAA"}), 4).unwrap();
        assert_eq!(&b[..], br#"{"plaintext":"AAAA"}"#);
    }

    #[test]
    fn read_file_is_bounded() {
        let dir = std::env::temp_dir().join(format!("anykms-http-zbuf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, b"0123456789").unwrap();
        assert_eq!(&read_file(&p, 10).unwrap()[..], b"0123456789");
        let e = read_file(&p, 9).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
