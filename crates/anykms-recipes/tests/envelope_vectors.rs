//! Envelope format v1 test vectors (`tests/vectors/envelope_v1.json`).
//!
//! Every future release must decrypt these. Regenerate only when adding vectors:
//! `ANYKMS_REGENERATE_VECTORS=1 cargo test -p anykms-recipes --test envelope_vectors`.
//!
//! The vectors are built here from AES-GCM, HKDF and SHA-256 directly, following
//! docs/envelope-format.md, not with the crate's envelope code (which has no deterministic-
//! encryption hook). That second implementation of the format doubles as a cross-check: the
//! library must open every valid vector it builds and reject every invalid one, and the
//! committed file must be exactly what it builds.
//!
//! The vectors use a deterministic **test KEK** (documented in docs/envelope-format.md) so any
//! implementation can reproduce them: AES-256-GCM with key
//! `K_v = SHA-256("anykms test kek <name> v<v>")` (`<name>` is the KEK name, `a` or `b`; `<v>` the
//! decimal version), nonce = first 12 bytes of `SHA-256(plaintext)`, framed as
//! `"testkek:v<v>:" || nonce || ciphertext || tag`.

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _};
use anykms_core::{
    Aead, AeadKeyWrap, Ciphertext, ErrorKind, KeyVersion, Result, Rewrap, Zeroizing,
};
use anykms_recipes::envelope::Padding;
use anykms_recipes::{EnvelopeAead, EnvelopeKeyring};
use serde_json::{Value, json};
use sha2::Digest as _;

/// The test KEK's key for KEK `name`, version `v`.
fn test_kek_key(name: &str, v: u8) -> [u8; 32] {
    sha2::Sha256::digest(format!("anykms test kek {name} v{v}")).into()
}

/// Encrypts under the test KEK (`name`, version `v`): `"testkek:v<v>:" || nonce || ct || tag`.
fn test_kek_seal(name: &str, v: u8, pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce = &sha2::Sha256::digest(pt)[..12];
    let ct = Aes256Gcm::new_from_slice(&test_kek_key(name, v))
        .unwrap()
        .encrypt(
            &aes_gcm::Nonce::try_from(nonce).unwrap(),
            Payload { msg: pt, aad },
        )
        .unwrap();
    let mut out = format!("testkek:v{v}:").into_bytes();
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypts a test-KEK ciphertext of KEK `name` whose version is at most `max_version`.
fn test_kek_open(name: &str, max_version: u8, ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let rest = ct.strip_prefix(b"testkek:v")?;
    let v = rest.first()?.wrapping_sub(b'0');
    let rest = rest.get(2..)?;
    if rest.len() < 28 || !(1..=max_version).contains(&v) {
        return None;
    }
    Aes256Gcm::new_from_slice(&test_kek_key(name, v))
        .unwrap()
        .decrypt(
            &aes_gcm::Nonce::try_from(&rest[..12]).unwrap(),
            Payload {
                msg: &rest[12..],
                aad,
            },
        )
        .ok()
}

/// The deterministic test KEK. `name` separates independent KEKs; `primary` is the version new
/// wraps use.
#[derive(Clone, Debug)]
struct TestKek {
    name: &'static str,
    primary: u8,
}

fn kek_err() -> anykms_core::Error {
    anykms_core::Error::new(
        ErrorKind::DecryptFailed,
        "testkek",
        anykms_core::Operation::Decrypt,
        "test kek failure",
    )
}

impl Aead for TestKek {
    async fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        Ok(Ciphertext::from_bytes(test_kek_seal(
            self.name,
            self.primary,
            pt,
            aad,
        )))
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        test_kek_open(self.name, self.primary, ct.as_bytes(), aad)
            .map(Zeroizing::new)
            .ok_or_else(kek_err)
    }

    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        Ok(ct
            .as_bytes()
            .get(9)
            .map(|d| KeyVersion::from_u64((d - b'0') as u64)))
    }
}

impl Rewrap for TestKek {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        let pt = self.decrypt(ct, aad).await?;
        self.encrypt(&pt, aad).await
    }
}

/// The test KEK as an envelope KEK (wrapping with empty AAD).
fn kek(name: &'static str, primary: u8) -> AeadKeyWrap<TestKek> {
    TestKek { name, primary }.into_key_wrap()
}

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/envelope_v1.json"
);

// The format, from docs/envelope-format.md (independent of `anykms_recipes::envelope`).

const HEADER_LEN: usize = 49;
const DEK_LEN: usize = 32;

/// Encryption step 2: `okm = HKDF-SHA256(salt = none, ikm = DEK, info, L = 64)`, split into
/// `(enc_key, commit)`. Any IKM length is accepted, as an implementation that forgets the
/// data-key length check would.
fn derive(dek: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut okm = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, dek)
        .expand(b"anykms/envelope/v1", &mut okm)
        .unwrap();
    (okm[..32].try_into().unwrap(), okm[32..].try_into().unwrap())
}

/// The padded flag (the only flag v1 defines).
const FLAG_PADDED: u8 = 0x04;

/// Encryption step 3: `magic || version || flags || commit || nonce`, flags `0`.
fn header(commit: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    flagged_header(0, commit, nonce)
}

fn flagged_header(flags: u8, commit: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut h = b"AKE\x01".to_vec();
    h.push(flags);
    h.extend_from_slice(commit);
    h.extend_from_slice(nonce);
    assert_eq!(h.len(), HEADER_LEN);
    h
}

/// Encryption step 4: `header || u64(len(user_aad)) || user_aad`.
fn gcm_aad(header: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut a = header.to_vec();
    a.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    a.extend_from_slice(aad);
    a
}

fn gcm(enc_key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(enc_key).unwrap()
}

/// Encryption step 5: AES-256-GCM under `enc_key` with the header (whatever commitment it holds)
/// in the AAD. The nonce is the header's.
fn seal_payload(enc_key: &[u8; 32], header: &[u8], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    gcm(enc_key)
        .encrypt(
            &aes_gcm::Nonce::try_from(&header[37..HEADER_LEN]).unwrap(),
            Payload {
                msg: pt,
                aad: &gcm_aad(header, aad),
            },
        )
        .unwrap()
}

/// Encryption step 7: `header || kek_id_len || kek_id || wrapped_dek_len || wrapped_dek || payload`.
fn envelope(header: &[u8], kek_id: &[u8], wrapped: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = header.to_vec();
    out.push(kek_id.len() as u8);
    out.extend_from_slice(kek_id);
    out.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
    out.extend_from_slice(wrapped);
    out.extend_from_slice(payload);
    out
}

/// Encryption steps 1-7 with a given data key and nonce, wrapping under test KEK `kek`, version 1.
fn seal(dek: &[u8], nonce: &[u8; 12], kek: &str, kek_id: &[u8], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    seal_flagged(0, dek, nonce, kek, kek_id, pt, aad)
}

/// [`seal`] with `flags` in the header; `pt` is sealed as given (already padded or not).
fn seal_flagged(
    flags: u8,
    dek: &[u8],
    nonce: &[u8; 12],
    kek: &str,
    kek_id: &[u8],
    pt: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let (enc_key, commit) = derive(dek);
    let h = flagged_header(flags, &commit, nonce);
    let payload = seal_payload(&enc_key, &h, pt, aad);
    envelope(&h, kek_id, &test_kek_seal(kek, 1, dek, b""), &payload)
}

/// Padding (encryption step 0 with a block policy): `pt || 0x80 || 0x00*`, to the next multiple of
/// `block` that leaves room for the marker.
fn pad_block(pt: &[u8], block: usize) -> Vec<u8> {
    let mut p = pt.to_vec();
    p.push(0x80);
    while !p.len().is_multiple_of(block) {
        p.push(0);
    }
    p
}

/// The parts of an envelope (decryption step 1, strict).
struct Parts<'a> {
    header: &'a [u8],
    commit: &'a [u8],
    nonce: &'a [u8],
    kek_id: &'a [u8],
    wrapped: &'a [u8],
    payload: &'a [u8],
}

fn parse(b: &[u8]) -> Option<Parts<'_>> {
    if b.len() < HEADER_LEN + 3 || &b[..4] != b"AKE\x01" || b[4] & !FLAG_PADDED != 0 {
        return None;
    }
    let kek_id_len = b[HEADER_LEN] as usize;
    let rest = b.get(HEADER_LEN + 1..)?;
    let kek_id = rest.get(..kek_id_len)?;
    let rest = &rest[kek_id_len..];
    let wrapped_len = u16::from_be_bytes(rest.get(..2)?.try_into().unwrap()) as usize;
    if !(1..=4096).contains(&wrapped_len) {
        return None;
    }
    let wrapped = rest.get(2..2 + wrapped_len)?;
    let payload = &rest[2 + wrapped_len..];
    if payload.len() < 16 {
        return None;
    }
    Some(Parts {
        header: &b[..HEADER_LEN],
        commit: &b[5..37],
        nonce: &b[37..HEADER_LEN],
        kek_id,
        wrapped,
        payload,
    })
}

/// Which decryption checks [`spec_open`] runs (all of them in a conforming implementation).
#[derive(Clone, Copy)]
struct Checks {
    dek_len: bool,
    commitment: bool,
    padding: bool,
}

const STRICT: Checks = Checks {
    dek_len: true,
    commitment: true,
    padding: true,
};

/// Decryption steps 1-5 with test KEK `kek` (versions up to `kek_versions`) and `kek_id`.
fn spec_open(
    b: &[u8],
    aad: &[u8],
    kek: &str,
    kek_versions: u8,
    kek_id: &str,
    checks: Checks,
) -> Option<Vec<u8>> {
    let p = parse(b)?;
    if p.kek_id != kek_id.as_bytes() {
        return None;
    }
    let dek = test_kek_open(kek, kek_versions, p.wrapped, b"")?;
    if checks.dek_len && dek.len() != DEK_LEN {
        return None;
    }
    let (enc_key, commit) = derive(&dek);
    if checks.commitment && commit[..] != *p.commit {
        return None;
    }
    let mut pt = gcm(&enc_key)
        .decrypt(
            &aes_gcm::Nonce::try_from(p.nonce).unwrap(),
            Payload {
                msg: p.payload,
                aad: &gcm_aad(p.header, aad),
            },
        )
        .ok()?;
    // Decryption step 6: a padded plaintext ends in `0x80 || 0x00*`; remove exactly that.
    if checks.padding && p.header[4] & FLAG_PADDED != 0 {
        while pt.last() == Some(&0) {
            pt.pop();
        }
        if pt.pop() != Some(0x80) {
            return None;
        }
    }
    Some(pt)
}

const PLAINTEXT: &[u8] = b"anykms envelope v1 test vector";
const AAD: &[u8] = b"row-1";

fn generate() -> Value {
    let dek = [0x11; 32];
    let p = seal(&dek, &[0x22; 12], "a", b"app-kek", PLAINTEXT, AAD);
    let empty = seal(&[0x33; 32], &[0x44; 12], "a", b"", b"", b"");
    let pp = parse(&p).unwrap();
    // The same envelope with its data key rewrapped: under KEK `a` version 2, and moved to KEK `b`.
    let rewrapped = envelope(
        pp.header,
        b"app-kek",
        &test_kek_seal("a", 2, &dek, b""),
        pp.payload,
    );
    let moved_wrapped = test_kek_seal("b", 1, &dek, b"");
    let moved = envelope(pp.header, b"new-kek", &moved_wrapped, pp.payload);

    let mut flipped_commit = p.clone();
    flipped_commit[5] ^= 1;
    let mut flags = p.clone();
    flags[4] = 1;
    let mut version2 = p.clone();
    version2[3] = 2;
    let truncated = p[..p.len() - 1].to_vec();
    // Wrapped DEK of `empty` grafted into `plain` (same KEK, other data key): the commitment fails.
    let swapped = envelope(
        pp.header,
        pp.kek_id,
        parse(&empty).unwrap().wrapped,
        pp.payload,
    );
    // `moved` relabeled to point at the other real KEK in a keyring: routing must not bypass the
    // commitment (the KEK cannot unwrap it).
    let relabeled = envelope(pp.header, b"app-kek", &moved_wrapped, pp.payload);
    // `plain`'s data key and nonce, a commitment that is not the data key's, and a payload sealed
    // under that header: everything but the key-commitment comparison accepts it.
    let (enc_key, mut wrong_commit) = derive(&dek);
    wrong_commit[0] ^= 1;
    let wrong_header = header(&wrong_commit, &[0x22; 12]);
    let commitment_mismatch = envelope(
        &wrong_header,
        b"app-kek",
        pp.wrapped,
        &seal_payload(&enc_key, &wrong_header, PLAINTEXT, AAD),
    );
    // A 16-byte data key, otherwise sealed exactly as specified (HKDF accepts a 16-byte IKM).
    let short_dek = seal(&[0x55; 16], &[0x66; 12], "a", b"app-kek", PLAINTEXT, AAD);
    // `PLAINTEXT` padded to 16-byte blocks (30 bytes and the marker: 32), flagged padded.
    let padded = seal_flagged(
        FLAG_PADDED,
        &[0x77; 32],
        &[0x88; 12],
        "a",
        b"app-kek",
        &pad_block(PLAINTEXT, 16),
        AAD,
    );
    // Flagged padded, but the GCM-valid plaintext has no marker (it ends in `r`): only the
    // padding check rejects it.
    let bad_marker = seal_flagged(
        FLAG_PADDED,
        &[0x99; 32],
        &[0xaa; 12],
        "a",
        b"app-kek",
        PLAINTEXT,
        AAD,
    );
    // `plain` (unpadded) with the padded flag set afterwards: the flag is in the GCM AAD.
    let mut padded_flag_on_plain = p.clone();
    padded_flag_on_plain[4] = FLAG_PADDED;
    let mut unknown_flag = p.clone();
    unknown_flag[4] = 0x08;

    let h = |b: &[u8]| hex::encode(b);
    json!({
        "format": "anykms envelope v1",
        "test_kek": "AES-256-GCM, K_v = SHA-256(\"anykms test kek <name> v<v>\"), nonce = SHA-256(pt)[..12], framing \"testkek:v<v>:\" || nonce || ct || tag",
        "valid": [
            {"name": "plain", "kek": "a", "kek_versions": 1, "kek_id": "app-kek", "aad": h(AAD), "plaintext": h(PLAINTEXT), "envelope": h(&p)},
            {"name": "empty", "kek": "a", "kek_versions": 1, "kek_id": "", "aad": "", "plaintext": "", "envelope": h(&empty)},
            {"name": "rewrapped", "kek": "a", "kek_versions": 2, "kek_id": "app-kek", "aad": h(AAD), "plaintext": h(PLAINTEXT), "envelope": h(&rewrapped)},
            {"name": "rewrap_to", "kek": "b", "kek_versions": 1, "kek_id": "new-kek", "aad": h(AAD), "plaintext": h(PLAINTEXT), "envelope": h(&moved)},
            {"name": "padded", "kek": "a", "kek_versions": 1, "kek_id": "app-kek", "aad": h(AAD), "plaintext": h(PLAINTEXT), "envelope": h(&padded),
             "description": "Flags 0x04: the plaintext is padded to 16-byte blocks (30 bytes, the 0x80 marker and one zero byte), and decryption removes the padding."}
        ],
        "invalid": [
            {"name": "flipped_commitment", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&flipped_commit)},
            {"name": "nonzero_flags", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&flags)},
            {"name": "unknown_flag", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&unknown_flag)},
            {"name": "padded_flag_on_unpadded", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&padded_flag_on_plain)},
            {"name": "unknown_version", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&version2)},
            {"name": "truncated", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&truncated)},
            {"name": "swapped_wrapped_dek", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&swapped)},
            {"name": "wrong_aad", "kek": "a", "kek_id": "app-kek", "aad": h(b"row-2"), "envelope": h(&p)},
            {"name": "kek_id_rewritten_to_other_keyring_kek", "kek": "keyring", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&relabeled)},
            {"name": "commitment_mismatch_gcm_valid", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&commitment_mismatch),
             "description": "Isolates decryption step 4 (key commitment). The data key unwraps and is 32 bytes, and the payload is valid AES-256-GCM under the data key's derived enc_key with this envelope's header (including its commitment) in the AAD, but the header's commitment is not the HKDF-derived one. Only the commitment comparison rejects it."},
            {"name": "short_dek", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&short_dek),
             "description": "Isolates the data-key length check (decryption step 3). The wrapped data key unwraps to 16 bytes; the commitment and the AES-256-GCM payload are computed from that 16-byte key exactly as specified (HKDF-SHA256 still yields a 32-byte enc_key and a matching commitment). An implementation without the length check accepts it."},
            {"name": "bad_padding_marker", "kek": "a", "kek_id": "app-kek", "aad": h(AAD), "envelope": h(&bad_marker),
             "description": "Isolates the padding check (decryption step 6). Flags 0x04, and the payload is valid AES-256-GCM under the committed data key, but its plaintext does not end in 0x80 followed by zero bytes. An implementation that ignores the padded flag returns the raw plaintext."}
        ]
    })
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn kek_for(name: &str, versions: u8) -> AeadKeyWrap<TestKek> {
    match name {
        "a" => kek("a", versions),
        _ => kek("b", versions),
    }
}

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).expect("vectors file")).unwrap()
}

fn vector<'a>(v: &'a Value, list: &str, name: &str) -> &'a Value {
    v[list]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {list} vector {name}"))
}

#[tokio::test]
async fn vectors_decrypt() {
    if std::env::var("ANYKMS_REGENERATE_VECTORS").is_ok_and(|v| v == "1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&generate()).unwrap() + "\n",
        )
        .unwrap();
    }
    let v = load();
    for c in v["valid"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let (kek_name, versions) = (
            c["kek"].as_str().unwrap(),
            c["kek_versions"].as_u64().unwrap() as u8,
        );
        let (bytes, aad) = (unhex(&c["envelope"]), unhex(&c["aad"]));
        let env =
            EnvelopeAead::new(c["kek_id"].as_str().unwrap(), kek_for(kek_name, versions)).unwrap();
        let pt = env
            .decrypt(&Ciphertext::from_bytes(bytes.clone()), &aad)
            .await
            .unwrap_or_else(|e| panic!("valid vector {name}: {e}"));
        assert_eq!(*pt, unhex(&c["plaintext"]), "{name}");
        let spec = spec_open(
            &bytes,
            &aad,
            kek_name,
            versions,
            c["kek_id"].as_str().unwrap(),
            STRICT,
        );
        assert_eq!(spec, Some(unhex(&c["plaintext"])), "{name} (spec)");
    }
    let keyring = EnvelopeKeyring::new("app-kek", kek("a", 2))
        .unwrap()
        .with_kek("new-kek", kek("b", 1))
        .unwrap();
    for c in v["invalid"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let ct = Ciphertext::from_bytes(unhex(&c["envelope"]));
        let aad = unhex(&c["aad"]);
        let r = if c["kek"] == "keyring" {
            keyring.decrypt(&ct, &aad).await
        } else {
            EnvelopeAead::new(c["kek_id"].as_str().unwrap(), kek("a", 2))
                .unwrap()
                .decrypt(&ct, &aad)
                .await
        };
        assert_eq!(
            r.map(|_| ()).unwrap_err().kind(),
            ErrorKind::DecryptFailed,
            "invalid vector {name}"
        );
        // `kek_id` "app-kek" routes to KEK `a` in the keyring too.
        let spec = spec_open(
            ct.as_bytes(),
            &aad,
            "a",
            2,
            c["kek_id"].as_str().unwrap(),
            STRICT,
        );
        assert_eq!(spec, None, "invalid vector {name} (spec)");
    }
}

#[test]
fn vectors_are_reproducible() {
    // Generation is deterministic; the committed file must be exactly what it produces.
    let committed = std::fs::read_to_string(PATH).unwrap();
    assert_eq!(
        committed,
        serde_json::to_string_pretty(&generate()).unwrap() + "\n"
    );
}

#[tokio::test]
async fn library_rewraps_match_vectors() {
    // The library's rewraps of `plain` are the independently built `rewrapped` and `rewrap_to`.
    let v = load();
    let plain = Ciphertext::from_bytes(unhex(&vector(&v, "valid", "plain")["envelope"]));
    let a2 = EnvelopeAead::new("app-kek", kek("a", 2)).unwrap();
    let b = EnvelopeAead::new("new-kek", kek("b", 1)).unwrap();
    let rewrapped = a2.rewrap(&plain).await.unwrap();
    assert_eq!(
        rewrapped.as_bytes(),
        unhex(&vector(&v, "valid", "rewrapped")["envelope"])
    );
    let a1 = EnvelopeAead::new("app-kek", kek("a", 1)).unwrap();
    let moved = a1.rewrap_to(&plain, &b).await.unwrap();
    assert_eq!(
        moved.as_bytes(),
        unhex(&vector(&v, "valid", "rewrap_to")["envelope"])
    );
}

/// The library's rejection of `name`: `DecryptFailed` after the data key unwrapped (the message
/// is not "envelope data key does not unwrap").
async fn assert_rejected_after_unwrap(v: &Value, name: &str) {
    let c = vector(v, "invalid", name);
    let err = EnvelopeAead::new("app-kek", kek("a", 1))
        .unwrap()
        .decrypt(&Ciphertext::from_bytes(unhex(&c["envelope"])), AAD)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed, "{name}");
    assert_eq!(
        err.message(),
        "wrong key or AAD, or a malformed or tampered envelope",
        "{name}"
    );
}

#[tokio::test]
async fn commitment_mismatch_vector_is_gcm_valid() {
    let v = load();
    let b = unhex(&vector(&v, "invalid", "commitment_mismatch_gcm_valid")["envelope"]);
    let p = parse(&b).unwrap();
    let dek = test_kek_open("a", 1, p.wrapped, b"").unwrap();
    assert_eq!(dek.len(), DEK_LEN);
    let (enc_key, commit) = derive(&dek);
    assert_ne!(commit[..], *p.commit, "the commitment must be wrong");
    // Raw AES-256-GCM under the derived key, with the header as written in the AAD, accepts it.
    let pt = gcm(&enc_key)
        .decrypt(
            &aes_gcm::Nonce::try_from(p.nonce).unwrap(),
            Payload {
                msg: p.payload,
                aad: &gcm_aad(p.header, AAD),
            },
        )
        .expect("GCM-valid");
    assert_eq!(pt, PLAINTEXT);
    let no_commitment = Checks {
        commitment: false,
        ..STRICT
    };
    assert_eq!(
        spec_open(&b, AAD, "a", 1, "app-kek", no_commitment).as_deref(),
        Some(PLAINTEXT)
    );
    assert_eq!(spec_open(&b, AAD, "a", 1, "app-kek", STRICT), None);
    assert_rejected_after_unwrap(&v, "commitment_mismatch_gcm_valid").await;
}

#[tokio::test]
async fn short_dek_vector_fails_only_the_length_check() {
    let v = load();
    let b = unhex(&vector(&v, "invalid", "short_dek")["envelope"]);
    let p = parse(&b).unwrap();
    assert_eq!(test_kek_open("a", 1, p.wrapped, b"").unwrap().len(), 16);
    // An implementation that skips the data-key length check opens it, commitment and all.
    let no_dek_len = Checks {
        dek_len: false,
        ..STRICT
    };
    assert_eq!(
        spec_open(&b, AAD, "a", 1, "app-kek", no_dek_len).as_deref(),
        Some(PLAINTEXT)
    );
    assert_eq!(spec_open(&b, AAD, "a", 1, "app-kek", STRICT), None);
    assert_rejected_after_unwrap(&v, "short_dek").await;
}

#[tokio::test]
async fn bad_padding_marker_vector_fails_only_the_padding_check() {
    let v = load();
    let b = unhex(&vector(&v, "invalid", "bad_padding_marker")["envelope"]);
    // Everything up to and including GCM accepts it; an implementation that ignores the padded
    // flag returns the plaintext as sealed.
    let no_padding = Checks {
        padding: false,
        ..STRICT
    };
    assert_eq!(
        spec_open(&b, AAD, "a", 1, "app-kek", no_padding).as_deref(),
        Some(PLAINTEXT)
    );
    assert_eq!(spec_open(&b, AAD, "a", 1, "app-kek", STRICT), None);
    assert_rejected_after_unwrap(&v, "bad_padding_marker").await;
}

#[tokio::test]
async fn library_padding_opens_with_the_spec() {
    // The other direction: what the library writes, the spec's decryption opens (marker, zero
    // bytes, block size and flag as specified), and the GCM plaintext is the spec's padding.
    let env = EnvelopeAead::new("app-kek", kek("a", 1))
        .unwrap()
        .with_padding(Padding::block(16));
    let ct = env.encrypt(PLAINTEXT, AAD).await.unwrap();
    assert_eq!(ct.as_bytes()[4], FLAG_PADDED);
    assert_eq!(
        spec_open(ct.as_bytes(), AAD, "a", 1, "app-kek", STRICT).as_deref(),
        Some(PLAINTEXT)
    );
    let raw = Checks {
        padding: false,
        ..STRICT
    };
    assert_eq!(
        spec_open(ct.as_bytes(), AAD, "a", 1, "app-kek", raw),
        Some(pad_block(PLAINTEXT, 16))
    );
}
