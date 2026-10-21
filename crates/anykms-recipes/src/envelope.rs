//! Envelope encryption with a KMS-wrapped data key.
//!
//! **Emulates:** AEAD over arbitrarily large payloads on any backend. **Enforced by:** this
//! process encrypts the payload (AES-256-GCM under a fresh per-message key, with key commitment);
//! the **KMS only wraps the 32-byte data key**, through the KEK's [`KeyWrap`]: a [`KeyWrapKey`]
//! from [`Registry::key_wrap`](anykms_core::Registry::key_wrap), or an [`Aead`] key adapted
//! explicitly to wrap with empty AAD, `EnvelopeAead::new(kek_id, key.into_key_wrap())` (see
//! [`AeadKeyWrap`]). Keys that only wrap, such as RSA-OAEP or AES key wrap, implement `KeyWrap`
//! directly. The KMS key never sees the payload or the caller's AAD. Format: `docs/envelope-format.md`; every future release decrypts v1.
//!
//! **Status:** format v1 is frozen and always decrypts, but its external review is pending, so it
//! is not yet recommended for long-lived data. The release that completes the review announces
//! the promotion in its release notes and drops this note; should the review
//! find a flaw, v1 still decrypts and new envelopes move to a new version.
//!
//! # Requirements
//!
//! - The KEK **MUST** be dedicated to envelopes. Data keys are wrapped with *empty* AAD (as in
//!   Tink's `KmsEnvelopeAead`, and because transit's `rewrap` ignores AAD), so any other code path
//!   that decrypts with empty AAD under the same KEK could unwrap envelope data keys. Do not mix
//!   native `DataKeys` or direct `Aead` use with `EnvelopeAead` on one KEK; give envelope KEKs
//!   their own mount (e.g. `transit-envelope/`) so policy enforces it.
//! - Anyone who can wrap under the KEK can create envelopes for any AAD: the recipe provides
//!   confidentiality and integrity, not proof of who wrote the data. With a symmetric KEK the
//!   writers are whoever has `encrypt` on it. With a public-key (RSA-OAEP) KEK, wrapping needs
//!   only the public key, so **every holder of the public key** can write envelopes that decrypt
//!   as genuine: the envelope then gives confidentiality only, and the AAD does not authenticate
//!   the writer. In an [`EnvelopeKeyring`] this holds for every KEK in the ring, so an RSA
//!   secondary opens the ring to its public-key holders even when the primary is symmetric.
//!   Likewise the key commitment
//!   covers the data key, not the AAD: an envelope's creator can make one envelope that is valid
//!   under two AADs (AES-GCM does not commit to the AAD under a known key).
//!
//! # Padding
//!
//! An envelope is exactly as long as its plaintext plus a fixed overhead, so it reveals the
//! plaintext length: a database column of envelopes tells short notes from long ones. Set a
//! [`Padding`] policy with [`EnvelopeAead::with_padding`] or [`EnvelopeKeyring::with_padding`] to
//! hide it; padded envelopes are marked as such, and every reader opens them.
//!
//! # Rewrapping
//!
//! Every rewrap replaces only the wrapped data key (and possibly `kek_id`); the payload is never
//! changed. Which one to use:
//!
//! | Method | Use it to | KEK needs | Data key | Checks |
//! |---|---|---|---|---|
//! | [`EnvelopeAead::rewrap_current`], [`EnvelopeKeyring::rewrap_current`] | rotate or migrate (the default): move to the current version of the KEK (a keyring: of its primary KEK), inside the KMS where the KEK can rewrap, otherwise locally | [`KeyWrap`] + [`Rewrap`] | stays in the KMS where the KEK rewraps, otherwise briefly in local memory | as `rewrap` or `rewrap_local` |
//! | [`EnvelopeAead::rewrap`] | the same, only inside the KMS (fails with `Unsupported` where the KEK cannot rewrap) | [`Rewrap`] (e.g. transit, AWS) | stays in the KMS | none |
//! | [`EnvelopeAead::rewrap_local`], [`EnvelopeKeyring::rewrap_local`] | the same, always locally, on any backend | [`KeyWrap`] | briefly in local memory | the data key unwraps and matches the key commitment; never sees the AAD or the payload |
//! | [`EnvelopeAead::rewrap_verified`], [`EnvelopeKeyring::rewrap_verified`] | the same, verifying each envelope against its row's AAD first (a migration that reports swapped or corrupted rows) | [`KeyWrap`] | briefly in local memory, and so is the plaintext (zeroized, never returned) | as `rewrap_local`, and the payload decrypts under the row's AAD |
//! | [`EnvelopeAead::rewrap_to`] | move to another KEK (another key or backend), rewriting `kek_id` | [`KeyWrap`] → [`KeyWrap`] | briefly in local memory | as `rewrap_local` |
//!
//! Every rewrap writes a new wrapped key, even for an envelope that is already current, so a
//! rotation or migration job skips those first and, once done, confirms that no envelope is
//! left behind with a completion scan. An envelope is current when it names the keyring's
//! [`primary_id`](EnvelopeKeyring::primary_id) and, where both sides report it, its data key is
//! wrapped under the primary KEK's current version (read from the KMS with `describe`). The
//! version in the envelope is **not authenticated** (see [`Aead::ciphertext_version`] on
//! [`EnvelopeAead`]): good enough to pick envelopes to rewrap, not a security decision.
//!
//! ```
//! use anykms_core::{Aead as _, Ciphertext, Describe as _, KeyVersion, KeyWrapKey, Result};
//! use anykms_recipes::{Envelope, EnvelopeKeyring};
//!
//! /// Whether `ct` still needs [`rewrap_current`](EnvelopeKeyring::rewrap_current). An envelope
//! /// naming a KEK the keyring does not have fails with `DecryptFailed`.
//! fn needs_rewrap(ring: &EnvelopeKeyring, current: Option<&KeyVersion>, ct: &Ciphertext)
//!     -> Result<bool> {
//!     if Envelope::parse(ct.as_bytes())?.kek_id() != ring.primary_id() {
//!         return Ok(true);
//!     }
//!     // Compare versions only where both are known: some wrapped keys do not reveal theirs, and
//!     // some backends rotate transparently (an AWS key's version is its ARN).
//!     Ok(match (ring.ciphertext_version(ct)?, current) {
//!         (Some(v), Some(c)) => &v != c,
//!         _ => false,
//!     })
//! }
//!
//! # async fn scan(ring: EnvelopeKeyring, primary: KeyWrapKey, rows: Vec<Ciphertext>)
//! #     -> Result<()> {
//! // `primary` is the primary KEK's handle, as opened for the keyring.
//! let info = primary.describe().await?;
//! let mut left = 0;
//! for ct in &rows {
//!     if needs_rewrap(&ring, info.primary_version(), ct)? {
//!         left += 1; // during the job: store `ring.rewrap_current(ct).await?` instead
//!     }
//! }
//! assert_eq!(left, 0, "the migration is complete");
//! # Ok(()) }
//! ```

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _};
use std::any::Any;
use std::sync::Arc;

use anykms_core::{
    Aead, AeadKey, AeadKeyWrap, Ciphertext, DynKeyWrap, Error, ErrorKind, KeyVersion, KeyWrap,
    KeyWrapKey, Operation, Result, Rewrap,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

const BACKEND: &str = "envelope";
const MAGIC: &[u8; 3] = b"AKE";
/// Format version 1.
pub const VERSION_1: u8 = 0x01;
const ACCEPTED_VERSIONS: &[u8] = &[VERSION_1];
/// Flag bit: the plaintext is padded (ISO/IEC 7816-4). The only flag v1 defines; bits `0x01` and
/// `0x02` are reserved for v2.
const FLAG_PADDED: u8 = 0x04;
const HKDF_INFO: &[u8] = b"anykms/envelope/v1";
const COMMIT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_WRAPPED: usize = 4096;
const DEK_LEN: usize = 32;
/// Maximum payload per envelope (AES-GCM limit with a single key: 2^36 - 32 bytes), padding
/// included.
pub const MAX_PLAINTEXT: u64 = (1 << 36) - 32;

/// How [`EnvelopeAead`] and [`EnvelopeKeyring`] pad plaintext before encrypting it, to hide its
/// exact length: [`Padding::NONE`] (the default), [`Padding::block`] or [`Padding::length`].
///
/// A policy only decides how new envelopes are written. A padded envelope says so in its
/// authenticated header, and every reader removes the padding of exactly those envelopes, whatever
/// its own policy: a policy can be turned on, off or changed without making stored envelopes
/// unreadable. Padding is ISO/IEC 7816-4 (a `0x80` marker, then zero bytes), so a padded envelope
/// is at least one byte longer than its plaintext.
///
/// Padding hides the length within a block or up to a bound, not the fact that values differ in
/// size beyond it. It is not needed for payloads whose length is public anyway.
///
/// ```
/// # use anykms_core::Aead as _;
/// use anykms_recipes::{EnvelopeAead, envelope::Padding};
/// # async fn f(kek: anykms_core::KeyWrapKey) -> anykms_core::Result<()> {
/// // Every SSN, phone number or short note takes 32 bytes, whatever its length.
/// let envelope = EnvelopeAead::new("app-kek", kek)?.with_padding(Padding::length(31));
/// let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
/// # Ok(()) }
/// ```
///
/// Invalid parameters in a constant are rejected at compile time:
///
/// ```compile_fail,E0080
/// const PADDING: anykms_recipes::envelope::Padding = anykms_recipes::envelope::Padding::block(1);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Padding(Policy);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
enum Policy {
    #[default]
    None,
    Block(usize),
    Length(usize),
}

impl Padding {
    /// No padding: envelopes reveal the exact plaintext length.
    pub const NONE: Self = Self(Policy::None);

    /// Pads to the next multiple of `size` bytes, always adding at least the marker byte: with
    /// `block(16)`, plaintexts of 0 to 15 bytes all take 16 bytes, 16 to 31 bytes take 32.
    ///
    /// # Panics
    ///
    /// Panics when `size` is less than 2; in a constant, that is a compile-time error.
    #[must_use]
    pub const fn block(size: usize) -> Self {
        assert!(size >= 2, "padding block size must be at least 2");
        Self(Policy::Block(size))
    }

    /// Pads every plaintext of up to `len` bytes to `len + 1` bytes (the extra byte holds the
    /// marker), hiding the length of each completely. Encrypting a longer plaintext fails with
    /// `InvalidArgument`.
    ///
    /// # Panics
    ///
    /// Panics when `len` is 0; in a constant, that is a compile-time error.
    #[must_use]
    pub const fn length(len: usize) -> Self {
        assert!(len >= 1, "padding length must be at least 1");
        Self(Policy::Length(len))
    }

    /// The padded plaintext, or `None` when this policy does not pad.
    fn pad(self, plaintext: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let target = match self.0 {
            Policy::None => return Ok(None),
            Policy::Block(size) => (plaintext.len() / size + 1).checked_mul(size),
            Policy::Length(len) if plaintext.len() > len => {
                return Err(Error::new(
                    ErrorKind::InvalidArgument,
                    BACKEND,
                    Operation::Encrypt,
                    format!(
                        "plaintext of {} bytes is longer than the padding length of {len} bytes",
                        plaintext.len()
                    ),
                ));
            }
            Policy::Length(len) => len.checked_add(1),
        };
        let target = target
            .filter(|&t| t as u64 <= MAX_PLAINTEXT)
            .ok_or_else(too_long)?;
        // Allocated once at its final size, so no reallocation leaves a copy of the plaintext.
        let mut padded = Zeroizing::new(Vec::with_capacity(target));
        padded.extend_from_slice(plaintext);
        padded.push(0x80);
        padded.resize(target, 0);
        Ok(Some(padded))
    }
}

/// Removes ISO/IEC 7816-4 padding: everything from the last non-zero byte, which must be `0x80`.
fn unpad(mut plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    let marker = plaintext
        .iter()
        .rposition(|&b| b != 0)
        .filter(|&i| plaintext[i] == 0x80)
        .ok_or_else(malformed)?;
    plaintext.truncate(marker);
    Ok(plaintext)
}

fn too_long() -> Error {
    Error::new(
        ErrorKind::InvalidArgument,
        BACKEND,
        Operation::Encrypt,
        "plaintext exceeds the envelope size limit",
    )
}

fn decrypt_failed(m: &'static str) -> Error {
    Error::new(ErrorKind::DecryptFailed, BACKEND, Operation::Decrypt, m)
}

/// The error for envelopes that do not open locally: malformed, tampered, foreign, wrong AAD, a
/// wrong data-key length or a data key that fails the key commitment. Deliberately one message
/// for all of these (no oracle between causes that involve the payload). Only a KEK that refuses
/// the wrapped key gets its own message ([`map_unwrap_error`]): that failure happens before the
/// data key or payload is touched, the KMS already reveals it (its own error and audit log), and
/// telling "the KMS refused the wrapped key" from "the envelope does not open" is what an
/// operator needs; it tells an attacker nothing about the payload.
fn malformed() -> Error {
    decrypt_failed("wrong key or AAD, or a malformed or tampered envelope")
}

/// [`malformed`] labeled with the caller-facing operation (e.g. `Rewrap`).
fn malformed_for(op: Operation) -> Error {
    malformed().with_operation(op)
}

/// Longest `kek_id`: its length is one byte in the format.
const MAX_KEK_ID: usize = 255;

/// Refuses a `kek_id` that does not fit the format with `InvalidArgument` on
/// [`Operation::Configure`].
fn check_kek_id_len(kek_id: &[u8]) -> Result<()> {
    if kek_id.len() > MAX_KEK_ID {
        return Err(configure_err(format!(
            "kek_id is longer than 255 bytes ({} bytes)",
            kek_id.len()
        )));
    }
    Ok(())
}

/// A `kek_id` for an error message: `kek_id`s are routing hints, not secrets, and naming them is
/// what lets an operator see a changed configuration. Debug-escaped (the envelope's id is
/// attacker-controlled), at most 255 bytes.
fn show_kek_id(kek_id: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(kek_id))
}

/// A parsed envelope (borrowing the input).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<'a> {
    version: u8,
    flags: u8,
    commit: &'a [u8],
    nonce: &'a [u8],
    kek_id: &'a [u8],
    wrapped_dek: &'a [u8],
    payload: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Parses an envelope strictly: magic, accepted version, no flags but the padding flag, exact
    /// lengths.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(3)? != MAGIC {
            return Err(malformed());
        }
        let version = r.u8()?;
        if !ACCEPTED_VERSIONS.contains(&version) {
            return Err(malformed());
        }
        let flags = r.u8()?;
        if flags & !FLAG_PADDED != 0 {
            return Err(malformed());
        }
        let commit = r.take(COMMIT_LEN)?;
        let nonce = r.take(NONCE_LEN)?;
        let kek_len = r.u8()? as usize;
        let kek_id = r.take(kek_len)?;
        let wrapped_len = u16::from_be_bytes(r.take(2)?.try_into().expect("2 bytes")) as usize;
        if wrapped_len == 0 || wrapped_len > MAX_WRAPPED {
            return Err(malformed());
        }
        let wrapped_dek = r.take(wrapped_len)?;
        let payload = r.0;
        if payload.len() < TAG_LEN {
            return Err(malformed());
        }
        Ok(Self {
            version,
            flags,
            commit,
            nonce,
            kek_id,
            wrapped_dek,
            payload,
        })
    }

    /// Format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The KEK routing hint (opaque, **not authenticated**).
    pub fn kek_id(&self) -> &'a [u8] {
        self.kek_id
    }

    /// The KMS-wrapped data key (backend-native ciphertext). Pass it to the KEK's
    /// `Aead::ciphertext_version` to find envelopes still wrapped under old key versions.
    pub fn wrapped_dek(&self) -> Ciphertext {
        Ciphertext::from_bytes(self.wrapped_dek.to_vec())
    }

    /// The authenticated payload (AES-GCM ciphertext and tag). Rewrapping never changes it.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Whether the plaintext is padded (see [`Padding`]). Read from the header without opening
    /// the envelope, so **not authenticated** until a decrypt succeeds.
    pub fn is_padded(&self) -> bool {
        self.flags & FLAG_PADDED != 0
    }

    fn header(&self) -> Vec<u8> {
        header(self.version, self.flags, self.commit, self.nonce)
    }

    /// Re-serializes with a new key-wrapping slot; the authenticated part is unchanged. Errors are
    /// labeled `Rewrap` (rewrapping is the only caller).
    fn with_slot(&self, kek_id: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
        serialize(
            Operation::Rewrap,
            self.flags,
            self.commit,
            self.nonce,
            kek_id,
            wrapped,
            self.payload,
        )
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(malformed());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}

fn header(version: u8, flags: u8, commit: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(5 + COMMIT_LEN + NONCE_LEN);
    h.extend_from_slice(MAGIC);
    h.push(version);
    h.push(flags);
    h.extend_from_slice(commit);
    h.extend_from_slice(nonce);
    h
}

fn gcm_aad(header: &[u8], user_aad: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(header.len() + 8 + user_aad.len());
    a.extend_from_slice(header);
    a.extend_from_slice(&(user_aad.len() as u64).to_be_bytes());
    a.extend_from_slice(user_aad);
    a
}

fn serialize(
    op: Operation,
    flags: u8,
    commit: &[u8],
    nonce: &[u8],
    kek_id: &[u8],
    wrapped: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if kek_id.len() > MAX_KEK_ID {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            BACKEND,
            op,
            "kek_id is longer than 255 bytes",
        ));
    }
    if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED {
        return Err(Error::new(
            ErrorKind::Backend,
            BACKEND,
            op,
            "wrapped data key has an unsupported size",
        ));
    }
    let kek_id_len = u8::try_from(kek_id.len()).expect("kek_id.len() <= MAX_KEK_ID (255)");
    let wrapped_len = u16::try_from(wrapped.len()).expect("wrapped.len() <= MAX_WRAPPED (4096)");
    let mut out = header(VERSION_1, flags, commit, nonce);
    out.reserve(1 + kek_id.len() + 2 + wrapped.len() + payload.len());
    out.push(kek_id_len);
    out.extend_from_slice(kek_id);
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(wrapped);
    out.extend_from_slice(payload);
    Ok(out)
}

// HKDF keeps its PRK as HMAC state, i.e. two SHA-256 cores keyed by the data key; sha2's
// `zeroize` feature (set in the workspace) wipes them on drop. Fails to build if it is lost.
const _: fn() = || {
    fn zeroized_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    zeroized_on_drop::<sha2::block_api::Sha256VarCore>();
};

/// Derives `(enc_key, commit)` from the data key.
fn derive(dek: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; COMMIT_LEN]) {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, dek);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(HKDF_INFO, &mut okm[..])
        .expect("64 bytes is a valid HKDF-SHA256 length");
    let mut enc = Zeroizing::new([0u8; 32]);
    enc.copy_from_slice(&okm[..32]);
    let mut commit = [0u8; COMMIT_LEN];
    commit.copy_from_slice(&okm[32..]);
    (enc, commit)
}

/// `N` random bytes from the operating system. An RNG failure (rare: a sandbox without
/// `getrandom`, an entropy source not yet initialized at early boot) is a `Backend` error, not a
/// panic.
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom::fill(&mut b[..]).map_err(|e| {
        Error::new(
            ErrorKind::Backend,
            BACKEND,
            Operation::Encrypt,
            format!("operating system RNG failed: {e}"),
        )
    })?;
    Ok(b)
}

/// Seals `plaintext` (already padded when `flags` says so) under `dek` with `nonce`, returning
/// `(commit, payload)`.
fn seal(
    dek: &[u8],
    nonce: &[u8; NONCE_LEN],
    flags: u8,
    plaintext: &[u8],
    user_aad: &[u8],
) -> Result<([u8; COMMIT_LEN], Vec<u8>)> {
    if plaintext.len() as u64 > MAX_PLAINTEXT {
        return Err(too_long());
    }
    let (enc, commit) = derive(dek);
    let h = header(VERSION_1, flags, &commit, nonce);
    let cipher = Aes256Gcm::new_from_slice(&enc[..]).expect("32-byte key");
    let n = aes_gcm::Nonce::try_from(&nonce[..]).expect("12-byte nonce");
    let payload = cipher
        .encrypt(
            &n,
            Payload {
                msg: plaintext,
                aad: &gcm_aad(&h, user_aad),
            },
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::Backend,
                BACKEND,
                Operation::Encrypt,
                "payload encryption failed",
            )
        })?;
    Ok((commit, payload))
}

/// Checks the key commitment: `commit` (derived from the unwrapped data key) must equal the
/// envelope's commitment. Runs before AES-GCM. The commitment is also in the GCM AAD, but that
/// alone does not commit the data key: whoever picks the data key can make GCM accept a header
/// carrying any commitment value. This comparison is what binds the payload to one data key.
fn check_commitment(env: &Envelope<'_>, commit: &[u8; COMMIT_LEN]) -> Result<()> {
    if !bool::from(commit[..].ct_eq(env.commit)) {
        return Err(malformed());
    }
    Ok(())
}

/// Opens an envelope given its unwrapped data key, removing the padding when the (now
/// authenticated) header says the plaintext is padded. A bad padding marker gets the same error as
/// every other failure; it can only come from the envelope's creator, as GCM has verified the
/// payload by then.
fn open(env: &Envelope<'_>, dek: &[u8], user_aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if dek.len() != DEK_LEN {
        return Err(malformed());
    }
    let (enc, commit) = derive(dek);
    check_commitment(env, &commit)?;
    let cipher = Aes256Gcm::new_from_slice(&enc[..]).expect("32-byte key");
    let n = aes_gcm::Nonce::try_from(env.nonce).map_err(|_| malformed())?;
    let plaintext = cipher
        .decrypt(
            &n,
            Payload {
                msg: env.payload,
                aad: &gcm_aad(&env.header(), user_aad),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| malformed())?;
    if env.is_padded() {
        unpad(plaintext)
    } else {
        Ok(plaintext)
    }
}

/// Maps a KEK unwrap error: failures that depend on the (attacker-supplied) wrapped key become
/// `DecryptFailed` (labeled `op`, the caller-facing operation) with the distinct message
/// "envelope data key does not unwrap", but keep the KEK backend's name, detail, retry hint and
/// the original error as source, so logs show which KMS refused the wrapped key; availability
/// and authorization errors propagate unchanged. The distinct message is not an oracle: see
/// [`malformed`].
fn map_unwrap_error(e: Error, op: Operation) -> Error {
    match e.kind() {
        ErrorKind::DecryptFailed | ErrorKind::InvalidArgument | ErrorKind::VerificationFailed => {
            let mut mapped = Error::new(
                ErrorKind::DecryptFailed,
                e.backend(),
                op,
                "envelope data key does not unwrap",
            );
            if let Some(d) = e.detail() {
                mapped = mapped.with_detail(d.clone());
            }
            if let Some(h) = e.retry_hint() {
                mapped = mapped.with_retry_hint(h);
            }
            mapped.with_source(e)
        }
        _ => e,
    }
}

async fn unwrap_dek<K: KeyWrap + ?Sized>(
    kek: &K,
    env: &Envelope<'_>,
    op: Operation,
) -> Result<Zeroizing<Vec<u8>>> {
    let dek = kek
        .unwrap_key(&env.wrapped_dek())
        .await
        .map_err(|e| map_unwrap_error(e, op))?;
    if dek.len() != DEK_LEN {
        return Err(malformed_for(op));
    }
    Ok(dek)
}

/// [`unwrap_dek`], then checks the data key against the envelope's key commitment, so a wrapped
/// key spliced into the (unauthenticated) slot is rejected instead of being re-wrapped. Rewrapping
/// never opens the payload, so this is the only check that ties the slot to the payload.
async fn unwrap_committed_dek<K: KeyWrap + ?Sized>(
    kek: &K,
    env: &Envelope<'_>,
    op: Operation,
) -> Result<Zeroizing<Vec<u8>>> {
    let dek = unwrap_dek(kek, env, op).await?;
    let (_, commit) = derive(&dek);
    check_commitment(env, &commit).map_err(|e| e.with_operation(op))?;
    Ok(dek)
}

/// Envelope encryption over any [`KeyWrap`] KEK. Implements [`Aead`] itself.
///
/// **Status:** format v1 is frozen and always decrypts; its external review is pending, so it is
/// not yet recommended for long-lived data (see the [module docs](self)).
///
/// A registry opens the KEK as a [`KeyWrapKey`] (`registry.key_wrap(uri)`); an [`Aead`] key held
/// otherwise is adapted explicitly, so the empty-AAD wrapping is visible at the call site:
///
/// ```
/// # use anykms_core::Aead as _;
/// # use anykms_recipes::EnvelopeAead;
/// # fn f(registry: anykms_core::Registry, aead: anykms_core::AeadKey) -> anykms_core::Result<()> {
/// let envelope = EnvelopeAead::new("app-kek", registry.key_wrap("local://default/kek")?)?;
/// let envelope = EnvelopeAead::new("app-kek", aead.into_key_wrap())?;
/// # Ok(()) }
/// ```
///
/// # Blocking
///
/// `encrypt` and `decrypt` (also through [`EnvelopeKeyring`]) run AES-GCM over the whole payload
/// synchronously inside the future, so the poll that does it blocks its thread for time
/// proportional to the payload size ([`MAX_PLAINTEXT`] is 64 GiB). On x86-64 with AES-NI that is
/// roughly 3 GB/s, about 0.3 ms per MB (100 MB: on the order of 100 ms); expect much slower
/// without hardware AES. Small fields need nothing. On tokio, keep large payloads off the async
/// workers: on a multi-thread runtime,
/// `block_in_place(|| Handle::current().block_on(envelope.encrypt(pt, aad)))` (borrowed data
/// works), or `spawn_blocking` with the same `block_on` inside (the closure must own the data and
/// a clone of the envelope). The rewrap methods never read the payload, except
/// [`rewrap_verified`](Self::rewrap_verified), which decrypts it like `decrypt`.
///
/// ```no_run
/// # async fn f(envelope: anykms_recipes::EnvelopeAead<anykms_core::KeyWrapKey>, blob: Vec<u8>)
/// # -> anykms_core::Result<()> {
/// use anykms_core::Aead as _;
/// // A large payload: run the AES-GCM pass on tokio's blocking pool.
/// let env = envelope.clone();
/// let ct = tokio::task::spawn_blocking(move || {
///     tokio::runtime::Handle::current().block_on(env.encrypt(&blob, b"aad"))
/// })
/// .await
/// .expect("encryption task panicked")?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct EnvelopeAead<K> {
    kek: K,
    kek_id: Vec<u8>,
    padding: Padding,
}

impl<K: std::fmt::Debug> std::fmt::Debug for EnvelopeAead<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("EnvelopeAead");
        d.field("kek", &self.kek)
            .field("kek_id", &String::from_utf8_lossy(&self.kek_id));
        if self.padding != Padding::NONE {
            d.field("padding", &self.padding);
        }
        d.finish()
    }
}

impl<K> EnvelopeAead<K> {
    /// Envelopes under `kek`, with `kek_id` written into new envelopes and required on decrypt.
    /// Use a stable logical name (e.g. `"app-kek"`), not a key URI: `hashivault://` and
    /// `openbao://` spell the same key differently. An empty `kek_id` is allowed, but envelopes
    /// written with it can only be read by an envelope (or [`EnvelopeKeyring`] entry) with an
    /// empty `kek_id` too.
    ///
    /// Fails with `InvalidArgument` if `kek_id` is longer than 255 bytes (the format's limit): a
    /// configuration bug, caught when the envelope is built rather than on first encrypt.
    pub fn new(kek_id: impl AsRef<[u8]>, kek: K) -> Result<Self>
    where
        K: KeyWrap,
    {
        check_kek_id_len(kek_id.as_ref())?;
        Ok(Self {
            kek,
            kek_id: kek_id.as_ref().to_vec(),
            padding: Padding::NONE,
        })
    }

    /// Pads the plaintext of new envelopes with `padding` (see [`Padding`]). Decryption ignores
    /// the policy: it removes the padding of exactly the envelopes that are marked padded.
    #[must_use]
    pub fn with_padding(mut self, padding: Padding) -> Self {
        self.padding = padding;
        self
    }

    /// The KEK.
    pub fn kek(&self) -> &K {
        &self.kek
    }

    /// The configured `kek_id`.
    pub fn kek_id(&self) -> &[u8] {
        &self.kek_id
    }

    /// The padding policy for new envelopes.
    pub fn padding(&self) -> Padding {
        self.padding
    }

    /// Refuses an envelope written under another `kek_id`, naming both ids (they are not secret,
    /// and the check runs before the KMS or the payload is touched, so it is no oracle).
    fn check_kek_id(&self, env: &Envelope<'_>, op: Operation) -> Result<()> {
        if env.kek_id != self.kek_id.as_slice() {
            let m = format!(
                "kek_id mismatch: the envelope names kek_id {}, this envelope is configured with {}",
                show_kek_id(env.kek_id),
                show_kek_id(&self.kek_id)
            );
            return Err(Error::new(ErrorKind::DecryptFailed, BACKEND, op, m));
        }
        Ok(())
    }
}

impl<K: KeyWrap> EnvelopeAead<K> {
    async fn encrypt_with(
        &self,
        dek: &[u8],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext> {
        let padded = self.padding.pad(plaintext)?;
        let (flags, plaintext) = match &padded {
            Some(p) => (FLAG_PADDED, &p[..]),
            None => (0, plaintext),
        };
        let (commit, payload) = seal(dek, nonce, flags, plaintext, aad)?;
        let wrapped = self.kek.wrap_key(dek).await?;
        Ok(Ciphertext::from_bytes(serialize(
            Operation::Encrypt,
            flags,
            &commit,
            nonce,
            &self.kek_id,
            wrapped.as_bytes(),
            &payload,
        )?))
    }

    /// Re-wraps the data key under the same KEK locally (unwrap + wrap). The data key is briefly
    /// in local memory (zeroized); the payload is never touched. Works with any KEK. See
    /// [Rewrapping](self#rewrapping) for the alternatives.
    ///
    /// What it checks: that the data key unwraps, and that it matches the envelope's key
    /// commitment, so an envelope whose wrapped-key slot was replaced (e.g. by another key wrapped
    /// under the same KEK) fails with `DecryptFailed` instead of being laundered to a fresh slot.
    /// It never sees the AAD or the payload: an envelope copied from another row, or one whose
    /// payload is corrupted, rewraps fine and still fails to decrypt afterwards. To verify rows,
    /// use [`rewrap_verified`](Self::rewrap_verified), or decrypt each with its own AAD.
    pub async fn rewrap_local(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        self.rewrap_to(ct, self).await
    }

    /// [`rewrap_local`](Self::rewrap_local) that first verifies the envelope against its row:
    /// it decrypts the payload with `aad`, the AAD the envelope was written with, and rewraps
    /// only if that succeeds. A migration that reports bad rows uses it: an envelope copied from
    /// another row (another AAD), a corrupted payload and a replaced wrapped-key slot all fail
    /// with `DecryptFailed` (labeled `Rewrap`), where `rewrap_local` catches only the last.
    ///
    /// The plaintext is never returned: it is zeroized as soon as the payload has opened. Unlike
    /// the other rewraps this reads the whole payload, so it costs (and blocks) like `decrypt`
    /// (see [Blocking](EnvelopeAead#blocking)); the payload is still not changed. Always local:
    /// the data key is unwrapped here to open the payload anyway. See
    /// [Rewrapping](self#rewrapping) for the alternatives.
    pub async fn rewrap_verified(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        self.move_to(ct, Some(aad), self).await
    }

    /// Moves an envelope to another KEK (another key, or another backend): unwraps the data key
    /// with this KEK, wraps it with `new`, and rewrites `kek_id`. Same exposure and checks as
    /// [`rewrap_local`](Self::rewrap_local), including the key-commitment check; the payload is
    /// never touched. See [Rewrapping](self#rewrapping) for the alternatives.
    pub async fn rewrap_to<K2: KeyWrap>(
        &self,
        ct: &Ciphertext,
        new: &EnvelopeAead<K2>,
    ) -> Result<Ciphertext> {
        self.move_to(ct, None, new).await
    }

    /// Unwraps the data key with this KEK (checking the key commitment), with `verify_aad` opens
    /// the payload under it first (the plaintext is dropped, so zeroized, at once), then wraps it
    /// with `new` and writes `new`'s `kek_id`.
    async fn move_to<K2: KeyWrap>(
        &self,
        ct: &Ciphertext,
        verify_aad: Option<&[u8]>,
        new: &EnvelopeAead<K2>,
    ) -> Result<Ciphertext> {
        let env =
            Envelope::parse(ct.as_bytes()).map_err(|e| e.with_operation(Operation::Rewrap))?;
        self.check_kek_id(&env, Operation::Rewrap)?;
        let dek = unwrap_committed_dek(&self.kek, &env, Operation::Rewrap).await?;
        if let Some(aad) = verify_aad {
            drop(open(&env, &dek, aad).map_err(|e| e.with_operation(Operation::Rewrap))?);
        }
        let wrapped = new.kek.wrap_key(&dek).await?;
        Ok(Ciphertext::from_bytes(
            env.with_slot(&new.kek_id, wrapped.as_bytes())?,
        ))
    }
}

impl<K: KeyWrap + Rewrap> EnvelopeAead<K> {
    /// Re-wraps the data key under the KEK's current version: inside the KMS
    /// ([`rewrap`](Self::rewrap)) where the KEK can, otherwise locally
    /// ([`rewrap_local`](Self::rewrap_local)). The method to rotate with: one call whatever the
    /// backend. The payload is never touched. See [Rewrapping](self#rewrapping) for the
    /// alternatives, and for skipping envelopes that are already current (this always writes a
    /// new wrapped key).
    ///
    /// Falls back to the local rewrap when the server-side rewrap fails with `Unsupported`: an
    /// opaque handle ([`KeyWrapKey`], or an [`AeadKey`] adapted with `.into_key_wrap()`) whose
    /// backend has no rewrap (GCP, Azure) returns it before any I/O. Every other error is
    /// returned as is. A KEK type that does not implement [`Rewrap`] at all calls `rewrap_local`
    /// directly.
    pub async fn rewrap_current(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        match self.rewrap(ct).await {
            Err(e) if e.kind() == ErrorKind::Unsupported => self.rewrap_local(ct).await,
            r => r,
        }
    }
}

impl<K: Rewrap> EnvelopeAead<K> {
    /// Re-wraps the data key under the KEK's current version **inside the KMS** (the data key
    /// never leaves it). The payload is never touched. On transit this uses server-side `rewrap`
    /// (with empty AAD, matching how [`AeadKeyWrap`] wraps). A KEK that cannot rewrap fails with
    /// `Unsupported`; [`rewrap_current`](Self::rewrap_current) falls back to the local rewrap
    /// instead. See [Rewrapping](self#rewrapping) for the alternatives.
    ///
    /// **No key-commitment check:** the data key never reaches this process, so unlike
    /// [`rewrap_local`](Self::rewrap_local) this cannot tell whether the wrapped-key slot still
    /// belongs to the payload. A tampered slot is re-wrapped as is and the envelope then fails to
    /// decrypt, as it would have before. `rewrap_local` checks the key commitment, but it does
    /// not vouch for the envelope either (it never sees the AAD or the payload): a migration
    /// that reports bad rows uses [`rewrap_verified`](Self::rewrap_verified).
    pub async fn rewrap(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        let env =
            Envelope::parse(ct.as_bytes()).map_err(|e| e.with_operation(Operation::Rewrap))?;
        self.check_kek_id(&env, Operation::Rewrap)?;
        let wrapped = self
            .kek
            .rewrap(&env.wrapped_dek(), b"")
            .await
            .map_err(|e| map_unwrap_error(e, Operation::Rewrap))?;
        Ok(Ciphertext::from_bytes(
            env.with_slot(&self.kek_id, wrapped.as_bytes())?,
        ))
    }
}

impl<K: KeyWrap> Aead for EnvelopeAead<K> {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        let dek = random::<DEK_LEN>()?;
        let nonce = random::<NONCE_LEN>()?;
        self.encrypt_with(&dek[..], &nonce, plaintext, aad).await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let env = Envelope::parse(ct.as_bytes())?;
        self.check_kek_id(&env, Operation::Decrypt)?;
        let dek = unwrap_dek(&self.kek, &env, Operation::Decrypt).await?;
        open(&env, &dek, aad)
    }

    /// The KEK version the data key is wrapped under. Like `decrypt`, fails with `DecryptFailed`
    /// when the envelope's `kek_id` is not this envelope's.
    ///
    /// Read from the envelope's key-wrapping slot without a KMS call, so **not authenticated**:
    /// anyone who can write the ciphertext can make it name another version. Good enough to pick
    /// envelopes to rewrap; not a basis for security decisions (only a successful `decrypt`
    /// proves which KEK wrapped the data key).
    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        let env = Envelope::parse(ct.as_bytes())?;
        self.check_kek_id(&env, Operation::Decrypt)?;
        self.kek.wrapped_key_version(&env.wrapped_dek())
    }
}

/// Envelopes under several KEKs, routed by `kek_id`: new envelopes use the primary KEK; decrypt
/// picks the KEK named by the envelope's `kek_id` from a **fixed** set (never opened as a URI).
/// Use it while migrating a table from one KEK to another, then move every envelope to the
/// primary with [`rewrap_current`](Self::rewrap_current) and confirm with a completion scan (see
/// [Rewrapping](self#rewrapping)) before removing the old KEK. The ring accepts envelopes wrapped
/// under **any** of its KEKs: with an RSA KEK in it, every holder of that public key can write
/// envelopes the ring decrypts, whatever the primary is (see [Requirements](self#requirements)).
///
/// **Status:** format v1 is frozen and always decrypts; its external review is pending, so it is
/// not yet recommended for long-lived data (see the [module docs](self)).
///
/// All KEKs have one type `K`. The default, the opaque [`KeyWrapKey`], holds KEKs of different
/// backends: [`new`](EnvelopeKeyring::new) and [`with_kek`](Self::with_kek) take any
/// [`IntoKek`], such as a registry's `KeyWrapKey`, an `Arc` of any [`KeyWrap`], or an AEAD key
/// adapted explicitly with `.into_key_wrap()`.
/// [`typed`](Self::typed) builds a keyring of one concrete type instead.
///
/// ```
/// # use std::sync::Arc;
/// # use anykms_core::Aead as _;
/// # use anykms_recipes::EnvelopeKeyring;
/// # fn f(registry: anykms_core::Registry, old: anykms_core::AeadKey) -> anykms_core::Result<()> {
/// let ring = EnvelopeKeyring::new("old-kek", old.into_key_wrap())?
///     .with_kek("new-kek", registry.key_wrap("local://default/new-kek")?)?
///     .with_primary("new-kek")?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct EnvelopeKeyring<K = KeyWrapKey> {
    keks: Vec<(Vec<u8>, K)>,
    primary: usize,
    padding: Padding,
}

impl<K> std::fmt::Debug for EnvelopeKeyring<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<String> = self
            .keks
            .iter()
            .map(|(id, _)| String::from_utf8_lossy(id).into_owned())
            .collect();
        let mut d = f.debug_struct("EnvelopeKeyring");
        d.field("kek_ids", &ids)
            .field("primary", &ids[self.primary]);
        if self.padding != Padding::NONE {
            d.field("padding", &self.padding);
        }
        d.finish()
    }
}

/// A KEK [`EnvelopeKeyring`] accepts as its KEK type `K`.
///
/// Every [`KeyWrap`] is one for its own type (for [`EnvelopeKeyring::typed`] keyrings). For the
/// default [`KeyWrapKey`], so are an `Arc` of any `KeyWrap` (`Arc<dyn DynKeyWrap>` included) and
/// an [`AeadKeyWrap`]. An [`Aead`] key is **not** a KEK by itself, here as for
/// [`EnvelopeAead::new`]: adapt it explicitly with `.into_key_wrap()` (wrapping with empty AAD), so
/// the dedicated-KEK requirement is visible at the call site.
///
/// A KEK keeps its server-side rewrap (used by [`EnvelopeKeyring::rewrap_current`]) when it is a
/// `KeyWrapKey` or an [`AeadKey`] adapted with `.into_key_wrap()`: both keep the key's rewrap
/// part. Other KEKs become a `KeyWrapKey` with the key-wrap part only and are rewrapped locally;
/// to keep a typed key's rewrap, build the `KeyWrapKey` yourself (`KeyWrapKey::full`, or `new`
/// and `with_rewrap`).
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use anykms_recipes::EnvelopeKeyring;
/// # fn f(aead: anykms_core::AeadKey) -> anykms_core::Result<()> {
/// let ring = EnvelopeKeyring::new("kek", aead)?; // an AEAD key is not a KEK by itself
/// # Ok(()) }
/// ```
///
/// ```
/// # use anykms_core::Aead as _;
/// # use anykms_recipes::EnvelopeKeyring;
/// # fn f(aead: anykms_core::AeadKey) -> anykms_core::Result<()> {
/// let ring = EnvelopeKeyring::new("kek", aead.into_key_wrap())?;
/// # Ok(()) }
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a KEK for this keyring",
    label = "not a key-wrapping key",
    note = "open the KEK with `registry.key_wrap(uri)`, or adapt an AEAD key explicitly with `.into_key_wrap()` (wraps with empty AAD; the KEK must be dedicated to envelopes)"
)]
pub trait IntoKek<K> {
    /// Converts the KEK.
    fn into_kek(self) -> K;
}

impl<K: KeyWrap> IntoKek<K> for K {
    fn into_kek(self) -> K {
        self
    }
}

impl<T: KeyWrap + 'static> IntoKek<KeyWrapKey> for Arc<T> {
    fn into_kek(self) -> KeyWrapKey {
        KeyWrapKey::new(BACKEND, self)
    }
}

impl IntoKek<KeyWrapKey> for Arc<dyn DynKeyWrap> {
    fn into_kek(self) -> KeyWrapKey {
        KeyWrapKey::new(BACKEND, self)
    }
}

impl<T: Aead + 'static> IntoKek<KeyWrapKey> for AeadKeyWrap<T> {
    fn into_kek(self) -> KeyWrapKey {
        // An `AeadKey` keeps its rewrap and describe parts, layers and backend name, as through
        // `KeyWrapKey::from_aead`. A generic `T` cannot be asked whether it implements `Rewrap`.
        let mut aead = Some(self.into_inner());
        if let Some(key) = (&mut aead as &mut dyn Any).downcast_mut::<Option<AeadKey>>() {
            return KeyWrapKey::from_aead(key.take().expect("set above"));
        }
        let aead = aead.expect("not taken");
        KeyWrapKey::new(BACKEND, Arc::new(AeadKeyWrap::new(aead)))
    }
}

fn configure_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, Operation::Configure, m)
}

impl EnvelopeKeyring {
    /// A keyring of KEKs of any type (each held as a [`KeyWrapKey`]) whose primary KEK is `kek`
    /// with id `kek_id`.
    ///
    /// Fails with `InvalidArgument` if `kek_id` is longer than 255 bytes (see
    /// [`EnvelopeAead::new`]).
    pub fn new(kek_id: impl AsRef<[u8]>, kek: impl IntoKek<KeyWrapKey>) -> Result<Self> {
        Self::typed(kek_id, kek.into_kek())
    }
}

impl<K> EnvelopeKeyring<K> {
    /// A keyring whose KEKs all have the type `K` (e.g. `AeadKey`, or `Arc<LocalAeadKey>`), with
    /// primary KEK `kek` with id `kek_id`. For KEKs of different types, use
    /// [`new`](EnvelopeKeyring::new).
    ///
    /// Fails with `InvalidArgument` if `kek_id` is longer than 255 bytes (see
    /// [`EnvelopeAead::new`]).
    pub fn typed(kek_id: impl AsRef<[u8]>, kek: K) -> Result<Self> {
        check_kek_id_len(kek_id.as_ref())?;
        Ok(Self {
            keks: vec![(kek_id.as_ref().to_vec(), kek)],
            primary: 0,
            padding: Padding::NONE,
        })
    }

    /// Pads the plaintext of new envelopes with `padding`, as [`EnvelopeAead::with_padding`].
    #[must_use]
    pub fn with_padding(mut self, padding: Padding) -> Self {
        self.padding = padding;
        self
    }

    /// The padding policy for new envelopes.
    pub fn padding(&self) -> Padding {
        self.padding
    }

    /// Adds a KEK for decryption (and as a possible primary).
    ///
    /// Fails with `InvalidArgument` if `kek_id` is already in the keyring (decryption routes by
    /// `kek_id`, so a duplicate would leave one of the KEKs unreachable) or is longer than 255
    /// bytes.
    pub fn with_kek(mut self, kek_id: impl AsRef<[u8]>, kek: impl IntoKek<K>) -> Result<Self> {
        let kek_id = kek_id.as_ref();
        check_kek_id_len(kek_id)?;
        if self.keks.iter().any(|(id, _)| id.as_slice() == kek_id) {
            return Err(configure_err(format!(
                "duplicate kek_id {}",
                show_kek_id(kek_id)
            )));
        }
        self.keks.push((kek_id.to_vec(), kek.into_kek()));
        Ok(self)
    }

    /// Selects the primary KEK by id. Fails with `InvalidArgument` for an id not in the keyring.
    pub fn with_primary(mut self, kek_id: impl AsRef<[u8]>) -> Result<Self> {
        let kek_id = kek_id.as_ref();
        self.primary = self
            .keks
            .iter()
            .position(|(id, _)| id.as_slice() == kek_id)
            .ok_or_else(|| configure_err(format!("unknown kek_id {}", show_kek_id(kek_id))))?;
        Ok(self)
    }

    /// The primary KEK's id: new envelopes, and every rewrap, use the primary KEK. An envelope
    /// whose [`Envelope::kek_id`] differs still needs a rewrap (see [Rewrapping](self#rewrapping)
    /// for the completion scan).
    pub fn primary_id(&self) -> &[u8] {
        &self.keks[self.primary].0
    }

    /// The ids of every KEK in the keyring, the primary included, in the order they were added.
    pub fn kek_ids(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.keks.iter().map(|(id, _)| id.as_slice())
    }

    /// The KEK the envelope's `kek_id` names. An unknown id fails naming it and the configured
    /// ones (see [`EnvelopeAead`]'s mismatch error).
    fn route(&self, ct: &Ciphertext, op: Operation) -> Result<usize> {
        let env = Envelope::parse(ct.as_bytes()).map_err(|e| e.with_operation(op))?;
        self.keks
            .iter()
            .position(|(id, _)| id.as_slice() == env.kek_id)
            .ok_or_else(|| {
                let configured: Vec<String> =
                    self.keks.iter().map(|(id, _)| show_kek_id(id)).collect();
                let m = format!(
                    "unknown kek_id: the envelope names kek_id {}, the keyring has {}",
                    show_kek_id(env.kek_id),
                    configured.join(", ")
                );
                Error::new(ErrorKind::DecryptFailed, BACKEND, op, m)
            })
    }
}

impl<K: KeyWrap + Clone> EnvelopeKeyring<K> {
    fn envelope_for(&self, idx: usize) -> EnvelopeAead<K> {
        let (id, kek) = &self.keks[idx];
        // The ids were checked when they were added to the keyring.
        EnvelopeAead {
            kek: kek.clone(),
            kek_id: id.clone(),
            padding: self.padding,
        }
    }

    /// Moves an envelope to the current version of the primary KEK, always locally: unwraps the
    /// data key with the KEK its `kek_id` names and wraps it with the primary, checking the key
    /// commitment like [`EnvelopeAead::rewrap_to`]; the payload is never touched. Envelopes
    /// already on the primary KEK are rewrapped too, so an older version of it moves to the
    /// current one. Works with any KEK; [`rewrap_current`](Self::rewrap_current) rewraps those
    /// inside the KMS where the primary can. See [Rewrapping](self#rewrapping).
    pub async fn rewrap_local(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        let idx = self.route(ct, Operation::Rewrap)?;
        self.envelope_for(idx)
            .rewrap_to(ct, &self.envelope_for(self.primary))
            .await
    }

    /// [`rewrap_local`](Self::rewrap_local) that first verifies the envelope against its row,
    /// decrypting the payload with `aad` (the plaintext is zeroized, never returned), as
    /// [`EnvelopeAead::rewrap_verified`]: an envelope copied from another row or a corrupted
    /// payload fails with `DecryptFailed` instead of moving to the primary.
    pub async fn rewrap_verified(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        let idx = self.route(ct, Operation::Rewrap)?;
        self.envelope_for(idx)
            .move_to(ct, Some(aad), &self.envelope_for(self.primary))
            .await
    }
}

impl<K: KeyWrap + Rewrap + Clone> EnvelopeKeyring<K> {
    /// Moves an envelope to the current version of the primary KEK: the method to finish a
    /// migration or rotation with. An envelope on another KEK of the ring is moved to the
    /// primary locally (as [`rewrap_local`](Self::rewrap_local)); one already on the primary KEK,
    /// whatever its version, is rewrapped with [`EnvelopeAead::rewrap_current`], inside the KMS
    /// where the primary can. The payload is never touched.
    ///
    /// Every call writes a new wrapped key, even for an envelope that is already current: skip
    /// those, and confirm the job is complete, with the scan in [Rewrapping](self#rewrapping).
    pub async fn rewrap_current(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        let idx = self.route(ct, Operation::Rewrap)?;
        let primary = self.envelope_for(self.primary);
        if idx == self.primary {
            primary.rewrap_current(ct).await
        } else {
            self.envelope_for(idx).rewrap_to(ct, &primary).await
        }
    }
}

impl<K: KeyWrap + Clone> Aead for EnvelopeKeyring<K> {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        self.envelope_for(self.primary)
            .encrypt(plaintext, aad)
            .await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let idx = self.route(ct, Operation::Decrypt)?;
        self.envelope_for(idx).decrypt(ct, aad).await
    }

    /// The version of the routed KEK the data key is wrapped under; **not authenticated**, as for
    /// [`EnvelopeAead`].
    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        let idx = self.route(ct, Operation::Decrypt)?;
        self.envelope_for(idx).ciphertext_version(ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anykms_core::{AeadKey, DynAead};

    #[test]
    fn debug_shows_kek_id_as_text() {
        let e = EnvelopeAead::new("kek-a", XorWrap).unwrap();
        assert_eq!(
            format!("{e:?}"),
            r#"EnvelopeAead { kek: XorWrap, kek_id: "kek-a" }"#
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        let (commit, payload) = seal(&[7; 32], &[1; 12], 0, b"hi", b"").unwrap();
        let good = serialize(
            Operation::Encrypt,
            0,
            &commit,
            &[1; 12],
            b"id",
            b"wrapped",
            &payload,
        )
        .unwrap();
        assert!(Envelope::parse(&good).is_ok());
        let mut v2 = good.clone();
        v2[3] = 2;
        assert!(Envelope::parse(&v2).is_err());
        let mut flags = good.clone();
        flags[4] = 1;
        assert!(Envelope::parse(&flags).is_err());
        for n in 0..good.len() - TAG_LEN {
            assert!(Envelope::parse(&good[..n]).is_err(), "truncated at {n}");
        }
        assert!(
            serialize(
                Operation::Encrypt,
                0,
                &commit,
                &[1; 12],
                &[0; 256],
                b"w",
                &payload
            )
            .is_err()
        );
        assert!(serialize(Operation::Encrypt, 0, &commit, &[1; 12], b"", b"", &payload).is_err());
    }

    #[test]
    fn commitment_rejects_other_dek() {
        let (commit, payload) = seal(&[7; 32], &[1; 12], 0, b"hi", b"a").unwrap();
        let bytes = serialize(
            Operation::Encrypt,
            0,
            &commit,
            &[1; 12],
            b"",
            b"w",
            &payload,
        )
        .unwrap();
        let env = Envelope::parse(&bytes).unwrap();
        assert_eq!(&*open(&env, &[7; 32], b"a").unwrap(), b"hi");
        assert!(open(&env, &[8; 32], b"a").is_err());
        assert!(open(&env, &[7; 32], b"b").is_err());
        assert!(open(&env, &[7; 16], b"a").is_err());
    }

    /// An envelope whose GCM layer is valid under `dek` but whose header carries `commit` instead
    /// of the commitment derived from `dek`. Only the commitment comparison can reject it.
    fn forged_commitment(dek: &[u8; 32], commit: &[u8; COMMIT_LEN], aad: &[u8]) -> Vec<u8> {
        let nonce = [1u8; NONCE_LEN];
        let (enc, _) = derive(dek);
        let h = header(VERSION_1, 0, commit, &nonce);
        let payload = Aes256Gcm::new_from_slice(&enc[..])
            .unwrap()
            .encrypt(
                &aes_gcm::Nonce::try_from(&nonce[..]).unwrap(),
                Payload {
                    msg: b"hi",
                    aad: &gcm_aad(&h, aad),
                },
            )
            .unwrap();
        serialize(Operation::Encrypt, 0, commit, &nonce, b"", b"w", &payload).unwrap()
    }

    #[test]
    fn commitment_check_is_enforced_independently_of_gcm() {
        let dek = [7u8; 32];
        let (enc, real_commit) = derive(&dek);
        let mut wrong = real_commit;
        wrong[0] ^= 1;
        let bytes = forged_commitment(&dek, &wrong, b"a");
        let env = Envelope::parse(&bytes).unwrap();
        // The GCM layer alone accepts it: the commitment in the AAD is whatever the header says.
        let gcm = Aes256Gcm::new_from_slice(&enc[..]).unwrap().decrypt(
            &aes_gcm::Nonce::try_from(env.nonce).unwrap(),
            Payload {
                msg: env.payload,
                aad: &gcm_aad(&env.header(), b"a"),
            },
        );
        assert_eq!(gcm.unwrap(), b"hi");
        // So only the commitment check makes `open` fail.
        assert!(check_commitment(&env, &real_commit).is_err());
        let err = open(&env, &dek, b"a").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptFailed);
        // Control: the same construction with the right commitment opens.
        let ok = forged_commitment(&dek, &real_commit, b"a");
        assert_eq!(
            &*open(&Envelope::parse(&ok).unwrap(), &dek, b"a").unwrap(),
            b"hi"
        );
    }

    /// A KEK whose unwrap (and rewrap) always fails with one error kind.
    struct FailingKek(ErrorKind);

    impl Aead for FailingKek {
        async fn encrypt(&self, _: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(b"wrapped".to_vec()))
        }

        async fn decrypt(&self, _: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Err(Error::new(self.0, "stub", Operation::Decrypt, "stub"))
        }

        fn ciphertext_version(&self, _: &Ciphertext) -> Result<Option<KeyVersion>> {
            Ok(Some(KeyVersion::from_u64(1)))
        }
    }

    impl Rewrap for FailingKek {
        async fn rewrap(&self, _: &Ciphertext, _: &[u8]) -> Result<Ciphertext> {
            Err(Error::new(self.0, "stub", Operation::Rewrap, "stub"))
        }
    }

    const ALL_KINDS: &[ErrorKind] = &[
        ErrorKind::NotFound,
        ErrorKind::PermissionDenied,
        ErrorKind::KeyStateInvalid,
        ErrorKind::DecryptFailed,
        ErrorKind::VerificationFailed,
        ErrorKind::InvalidArgument,
        ErrorKind::KeyMismatch,
        ErrorKind::Unsupported,
        ErrorKind::Configuration,
        ErrorKind::Throttled,
        ErrorKind::Unavailable,
        ErrorKind::Timeout,
        ErrorKind::Backend,
    ];

    fn hidden(kind: ErrorKind) -> bool {
        matches!(
            kind,
            ErrorKind::DecryptFailed | ErrorKind::InvalidArgument | ErrorKind::VerificationFailed
        )
    }

    fn assert_mapped(kind: ErrorKind, e: &Error, op: Operation, ctx: &str) {
        if hidden(kind) {
            assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{ctx} {kind:?}");
            // The KEK backend stays visible; the original error is kept as the source.
            assert_eq!(e.backend(), "stub", "{ctx} {kind:?}");
            assert_eq!(e.operation(), op, "{ctx} {kind:?}");
            let src = std::error::Error::source(e)
                .and_then(|s| s.downcast_ref::<Error>())
                .expect("source");
            assert_eq!(src.kind(), kind, "{ctx}");
        } else {
            assert_eq!(e.kind(), kind, "{ctx} {kind:?} must propagate unchanged");
            assert_eq!(
                e.backend(),
                "stub",
                "{ctx} {kind:?} must propagate unchanged"
            );
        }
    }

    #[tokio::test]
    async fn unwrap_errors_are_mapped_by_kind() {
        let ct = EnvelopeAead::new("", FailingKek(ErrorKind::Backend).into_key_wrap())
            .unwrap()
            .encrypt(b"hi", b"")
            .await
            .unwrap();
        for &kind in ALL_KINDS {
            let env = EnvelopeAead::new("", FailingKek(kind).into_key_wrap()).unwrap();
            let e = env.decrypt(&ct, b"").await.unwrap_err();
            assert_mapped(kind, &e, Operation::Decrypt, "decrypt");
            let e = env.rewrap_local(&ct).await.unwrap_err();
            assert_mapped(kind, &e, Operation::Rewrap, "rewrap_local");
            let e = env.rewrap_to(&ct, &env).await.unwrap_err();
            assert_mapped(kind, &e, Operation::Rewrap, "rewrap_to");
            let e = env.rewrap(&ct).await.unwrap_err();
            assert_mapped(kind, &e, Operation::Rewrap, "rewrap");
            // `Unsupported` falls back to the local rewrap, whose unwrap fails the same way.
            let e = env.rewrap_current(&ct).await.unwrap_err();
            assert_mapped(kind, &e, Operation::Rewrap, "rewrap_current");
            let e = env.rewrap_verified(&ct, b"").await.unwrap_err();
            assert_mapped(kind, &e, Operation::Rewrap, "rewrap_verified");
        }
    }

    #[tokio::test]
    async fn kek_id_is_checked_everywhere() {
        let a = EnvelopeAead::new("a", FailingKek(ErrorKind::Backend).into_key_wrap()).unwrap();
        let b = EnvelopeAead::new("b", FailingKek(ErrorKind::Backend).into_key_wrap()).unwrap();
        let ct = a.encrypt(b"hi", b"").await.unwrap();
        assert_eq!(
            a.ciphertext_version(&ct).unwrap(),
            Some(KeyVersion::from_u64(1))
        );
        let e = b.ciphertext_version(&ct).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::DecryptFailed);
        let e = b.decrypt(&ct, b"").await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::DecryptFailed, Operation::Decrypt)
        );
        // The message names both ids, so a changed configuration is easy to spot.
        assert_eq!(
            e.message(),
            r#"kek_id mismatch: the envelope names kek_id "a", this envelope is configured with "b""#
        );
        let kek = std::sync::Arc::new(FailingKek(ErrorKind::Backend).into_key_wrap());
        let ring = EnvelopeKeyring::new("b", kek.clone())
            .unwrap()
            .with_kek("c", kek)
            .unwrap();
        let e = ring.decrypt(&ct, b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::DecryptFailed);
        assert_eq!(
            e.message(),
            r#"unknown kek_id: the envelope names kek_id "a", the keyring has "b", "c""#
        );
        for e in [
            b.rewrap(&ct).await.unwrap_err(),
            b.rewrap_local(&ct).await.unwrap_err(),
            b.rewrap_current(&ct).await.unwrap_err(),
            b.rewrap_verified(&ct, b"").await.unwrap_err(),
            b.rewrap_to(&ct, &a).await.unwrap_err(),
        ] {
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::DecryptFailed, Operation::Rewrap)
            );
        }
    }

    #[test]
    fn kek_ids_longer_than_255_bytes_are_refused_when_configured() {
        let ok = "k".repeat(255);
        let long = "k".repeat(256);
        let _ = EnvelopeAead::new(&ok, XorWrap).unwrap();
        let ring = EnvelopeKeyring::typed(&ok, XorWrap)
            .unwrap()
            .with_kek("x", XorWrap)
            .unwrap();
        let e = ring.with_kek(&long, XorWrap).unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::InvalidArgument, Operation::Configure)
        );
        for e in [
            EnvelopeAead::new(&long, XorWrap).unwrap_err(),
            EnvelopeKeyring::typed(&long, XorWrap).unwrap_err(),
        ] {
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::InvalidArgument, Operation::Configure)
            );
        }
    }

    /// A KEK that only wraps keys (no `Aead`), as an RSA-OAEP or AES-KW key would.
    #[derive(Clone, Debug)]
    struct XorWrap;

    impl KeyWrap for XorWrap {
        async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(
                key.iter().map(|b| b ^ 0x5a).collect::<Vec<_>>(),
            ))
        }

        async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(
                wrapped.as_bytes().iter().map(|b| b ^ 0x5a).collect(),
            ))
        }
    }

    /// Canary for the workspace's `zeroize >= 1.9.1`: 1.9.0's `Zeroizing` `Debug` printed its
    /// bytes, so a decrypted plaintext formatted with `{:?}` (a log line, an `expect` message)
    /// leaked it.
    #[tokio::test]
    async fn debug_of_a_decrypt_result_does_not_print_the_plaintext() {
        let env = EnvelopeAead::new("kw", XorWrap).unwrap();
        let ct = env.encrypt(b"SECRET", b"").await.unwrap();
        let shown = format!(
            "{:?} {:?}",
            env.decrypt(&ct, b"").await,
            env.decrypt_utf8(&ct, b"").await
        );
        assert!(shown.contains("Ok("), "{shown}");
        assert!(
            !shown.contains("SECRET") && !shown.contains("83, 69, 67, 82, 69, 84"),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn key_wrap_only_keks_back_envelopes() {
        let env = EnvelopeAead::new("kw", XorWrap).unwrap();
        let ct = env.encrypt(b"hi", b"a").await.unwrap();
        assert_eq!(&*env.decrypt(&ct, b"a").await.unwrap(), b"hi");
        assert_eq!(env.ciphertext_version(&ct).unwrap(), None);
        // Mixed KEK types in one keyring, each held as a `KeyWrapKey`.
        let xor: Arc<dyn DynKeyWrap> = Arc::new(XorWrap);
        let ring = EnvelopeKeyring::new("kw", xor)
            .unwrap()
            .with_kek("aead", FailingKek(ErrorKind::Backend).into_key_wrap())
            .unwrap();
        assert_eq!(&*ring.decrypt(&ct, b"a").await.unwrap(), b"hi");
    }

    /// Replaces the wrapped-key slot of `ct` with another 32-byte key wrapped under `kek`: the
    /// KEK unwraps it fine, only the key commitment can tell it does not belong to the payload.
    async fn splice_foreign_dek<K: KeyWrap>(kek: &K, ct: &Ciphertext) -> Ciphertext {
        let env = Envelope::parse(ct.as_bytes()).unwrap();
        let foreign = kek.wrap_key(&[0x42; DEK_LEN]).await.unwrap();
        Ciphertext::from_bytes(env.with_slot(env.kek_id, foreign.as_bytes()).unwrap())
    }

    fn assert_rejected(r: Result<Ciphertext>, ctx: &str) {
        let e = r.expect_err(ctx);
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::DecryptFailed, Operation::Rewrap),
            "{ctx}"
        );
    }

    #[tokio::test]
    async fn local_rewraps_check_the_key_commitment() {
        let old = EnvelopeAead::new("old", XorWrap).unwrap();
        let new = EnvelopeAead::new("new", XorWrap).unwrap();
        let ct = old.encrypt(b"hi", b"a").await.unwrap();
        // Controls: the untampered envelope rewraps and still decrypts.
        let r = old.rewrap_local(&ct).await.unwrap();
        assert_eq!(&*old.decrypt(&r, b"a").await.unwrap(), b"hi");
        let m = old.rewrap_to(&ct, &new).await.unwrap();
        assert_eq!(&*new.decrypt(&m, b"a").await.unwrap(), b"hi");

        let forged = splice_foreign_dek(&XorWrap, &ct).await;
        assert_eq!(
            old.decrypt(&forged, b"a").await.unwrap_err().kind(),
            ErrorKind::DecryptFailed
        );
        assert_rejected(old.rewrap_local(&forged).await, "rewrap_local");
        assert_rejected(old.rewrap_to(&forged, &new).await, "rewrap_to");

        let ring = EnvelopeKeyring::typed("old", XorWrap)
            .unwrap()
            .with_kek("new", XorWrap)
            .unwrap()
            .with_primary("new")
            .unwrap();
        let m = ring.rewrap_local(&ct).await.unwrap();
        assert_eq!(&*ring.decrypt(&m, b"a").await.unwrap(), b"hi");
        assert_rejected(ring.rewrap_local(&forged).await, "keyring rewrap_local");
        assert_rejected(old.rewrap_verified(&forged, b"a").await, "rewrap_verified");
        assert_rejected(
            ring.rewrap_verified(&forged, b"a").await,
            "keyring rewrap_verified",
        );
    }

    /// The row-level damage only a verifying rewrap catches: an envelope stored under another
    /// row's AAD, and a corrupted payload. `rewrap_local` passes both (they fail later, on
    /// decrypt); `rewrap_verified` refuses them.
    #[tokio::test]
    async fn verified_rewraps_catch_swapped_rows_and_corrupted_payloads() {
        let env = EnvelopeAead::new("old", XorWrap).unwrap();
        let ring = EnvelopeKeyring::typed("old", XorWrap)
            .unwrap()
            .with_kek("new", XorWrap)
            .unwrap()
            .with_primary("new")
            .unwrap();
        let row1 = env.encrypt(b"row 1", b"rows/1").await.unwrap();
        // Controls: an intact envelope rewraps under its own AAD, payload unchanged.
        let r = env.rewrap_verified(&row1, b"rows/1").await.unwrap();
        assert_eq!(
            Envelope::parse(r.as_bytes()).unwrap().payload(),
            Envelope::parse(row1.as_bytes()).unwrap().payload()
        );
        assert_eq!(&*env.decrypt(&r, b"rows/1").await.unwrap(), b"row 1");
        let m = ring.rewrap_verified(&row1, b"rows/1").await.unwrap();
        assert_eq!(Envelope::parse(m.as_bytes()).unwrap().kek_id(), b"new");
        assert_eq!(&*ring.decrypt(&m, b"rows/1").await.unwrap(), b"row 1");

        // Row 1's envelope copied into row 6.
        let swapped = row1.clone();
        // One payload bit flipped.
        let mut bytes = row1.as_bytes().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let corrupted = Ciphertext::from_bytes(bytes);
        for (ct, aad, ctx) in [
            (&swapped, &b"rows/6"[..], "swapped row"),
            (&corrupted, &b"rows/1"[..], "corrupted payload"),
        ] {
            let r = env.rewrap_local(ct).await.expect(ctx);
            assert!(env.decrypt(&r, aad).await.is_err(), "{ctx}");
            assert!(ring.rewrap_local(ct).await.is_ok(), "{ctx}");
            assert_rejected(env.rewrap_verified(ct, aad).await, ctx);
            assert_rejected(ring.rewrap_verified(ct, aad).await, ctx);
        }
    }

    /// A KEK whose wrapped keys are too large for the format's slot.
    struct OversizedWrap;

    impl KeyWrap for OversizedWrap {
        async fn wrap_key(&self, _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(vec![0; MAX_WRAPPED + 1]))
        }

        async fn unwrap_key(&self, _: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
            unreachable!("never wraps a usable key")
        }
    }

    #[tokio::test]
    async fn slot_errors_name_the_callers_operation() {
        let env = EnvelopeAead::new("kw", XorWrap).unwrap();
        let ct = env.encrypt(b"hi", b"").await.unwrap();
        let big = EnvelopeAead::new("big", OversizedWrap).unwrap();
        let e = env.rewrap_to(&ct, &big).await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Backend, Operation::Rewrap)
        );
        let e = big.encrypt(b"hi", b"").await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Backend, Operation::Encrypt)
        );
    }

    #[test]
    fn keyring_rejects_duplicate_and_unknown_kek_ids() {
        let k = || Arc::new(FailingKek(ErrorKind::Backend).into_key_wrap());
        let ring = EnvelopeKeyring::new("a", k())
            .unwrap()
            .with_kek("b", k())
            .unwrap();
        let e = ring.clone().with_kek("a", k()).unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::InvalidArgument, Operation::Configure)
        );
        assert_eq!(e.message(), r#"duplicate kek_id "a""#);
        assert_eq!(ring.primary_id(), b"a");
        assert_eq!(ring.kek_ids().collect::<Vec<_>>(), [b"a", b"b"]);
        assert_eq!(ring.clone().with_primary("b").unwrap().primary_id(), b"b");
        let e = ring.with_primary("c").unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::InvalidArgument, Operation::Configure)
        );
        assert_eq!(e.message(), r#"unknown kek_id "c""#);
    }

    /// Every way a caller holds a KEK goes into the default keyring without annotations or casts;
    /// AEAD keys only once adapted explicitly with `.into_key_wrap()`. `typed` keeps one concrete
    /// type.
    #[tokio::test]
    async fn keyring_accepts_keks_without_casts() {
        let handle = AeadKey::new("test", Arc::new(FailingKek(ErrorKind::Backend)));
        let dyn_aead: Arc<dyn DynAead> = Arc::new(FailingKek(ErrorKind::Backend));
        let dyn_wrap: Arc<dyn DynKeyWrap> = Arc::new(XorWrap);
        let ring = EnvelopeKeyring::new("concrete", Arc::new(XorWrap))
            .unwrap()
            .with_kek("adapted", FailingKek(ErrorKind::Backend).into_key_wrap())
            .unwrap()
            .with_kek("handle", handle.clone().into_key_wrap())
            .unwrap()
            .with_kek("key-wrap-key", KeyWrapKey::from_aead(handle.clone()))
            .unwrap()
            .with_kek("dyn-aead", dyn_aead.into_key_wrap())
            .unwrap()
            .with_kek("dyn-wrap", dyn_wrap)
            .unwrap()
            .with_kek("arc-adapted", Arc::new(handle.clone().into_key_wrap()))
            .unwrap()
            .with_primary("dyn-wrap")
            .unwrap();
        let ct = ring.encrypt(b"hi", b"").await.unwrap();
        assert_eq!(&*ring.decrypt(&ct, b"").await.unwrap(), b"hi");
        let _ = EnvelopeKeyring::new("handle", handle.clone().into_key_wrap()).unwrap();

        let typed = EnvelopeKeyring::typed("x", XorWrap)
            .unwrap()
            .with_kek("y", XorWrap)
            .unwrap();
        let ct = typed.encrypt(b"hi", b"").await.unwrap();
        assert_eq!(&*typed.decrypt(&ct, b"").await.unwrap(), b"hi");
        let _: EnvelopeKeyring<AeadKeyWrap<AeadKey>> =
            EnvelopeKeyring::typed("x", handle.clone().into_key_wrap())
                .unwrap()
                .with_kek("y", handle.into_key_wrap())
                .unwrap();
    }
}
