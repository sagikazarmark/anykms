# anykms envelope format, version 1

Status: **frozen** at the end of M3: every future release decrypts v1. Amended once before the
first release, with nothing published yet: flag `0x04` marks a padded plaintext
([Padding](#padding)); every earlier v1 envelope reads as before. Test vectors:
`crates/anykms-recipes/tests/vectors/envelope_v1.json` (positive and negative). The plan asks for a
review outside the team before long-lived data relies on it. That review is **pending**; so far
the format has only been reviewed by the project's own design and security reviews. The external
review is a **release gate**: 0.1 is not promoted for long-lived data until it is done
(`docs/PLAN.md` §10, M4). The release that completes it announces the promotion in its release
notes, and removes the status notes from this document, the README and the
rustdoc. The review can add constraints to v2 or retire v1 for new data; v1 envelopes always
decrypt.

Implemented by `anykms_recipes::EnvelopeAead` (single KEK) and `EnvelopeKeyring` (several KEKs
routed by `kek_id`).

## Layout

All integers are big-endian.

| Offset | Size | Field | Authenticated by GCM |
|---|---|---|---|
| 0 | 3 | magic `"AKE"` (`41 4b 45`) | yes |
| 3 | 1 | version `0x01` | yes |
| 4 | 1 | flags: `0x00`, or `0x04` for a padded plaintext ([Padding](#padding)); every other bit is reserved for v2 (see [Future versions](#future-versions)) | yes |
| 5 | 32 | `commit`: key commitment | yes |
| 37 | 12 | `nonce`: AES-GCM nonce | yes |
| 49 | 1 | `kek_id_len` (0..=255) | **no** |
| 50 | `kek_id_len` | `kek_id`: opaque routing hint | **no** |
| … | 2 | `wrapped_dek_len` (1..=4096) | **no** |
| … | `wrapped_dek_len` | `wrapped_dek`: backend-native KEK ciphertext of the DEK | **no** |
| … | rest (≥ 16) | AES-256-GCM ciphertext ‖ 16-byte tag | — |

`kek_id` and `wrapped_dek` form the **key-wrapping slot**. It is deliberately outside the GCM AAD
so it can be replaced (rewrap, migration to another KEK) without touching the payload.

## Encryption

0. With a padding policy, pad the plaintext as in [Padding](#padding) and set `flags = 0x04`;
   otherwise `flags = 0x00` and the plaintext is used as is. The steps below seal the (padded)
   plaintext.
1. Draw a fresh 32-byte data key `DEK` and a 12-byte `nonce` from the OS CSPRNG. A DEK encrypts
   exactly one message, so a random nonce is safe.
2. `okm = HKDF-SHA256(salt = none, ikm = DEK, info = "anykms/envelope/v1", L = 64)`.
   `enc_key = okm[0..32]`, `commit = okm[32..64]`.
3. `header = magic ‖ version ‖ flags ‖ commit ‖ nonce` (49 bytes).
4. `gcm_aad = header ‖ u64(len(user_aad)) ‖ user_aad`.
5. `payload = AES-256-GCM(enc_key, nonce, plaintext, gcm_aad)`. The plaintext, padding
   included, must be at most 2^36 − 32 bytes.
6. `wrapped_dek = KEK.wrap_key(DEK)`, which for an AEAD KEK (adapted with `AeadKeyWrap`) is
   `KEK.encrypt(DEK, aad = "")`. Empty AAD matches Tink's `KmsEnvelopeAead`; it keeps
   server-side rewrap possible (transit's `rewrap` ignores AAD) and keeps the caller's AAD out of
   KMS audit logs.
7. Output `header ‖ kek_id_len ‖ kek_id ‖ wrapped_dek_len ‖ wrapped_dek ‖ payload`.

## Decryption

1. Parse strictly. Check the magic and the version against the accepted list (`{0x01}`; no
   downgrade). Flags must be `0x00` or `0x04`. Lengths must be exact:
   `1 ≤ wrapped_dek_len ≤ 4096`, payload ≥ 16 bytes.
2. Single-KEK mode: `kek_id` must equal the configured id, otherwise `DecryptFailed` ("kek_id
   mismatch") **before any KMS call**. The same check guards `ciphertext_version` and every
   rewrap operation. Keyring mode: `kek_id` selects a KEK from a fixed set of unique ids
   (a duplicate id is rejected when the keyring is built), otherwise `DecryptFailed` ("unknown
   kek_id"). Both messages name the envelope's `kek_id` and the configured one(s), escaped, so an
   operator can recognize a changed configuration: `kek_id`s are not secret, and the check runs
   before the KEK or the payload is used, so it reveals nothing about either. `kek_id` is never
   interpreted as a URI. Configured ids longer than 255 bytes are refused when the envelope or
   keyring is built.
3. `DEK = KEK.decrypt(wrapped_dek, aad = "")`. `DEK` must be exactly 32 bytes.
4. Derive `(enc_key, commit')` as above. Compare `commit'` with `commit` **in constant time
   before** running GCM.
5. Decrypt the payload with AES-256-GCM using the same `gcm_aad`.
6. If `flags` is `0x04`, remove the padding: drop the trailing zero bytes, then require and drop a
   `0x80` byte. A plaintext without it (including an empty or all-zero one) is rejected. Readers
   unpad by this flag alone, never by their own padding policy.

### Errors

- Availability and authorization errors from the KMS propagate unchanged: `PermissionDenied`,
  `Throttled`, `Unavailable`, `Timeout`, `NotFound`, `KeyStateInvalid` (and every other kind not
  listed below, such as `Backend` or `Unsupported`).
- Everything that depends on the attacker-supplied wrapped key or payload becomes `DecryptFailed`.
  The error's operation is the caller's: `decrypt`, or `rewrap` for the rewrap operations below.
  Two messages are used:
  - "envelope data key does not unwrap" when the KMS refuses the wrapped key (a KMS
    `DecryptFailed`/`InvalidArgument`/`VerificationFailed`). The error keeps the KEK backend's
    name and detail, and the KMS error as its source.
  - "wrong key or AAD, or a malformed or tampered envelope" for everything after a successful
    unwrap or before it: a malformed envelope, a wrong DEK length, a commitment mismatch, a
    bad GCM tag (which also covers a wrong AAD) and bad padding, with no further distinction
    among them.

  Separating the KEK refusal is safe: it happens before the DEK or the payload is used, and the
  KMS reveals it anyway (its own error, audit log and timing). The causes that involve the DEK,
  the commitment or the payload share one message, so the error is no oracle on the payload.
- A `KeyStateInvalid` from the unwrap reveals the slot's KEK version policy (for example "below
  the minimum decryption version"). This is not secret: `ciphertext_version` exposes the version
  anyway.

## Padding

AES-GCM ciphertext is exactly as long as its plaintext, so an envelope reveals the plaintext
length. Padding hides it, within a block or up to a bound. It is ISO/IEC 7816-4: the plaintext,
one `0x80` byte, then zero bytes up to the target length. The marker is always present, so a padded
plaintext is at least one byte longer than the original. Two policies are defined; both only
choose the target length, and a reader needs neither:

- **block(`n`)**, `n ≥ 2`: the target is the next multiple of `n` above the plaintext length
  (`(len / n + 1) · n`). With `n = 16`, plaintexts of 0 to 15 bytes take 16 bytes.
- **length(`n`)**, `n ≥ 1`: the target is `n + 1` for every plaintext of up to `n` bytes; a
  longer plaintext is refused when encrypting (`InvalidArgument`), never truncated.

The flag, not the reader's configuration, decides whether to unpad (decryption step 6). A writer
can therefore turn padding on, off or change its policy at any time: stored envelopes stay
readable, and a rewrap keeps the payload, so its padding, as it is.

## Security notes

- **Padding.** The flag is part of the GCM AAD, so it cannot be set or cleared on someone else's
  envelope (vector `padded_flag_on_unpadded`). Padding is removed only after GCM has
  authenticated the payload, and bad padding gets the same error as every other failure, so
  there is no padding oracle: only the envelope's creator, who knows the plaintext anyway, can
  produce a GCM-valid payload with bad padding. Padding hides lengths within a block or up to the
  bound only; a block policy still reveals which block-sized bucket a plaintext falls in.
- **Key commitment.** `commit` binds the envelope to exactly one DEK (HKDF output, about 128-bit
  collision resistance), so a crafted envelope cannot decrypt under two different keys
  ("invisible salamanders"). This holds even when a keyring tries several KEKs. The explicit
  comparison in step 4 is required even though `commit` is part of the GCM AAD: whoever chooses a
  DEK can make GCM accept a header carrying *any* commitment value, so only the comparison ties
  the envelope to the DEK.
- **The commitment covers the DEK, not the AAD.** Neither the user AAD nor `kek_id` is an input
  to `commit`. GCM authenticates the AAD against anyone who does not know the DEK, so tampering
  with the AAD of someone else's envelope is detected. But AES-GCM is not committing: whoever
  knows the DEK, including the envelope's creator, can compute one ciphertext and tag that is
  valid under two different AADs (choose the second AAD, then solve the GHASH equation for a
  block of it or of the ciphertext). Such an envelope decrypts, to the same plaintext, under
  both AADs, so it does not prove which AAD its creator meant. That is consistent with the no-authorship model below: the creator is
  already trusted to choose the plaintext and the AAD, and anyone who can create envelopes can
  create one per AAD anyway. Applications that need an envelope bound to exactly one context
  should not rely on the AAD alone for that against a malicious creator. A future format version
  could bind the AAD into the commitment, for example with `info = "anykms/envelope/v2" ‖
  SHA-256(user_aad)` in the HKDF step (v1 stays as specified).
- **`kek_id`** is outside both the commitment and the GCM AAD, and doesn't need protection: it is
  only a hint (see the next note).
- **Unauthenticated slot.** Replacing `wrapped_dek` either yields a different DEK, which fails the
  commitment, or the same DEK, which is a legitimate rewrap. Rewriting `kek_id` only changes which
  configured KEK is tried; the commitment still guards the result.
- **Dedicated KEK (requirement).** Because DEKs are wrapped with empty AAD, any code path that
  decrypts with empty AAD under the same KEK could unwrap DEKs. A KEK **MUST** be used only for
  envelopes. Give envelope KEKs their own mount (for example `transit-envelope/`) and policy.
- **No authorship.** Anyone who can wrap a data key under the KEK can create valid envelopes for
  any AAD. With a symmetric KEK that is whoever has `encrypt` (or wrap) on it. With a public-key
  (RSA-OAEP) KEK, wrapping needs only the public key, so **every holder of the public key** can
  write envelopes that decrypt as genuine: IAM on the KEK limits who reads, not who writes. The
  format provides confidentiality and integrity, not proof of who wrote the data, and under a
  public-key KEK it provides confidentiality only: neither the commitment nor the AAD
  authenticates the writer. A keyring trusts every KEK in it, so one RSA KEK in the ring makes
  the whole keyring's writer set "every holder of that public key", whatever the primary is.

## Operations on the slot

| Operation | Use it to | KEK requirement | DEK exposure | Payload |
|---|---|---|---|---|
| `rewrap_current` (also on `EnvelopeKeyring`, moving to its primary KEK) | rotate or migrate: move to the KEK's current version, server-side where the KEK can rewrap, otherwise as `rewrap_local` | `KeyWrap + Rewrap` | none where rewrapped server-side, otherwise briefly in local memory (zeroized) | unchanged |
| `rewrap` | move to the KEK's current version after a rotation, only inside the KMS | `KeyWrap + Rewrap` (for example transit server-side rewrap) | none: stays in the KMS | unchanged |
| `rewrap_local` (also on `EnvelopeKeyring`, moving to its primary KEK) | the same on any backend, checking the key commitment | any `KeyWrap` | briefly in local memory (zeroized) | unchanged |
| `rewrap_verified(&ct, aad)` (also on `EnvelopeKeyring`) | the same, after decrypting the payload with the row's AAD: catches an envelope copied from another row and a corrupted payload, which `rewrap_local` (it never sees the AAD or the payload) passes | any `KeyWrap` | briefly in local memory (zeroized), and so is the plaintext (zeroized, never returned) | read, unchanged |
| `rewrap_to(&ct, &new_envelope)` (the target `EnvelopeAead` carries the new KEK and `kek_id`) | move to another KEK or backend | any `KeyWrap` → any `KeyWrap` | briefly in local memory (zeroized) | unchanged |

Every rewrap writes a new slot, even for an envelope that is already current. To find the envelopes
that still need one, and to confirm a migration is complete, compare `Envelope::parse(bytes).kek_id()`
with the keyring's `primary_id()` and, where both are known, the KEK's
`KeyWrap::wrapped_key_version` of `wrapped_dek()` with the KEK's current version (the slot is not
authenticated, so this selects envelopes; it is not a security decision).

## Test vectors

`crates/anykms-recipes/tests/vectors/envelope_v1.json` holds two lists. A conforming
implementation **must** decrypt every `valid` vector to its `plaintext` and **must reject** every
`invalid` vector. The vectors are built by `tests/envelope_vectors.rs` from AES-GCM, HKDF and
SHA-256 directly, following this document, not with the library's envelope code; the test checks
that the library opens and rejects them as listed and that the file is exactly what that builder
produces.

Valid:

- `plain`, `empty`: a fresh envelope, and one with empty plaintext, AAD and `kek_id`.
- `rewrapped`: `plain` with its data key rewrapped under version 2 of the same KEK.
- `rewrap_to`: `plain` moved to another KEK (`kek_id` `new-kek`).
- `padded`: flags `0x04`, the plaintext padded to 16-byte blocks (its 30 bytes, the marker and
  one zero byte).

Invalid:

- `flipped_commitment`: `plain` with one commitment bit flipped.
- `nonzero_flags`, `unknown_flag`, `unknown_version`: `plain` with the reserved flag `0x01`, the
  undefined flag `0x08`, or version `0x02` (parsing).
- `padded_flag_on_unpadded`: `plain` with flags set to `0x04` afterwards (GCM fails: the flags are
  authenticated).
- `truncated`: `plain` without its last byte (GCM fails).
- `swapped_wrapped_dek`: another envelope's wrapped data key in the slot (the commitment fails).
- `wrong_aad`: `plain` with another AAD (GCM fails).
- `kek_id_rewritten_to_other_keyring_kek`: a slot relabeled to another KEK of a keyring (the
  unwrap fails).
- `commitment_mismatch_gcm_valid`: isolates the key-commitment comparison (decryption step 4).
  The data key unwraps and is 32 bytes, and the payload is valid AES-256-GCM under its derived
  `enc_key` with this envelope's header, wrong commitment included, in the AAD. Only the
  commitment comparison rejects it.
- `short_dek`: isolates the data-key length check (decryption step 3). The wrapped data key
  unwraps to 16 bytes, and the commitment and payload are computed from it exactly as specified
  (HKDF-SHA256 of a 16-byte key still yields a 32-byte `enc_key` and a matching commitment), so
  only the length check rejects it.
- `bad_padding_marker`: isolates the padding check (decryption step 6). Flags `0x04`, and the
  payload is valid AES-256-GCM under the committed data key, but its plaintext does not end in
  `0x80` and zero bytes. Only the padding check rejects it; an implementation that ignores the
  flag returns the raw plaintext.

Each `invalid` entry names the KEK to try (`a`, or `keyring` for a keyring of `app-kek` = KEK `a`
and `new-kek` = KEK `b`), the configured `kek_id` and the AAD.

## Test KEK used by the vectors

The vectors use a deterministic test KEK so any implementation can reproduce them:

- AES-256-GCM with key `K_v = SHA-256("anykms test kek <name> v<v>")`.
- Nonce: the first 12 bytes of `SHA-256(plaintext)`.
- Framing: `"testkek:v<v>:" ‖ nonce ‖ ciphertext ‖ tag`.

It exists only for the vectors and must never be used for real data.

## Future versions

New versions are added to the accepted list and never replace v1. Readers reject any version they
do not know and, within v1, any flag but `0x04` (padded).

Version 2 is committed to carry two features together, so a single format change covers both:

- **Several wrapped-key slots.** One DEK wrapped under N KEKs (for example two cloud regions and
  a break-glass Vault key), any one of which can decrypt. v1 has exactly one slot, which is why
  this needs a new version rather than a flag.
- **Streaming (segmented) payloads** in the style of Tink's streaming AEAD, for objects that do
  not fit in memory.

Flag bits (bits 0 and 1 are reserved for v2 and must be zero in v1):

| Bit | Mask | Meaning |
|---|---|---|
| 0 | `0x01` | v2: segmented payload (streaming) |
| 1 | `0x02` | v2: multi-slot: a slot count precedes the slots |
| 2 | `0x04` | v1 and later: the plaintext is padded ([Padding](#padding)) |
| 3–7 | `0xf8` | reserved; must be zero |

Requirements on v2, whatever its layout:

- **Readers cap the number of wrapped-key slots** and reject an envelope with more slots before
  any KMS call (as the AWS Encryption SDK's `max_encrypted_data_keys` does). Each slot a reader
  tries can cost a KMS request, so without a cap a crafted envelope turns one decrypt into
  arbitrarily many KMS calls. The cap is configurable, with a small default.
- **Reader-first rollout.** A release that reads v2 ships, and is deployed everywhere, before
  any release writes v2 by default; writing v2 is an explicit opt-in until then. A fleet in
  which some readers predate v2 would otherwise fail to decrypt new data (they reject the
  unknown version).

The exact v2 layout is designed with the external review (see the status note at the top) and
gets its own test vectors. Adopting the AWS Encryption SDK message format instead was considered
and rejected (`docs/PLAN.md` §21); an ESDK-compatible reader remains possible later.
