# anykms canonical AAD, version 1

Status: **draft, pinned by vectors.** This document specifies one deterministic encoding of a
purpose and key/value fields into AAD bytes, so that every writer and reader of a ciphertext,
in any language, produces identical bytes from the same fields. anykms ships **no code** that
produces these bytes: applications implement the encoding themselves (the guide shows one in
[Choosing AAD](guide.md#choosing-aad)) and check it against the test vectors in
`crates/anykms-recipes/tests/vectors/aad_v1.json`. A type that implements it may be added later
(`docs/PLAN.md` §29 lists the triggers); it will produce exactly these bytes.

The encoding's review outside the project is **pending**, in the scope of the envelope v1 external
review (`docs/envelope-format.md`), so it is not yet recommended for long-lived data. Unlike an
envelope, an AAD is never stored: it is rebuilt from the row's fields at decrypt time, so nothing
in a ciphertext says which encoding produced its AAD. A row bound to v1 bytes therefore stays on v1
until the application re-encrypts it or records the encoding version beside it. For that reason v1
is pinned from this document's first release: if the review changes anything, the result is a new
label (`anykms/aad/v2`), and v1 stays specified here. The release that completes the review
announces the promotion in its release notes and removes this status note.

## What it is for

The envelope recipe (`EnvelopeAead`, `EnvelopeKeyring`) and every `Aead` key take AAD as raw
bytes. Applications bind a ciphertext to its row with them (`users/42/ssn` in the examples), and
each invents its own layout. Concatenation without lengths is ambiguous (`("a","bc")` and
`("ab","c")` collide), field order drifts between writers, and nothing marks which kind of record
a ciphertext belongs to. This encoding fixes all three with a purpose tag, length prefixes and a
sorted field order. It is misuse resistance for the application's binding convention, not a
cryptographic strengthening: what the AAD guarantees is whatever the AEAD guarantees for its AAD
(see [Security notes](#security-notes)).

Two paths consume the bytes:

- **Envelope.** `EnvelopeAead::encrypt(pt, aad)`: the bytes enter the local AES-GCM AAD only
  (`docs/envelope-format.md`, encryption step 4). The KMS never sees them: the data key is wrapped
  with empty AAD. No backend limit applies.
- **A backend `Aead` key directly.** The bytes reach the backend, which may log them (AWS records
  them hex-encoded in CloudTrail under `associatedData`) and caps them (AWS: 3072 bytes,
  `anykms_aws::MAX_AAD_BYTES`). The total cap below keeps every valid encoding within that limit.
  Transit's server-side `rewrap` is `Unsupported` with non-empty AAD, as for any AAD.

## Layout

All integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 14 | label `"anykms/aad/v1\0"` (`61 6e 79 6b 6d 73 2f 61 61 64 2f 76 31 00`) |
| 14 | 2 | `n`: number of fields, `purpose` included (1..=16) |
| 16 | … | `n` fields, in key order (below) |

Each field is `u16 key_len ‖ key ‖ u16 value_len ‖ value`. Keys and values are UTF-8; lengths
count bytes.

## Encoding

1. Collect the application's fields and add the field `purpose` with the purpose name as its
   value. `purpose` is an ordinary field: it is counted in `n` and sorted with the rest.
2. Check every rule in [Rules](#rules); a violation is an error (`InvalidArgument` in anykms
   terms, operation `Construct`). An error names the rule and may name the key; it never carries
   a value.
3. Sort the fields by key in unsigned-byte lexicographic order (`memcmp`; a shorter key that is a
   prefix of a longer one sorts first). Keys are unique, so the order is total and the output does
   not depend on the order the fields were given in.
4. Output `label ‖ u16(n) ‖ fields`.

There is **no decoder**. A reader rebuilds the AAD from the same fields it trusts for the row and
passes it to `decrypt`; it never parses AAD bytes from storage, because AAD is not stored. The
encoding is nonetheless self-delimiting (every length is explicit), so a test-only decoder is
possible and the vectors below are checked with one.

## Rules

Classes: **wire** rules change the bytes of valid inputs or what inputs are representable; they
never change within v1. **Policy** rules bound the accepted inputs; a later release may widen
them (never narrow them) without a new label, see [Raising a cap](#raising-a-cap).

| Rule | Class | Detail |
|---|---|---|
| Label | wire | `anykms/aad/v1` followed by one NUL byte; a later version uses a different label |
| Widths | wire | `u16` field count, `u16` key length, `u16` value length, all big-endian |
| `purpose` is a field | wire | key `purpose`, value = the purpose name; counted and sorted like any field |
| Key order | wire | unsigned-byte lexicographic on the key bytes |
| Unique keys | wire | a duplicate key is rejected; the encoding is of a map |
| Values byte-exact | wire | UTF-8 as given: no Unicode normalization, no case folding, no trimming. `é` as U+00E9 and as `e` U+0301 are different values |
| Non-empty values | policy, MUST | an empty value (an id that was not set) is the misuse this encoding exists to catch |
| Purpose name | policy | 1..=48 bytes, `[a-z][a-z0-9-]*` |
| Keys | policy | 1..=32 bytes, `[a-z][a-z0-9_]*`; the key `purpose` is reserved for the purpose field |
| Values | policy | 1..=255 bytes; no control characters (Unicode general category Cc: U+0000–U+001F, U+007F–U+009F) |
| Field count | policy | at most 15 application fields (16 with `purpose`); zero application fields is valid |
| Total length | policy | the encoding is at most 3072 bytes |

The per-field caps alone would allow 4440 bytes (14 + 2 + 59 for a 48-byte purpose + 15 × 291);
the total cap is the operative bound, chosen so that every valid encoding fits the smallest
backend AAD limit (`anykms_aws::MAX_AAD_BYTES`), which "may only ever rise".

The charsets are policy, not needed for injectivity: they keep keys and purpose names safe to
print in errors and logs, and they make a key unable to collide with AWS's reserved
encryption-context key `associatedData` should the same fields ever be sent as a native context.

### Raising a cap

A cap may rise in a minor release. Because decrypting needs the identical bytes, a reader on an
older release cannot rebuild an AAD that a newer writer produced beyond the old cap; the same
reader-first rule as for envelope v2 applies (`docs/envelope-format.md`, Future versions): deploy
readers that accept the new cap everywhere before any writer uses it. An application that writes
within the old caps is unaffected.

## Security notes

- **What the AAD protects.** The AEAD authenticates the AAD against anyone who does not have the
  key (through the envelope: the data key; directly: the backend key). An attacker who can read
  and rewrite stored ciphertexts but cannot wrap under the KEK cannot move a ciphertext to another
  row, another purpose or another field value. This encoding adds that two writers of the same
  fields produce the same bytes, that a field cannot be silently empty, and that records of
  different purposes never share an AAD even when their other fields coincide.
- **Not in the envelope's key commitment.** Envelope v1 commits to the data key, not to the AAD
  (`docs/envelope-format.md`, Security notes). Whoever knows the data key, including the
  envelope's creator, can make one payload that decrypts under two AADs. Structuring the AAD
  changes nothing about that.
- **No authorship.** Anyone who can wrap under the KEK can write a fresh ciphertext for any
  context, with a software KEK: anyone holding its secret. The AAD does not say who wrote the
  row.
- **No freshness.** An AAD binds identity, not generation: a row's own older ciphertext passes
  under the same AAD. An application that needs anti-rollback adds a generation field itself.
- **Not stored, so rebuilt from trusted data.** The reader must take the fields from data it
  trusts for the row (its primary key, its tenant), never from the ciphertext's surroundings an
  attacker controls. Normalization the application applies to a field (lower-casing an e-mail
  address) must be applied identically before encoding, on write and on read.
- **Not secret.** AAD is not encrypted; on a direct backend `Aead` it is sent to and may be logged
  by the backend. Put identifiers in it, not data.
- **Errors.** A rule violation is a caller error (`InvalidArgument`), raised before any key is
  used. Error messages may name the rule and the key, never a value.
- **Versioning.** The encoding version is the label. A record *schema* version belongs in the
  purpose name (`session`, then `session-v2`) or in a field, never in a change of the encoding. A
  reader never tries several encoding versions on one ciphertext: each decrypt rebuilds exactly
  one AAD.

## Test vectors

`crates/anykms-recipes/tests/vectors/aad_v1.json` holds two lists. A conforming implementation
**must** produce the `aad` bytes of every `valid` vector from its `purpose` and `fields` (given in
an arbitrary order) and **must reject** every `invalid` vector for the `rule` it names. The vectors
are built by `tests/aad_vectors.rs` from this document; the test checks that the file is exactly
what that builder produces and that the builder's own decoder round-trips every valid vector.

Valid:

- `purpose_only`: one field, `purpose = session`.
- `two_fields`: `purpose = escrow` with `record` and `owner`, given in that order; the output
  sorts `owner`, `purpose`, `record`.
- `underscore_order`: keys `ab`, `a_b` and `a`: `_` (0x5f) sorts before `b`, and the prefix `a`
  first.
- `digit_order`: keys `k2`, `k10`, `k1` sort `k1`, `k10`, `k2` (bytes, not numbers).
- `max_fields`: a 48-byte purpose with a 32-byte key and a 255-byte value, and 14 more fields:
  every per-field cap at its maximum, within the total cap.
- `total_cap`: exactly 3072 bytes.
- `utf8_nfc`, `utf8_nfd`: the same text in two normalization forms encodes to different bytes.
- `u64_text`: `0` and `18446744073709551615` as the decimal text an application writes for
  integers.

Invalid, one per rule: `duplicate_key`, `reserved_key`, `empty_value`, `empty_purpose`,
`value_too_long` (256 bytes), `key_too_long` (33 bytes), `too_many_fields` (16),
`purpose_too_long` (49 bytes), `key_uppercase`, `key_digit_first`, `key_hyphen`,
`purpose_underscore`, `key_non_ascii`, `value_newline`, `value_nul`, `total_too_long` (3073
bytes).

## Future versions

A new version is a new label and a new document section; v1 is never reinterpreted. Candidates
the external review may raise: binding the AAD into the envelope's key commitment (an envelope
v2 matter, not a change to these bytes) and a native encryption-context mapping on AWS (the same
fields as a string map, which this layout supports as it stands: every value is a UTF-8 string and
no key can equal `associatedData`).
