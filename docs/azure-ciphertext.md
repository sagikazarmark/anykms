# Azure ciphertext frame

anykms-azure stores what Azure Key Vault and Managed HSM return from `wrapkey` and `encrypt` in a
small frame that names the algorithm and the key version. This is a **wire format**
(PLAN §23 Q9): data written today must stay readable, so the layout below never changes; a new
algorithm or variant gets a new algorithm byte, never a reinterpretation of an existing one.

Azure itself embeds no key version in RSA-OAEP or AES key-wrap output, and returns AES-GCM's IV and
tag as separate fields. Without the frame, unwrapping would need the version from somewhere else.

## Layout

```
offset  size   field
0       3      magic "AZK" (0x41 0x5a 0x4b)
3       1      format 0x01
4       1      alg
5       1      vlen, 1..=64
6       vlen   version: [0-9a-z]
6+vlen  ...    body
```

| alg | Azure `alg` | body | where |
|---|---|---|---|
| `0x01` | `RSA-OAEP-256` (SHA-256, MGF1-SHA-256) | the `wrapkey` output: exactly the modulus size (256 bytes for RSA-2048) | `KeyWrap` on RSA keys (vaults and Managed HSM) |
| `0x02` | `A256GCM` | `iv` (12 bytes) ‖ ciphertext ‖ `tag` (16 bytes) | `Aead` on Managed HSM `oct-HSM` keys |
| `0x03` | `A256KW` (RFC 3394) | the `wrapkey` output: input length + 8 | `KeyWrap` on Managed HSM `oct-HSM` keys |

Rules a parser enforces (`anykms_azure::framing::parse`):

- the magic, format `0x01` and a known algorithm byte;
- `vlen` from 1 to 64 and a version of lowercase letters and digits (Azure issues 32 hex
  characters today; the length prefix keeps a future format readable). The key handles accept
  32-hex versions only today: another version in a well-formed frame is `DecryptFailed` (or
  `InvalidArgument` for a signature's version) before any request;
- an RSA body of at least one byte (its exact size is checked against the key before unwrapping),
  a GCM body of at least 28 bytes (an empty ciphertext is representable), an A256KW body of at
  least 24 bytes and a multiple of 8.

The frame is not authenticated by itself. A tampered version makes the vault use another key
version, which fails to decrypt (`DecryptFailed`); a tampered algorithm byte is refused by the
handle before any request. AES-GCM authenticates the ciphertext and the AAD, not the frame.

## Interoperability

Azure tools (SDKs, `az keyvault key decrypt`) do not understand the frame. To hand data to them,
strip it: `framing::parse(bytes)` gives the algorithm, the version (append it to the key id:
`https://<vault>/keys/<name>/<version>`) and the body; for A256GCM, `Frame::gcm_parts` gives the
`iv`, ciphertext and `tag` fields of Azure's `decrypt` request. To import data wrapped by another
tool, build a frame with `framing::encode` (or `encode_gcm`) from the version in its key id.

Wrapped keys produced with `RSA-OAEP` (SHA-1) or `RSA1_5` cannot be framed: anykms does not
unwrap them (docs/cloud/azure.md Q6).

## Test vectors

`crates/anykms-azure/tests/vectors/frames.json`, checked by `tests/vectors.rs`:

| name | frame (hex, abridged) | decrypts to |
|---|---|---|
| `rsa-oaep-256` | `415a4b 01 01 20` ‖ `"0123456789abcdef0123456789abcdef"` ‖ 256-byte body | `000102…1f` under `tests/data/rsa_2048.pk8.pem` |
| `a256gcm` | `415a4b 01 02 20` ‖ version ‖ `22…22` (iv) ‖ 25-byte ciphertext ‖ tag | `"anykms azure frame vector"`, key `11…11`, AAD `"users/42"` |
| `a256kw (RFC 3394 4.6)` | `415a4b 01 03 20` ‖ version ‖ `28c9f404…7a02dd21` | `00112233…0c0d0e0f` under KEK `000102…1f` |
| `non-hex version` | `415a4b 01 01 02 "v7"` ‖ body | (parse only) |

plus twelve invalid frames with the error each must produce. To check the RSA vector with OpenSSL:

```sh
jq -r '.valid[0].body' crates/anykms-azure/tests/vectors/frames.json | xxd -r -p > body.bin
openssl pkeyutl -decrypt -inkey crates/anykms-azure/tests/data/rsa_2048.pk8.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
  -in body.bin | xxd -p
```
