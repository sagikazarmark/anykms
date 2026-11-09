//! Canonical AAD v1 test vectors (`tests/vectors/aad_v1.json`), from docs/aad-format.md.
//!
//! anykms has no implementation of this encoding: it is a specification applications implement
//! (see the status note in the document). The builder below is the reference the vectors are made
//! with, written from the document alone, and the committed file must be exactly what it produces.
//! Regenerate only when adding vectors:
//! `ANYKMS_REGENERATE_VECTORS=1 cargo test -p anykms-recipes --test aad_vectors`.
//!
//! With the `envelope` feature, the vectors also go through `EnvelopeAead` over an in-process key:
//! a round trip, and a decrypt under an AAD that differs in one field value fails `DecryptFailed`.

use serde_json::{Value, json};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/aad_v1.json");

// The encoding, from docs/aad-format.md.

const LABEL: &[u8] = b"anykms/aad/v1\0";
const MAX_PURPOSE_LEN: usize = 48;
const MAX_KEY_LEN: usize = 32;
const MAX_VALUE_LEN: usize = 255;
const MAX_FIELDS: usize = 15;
const MAX_TOTAL_LEN: usize = 3072;
const PURPOSE_KEY: &str = "purpose";

/// The rule a context breaks, one variant per rule in the document's table; `invalid` vectors
/// name these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    EmptyPurpose,
    PurposeTooLong,
    PurposeCharset,
    ReservedKey,
    DuplicateKey,
    EmptyKey,
    KeyTooLong,
    KeyCharset,
    EmptyValue,
    ValueTooLong,
    ValueControlChar,
    TooManyFields,
    TotalTooLong,
}

impl Rule {
    fn name(self) -> &'static str {
        match self {
            Self::EmptyPurpose => "empty_purpose",
            Self::PurposeTooLong => "purpose_too_long",
            Self::PurposeCharset => "purpose_charset",
            Self::ReservedKey => "reserved_key",
            Self::DuplicateKey => "duplicate_key",
            Self::EmptyKey => "empty_key",
            Self::KeyTooLong => "key_too_long",
            Self::KeyCharset => "key_charset",
            Self::EmptyValue => "empty_value",
            Self::ValueTooLong => "value_too_long",
            Self::ValueControlChar => "value_control_char",
            Self::TooManyFields => "too_many_fields",
            Self::TotalTooLong => "total_too_long",
        }
    }
}

/// `[a-z][a-z0-9<extra>]*`.
fn name_ok(s: &str, extra: char) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == extra)
}

fn check_key(key: &str) -> Result<(), Rule> {
    if key.is_empty() {
        return Err(Rule::EmptyKey);
    }
    if key.len() > MAX_KEY_LEN {
        return Err(Rule::KeyTooLong);
    }
    if !name_ok(key, '_') {
        return Err(Rule::KeyCharset);
    }
    if key == PURPOSE_KEY {
        return Err(Rule::ReservedKey);
    }
    Ok(())
}

fn check_value(value: &str) -> Result<(), Rule> {
    if value.is_empty() {
        return Err(Rule::EmptyValue);
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(Rule::ValueTooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(Rule::ValueControlChar);
    }
    Ok(())
}

fn check_purpose(purpose: &str) -> Result<(), Rule> {
    if purpose.is_empty() {
        return Err(Rule::EmptyPurpose);
    }
    if purpose.len() > MAX_PURPOSE_LEN {
        return Err(Rule::PurposeTooLong);
    }
    if !name_ok(purpose, '-') {
        return Err(Rule::PurposeCharset);
    }
    Ok(())
}

/// Encoding steps 1-4: the canonical AAD of `purpose` over `fields` (in any order), or the first
/// rule the input breaks.
fn encode(purpose: &str, fields: &[(&str, &str)]) -> Result<Vec<u8>, Rule> {
    check_purpose(purpose)?;
    if fields.len() > MAX_FIELDS {
        return Err(Rule::TooManyFields);
    }
    let mut all: Vec<(&str, &str)> = Vec::with_capacity(fields.len() + 1);
    for (k, v) in fields {
        check_key(k)?;
        check_value(v)?;
        all.push((k, v));
    }
    all.push((PURPOSE_KEY, purpose));
    // Step 3: unsigned-byte lexicographic key order (`[u8]: Ord` is exactly that).
    all.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if all.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Rule::DuplicateKey);
    }
    // Step 4.
    let mut out = LABEL.to_vec();
    out.extend_from_slice(&u16::try_from(all.len()).unwrap().to_be_bytes());
    for (k, v) in &all {
        out.extend_from_slice(&u16::try_from(k.len()).unwrap().to_be_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    if out.len() > MAX_TOTAL_LEN {
        return Err(Rule::TotalTooLong);
    }
    Ok(out)
}

/// Test-only decoder (the format defines none): the fields in encoded order, if `bytes` is a
/// well-formed v1 encoding. Checks framing only, not the rules.
fn decode(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    let rest = bytes.strip_prefix(LABEL)?;
    let n = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
    let mut rest = &rest[2..];
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        let klen = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        let key = std::str::from_utf8(rest.get(2..2 + klen)?).ok()?;
        rest = &rest[2 + klen..];
        let vlen = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        let value = std::str::from_utf8(rest.get(2..2 + vlen)?).ok()?;
        rest = &rest[2 + vlen..];
        fields.push((key.to_owned(), value.to_owned()));
    }
    rest.is_empty().then_some(fields)
}

// The vectors.

/// A key of exactly `MAX_KEY_LEN` bytes, unique per `i`.
fn long_key(i: usize) -> String {
    format!("k{i:02}_{}", "x".repeat(MAX_KEY_LEN - 4))
}

/// `max_fields`: every per-field cap at its maximum, within the total cap.
fn max_fields() -> (String, Vec<(String, String)>) {
    let purpose = format!("p-{}", "x".repeat(MAX_PURPOSE_LEN - 2));
    assert_eq!(purpose.len(), MAX_PURPOSE_LEN);
    // 14 + 2 + (2 + 7 + 2 + 48) = 75 bytes before the fields. The first field takes the full
    // 255-byte value (291 bytes); 3072 - 75 - 291 = 2706 leaves at most 193 bytes for each of the
    // other 14, i.e. values of at most 157 bytes. They take 150: the total is 2970.
    let mut fields = vec![(long_key(0), "v".repeat(MAX_VALUE_LEN))];
    for i in 1..MAX_FIELDS {
        fields.push((long_key(i), "v".repeat(150)));
    }
    (purpose, fields)
}

/// `total_cap`: exactly `MAX_TOTAL_LEN` bytes.
fn total_cap(extra: usize) -> (String, Vec<(String, String)>) {
    let purpose = "total-cap".to_owned();
    // 14 + 2 + (2 + 7 + 2 + 9) = 36 bytes before the fields; 10 fields of 291 = 2910; the last
    // field fills the rest: 3072 - 36 - 2910 = 126 = 2 + 32 + 2 + 90.
    let mut fields: Vec<(String, String)> = (0..10)
        .map(|i| (long_key(i), "v".repeat(MAX_VALUE_LEN)))
        .collect();
    fields.push((long_key(10), "v".repeat(90 + extra)));
    (purpose, fields)
}

fn pairs(fields: &[(String, String)]) -> Vec<(&str, &str)> {
    fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn valid(name: &str, purpose: &str, fields: &[(&str, &str)], description: Option<&str>) -> Value {
    let aad = encode(purpose, fields).unwrap_or_else(|r| panic!("{name}: {r:?}"));
    let mut v = json!({
        "name": name,
        "purpose": purpose,
        "fields": fields.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "aad": hex::encode(&aad),
    });
    if let Some(d) = description {
        v["description"] = json!(d);
    }
    v
}

fn invalid(name: &str, rule: Rule, purpose: &str, fields: &[(&str, &str)]) -> Value {
    assert_eq!(encode(purpose, fields), Err(rule), "{name}");
    json!({
        "name": name,
        "rule": rule.name(),
        "purpose": purpose,
        "fields": fields.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
    })
}

fn generate() -> Value {
    let (mp, mf) = max_fields();
    let (tp, tf) = total_cap(0);
    let (op, of) = total_cap(1);
    let long_value = "v".repeat(MAX_VALUE_LEN + 1);
    let long_key_33 = format!("k{}", "x".repeat(MAX_KEY_LEN));
    let long_purpose = format!("p{}", "x".repeat(MAX_PURPOSE_LEN));
    let sixteen: Vec<String> = (0..=MAX_FIELDS).map(|i| format!("f{i}")).collect();
    let sixteen: Vec<(&str, &str)> = sixteen.iter().map(|k| (k.as_str(), "v")).collect();
    json!({
        "format": "anykms canonical AAD v1",
        "label": hex::encode(LABEL),
        "valid": [
            valid("purpose_only", "session", &[], Some("One field: purpose alone is a valid AAD.")),
            valid("two_fields", "escrow", &[("record", "r-42"), ("owner", "7")],
                Some("Fields given as record, owner; the output sorts owner, purpose, record.")),
            valid("underscore_order", "order", &[("ab", "3"), ("a_b", "2"), ("a", "1")],
                Some("Unsigned-byte key order: a, a_b (0x5f sorts before b), ab.")),
            valid("digit_order", "order", &[("k2", "2"), ("k10", "10"), ("k1", "1")],
                Some("Keys sort as bytes, not numbers: k1, k10, k2.")),
            valid("max_fields", &mp, &pairs(&mf),
                Some("A 48-byte purpose, 15 fields with 32-byte keys, one 255-byte value: every per-field cap at its maximum, within the total cap.")),
            valid("total_cap", &tp, &pairs(&tf), Some("Exactly 3072 bytes, the total cap.")),
            valid("utf8_nfc", "text", &[("name", "caf\u{e9}")], Some("U+00E9: bytes c3 a9.")),
            valid("utf8_nfd", "text", &[("name", "cafe\u{301}")],
                Some("e then U+0301: bytes 65 cc 81. Values are byte-exact: no normalization.")),
            valid("u64_text", "ints", &[("min", "0"), ("max", "18446744073709551615")],
                Some("Integers as the decimal text an application writes; there is no number kind on the wire.")),
        ],
        "invalid": [
            invalid("duplicate_key", Rule::DuplicateKey, "p", &[("a", "1"), ("a", "2")]),
            invalid("reserved_key", Rule::ReservedKey, "p", &[("purpose", "x")]),
            invalid("empty_value", Rule::EmptyValue, "p", &[("a", "")]),
            invalid("empty_purpose", Rule::EmptyPurpose, "", &[("a", "1")]),
            invalid("value_too_long", Rule::ValueTooLong, "p", &[("a", &long_value)]),
            invalid("key_too_long", Rule::KeyTooLong, "p", &[(&long_key_33, "1")]),
            invalid("too_many_fields", Rule::TooManyFields, "p", &sixteen),
            invalid("purpose_too_long", Rule::PurposeTooLong, &long_purpose, &[]),
            invalid("key_uppercase", Rule::KeyCharset, "p", &[("Key", "1")]),
            invalid("key_digit_first", Rule::KeyCharset, "p", &[("1key", "1")]),
            invalid("key_hyphen", Rule::KeyCharset, "p", &[("a-b", "1")]),
            invalid("purpose_underscore", Rule::PurposeCharset, "a_b", &[]),
            invalid("key_non_ascii", Rule::KeyCharset, "p", &[("caf\u{e9}", "1")]),
            invalid("value_newline", Rule::ValueControlChar, "p", &[("a", "1\n")]),
            invalid("value_nul", Rule::ValueControlChar, "p", &[("a", "1\0")]),
            invalid("total_too_long", Rule::TotalTooLong, &op, &pairs(&of)),
        ],
    })
}

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).expect("vectors file")).unwrap()
}

fn fields_of(v: &Value) -> Vec<(String, String)> {
    v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f[0].as_str().unwrap().to_owned(),
                f[1].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn vectors_are_reproducible() {
    if std::env::var("ANYKMS_REGENERATE_VECTORS").is_ok_and(|v| v == "1") {
        std::fs::write(
            PATH,
            serde_json::to_string_pretty(&generate()).unwrap() + "\n",
        )
        .unwrap();
    }
    // Generation is deterministic; the committed file must be exactly what it produces.
    let committed = std::fs::read_to_string(PATH).unwrap();
    assert_eq!(
        committed,
        serde_json::to_string_pretty(&generate()).unwrap() + "\n"
    );
}

#[test]
fn valid_vectors_encode_in_any_field_order() {
    let v = load();
    for c in v["valid"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let purpose = c["purpose"].as_str().unwrap();
        let fields = fields_of(c);
        let mut given = pairs(&fields);
        let expected = hex::decode(c["aad"].as_str().unwrap()).unwrap();
        assert_eq!(encode(purpose, &given).unwrap(), expected, "{name}");
        given.reverse();
        assert_eq!(
            encode(purpose, &given).unwrap(),
            expected,
            "{name} (reversed)"
        );
        // Framing: the label, then exactly the sorted fields, purpose included.
        let decoded = decode(&expected).unwrap_or_else(|| panic!("{name}: decode"));
        assert_eq!(decoded.len(), fields.len() + 1, "{name}");
        assert!(
            decoded
                .windows(2)
                .all(|w| w[0].0.as_bytes() < w[1].0.as_bytes()),
            "{name}: keys in order"
        );
        assert!(
            decoded
                .iter()
                .any(|(k, v)| k == PURPOSE_KEY && v == purpose),
            "{name}: purpose field"
        );
        assert!(expected.len() <= MAX_TOTAL_LEN, "{name}");
    }
}

#[test]
fn invalid_vectors_are_rejected_for_their_rule() {
    let v = load();
    for c in v["invalid"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let fields = fields_of(c);
        let r = encode(c["purpose"].as_str().unwrap(), &pairs(&fields));
        assert_eq!(
            r.map(|_| ()).unwrap_err().name(),
            c["rule"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn caps_are_pinned() {
    let v = load();
    let aad = |name: &str| {
        let c = v["valid"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        hex::decode(c["aad"].as_str().unwrap()).unwrap()
    };
    assert_eq!(aad("total_cap").len(), MAX_TOTAL_LEN);
    assert_eq!(aad("purpose_only"), {
        let mut b = LABEL.to_vec();
        b.extend_from_slice(&[0, 1, 0, 7]);
        b.extend_from_slice(b"purpose");
        b.extend_from_slice(&[0, 7]);
        b.extend_from_slice(b"session");
        b
    });
    // The NFC and NFD vectors differ only in the value bytes.
    assert_ne!(aad("utf8_nfc"), aad("utf8_nfd"));
}

#[cfg(feature = "envelope")]
mod envelope {
    use anykms_core::{Aead as _, ErrorKind};
    use anykms_local::LocalKeyset;
    use anykms_recipes::EnvelopeAead;

    use super::{encode, load};

    #[tokio::test]
    async fn round_trip_and_one_field_differs() {
        let ks = LocalKeyset::builder().aead("kek").build();
        let env = EnvelopeAead::new("kek", ks.aead_key("kek").into_key_wrap()).unwrap();
        let v = load();
        let two = v["valid"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "two_fields")
            .unwrap();
        let aad = hex::decode(two["aad"].as_str().unwrap()).unwrap();
        assert_eq!(
            aad,
            encode("escrow", &[("record", "r-42"), ("owner", "7")]).unwrap()
        );
        let ct = env.encrypt(b"123-45-6789", &aad).await.unwrap();
        assert_eq!(&*env.decrypt(&ct, &aad).await.unwrap(), b"123-45-6789");
        // The same record under another owner, and under another purpose.
        for other in [
            encode("escrow", &[("record", "r-42"), ("owner", "8")]).unwrap(),
            encode("session", &[("record", "r-42"), ("owner", "7")]).unwrap(),
        ] {
            let err = env.decrypt(&ct, &other).await.map(|_| ()).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::DecryptFailed);
        }
    }
}
