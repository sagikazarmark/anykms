//! AWS KMS key URIs (Tink's format, so Tink key URIs open unchanged):
//!
//! ```text
//! aws-kms://arn:<partition>:kms:<region>:<account>:key/<key-id>
//! aws-kms://arn:<partition>:kms:<region>:<account>:alias/<alias-name>
//! ```
//!
//! The URI names partition, region and account, never a host: the endpoint is derived from the
//! partition and region or configured (see [`AwsProviderBuilder`](crate::AwsProviderBuilder)).
//! The grammar is strict:
//!
//! - partition `[a-z][a-z0-9-]{0,31}` (`aws`, `aws-cn` and `aws-us-gov` have built-in endpoints;
//!   others need a configured endpoint);
//! - region: the AWS region shape `<area>-<name>[-<name>...]-<number>` (`eu-west-1`,
//!   `us-gov-west-1`, `ap-southeast-7`, `us-iso-east-1`): a 2 to 4 letter area, 1 to 3 lowercase
//!   alphabetic names and a 1 or 2 digit number, at most 32 characters. Labels such as `s3` or
//!   `kms` are refused, so a derived endpoint is always `kms.<region>.<partition suffix>`;
//! - the region belongs to the partition: `cn-*` only in `aws-cn`, `us-gov-*` only in
//!   `aws-us-gov`, the ISO and European Sovereign Cloud prefixes only in their partitions
//!   (`us-iso-*` in `aws-iso`, `us-isob-*` in `aws-iso-b`, `eu-isoe-*` in `aws-iso-e`,
//!   `us-isof-*` in `aws-iso-f`, `eusc-*` in `aws-eusc`), and `aws` regions have a 2 letter area;
//! - account: 12 digits;
//! - key id: a lowercase UUID or `mrk-` followed by 32 lowercase hex digits (multi-Region keys);
//! - alias name: `[A-Za-z0-9/_-]{1,256}`, never `aws/...` (AWS managed keys cannot be application
//!   keys).
//!
//! No query, fragment, percent-encoding or whitespace. Bare key ids and alias names are refused:
//! the region and account must be explicit.

use anykms_core::{Error, ErrorKind, KeyUri, Operation, Result};

use crate::BACKEND;

/// The URI scheme of AWS KMS keys.
pub const SCHEME: &str = "aws-kms";

/// URI schemes routed to the AWS provider.
pub const SCHEMES: &[&str] = &[SCHEME];

/// What a key URI names inside an account: a key or an alias.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum KeyRef {
    /// `key/<key-id>`: a key id (UUID or `mrk-...`).
    Key(String),
    /// `alias/<name>`: an alias name, without the `alias/` prefix.
    Alias(String),
}

/// A parsed `aws-kms://` key URI.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AwsKeyRef {
    pub(crate) partition: String,
    pub(crate) region: String,
    pub(crate) account: String,
    pub(crate) key: KeyRef,
    pub(crate) arn: String,
}

impl AwsKeyRef {
    /// Parses a key URI of the `aws-kms` scheme.
    pub fn parse(uri: &KeyUri) -> Result<Self> {
        if !SCHEMES.contains(&uri.scheme()) {
            return Err(bad("not an aws-kms:// URI"));
        }
        let arn = uri
            .rest()
            .strip_prefix("//")
            .ok_or_else(|| bad("aws-kms URIs have the form aws-kms://arn:<partition>:kms:..."))?;
        Self::parse_arn(arn)
    }

    /// Parses a KMS key or alias ARN (`arn:<partition>:kms:<region>:<account>:key/<id>` or
    /// `...:alias/<name>`).
    pub fn parse_arn(arn: &str) -> Result<Self> {
        if arn.contains(['?', '#', '%']) {
            return Err(bad(
                "aws-kms URIs take no query, fragment or percent-encoding",
            ));
        }
        let Some(rest) = arn.strip_prefix("arn:") else {
            return Err(bad(
                "aws-kms URIs need a full ARN (aws-kms://arn:<partition>:kms:<region>:<account>:key/<id>); \
                 bare key ids and alias names are refused because the region and account must be explicit",
            ));
        };
        let mut parts = rest.splitn(5, ':');
        let (Some(partition), Some(service), Some(region), Some(account), Some(resource)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(bad(
                "malformed ARN: expected arn:<partition>:kms:<region>:<account>:<resource>",
            ));
        };
        if !partition_ok(partition) {
            return Err(bad("malformed ARN partition"));
        }
        if service != "kms" {
            return Err(bad("not a KMS ARN (service must be kms)"));
        }
        if !region_ok(region) {
            return Err(bad("malformed ARN region"));
        }
        if !region_in_partition(partition, region) {
            return Err(bad("the ARN region does not belong to its partition"));
        }
        if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("the ARN account must be 12 digits"));
        }
        let key = if let Some(id) = resource.strip_prefix("key/") {
            if !key_id_ok(id) {
                return Err(bad(
                    "malformed key id: expected a lowercase UUID or mrk- and 32 lowercase hex digits",
                ));
            }
            KeyRef::Key(id.to_owned())
        } else if let Some(name) = resource.strip_prefix("alias/") {
            if !alias_ok(name) {
                return Err(bad(
                    "malformed alias name: 1 to 256 characters of A-Z a-z 0-9 / _ -",
                ));
            }
            if name.starts_with("aws/") {
                return Err(bad(
                    "aws/ aliases name AWS managed keys, which cannot be application keys; \
                     use a customer managed key",
                ));
            }
            KeyRef::Alias(name.to_owned())
        } else {
            return Err(bad("the ARN resource must be key/<id> or alias/<name>"));
        };
        Ok(Self {
            partition: partition.to_owned(),
            region: region.to_owned(),
            account: account.to_owned(),
            key,
            arn: arn.to_owned(),
        })
    }

    /// The partition (`aws`, `aws-cn`, `aws-us-gov`, ...).
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// The region.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The 12-digit account.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The key id (`key/<id>` ARNs), `None` for aliases.
    pub fn key_id(&self) -> Option<&str> {
        match &self.key {
            KeyRef::Key(k) => Some(k),
            KeyRef::Alias(_) => None,
        }
    }

    /// The alias name without the `alias/` prefix (`alias/<name>` ARNs), `None` for keys.
    pub fn alias_name(&self) -> Option<&str> {
        match &self.key {
            KeyRef::Alias(a) => Some(a),
            KeyRef::Key(_) => None,
        }
    }

    /// The ARN as written.
    pub fn arn(&self) -> &str {
        &self.arn
    }

    /// Whether this names an alias.
    pub fn is_alias(&self) -> bool {
        matches!(self.key, KeyRef::Alias(_))
    }
}

/// Whether `s` is a well-formed KMS **key** ARN (not an alias): what a key version is.
pub(crate) fn is_key_arn(s: &str) -> bool {
    AwsKeyRef::parse_arn(s).is_ok_and(|r| matches!(r.key, KeyRef::Key(_)))
}

fn bad(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::ParseUri, m)
}

fn partition_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The AWS region shape: `<area>-<name>[-<name>...]-<number>`, e.g. `eu-west-1`,
/// `us-gov-west-1`, `eusc-de-east-1`.
pub(crate) fn region_ok(s: &str) -> bool {
    let alpha = |p: &str, max: usize| {
        (1..=max).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_lowercase())
    };
    let parts: Vec<&str> = s.split('-').collect();
    let (Some(area), Some(number)) = (parts.first(), parts.last()) else {
        return false;
    };
    s.len() <= 32
        && (3..=5).contains(&parts.len())
        && (2..=4).contains(&area.len())
        && alpha(area, 4)
        && parts[1..parts.len() - 1].iter().all(|p| alpha(p, 12))
        && (1..=2).contains(&number.len())
        && number.bytes().all(|c| c.is_ascii_digit())
        && !number.starts_with('0')
}

/// Region prefixes reserved to one partition.
const RESERVED_PREFIXES: &[(&str, &str)] = &[
    ("aws-cn", "cn-"),
    ("aws-us-gov", "us-gov-"),
    ("aws-iso", "us-iso-"),
    ("aws-iso-b", "us-isob-"),
    ("aws-iso-e", "eu-isoe-"),
    ("aws-iso-f", "us-isof-"),
    ("aws-eusc", "eusc-"),
];

/// Whether `region` (already [`region_ok`]) belongs to `partition`. Partitions anykms has no
/// built-in endpoints for accept any region of a prefix no other known partition reserves.
fn region_in_partition(partition: &str, region: &str) -> bool {
    for (p, prefix) in RESERVED_PREFIXES {
        if region.starts_with(prefix) {
            return partition == *p;
        }
        if partition == *p {
            return false;
        }
    }
    match partition {
        "aws" => region.find('-') == Some(2),
        _ => true,
    }
}

fn lower_hex(s: &str) -> bool {
    s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn key_id_ok(id: &str) -> bool {
    if let Some(h) = id.strip_prefix("mrk-") {
        return h.len() == 32 && lower_hex(h);
    }
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && lower_hex(g))
}

fn alias_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    fn parse(s: &str) -> Result<AwsKeyRef> {
        AwsKeyRef::parse(&s.parse::<KeyUri>()?)
    }

    #[test]
    fn accepts_keys_mrks_and_aliases() {
        let r = parse(&format!("aws-kms://{KEY}")).unwrap();
        assert_eq!(r.partition(), "aws");
        assert_eq!(r.region(), "eu-west-1");
        assert_eq!(r.account(), "111122223333");
        assert_eq!(r.key_id(), Some("1234abcd-12ab-34cd-56ef-1234567890ab"));
        assert_eq!(r.alias_name(), None);
        assert_eq!(r.arn(), KEY);
        assert!(!r.is_alias());
        let r = parse(
            "aws-kms://arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab",
        )
        .unwrap();
        assert!(r.key_id().is_some_and(|k| k.starts_with("mrk-")));
        let r =
            parse("aws-kms://arn:aws-cn:kms:cn-north-1:111122223333:alias/app/kek_1-x").unwrap();
        assert_eq!(r.alias_name(), Some("app/kek_1-x"));
        assert_eq!(r.key_id(), None);
        assert!(r.is_alias());
        parse("aws-kms://arn:aws-us-gov:kms:us-gov-west-1:111122223333:alias/a").unwrap();
        parse("aws-kms://arn:aws-iso:kms:us-iso-east-1:111122223333:alias/a").unwrap();
        for (partition, region) in [
            ("aws", "us-east-1"),
            ("aws", "ap-southeast-7"),
            ("aws", "il-central-1"),
            ("aws", "ca-west-1"),
            ("aws-cn", "cn-northwest-1"),
            ("aws-iso-b", "us-isob-east-1"),
            ("aws-iso-e", "eu-isoe-west-1"),
            ("aws-iso-f", "us-isof-south-1"),
            ("aws-eusc", "eusc-de-east-1"),
            ("aws-future", "xy-north-12"),
        ] {
            parse(&format!(
                "aws-kms://arn:{partition}:kms:{region}:111122223333:alias/a"
            ))
            .unwrap();
        }
        assert!(is_key_arn(KEY));
        assert!(!is_key_arn("arn:aws:kms:eu-west-1:111122223333:alias/a"));
        assert!(!is_key_arn("1"));
    }

    #[test]
    fn rejects_everything_else() {
        let long_alias = format!(
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/{}",
            "a".repeat(257)
        );
        for bad in [
            "aws-kms:arn:aws:kms:eu-west-1:111122223333:alias/a",
            "aws-kms://1234abcd-12ab-34cd-56ef-1234567890ab",
            "aws-kms://alias/a",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333",
            "aws-kms://arn:aws:s3:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "aws-kms://arn:AWS:kms:eu-west-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:EU-west-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms::111122223333:alias/a",
            "aws-kms://arn:aws:kms:cn-north-1:111122223333:alias/a",
            "aws-kms://arn:aws-cn:kms:eu-west-1:111122223333:alias/a",
            "aws-kms://arn:aws-us-gov:kms:us-east-1:111122223333:alias/a",
            // Labels that are not regions (a derived host must stay a KMS endpoint).
            "aws-kms://arn:aws:kms:s3:111122223333:alias/a",
            "aws-kms://arn:aws:kms:kms:111122223333:alias/a",
            "aws-kms://arn:aws:kms:a1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:s3-us-west-2:111122223333:alias/a",
            "aws-kms://arn:aws:kms:s3-external-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-west:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-west-01:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-west-123:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu--west-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-west-1-:111122223333:alias/a",
            "aws-kms://arn:aws:kms:-eu-west-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-w3st-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:abcde-west-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-a-b-c-d-1:111122223333:alias/a",
            // Regions of another partition.
            "aws-kms://arn:aws:kms:us-iso-east-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eusc-de-east-1:111122223333:alias/a",
            "aws-kms://arn:aws-iso:kms:us-east-1:111122223333:alias/a",
            "aws-kms://arn:aws-iso:kms:us-isob-east-1:111122223333:alias/a",
            "aws-kms://arn:aws-eusc:kms:eu-west-1:111122223333:alias/a",
            "aws-kms://arn:aws-future:kms:cn-north-1:111122223333:alias/a",
            "aws-kms://arn:aws:kms:eu-west-1:11112222333:alias/a",
            "aws-kms://arn:aws:kms:eu-west-1:1111222233334:alias/a",
            "aws-kms://arn:aws:kms:eu-west-1:11112222333x:alias/a",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:key/1234ABCD-12ab-34cd-56ef-1234567890ab",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:key/1234abcd12ab34cd56ef1234567890ab",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:key/mrk-1234",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:key/",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/aws/ebs",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/a.b",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/a:b",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/a?x=1",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/a#f",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/a%2Fb",
            "aws-kms://arn:aws:kms:eu-west-1:111122223333:grant/a",
            "hashivault://arn:aws:kms:eu-west-1:111122223333:alias/a",
            &long_alias,
        ] {
            let e = parse(bad).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{bad}");
        }
    }

    #[test]
    fn hints() {
        let e = parse("aws-kms://alias/a").unwrap_err();
        assert!(
            e.to_string()
                .contains("region and account must be explicit"),
            "{e}"
        );
        let e = parse("aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/aws/ebs").unwrap_err();
        assert!(e.to_string().contains("AWS managed"), "{e}");
    }
}
