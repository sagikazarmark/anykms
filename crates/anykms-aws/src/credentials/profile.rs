//! Shared config and credentials files (`~/.aws/config`, `~/.aws/credentials`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anykms_core::{BoxFuture, Result};
use zeroize::Zeroizing;

use super::{CredentialSource, Credentials, SourceContext, Vars, config_err};

/// One INI section: keys (lowercase) → values.
pub(crate) type Section = BTreeMap<String, Zeroizing<String>>;

/// Parses the AWS INI dialect: `[section]` headers, `key = value` lines, full-line comments
/// (`#`, `;`) and inline comments after whitespace. Indented continuation lines (nested
/// settings such as `s3 =`) are skipped. Keys are case-insensitive. A `key = value` line outside
/// any section, or a line that is neither, is an error (the line number only, never content).
pub(crate) fn parse_ini(text: &str) -> std::result::Result<BTreeMap<String, Section>, usize> {
    let mut out: BTreeMap<String, Section> = BTreeMap::new();
    let mut current: Option<String> = None;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        if raw.starts_with([' ', '\t']) && !raw.trim().is_empty() {
            // A continuation (nested) line: only valid under a key; skipped.
            if current.is_none() {
                return Err(line_no);
            }
            continue;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(h) = line.strip_prefix('[') {
            let h = strip_inline_comment(h);
            let name = h.strip_suffix(']').ok_or(line_no)?.trim();
            if name.is_empty() {
                return Err(line_no);
            }
            out.entry(name.to_owned()).or_default();
            current = Some(name.to_owned());
            continue;
        }
        let (k, v) = line.split_once('=').ok_or(line_no)?;
        let k = k.trim().to_ascii_lowercase();
        if k.is_empty() {
            return Err(line_no);
        }
        let section = current.as_ref().ok_or(line_no)?;
        let v = strip_inline_comment(v).trim();
        out.get_mut(section)
            .expect("section exists")
            .insert(k, Zeroizing::new(v.to_owned()));
    }
    Ok(out)
}

/// Cuts a comment that starts with whitespace followed by `#` or `;`.
fn strip_inline_comment(s: &str) -> &str {
    let b = s.as_bytes();
    for i in 1..b.len() {
        if matches!(b[i], b'#' | b';') && b[i - 1].is_ascii_whitespace() {
            return &s[..i];
        }
    }
    s
}

/// Static credentials from a named profile of the shared files: `aws_access_key_id` +
/// `aws_secret_access_key` (+ `aws_session_token`).
///
/// Profiles that get credentials another way, IAM Identity Center (`sso_*`), role chaining
/// (`role_arn` with `source_profile`, `credential_source` or `web_identity_token_file`) or
/// `credential_process`, are refused with `Configuration`: use the AWS SDK's credentials
/// through the `sdk-credentials` feature, or a custom [`CredentialSource`].
#[derive(Debug, Clone)]
pub struct ProfileCredentials {
    name: Option<String>,
    config_file: Option<PathBuf>,
    credentials_file: Option<PathBuf>,
    vars: Vars,
}

/// The `Configuration` error for a profile that needs the AWS SDK's credentials.
fn needs_sdk(name: &str, what: &str) -> anykms_core::Error {
    config_err(format!(
        "AWS profile {name:?} uses {what}, which anykms does not resolve itself; use the AWS \
         SDK's credentials through the `sdk-credentials` feature, or a custom CredentialSource"
    ))
}

impl ProfileCredentials {
    /// The profile named by `AWS_PROFILE` (else `default`), files from `AWS_CONFIG_FILE` /
    /// `AWS_SHARED_CREDENTIALS_FILE` (else `~/.aws/config` and `~/.aws/credentials`), read
    /// when credentials are first needed.
    pub fn new() -> Self {
        Self::from_vars(Vars::from_env())
    }

    /// The profile `name` (instead of `AWS_PROFILE`).
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::new()
        }
    }

    /// Reads this config file instead of `AWS_CONFIG_FILE` / `~/.aws/config`.
    pub fn config_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_file = Some(path.into());
        self
    }

    /// Reads this credentials file instead of `AWS_SHARED_CREDENTIALS_FILE` /
    /// `~/.aws/credentials`.
    pub fn credentials_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.credentials_file = Some(path.into());
        self
    }

    /// Like `new`, reading variables from `lookup` instead of the process environment (empty
    /// values count as unset).
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self::from_vars(Vars::from_fn(lookup))
    }

    pub(crate) fn from_vars(vars: Vars) -> Self {
        Self {
            name: None,
            config_file: None,
            credentials_file: None,
            vars,
        }
    }

    /// The profile name and whether it was chosen explicitly.
    fn profile_name(&self) -> (String, bool) {
        if let Some(n) = &self.name {
            return (n.clone(), true);
        }
        match self
            .vars
            .get("AWS_PROFILE")
            .or_else(|| self.vars.get("AWS_DEFAULT_PROFILE"))
        {
            Some(n) => (n.to_owned(), true),
            None => ("default".to_owned(), false),
        }
    }

    fn paths(&self) -> (Option<PathBuf>, Option<PathBuf>) {
        let home = self.vars.home().map(|h| h.join(".aws"));
        let config = self
            .config_file
            .clone()
            .or_else(|| self.vars.get("AWS_CONFIG_FILE").map(PathBuf::from))
            .or_else(|| home.as_ref().map(|h| h.join("config")));
        let creds = self
            .credentials_file
            .clone()
            .or_else(|| {
                self.vars
                    .get("AWS_SHARED_CREDENTIALS_FILE")
                    .map(PathBuf::from)
            })
            .or_else(|| home.as_ref().map(|h| h.join("credentials")));
        (config, creds)
    }

    /// The profile's merged settings (credentials file over config file), `None` when neither
    /// file has it.
    pub(crate) fn section(&self) -> Result<Option<Section>> {
        let (name, _) = self.profile_name();
        let (config, creds) = self.paths();
        let mut found = false;
        let mut merged = Section::new();
        if let Some(p) = config
            && let Some(ini) = read_ini(&p)?
        {
            let wanted = if name == "default" {
                vec!["default".to_owned(), "profile default".to_owned()]
            } else {
                vec![format!("profile {name}")]
            };
            for w in wanted {
                if let Some(s) = ini.get(&w) {
                    found = true;
                    merged.extend(s.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
            }
        }
        if let Some(p) = creds
            && let Some(ini) = read_ini(&p)?
            && let Some(s) = ini.get(&name)
        {
            found = true;
            merged.extend(s.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        Ok(found.then_some(merged))
    }

    /// Whether the chain should use this source: the profile was named explicitly, or a file
    /// has it.
    pub(crate) fn configured(&self) -> Result<bool> {
        Ok(self.profile_name().1 || self.section()?.is_some())
    }

    pub(crate) fn resolve(&self) -> Result<Credentials> {
        let (name, _) = self.profile_name();
        let s = self.section()?.ok_or_else(|| {
            config_err(format!(
                "AWS profile {name:?} not found in the shared config or credentials file"
            ))
        })?;
        let get = |k: &str| s.get(k).map(|v| v.as_str()).filter(|v| !v.is_empty());
        if get("sso_start_url").is_some() || get("sso_session").is_some() {
            return Err(needs_sdk(&name, "IAM Identity Center (SSO)"));
        }
        if get("role_arn").is_some() {
            return Err(needs_sdk(&name, "an assumed role (role_arn)"));
        }
        if get("aws_access_key_id").is_some() || get("aws_secret_access_key").is_some() {
            let (Some(id), Some(secret)) = (get("aws_access_key_id"), get("aws_secret_access_key"))
            else {
                return Err(config_err(format!(
                    "AWS profile {name:?} must set aws_access_key_id and aws_secret_access_key \
                     together"
                )));
            };
            let c = Credentials::new(id, secret, get("aws_session_token").map(str::to_owned));
            c.validate()?;
            return Ok(c);
        }
        if get("credential_process").is_some() {
            return Err(needs_sdk(&name, "credential_process"));
        }
        Err(config_err(format!(
            "AWS profile {name:?} has no credentials"
        )))
    }
}

impl Default for ProfileCredentials {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads and parses an INI file; `None` if it does not exist.
fn read_ini(path: &Path) -> Result<Option<BTreeMap<String, Section>>> {
    let bytes = match anykms_http::zbuf::read_file(path, super::MAX_CREDENTIAL_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(config_err(format!(
                "cannot read AWS shared file {}: {}",
                path.display(),
                e.kind()
            )));
        }
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| config_err(format!("AWS shared file {} is not UTF-8", path.display())))?;
    parse_ini(text).map(Some).map_err(|line| {
        config_err(format!(
            "malformed AWS shared file {} (line {line})",
            path.display()
        ))
    })
}

impl CredentialSource for ProfileCredentials {
    fn kind(&self) -> &'static str {
        "profile"
    }

    fn credentials<'a>(&'a self, _: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(async move { self.resolve() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anykms_core::ErrorKind;

    #[test]
    fn ini() {
        let t = "# comment\n; also\n[default]\naws_access_key_id = AKID ; inline\nAWS_Secret_Access_Key=S#notacomment\n\n[profile p]\nregion = eu-west-1\ns3 =\n  max_concurrent_requests = 10\n[ sso-session x ]\n";
        let ini = parse_ini(t).unwrap();
        let d = &ini["default"];
        assert_eq!(d["aws_access_key_id"].as_str(), "AKID");
        assert_eq!(d["aws_secret_access_key"].as_str(), "S#notacomment");
        assert_eq!(ini["profile p"]["region"].as_str(), "eu-west-1");
        assert!(ini.contains_key("sso-session x"));
        assert_eq!(parse_ini("k = v\n"), Err(1));
        assert_eq!(parse_ini("[a]\nnot a pair\n"), Err(2));
        assert_eq!(parse_ini("[a\n"), Err(1));
        assert_eq!(parse_ini("[]\n"), Err(1));
        assert_eq!(parse_ini("  indented\n"), Err(1));
        assert_eq!(parse_ini("[a]\n= v\n"), Err(2));
    }

    fn dir(name: &str, config: &str, creds: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("anykms-aws-profile-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("config"), config).unwrap();
        std::fs::write(d.join("credentials"), creds).unwrap();
        d
    }

    fn source(d: &Path, profile: Option<&str>) -> ProfileCredentials {
        let mut s = ProfileCredentials::from_vars(Vars::default())
            .config_file(d.join("config"))
            .credentials_file(d.join("credentials"));
        s.name = profile.map(str::to_owned);
        s
    }

    #[test]
    fn resolves_profiles() {
        let d = dir(
            "resolve",
            "[default]\nregion = us-east-1\n[profile proc]\ncredential_process = echo hi\n\
             [profile wi]\nrole_arn = arn:aws:iam::111122223333:role/r\nweb_identity_token_file = /t\nregion = eu-west-1\n\
             [profile chain]\nrole_arn = arn:aws:iam::111122223333:role/r\nsource_profile = default\n\
             [profile sso]\nsso_session = s\n[profile empty]\n[profile half]\naws_access_key_id = A\n",
            "[default]\naws_access_key_id = AKID\naws_secret_access_key = SECRET\n",
        );
        let s = source(&d, None);
        assert!(s.configured().unwrap());
        assert_eq!(s.resolve().unwrap().access_key_id(), "AKID");
        // Profiles that need the AWS SDK name the feature that provides it.
        for (p, needle) in [
            ("proc", "credential_process"),
            ("wi", "role_arn"),
            ("chain", "role_arn"),
            ("sso", "SSO"),
        ] {
            let e = source(&d, Some(p)).resolve().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration);
            let m = e.to_string();
            assert!(
                m.contains(needle) && m.contains("sdk-credentials"),
                "{p}: {e}"
            );
        }
        for (p, needle) in [
            ("empty", "no credentials"),
            ("half", "together"),
            ("missing", "not found"),
        ] {
            let e = source(&d, Some(p)).resolve().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration);
            assert!(e.to_string().contains(needle), "{p}: {e}");
        }
        // An explicit profile is "configured" even when missing (so the chain reports it).
        assert!(source(&d, Some("missing")).configured().unwrap());
        // No files, no explicit profile: not configured.
        let none = ProfileCredentials::from_vars(Vars::default())
            .config_file(d.join("nope"))
            .credentials_file(d.join("nope2"));
        assert!(!none.configured().unwrap());
        // A malformed file names the line, not the content.
        let bad = dir("bad", "[default]\nSECRETLINE\n", "");
        let e = source(&bad, None).resolve().unwrap_err();
        assert!(
            e.to_string().contains("line 2") && !e.to_string().contains("SECRETLINE"),
            "{e}"
        );
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(&bad).unwrap();
    }
}
