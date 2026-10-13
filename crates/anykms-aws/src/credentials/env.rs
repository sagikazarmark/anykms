//! Fixed credentials and the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` variables.

use anykms_core::{BoxFuture, Result};

use super::{CredentialSource, Credentials, SourceContext, Vars, config_err};

/// Fixed credentials (never refreshed).
#[derive(Debug, Clone)]
pub struct StaticCredentials(Credentials);

impl StaticCredentials {
    /// These credentials.
    pub fn new(credentials: Credentials) -> Self {
        Self(credentials)
    }
}

impl CredentialSource for StaticCredentials {
    fn kind(&self) -> &'static str {
        "static"
    }

    fn credentials<'a>(&'a self, _: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(async move {
            self.0.validate()?;
            Ok(self.0.clone())
        })
    }
}

/// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read when the source is
/// created (a snapshot: later changes to the environment are not seen).
#[derive(Debug, Clone)]
pub struct EnvCredentials {
    vars: Vars,
}

impl EnvCredentials {
    /// A snapshot of the process environment.
    pub fn new() -> Self {
        Self {
            vars: Vars::from_env(),
        }
    }

    /// Like `new`, reading variables from `lookup` instead of the process environment (empty
    /// values count as unset).
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self::from_vars(Vars::from_fn(lookup))
    }

    pub(crate) fn from_vars(vars: Vars) -> Self {
        Self { vars }
    }

    /// Whether the variables are set at all (for the chain).
    pub(crate) fn configured(vars: &Vars) -> bool {
        vars.get("AWS_ACCESS_KEY_ID").is_some() || vars.get("AWS_SECRET_ACCESS_KEY").is_some()
    }

    pub(crate) fn load(vars: &Vars) -> Result<Credentials> {
        let (Some(id), Some(secret)) = (
            vars.get("AWS_ACCESS_KEY_ID"),
            vars.get("AWS_SECRET_ACCESS_KEY"),
        ) else {
            return Err(config_err(
                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together",
            ));
        };
        let c = Credentials::new(id, secret, vars.get("AWS_SESSION_TOKEN").map(str::to_owned));
        c.validate()?;
        Ok(c)
    }
}

impl Default for EnvCredentials {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialSource for EnvCredentials {
    fn kind(&self) -> &'static str {
        "environment"
    }

    fn credentials<'a>(&'a self, _: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        Box::pin(async move { Self::load(&self.vars) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anykms_core::ErrorKind;

    #[test]
    fn env() {
        let v = Vars::from_fn(|k| match k {
            "AWS_ACCESS_KEY_ID" => Some("AKID".into()),
            "AWS_SECRET_ACCESS_KEY" => Some("SECRET".into()),
            "AWS_SESSION_TOKEN" => Some("TOKEN".into()),
            _ => None,
        });
        assert!(EnvCredentials::configured(&v));
        let c = EnvCredentials::load(&v).unwrap();
        assert_eq!(c.session_token(), Some("TOKEN"));
        let half = Vars::from_fn(|k| (k == "AWS_ACCESS_KEY_ID").then(|| "AKID".into()));
        assert!(EnvCredentials::configured(&half));
        assert_eq!(
            EnvCredentials::load(&half).unwrap_err().kind(),
            ErrorKind::Configuration
        );
        assert!(!EnvCredentials::configured(&Vars::default()));
    }
}
