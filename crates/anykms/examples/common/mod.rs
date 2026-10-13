// Shared by the examples: a Registry with the local backend, plus (with the `transit` feature)
// Vault/OpenBao when VAULT_ADDR/BAO_ADDR is set. Keys come from env URIs (e.g.
// ANYKMS_KEK_URI=hashivault:///transit/keys/app-kek) or default to in-memory local keys.

use anykms::local::{LocalKeyset, LocalProvider};
use anykms::{KeyUri, Registry};

#[allow(dead_code)] // not every example uses it
pub fn registry() -> anykms::Result<Registry> {
    Ok(registry_with_keyset()?.0)
}

/// The registry plus the in-memory keyset behind its `local://default/...` keys, for examples
/// that perform admin operations (such as rotation) on local keys.
#[allow(dead_code)] // not every example needs the keyset
pub fn registry_with_keyset() -> anykms::Result<(Registry, LocalKeyset)> {
    let ks = LocalKeyset::builder()
        .aead("kek")
        .ecdsa_p256("release")
        .hmac("tokens")
        .build();
    let registry = server_providers()?
        .provider(LocalProvider::new(ks.clone()).allow_ephemeral_local_keys())
        // Every handle retries transient failures, with one budget.
        .layer(anykms::retry_layer())
        .build()?;
    Ok((registry, ks))
}

/// Vault or OpenBao from the environment (`VAULT_ADDR`, `BAO_ADDR`, ...). Without the `transit`
/// feature this registers nothing.
fn server_providers() -> anykms::Result<anykms::DefaultProviders> {
    #[cfg(not(feature = "transit"))]
    if ["VAULT_ADDR", "BAO_ADDR"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
    {
        eprintln!("note: VAULT_ADDR/BAO_ADDR ignored; rebuild with `--features transit` to use it");
    }
    anykms::with_default_providers()
}

pub fn uri(var: &str, default: &str) -> anykms::Result<KeyUri> {
    std::env::var(var)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
}
