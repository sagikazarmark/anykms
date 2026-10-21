//! Case registry.

use std::future::Future;
use std::sync::Arc;

use anykms_core::{BoxFuture, MacAlgorithm, SignatureAlgorithm};

use crate::ctx::{CaseResult, Ctx, Path};
use crate::fixture::{Feature, Fixture, TestKeyKind};
use recipes::RewrapVia;

mod aead;
mod capabilities;
mod datakeys;
mod errors;
mod layers;
mod mac;
mod preflight;
mod recipes;
mod sign;
pub(crate) mod util;

pub(crate) type CaseFn<F> = Arc<dyn Fn(Ctx<F>) -> BoxFuture<'static, CaseResult> + Send + Sync>;

pub(crate) struct Case<F> {
    pub(crate) name: String,
    /// Features the case needs: it runs only when every one is supported.
    pub(crate) requires: Vec<Feature>,
    /// Behavior declarations the case reads without being gated on them (e.g.
    /// [`Feature::RewrapWithAad`]): they must be declared, whatever their support.
    pub(crate) consults: Vec<Feature>,
    pub(crate) both_paths: bool,
    pub(crate) run: CaseFn<F>,
}

impl<F> Case<F> {
    /// The paths the case runs on.
    pub(crate) fn paths(&self) -> &'static [Path] {
        if self.both_paths {
            &[Path::Typed, Path::Registry]
        } else {
            &[Path::Typed]
        }
    }

    /// Declares the behavior features the case reads.
    fn consults(mut self, features: &[Feature]) -> Self {
        self.consults.extend_from_slice(features);
        self
    }

    /// Runs the case on the typed path only.
    fn typed_only(mut self) -> Self {
        self.both_paths = false;
        self
    }
}

fn case<F, Fut>(
    name: impl Into<String>,
    requires: &[Feature],
    f: impl Fn(Ctx<F>) -> Fut + Send + Sync + 'static,
) -> Case<F>
where
    F: Fixture,
    Fut: Future<Output = CaseResult> + Send + 'static,
{
    Case {
        name: name.into(),
        requires: requires.to_vec(),
        consults: Vec::new(),
        both_paths: true,
        run: Arc::new(move |c| Box::pin(f(c))),
    }
}

/// Every case, with the features it requires (see the gating table in `docs/cloud/shared.md`
/// §1.2). A case covers one key family; cases that would branch on a feature are split instead,
/// so a case that did not run is never reported as passed.
pub(crate) fn all<F: Fixture>() -> Vec<Case<F>> {
    use Feature::{
        Aead, BackendInfo, DataKeys, Describe, DescribeVersionState, Disable, DisableVersion,
        EmptyMessage, EmptyPlaintext, Extension, KeyWrap, KeyWrapPublicKeys, KeyWrapRewrap, Mac,
        MacInputLimit, MessageInputLimit, MinDecryptionVersion, NativeCiphertext,
        OversizePlaintext, PreflightState, RequestCount, Rewrap, RewrapWithAad, Rotate,
        RotateKeyWrap, RotateMac, RotateSigning, ServerErrorMessages, Signing, Throttle,
        UnauthorizedProvider, UsedPrimary, WrappedDataKeys,
    };
    use TestKeyKind::{Aead as AeadKey, KeyWrap as KeyWrapKey};
    // Cases whose expected error kinds the backend derives from server error messages.
    const MSG: Feature = ServerErrorMessages;
    let p256 = Signing(SignatureAlgorithm::EcdsaP256Sha256);
    let ed25519 = Signing(SignatureAlgorithm::Ed25519);
    let mut v = vec![
        // AEAD
        case("aead::roundtrip", &[Aead], aead::roundtrip::<F>),
        case(
            "aead::roundtrip_empty",
            &[Aead, EmptyPlaintext],
            aead::roundtrip_empty::<F>,
        ),
        case(
            "aead::authentication_failures",
            &[Aead],
            aead::authentication_failures::<F>,
        ),
        case("aead::rotation", &[Aead, Rotate], aead::rotation::<F>),
        case(
            "aead::min_decryption_version",
            &[Aead, Rotate, MinDecryptionVersion, MSG],
            aead::min_decryption_version::<F>,
        ),
        case(
            "aead::disabled_key",
            &[Aead, Disable, Describe, MSG],
            aead::disabled_key::<F>,
        ),
        case(
            "aead::disabled_version",
            &[Aead, Rotate, DisableVersion, MSG],
            aead::disabled_version::<F>,
        )
        .consults(&[Describe]),
        case(
            "aead::disabled_primary_version",
            &[Aead, DisableVersion, MSG],
            aead::disabled_primary_version::<F>,
        )
        .consults(&[Describe]),
        case(
            "aead::oversize_plaintext",
            &[Aead, OversizePlaintext],
            aead::oversize_plaintext::<F>,
        ),
        case(
            "aead::native_ciphertext_without_aad",
            &[Aead, NativeCiphertext],
            aead::native_ciphertext::<F>,
        ),
        case(
            "aead::ciphertext_version",
            &[Aead, Describe],
            aead::ciphertext_version::<F>,
        ),
        case(
            "aead::decrypt_with_info",
            &[Aead],
            aead::decrypt_with_info::<F>,
        )
        .consults(&[UsedPrimary]),
        case(
            "aead::used_primary_after_rotation",
            &[Aead, Rotate, UsedPrimary],
            aead::used_primary_after_rotation::<F>,
        ),
        case(
            "rewrap::to_primary_version",
            &[Aead, Rewrap, Rotate],
            aead::rewrap::<F>,
        ),
        case(
            "rewrap::with_aad",
            &[Aead, Rewrap],
            aead::rewrap_with_aad::<F>,
        )
        .consults(&[RewrapWithAad]),
        case(
            "datakeys::roundtrip",
            &[Aead, DataKeys],
            aead::datakey_roundtrip::<F>,
        ),
        case("datakeys::aad", &[Aead, DataKeys], aead::datakey_aad::<F>),
        case(
            "datakeys::wrapped_only",
            &[Aead, WrappedDataKeys],
            datakeys::wrapped_only::<F>,
        ),
        case(
            "datakeys::wrapped_only_aad",
            &[Aead, WrappedDataKeys],
            datakeys::wrapped_only_aad::<F>,
        ),
        case(
            "datakeys::source::roundtrip",
            &[DataKeys],
            datakeys::source_roundtrip::<F>,
        )
        .consults(&[Aead, Describe]),
        case(
            "datakeys::source::aad",
            &[DataKeys],
            datakeys::source_aad::<F>,
        )
        .consults(&[Aead]),
        case(
            "layers::extension_calls_are_layered",
            &[Aead, Extension],
            layers::extension_calls_are_layered::<F>,
        ),
        // Describe
        case("describe::aead_key", &[Aead, Describe], aead::describe::<F>),
        case(
            "describe::preflight",
            &[Aead, Describe, p256],
            aead::preflight::<F>,
        ),
        case(
            "describe::preflight_disabled",
            &[Disable, Describe, PreflightState],
            preflight::preflight_disabled::<F>,
        ),
        case(
            "describe::preflight_disabled_version",
            &[DisableVersion, Describe, PreflightState],
            preflight::preflight_disabled_version::<F>,
        ),
        case(
            "describe::generic_preflight_disabled_primary",
            &[DisableVersion, Describe, DescribeVersionState],
            preflight::generic_preflight_disabled_primary::<F>,
        ),
        case(
            "keywrap::disabled_key",
            &[KeyWrap, Disable, Describe, PreflightState],
            aead::key_wrap_disabled_key::<F>,
        ),
        case(
            "describe::key_wrap_key",
            &[KeyWrap, Describe],
            aead::describe_key_wrap::<F>,
        ),
        case("describe::hmac_key", &[Mac, Describe], mac::describe::<F>),
        case(
            "keywrap::public_key_wraps",
            &[KeyWrap, KeyWrapPublicKeys],
            capabilities::key_wrap_public_key_wraps::<F>,
        ),
        case(
            "describe::backend_info",
            &[Describe, BackendInfo],
            capabilities::backend_info::<F>,
        ),
        case(
            "describe::version_algorithms::signing",
            &[p256, Describe],
            sign::version_algorithms::<F>,
        ),
        case(
            "describe::version_algorithms::mac",
            &[Mac, Describe],
            mac::version_algorithms::<F>,
        ),
        // Errors and hygiene, per key family.
        case(
            "errors::missing_key::aead",
            &[Aead],
            errors::missing_key_aead::<F>,
        )
        .consults(&[Describe]),
        case(
            "errors::missing_key::key_wrap",
            &[KeyWrap],
            errors::missing_key_key_wrap::<F>,
        )
        .consults(&[Describe]),
        case(
            "errors::missing_key::mac",
            &[Mac],
            errors::missing_key_mac::<F>,
        )
        .consults(&[Describe]),
        case("errors::missing_key::signing", &[p256], |c| {
            errors::missing_key_signing::<F>(c, SignatureAlgorithm::EcdsaP256Sha256)
        })
        .consults(&[Describe]),
        case("errors::missing_key::message_signing", &[ed25519], |c| {
            errors::missing_key_signing::<F>(c, SignatureAlgorithm::Ed25519)
        })
        .consults(&[Describe]),
        case("errors::parse_uri_is_configuration::aead", &[Aead], |c| {
            errors::parse_uri_is_configuration::<F>(c, AeadKey)
        }),
        case(
            "errors::parse_uri_is_configuration::key_wrap",
            &[KeyWrap],
            |c| errors::parse_uri_is_configuration::<F>(c, KeyWrapKey),
        ),
        case(
            "errors::forged_versions_do_not_flush",
            &[p256],
            errors::forged_versions_do_not_flush::<F>,
        )
        .consults(&[RequestCount]),
        case(
            "errors::local_checks_name_the_key::mac",
            &[Mac],
            errors::local_checks_name_the_key_mac::<F>,
        ),
        case(
            "errors::local_checks_name_the_key::signing",
            &[p256],
            errors::local_checks_name_the_key_signing::<F>,
        ),
        // These use their own provider, so running them through the Registry path would not add
        // coverage.
        case(
            "errors::unauthorized::aead",
            &[Aead, UnauthorizedProvider],
            errors::unauthorized_aead::<F>,
        )
        .typed_only(),
        case(
            "errors::unauthorized::key_wrap",
            &[KeyWrap, UnauthorizedProvider],
            errors::unauthorized_key_wrap::<F>,
        )
        .typed_only(),
        case(
            "errors::unauthorized::signing",
            &[p256, UnauthorizedProvider],
            errors::unauthorized_signing::<F>,
        )
        .typed_only(),
        case(
            "errors::throttled",
            &[Aead, Throttle],
            errors::throttled::<F>,
        ),
        case(
            "hygiene::errors_do_not_leak_inputs::aead",
            &[Aead],
            errors::hygiene_aead::<F>,
        ),
        case(
            "hygiene::errors_do_not_leak_inputs::data_keys",
            &[Aead, DataKeys],
            errors::hygiene_data_keys::<F>,
        )
        .consults(&[Mac]),
        case(
            "hygiene::errors_do_not_leak_inputs::key_wrap",
            &[KeyWrap],
            errors::hygiene_key_wrap::<F>,
        ),
        case(
            "hygiene::errors_do_not_leak_inputs::mac",
            &[Mac],
            errors::hygiene_mac::<F>,
        ),
        // Recipes over AEAD keys used as KEKs, and over native key-wrapping keys.
        case("recipes::envelope::roundtrip", &[Aead], |c| {
            recipes::envelope_roundtrip::<F>(c, AeadKey)
        }),
        case("recipes::envelope::format", &[Aead], |c| {
            recipes::envelope_format::<F>(c, AeadKey)
        }),
        case("recipes::envelope::rewrap", &[Aead, Rewrap, Rotate], |c| {
            recipes::envelope_rewrap::<F>(c, AeadKey, RewrapVia::Server, true)
        }),
        case("recipes::envelope::rewrap_local", &[Aead, Rotate], |c| {
            recipes::envelope_rewrap::<F>(c, AeadKey, RewrapVia::Local, true)
        }),
        // Server-side where the KEK can rewrap, otherwise locally: needs no `Rewrap`.
        case("recipes::envelope::rewrap_current", &[Aead, Rotate], |c| {
            recipes::envelope_rewrap::<F>(c, AeadKey, RewrapVia::Current, true)
        }),
        case("recipes::envelope::rewrap_to_and_keyring", &[Aead], |c| {
            recipes::envelope_rewrap_to_and_keyring::<F>(c, AeadKey)
        }),
        case("recipes::envelope_native::roundtrip", &[KeyWrap], |c| {
            recipes::envelope_roundtrip::<F>(c, KeyWrapKey)
        }),
        case("recipes::envelope_native::format", &[KeyWrap], |c| {
            recipes::envelope_format::<F>(c, KeyWrapKey)
        }),
        case(
            "recipes::envelope_native::rewrap",
            &[KeyWrap, KeyWrapRewrap, RotateKeyWrap],
            |c| recipes::envelope_rewrap::<F>(c, KeyWrapKey, RewrapVia::Server, true),
        ),
        // Server-side rewrap where native KEKs never rotate (AWS RSA keys): the data key is
        // rewrapped to the same key.
        case(
            "recipes::envelope_native::rewrap_unrotated",
            &[KeyWrap, KeyWrapRewrap],
            |c| recipes::envelope_rewrap::<F>(c, KeyWrapKey, RewrapVia::Server, false),
        ),
        case(
            "recipes::envelope_native::rewrap_local",
            &[KeyWrap, RotateKeyWrap],
            |c| recipes::envelope_rewrap::<F>(c, KeyWrapKey, RewrapVia::Local, true),
        ),
        case(
            "recipes::envelope_native::rewrap_current",
            &[KeyWrap, RotateKeyWrap],
            |c| recipes::envelope_rewrap::<F>(c, KeyWrapKey, RewrapVia::Current, true),
        ),
        case(
            "recipes::envelope_native::rewrap_to_and_keyring",
            &[KeyWrap],
            |c| recipes::envelope_rewrap_to_and_keyring::<F>(c, KeyWrapKey),
        ),
        case(
            "recipes::emulated_data_keys",
            &[Aead],
            recipes::emulated_data_keys::<F>,
        ),
        case("recipes::keywrap_data_keys::aead", &[Aead], |c| {
            datakeys::keywrap_data_keys::<F>(c, AeadKey)
        })
        .consults(&[RequestCount]),
        case("recipes::keywrap_data_keys::key_wrap", &[KeyWrap], |c| {
            datakeys::keywrap_data_keys::<F>(c, KeyWrapKey)
        })
        .consults(&[RequestCount]),
        case(
            "capabilities::handles_match_declaration",
            &[],
            capabilities::handles_match_declaration::<F>,
        )
        .consults(&[
            Aead,
            Rewrap,
            DataKeys,
            WrappedDataKeys,
            Describe,
            KeyWrap,
            KeyWrapRewrap,
            Mac,
            RequestCount,
        ]),
        case(
            "capabilities::semantics_match_caps",
            &[],
            capabilities::semantics_match_caps::<F>,
        )
        .consults(&[
            Aead,
            KeyWrap,
            Mac,
            UsedPrimary,
            MacInputLimit,
            MessageInputLimit,
        ]),
    ];
    for &alg in SignatureAlgorithm::ALL {
        let a = alg.as_str();
        let req = [Signing(alg)];
        v.push(case(format!("sign::{a}::roundtrip"), &req, move |c| {
            sign::roundtrip::<F>(c, alg)
        }));
        v.push(case(format!("sign::{a}::tampered"), &req, move |c| {
            sign::tampered::<F>(c, alg)
        }));
        v.push(case(format!("sign::{a}::malformed"), &req, move |c| {
            sign::malformed::<F>(c, alg)
        }));
        v.push(case(
            format!("sign::{a}::input_validation"),
            &req,
            move |c| sign::input_validation::<F>(c, alg),
        ));
        v.push(case(
            format!("sign::{a}::rejected_before_io"),
            &[Signing(alg), RequestCount],
            move |c| sign::rejected_before_io::<F>(c, alg),
        ));
        v.push(case(
            format!("sign::{a}::key_type_mismatch"),
            &req,
            move |c| sign::key_type_mismatch::<F>(c, alg),
        ));
        v.push(case(
            format!("sign::{a}::rotation"),
            &[Signing(alg), RotateSigning],
            move |c| sign::rotation::<F>(c, alg),
        ));
        v.push(case(
            format!("sign::{a}::min_decryption_version"),
            &[
                Signing(alg),
                RotateSigning,
                MinDecryptionVersion,
                Describe,
                MSG,
            ],
            move |c| sign::min_decryption_version::<F>(c, alg),
        ));
        v.push(case(
            format!("sign::{a}::disabled_key"),
            &[Signing(alg), Disable, MSG],
            move |c| sign::disabled_key::<F>(c, alg),
        ));
        v.push(
            case(
                format!("sign::{a}::disabled_version"),
                &[Signing(alg), DisableVersion, MSG],
                move |c| sign::disabled_version::<F>(c, alg),
            )
            .consults(&[Describe]),
        );
        v.push(case(
            format!("sign::{a}::public_key_and_describe"),
            &[Signing(alg), Describe],
            move |c| sign::public_key::<F>(c, alg),
        ));
        v.push(case(
            format!("sign::{a}::foreign_versions"),
            &[Signing(alg), Describe],
            move |c| sign::foreign_versions::<F>(c, alg),
        ));
        if alg.is_message_signing() {
            v.push(case(
                format!("sign::{a}::input_limit"),
                &[Signing(alg), MessageInputLimit],
                move |c| sign::input_limit::<F>(c, alg),
            ));
            v.push(case(
                format!("sign::{a}::empty_message"),
                &[Signing(alg), EmptyMessage],
                move |c| sign::empty_message::<F>(c, alg),
            ));
        }
        v.push(case(
            format!("recipes::cached_verifier::{a}"),
            &[Signing(alg), RotateSigning],
            move |c| recipes::cached_verifier::<F>(c, alg),
        ));
        v.push(case(format!("recipes::jws::{a}"), &req, move |c| {
            recipes::jws::<F>(c, alg)
        }));
        v.push(case(
            format!("recipes::algorithm_pinning::{a}"),
            &req,
            move |c| recipes::algorithm_pinning::<F>(c, alg),
        ));
    }
    v.push(case(
        "mac::aead_key_as_mac",
        &[Mac, Aead],
        mac::aead_key_as_mac::<F>,
    ));
    v.push(case(
        "mac::hmac_key_as_aead",
        &[Mac, Aead],
        mac::hmac_key_as_aead::<F>,
    ));
    v.push(case(
        "mac::signing_key_as_mac",
        &[Mac, p256],
        mac::signing_key_as_mac::<F>,
    ));
    v.push(case(
        "mac::empty_input",
        &[Mac, EmptyMessage],
        mac::empty_input::<F>,
    ));
    v.push(
        case(
            "mac::disabled_version",
            &[Mac, DisableVersion, MSG],
            mac::disabled_version::<F>,
        )
        .consults(&[Describe]),
    );
    for &alg in MacAlgorithm::ALL {
        let a = alg.as_str();
        v.push(case(format!("mac::{a}::roundtrip"), &[Mac], move |c| {
            mac::roundtrip::<F>(c, alg)
        }));
        v.push(case(format!("mac::{a}::failures"), &[Mac], move |c| {
            mac::failures::<F>(c, alg)
        }));
        v.push(case(
            format!("mac::{a}::rotation"),
            &[Mac, RotateMac],
            move |c| mac::rotation::<F>(c, alg),
        ));
        v.push(case(
            format!("mac::{a}::input_limit"),
            &[Mac, MacInputLimit],
            move |c| mac::input_limit::<F>(c, alg),
        ));
    }
    v
}
