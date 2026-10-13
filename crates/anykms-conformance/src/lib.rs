//! The anykms conformance suite.
//!
//! **When to use this crate.** Applications never need it: they depend on the [`anykms`] facade.
//! Depend on `anykms-conformance` as a dev-dependency when you implement a backend, in this
//! repository or in a third-party crate, to run the shared cases against your
//! [`Provider`](anykms_core::Provider) and its key handles. The [`minimal_backend`] example is a
//! complete toy backend, in about 250 lines, that passes the suite; the `Provider` rustdoc lists
//! the error kinds the cases expect.
//!
//! [`anykms`]: https://docs.rs/anykms
//! [`minimal_backend`]: https://github.com/sagikazarmark/anykms/blob/main/crates/anykms-conformance/examples/minimal_backend.rs
//!
//! Every backend crate runs the same cases through a [`Fixture`]. Wire it up as a test target with
//! `harness = false`:
//!
//! ```toml
//! [[test]]
//! name = "conformance"
//! harness = false
//! ```
//!
//! ```ignore
//! // tests/conformance.rs
//! fn main() -> std::process::ExitCode {
//!     anykms_conformance::run(async || MyFixture::new().await)
//! }
//! ```
//!
//! The harness uses one tokio runtime and one fixture per test binary and calls
//! [`Fixture::probe`] once. Each case ends as *passed*, *failed*, *ignored* with kind `n/a` (the
//! backend lacks the feature by design) or *ignored* with kind `skip` (the fixture cannot provide
//! the feature here). Nothing that did not run is reported as passed: when ignored cases are run
//! anyway (`--include-ignored`), they fail with the reason. With `ANYKMS_FAIL_ON_SKIP=1` (CI),
//! `skip` cases are not ignored but fail, so a fixture cannot silently lose coverage.
//!
//! Cases are gated on the [`Feature`]s the fixture declares in [`Fixture::probe`]. A case whose
//! features are all supported runs; one requiring a feature declared not applicable or lacking is
//! ignored; and one requiring a feature the fixture did not declare at all **fails**, as does the
//! `conformance::declarations` trial, which lists every such feature. So a capability added to the
//! suite later is a loud failure for a fixture that has not caught up, not a silent loss of
//! coverage.
//!
//! Where backends legitimately differ (version shape, primary versions, data-key AAD, input
//! limits, ...), cases read the [`KeySemantics`](anykms_core::KeySemantics) of the handle they
//! opened. A handle that declares no `KeySemantics` fails the case. On the typed path, carry the
//! typed handles' semantics through the bridges ([`AeadKeyHandles::with_semantics`],
//! [`DigestKeyHandles::with_semantics`], ...), and the typed handles' own `Preflight` checks
//! where they implement one ([`AeadKeyHandles::with_preflight`],
//! [`DigestKeyHandles::with_preflight`], ...), so the `typed::` preflight cases run the backend's
//! check.
//!
//! Most cases run twice: through the backend's typed handles bridged into the dyn layer
//! (`typed::`, see [`TypedHandles`]) and through a [`Registry`](anykms_core::Registry) holding the
//! fixture's provider (`registry::`).
//!
//! # Stability
//!
//! The fixture API may change in minor releases while backends are added. New [`Feature`]s and
//! new cases land only in a `0.(x+1)` release, never in a patch: an undeclared feature fails the
//! run, so a patch release never adds a feature or case that a passing fixture has not
//! declared or met. Depend on `anykms-conformance` as a dev-dependency with the same `0.x` as the
//! anykms crates the backend uses.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

mod cases;
mod ctx;
mod fixture;
#[cfg(feature = "fixture-helpers")]
mod helpers;

#[cfg(feature = "fixture-helpers")]
pub use helpers::{FreshKeys, KeySpecTable, RunId};

/// Paths for the exported macros; not part of the API.
#[doc(hidden)]
pub mod __private {
    pub use anykms_core;
}

use std::process::ExitCode;
use std::sync::Arc;

use libtest_mimic::{Arguments, Trial};

use cases::Case;
pub use fixture::{
    AeadKeyHandles, Counting, DigestKeyHandles, Feature, Fixture, FixtureCaps, KeyUse,
    KeyWrapKeyHandles, MacKeyHandles, MessageKeyHandles, Support, TestKey, TestKeyKind,
    TypedHandles,
};

/// Builds the fixture, probes it, and runs every case. Returns the process exit code.
pub fn run<F, M>(make: M) -> ExitCode
where
    F: Fixture,
    M: AsyncFnOnce() -> F,
{
    run_or_skip(async || Ok::<F, String>(make().await))
}

/// Like [`run`], but the fixture may be unavailable (e.g. no server running). Then every case is
/// reported as ignored with kind `skip` and the reason, never as passed. Set
/// `ANYKMS_REQUIRE_FIXTURE=1` (as CI does) to make an unavailable fixture a failure instead.
pub fn run_or_skip<F, M>(make: M) -> ExitCode
where
    F: Fixture,
    M: AsyncFnOnce() -> Result<F, String>,
{
    let args = Arguments::from_args();
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );
    let fx = match rt.block_on(make()) {
        Ok(fx) => Arc::new(fx),
        Err(reason) => {
            if std::env::var("ANYKMS_REQUIRE_FIXTURE").is_ok_and(|v| v == "1") {
                eprintln!(
                    "anykms conformance: fixture unavailable and ANYKMS_REQUIRE_FIXTURE=1: {reason}"
                );
                return ExitCode::FAILURE;
            }
            eprintln!("anykms conformance: fixture unavailable, skipping every case: {reason}");
            let skipped = |name: String| {
                let r = reason.clone();
                Trial::test(name, move || Err(format!("not run (skip): {r}").into()))
                    .with_ignored_flag(true)
                    .with_kind("skip")
            };
            let mut trials = vec![skipped(DECLARATIONS.to_owned())];
            for c in cases::all::<F>() {
                for p in c.paths() {
                    trials.push(skipped(format!("{p}::{}", c.name)));
                }
            }
            return libtest_mimic::run(&args, trials).exit_code();
        }
    };
    let caps = Arc::new(rt.block_on(fx.probe()));
    let registry = anykms_core::Registry::builder()
        .provider_arc(fx.provider())
        .build()
        .expect("fixture provider registers");
    let typed = fx.typed();

    let fail_on_skip = std::env::var("ANYKMS_FAIL_ON_SKIP").is_ok_and(|v| v == "1");
    let all = cases::all::<F>();
    let mut trials = vec![declarations_trial(&caps, &all)];
    let mut ignored = Vec::new();
    for case in all {
        let gate = gate(&caps, &case);
        for &path in case.paths() {
            let name = format!("{}::{}", path, case.name);
            let ctx = ctx::Ctx::new(
                fx.clone(),
                caps.clone(),
                registry.clone(),
                typed.clone(),
                path,
            );
            let rt = rt.clone();
            let body = case.run.clone();
            let gate_body = gate.clone();
            let mut trial = Trial::test(name.clone(), move || match &gate_body {
                Gate::Run => rt.block_on(body(ctx)).map_err(Into::into),
                Gate::Ignore(kind, reason) => Err(format!("not run ({kind}): {reason}").into()),
                Gate::Undeclared(features) => Err(undeclared_message(features).into()),
            });
            match &gate {
                Gate::Run | Gate::Undeclared(_) => {}
                Gate::Ignore(kind, _) if *kind == "skip" && fail_on_skip => {
                    // CI: a feature the fixture should provide but did not is a failure, so
                    // coverage cannot silently drop. `n/a` (absent by design) stays ignored.
                    trial = trial.with_kind(*kind);
                }
                Gate::Ignore(kind, reason) => {
                    trial = trial.with_ignored_flag(true).with_kind(*kind);
                    ignored.push(format!("{name} [{kind}]: {reason}"));
                }
            }
            trials.push(trial);
        }
    }

    eprintln!("anykms conformance: fixture {:?}", fx.name());
    let conclusion = libtest_mimic::run(&args, trials);
    if !ignored.is_empty() && !args.list {
        eprintln!("\nignored cases:");
        for i in &ignored {
            eprintln!("  {i}");
        }
    }
    conclusion.exit_code()
}

/// The name of the trial that checks the fixture's declarations.
const DECLARATIONS: &str = "conformance::declarations";

/// Whether a case runs.
#[derive(Clone)]
enum Gate {
    Run,
    /// Ignored with kind `n/a` or `skip` and the reason.
    Ignore(&'static str, String),
    /// Fails: the fixture did not declare these features.
    Undeclared(Vec<Feature>),
}

/// A case is ignored when a feature it requires is not applicable or lacking (the first such
/// feature gives the reason); otherwise it fails when a feature it requires or consults is
/// undeclared, and runs when every feature it requires is supported.
fn gate<F>(caps: &FixtureCaps, case: &Case<F>) -> Gate {
    let mut undeclared = Vec::new();
    for &f in &case.requires {
        match caps.support(f) {
            Support::Yes => {}
            Support::NotApplicable(r) => return Gate::Ignore("n/a", r),
            Support::FixtureLacks(r) => return Gate::Ignore("skip", r),
            _ => undeclared.push(f),
        }
    }
    for &f in &case.consults {
        if caps.support(f) == Support::Undeclared && !undeclared.contains(&f) {
            undeclared.push(f);
        }
    }
    if undeclared.is_empty() {
        Gate::Run
    } else {
        Gate::Undeclared(undeclared)
    }
}

fn undeclared_message(features: &[Feature]) -> String {
    let list: Vec<String> = features.iter().map(|f| format!("Feature::{f:?}")).collect();
    format!(
        "undeclared feature: declare {} in probe() (supports, not_applicable or lacks)",
        list.join(", ")
    )
}

/// The `conformance::declarations` trial: fails listing every feature a case requires or
/// consults that the fixture left undeclared. It checks every case, whatever filter the run uses.
fn declarations_trial<F>(caps: &FixtureCaps, all: &[Case<F>]) -> Trial {
    let mut missing: Vec<Feature> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for case in all {
        if let Gate::Undeclared(fs) = gate(caps, case) {
            names.push(case.name.clone());
            for f in fs {
                if !missing.contains(&f) {
                    missing.push(f);
                }
            }
        }
    }
    Trial::test(DECLARATIONS, move || {
        if missing.is_empty() {
            return Ok(());
        }
        Err(format!(
            "{}; needed by {} case(s): {}",
            undeclared_message(&missing),
            names.len(),
            names.join(", ")
        )
        .into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(requires: &[Feature], consults: &[Feature]) -> Case<()> {
        Case {
            name: "x".to_owned(),
            requires: requires.to_vec(),
            consults: consults.to_vec(),
            both_paths: true,
            run: Arc::new(|_| Box::pin(async { Ok(()) })),
        }
    }

    fn undeclared(g: Gate) -> Vec<Feature> {
        match g {
            Gate::Undeclared(f) => f,
            _ => Vec::new(),
        }
    }

    #[test]
    fn gating() {
        use Feature::*;
        let caps = FixtureCaps::new()
            .supports_all(&[Aead, Mac])
            .not_applicable(Rewrap, "no")
            .lacks(Rotate, "here");
        assert!(matches!(gate(&caps, &case(&[Aead, Mac], &[])), Gate::Run));
        assert!(matches!(
            gate(&caps, &case(&[Aead, Rewrap], &[])),
            Gate::Ignore("n/a", _)
        ));
        assert!(matches!(
            gate(&caps, &case(&[Rotate], &[])),
            Gate::Ignore("skip", _)
        ));
        // Undeclared fails, unless another required feature already ignores the case.
        assert_eq!(
            undeclared(gate(&caps, &case(&[Aead, DataKeys], &[]))),
            [DataKeys]
        );
        assert!(matches!(
            gate(&caps, &case(&[DataKeys, Rewrap], &[])),
            Gate::Ignore("n/a", _)
        ));
        // Consulted features must be declared, but need not be supported.
        assert!(matches!(gate(&caps, &case(&[Aead], &[Rewrap])), Gate::Run));
        assert_eq!(
            undeclared(gate(&caps, &case(&[Aead], &[RewrapWithAad]))),
            [RewrapWithAad]
        );
    }
}
