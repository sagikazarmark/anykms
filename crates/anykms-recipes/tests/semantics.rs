//! `CachedVerifier` does not implement `Semantics`: it turns backend verification into local
//! verification, a behavior `KeySemantics` describes, so it must not forward its source's value
//! (the forwarding rule of `anykms_core::Semantics`).

use anykms_core::{PublicKeysKey, Semantics};
use anykms_recipes::CachedVerifier;

/// Compile-time negative trait check (the `static_assertions::assert_not_impl_any!` pattern):
/// `some_item` resolves for every type through the `()` impl; a type that also implements
/// `Semantics` matches the `Implemented` impl too, so the inferred parameter becomes ambiguous
/// and the crate fails to compile.
trait AmbiguousIfSemantics<A> {
    fn some_item() {}
}

impl<T: ?Sized> AmbiguousIfSemantics<()> for T {}

#[allow(dead_code)]
struct Implemented;

impl<T: ?Sized + Semantics> AmbiguousIfSemantics<Implemented> for T {}

/// The realistic source: an opaque handle, which itself implements `Semantics`.
const _: fn() = || {
    let _ = <CachedVerifier<PublicKeysKey> as AmbiguousIfSemantics<_>>::some_item;
};

#[test]
fn the_pattern_detects_an_implementation() {
    // The check above would not compile for `PublicKeysKey`, which implements `Semantics`; this
    // asserts the premise at run time instead.
    fn implements<T: Semantics>() {}
    implements::<PublicKeysKey>();
}
