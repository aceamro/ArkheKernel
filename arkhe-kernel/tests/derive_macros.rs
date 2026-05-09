//! Integration tests for `#[derive(ArkheComponent)]` and
//! `#[derive(ArkheEvent)]`. Lives outside `src/` to exercise the macros
//! through the same `::arkhe_kernel::...` paths an external
//! domain crate would use.
//!
//! `ArkheAction` is already exercised via the `examples/dice` integration
//! example, so this file focuses on the two new derives.
//!
//! Byte-identity witnesses (`component_canonical_bytes_pinned`,
//! `event_canonical_bytes_pinned`) ASSUME postcard wire format stability
//! via semver discipline; postcard major bump = explicit spec drift
//! correction trigger (Layer A item 3 `silent_ast_risk` direct closure).

use arkhe_kernel::abi::TypeCode;
use arkhe_kernel::state::{Component, DeserializeError, Event};
use arkhe_kernel::{ArkheComponent, ArkheEvent};

use serde::{Deserialize, Serialize};

// Compile-time `Sealed` bound witness for derived types. If the macro
// stops emitting the `_sealed::Sealed` impl, this const block fails
// typeck. Zero runtime cost, zero baseline drift (no `#[test]`).
const _: fn() = || {
    fn assert_sealed<T: ::arkhe_kernel::state::traits::_sealed::Sealed>() {}
    assert_sealed::<CounterComponent>();
    assert_sealed::<PostCreatedEvent>();
};

// ---- Component ----

#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 5001, schema_version = 1)]
struct CounterComponent {
    value: u64,
    label: String,
}

#[test]
fn component_derive_emits_consts() {
    assert_eq!(CounterComponent::TYPE_CODE, TypeCode(5001));
    assert_eq!(CounterComponent::SCHEMA_VERSION, 1);
}

#[test]
fn component_canonical_roundtrip() {
    let c = CounterComponent {
        value: 42,
        label: "hits".into(),
    };
    let bytes = c.canonical_bytes();
    let back = CounterComponent::from_bytes(1, &bytes).expect("roundtrip");
    assert_eq!(back.value, 42);
    assert_eq!(back.label, "hits");
    assert!(c.approx_size() > 0);
}

#[test]
fn component_schema_version_mismatch_errors() {
    let c = CounterComponent {
        value: 1,
        label: "x".into(),
    };
    let bytes = c.canonical_bytes();
    let res = CounterComponent::from_bytes(99, &bytes);
    assert!(matches!(
        res,
        Err(DeserializeError::SchemaVersionMismatch {
            expected: 1,
            got: 99
        })
    ));
}

// `schema_version` defaults to 1 when omitted from `#[arkhe(...)]`.
#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 5002)]
struct DefaultedComponent {
    flag: bool,
}

#[test]
fn component_schema_version_defaults_to_one() {
    assert_eq!(DefaultedComponent::TYPE_CODE, TypeCode(5002));
    assert_eq!(DefaultedComponent::SCHEMA_VERSION, 1);
}

// Byte-identity witness — Layer A item 3 (Principal+KernelEvent+
// StepStage derives) `silent_ast_risk` ("canonical bytes mutation =
// potential A1 bit-identical replay violation") direct closure. Pins the
// exact postcard wire bytes for a Component fixture; a postcard
// re-encoding shift (silent AST mutation, varint behaviour change, field
// reorder) breaks this assertion before it can propagate into a chain
// hash divergence (E14 ⇒ A1, A14 canonical encoding). Dual-witness:
// byte-identity (rewrite catch) + parse-back (silent edit catch).
#[test]
fn component_canonical_bytes_pinned() {
    let c = CounterComponent {
        value: 42,
        label: "hits".into(),
    };
    let bytes = c.canonical_bytes();
    // postcard varint(42) = 0x2A, varint(len=4) = 0x04, "hits" UTF-8 bytes.
    let expected: &[u8] = &[0x2A, 0x04, b'h', b'i', b't', b's'];
    assert_eq!(bytes.as_slice(), expected);
    // Round-trip parse-back through the kernel-side wrapper.
    let parsed = CounterComponent::from_bytes(1, &bytes).expect("roundtrip");
    assert_eq!(parsed.value, 42);
    assert_eq!(parsed.label, "hits");
}

// ---- Event ----

#[derive(Debug, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 8001, schema_version = 1)]
struct PostCreatedEvent {
    author_id: u64,
    body: String,
}

#[test]
fn event_derive_emits_consts() {
    assert_eq!(PostCreatedEvent::TYPE_CODE, TypeCode(8001));
    assert_eq!(PostCreatedEvent::SCHEMA_VERSION, 1);
}

#[test]
fn event_canonical_roundtrip() {
    let e = PostCreatedEvent {
        author_id: 7,
        body: "first post".into(),
    };
    let bytes = e.canonical_bytes();
    let back = PostCreatedEvent::from_bytes(1, &bytes).expect("roundtrip");
    assert_eq!(back.author_id, 7);
    assert_eq!(back.body, "first post");
}

#[test]
fn event_schema_version_mismatch_errors() {
    let e = PostCreatedEvent {
        author_id: 1,
        body: "x".into(),
    };
    let bytes = e.canonical_bytes();
    let res = PostCreatedEvent::from_bytes(7, &bytes);
    assert!(matches!(
        res,
        Err(DeserializeError::SchemaVersionMismatch {
            expected: 1,
            got: 7
        })
    ));
}

#[test]
fn event_debug_supertrait_holds() {
    // The Event trait carries Debug as a supertrait; the macro doesn't
    // emit Debug for the user, but the user's #[derive(Debug)] above is
    // what satisfies it. This test just confirms the bound is reachable.
    fn requires_event_debug<E: Event + std::fmt::Debug>(_: &E) {}
    let e = PostCreatedEvent {
        author_id: 0,
        body: String::new(),
    };
    requires_event_debug(&e);
}

// Byte-identity witness — sibling of `component_canonical_bytes_pinned`
// for the Event derive surface. Same threat model: postcard canonical
// encoding mutation upstream of WalRecord embedding (Event
// canonical_bytes feed into chain hash via action_bytes). Dual-witness
// shape: byte-identity + parse-back.
#[test]
fn event_canonical_bytes_pinned() {
    let e = PostCreatedEvent {
        author_id: 7,
        body: "first post".into(),
    };
    let bytes = e.canonical_bytes();
    // postcard varint(7) = 0x07, varint(len=10) = 0x0A, "first post" UTF-8.
    let expected: &[u8] = &[
        0x07, 0x0A, b'f', b'i', b'r', b's', b't', b' ', b'p', b'o', b's', b't',
    ];
    assert_eq!(bytes.as_slice(), expected);
    // Round-trip parse-back through the kernel-side wrapper.
    let parsed = PostCreatedEvent::from_bytes(1, &bytes).expect("roundtrip");
    assert_eq!(parsed.author_id, 7);
    assert_eq!(parsed.body, "first post");
}
