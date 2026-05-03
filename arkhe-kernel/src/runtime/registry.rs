//! `ActionRegistry` — TypeCode → deserializer fn-pointer table.
//!
//! Each registered Action is reachable through a monomorphic function
//! pointer (discipline: no vtable on the deserialize path; vtable
//! arises only at the single `compute_dyn` call inside the kernel scheduler
//! tick).

use std::collections::BTreeMap;

use crate::abi::TypeCode;
use crate::state::{Action, ActionContext, DeserializeError, Op};

/// Object-safe wrapper exposing the subset of Action methods that Kernel
/// dispatch needs. `impl<T: Action> ActionDyn for T` blanket-applies to
/// every registered type. `canonical_bytes_dyn` is the test/snapshot
/// round-trip surface (production callers ship with the deferred snapshot
/// integration).
pub(crate) trait ActionDyn: 'static {
    #[cfg_attr(not(test), allow(dead_code))]
    fn canonical_bytes_dyn(&self) -> Vec<u8>;
    fn compute_dyn(&self, ctx: &ActionContext) -> Vec<Op>;
}

impl<T: Action> ActionDyn for T {
    fn canonical_bytes_dyn(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
    fn compute_dyn(&self, ctx: &ActionContext) -> Vec<Op> {
        self.compute(ctx)
    }
}

pub(crate) type ActionDeserializer = fn(u32, &[u8]) -> Result<Box<dyn ActionDyn>, DeserializeError>;

#[derive(Clone)]
pub(crate) struct ActionRegistration {
    pub schema_version: u32,
    pub deserializer: ActionDeserializer,
}

#[derive(Default)]
pub(crate) struct ActionRegistry {
    by_type_code: BTreeMap<TypeCode, ActionRegistration>,
}

impl ActionRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register<A: Action>(&mut self) {
        let reg = ActionRegistration {
            schema_version: A::SCHEMA_VERSION,
            deserializer: |version, bytes| {
                A::from_bytes(version, bytes).map(|boxed| boxed as Box<dyn ActionDyn>)
            },
        };
        self.by_type_code.insert(A::TYPE_CODE, reg);
    }

    pub(crate) fn get(&self, tc: TypeCode) -> Option<&ActionRegistration> {
        self.by_type_code.get(&tc)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.by_type_code.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Principal;
    use crate::state::traits::_sealed::Sealed;
    use crate::state::{ActionCompute, ActionDeriv};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct ProbeAction;
    impl Sealed for ProbeAction {}
    impl ActionDeriv for ProbeAction {
        const TYPE_CODE: TypeCode = TypeCode(0xAB_CD);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for ProbeAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            Vec::new()
        }
    }

    #[test]
    fn registry_register_and_lookup() {
        let mut r = ActionRegistry::new();
        assert_eq!(r.len(), 0);
        r.register::<ProbeAction>();
        assert_eq!(r.len(), 1);
        let reg = r.get(TypeCode(0xAB_CD)).expect("registered");
        assert_eq!(reg.schema_version, 1);
    }

    #[test]
    fn registry_deserializer_roundtrip() {
        let mut r = ActionRegistry::new();
        r.register::<ProbeAction>();
        let reg = r.get(TypeCode(0xAB_CD)).unwrap();
        let action = (reg.deserializer)(1, &[]).expect("deserialize");
        let _bytes = action.canonical_bytes_dyn();
        // Smoke: compute returns empty Op vec for probe.
        let inst = crate::state::Instance::new(
            crate::abi::InstanceId::new(1).unwrap(),
            crate::state::InstanceConfig::default(),
        );
        let ctx = ActionContext::new(None, crate::abi::Tick(0), inst.id(), &inst);
        assert!(action.compute_dyn(&ctx).is_empty());
        let _ = Principal::System;
    }

    #[test]
    fn registry_unknown_type_code_returns_none() {
        let r = ActionRegistry::new();
        assert!(r.get(TypeCode(0xDEAD)).is_none());
    }
}
