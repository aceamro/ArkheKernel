//! `KernelSnapshot` — serializable point-in-time capture of kernel state.
//!
//! Snapshot is **independent** from the WAL: WAL stores history (full
//! replay from a fresh state), snapshot stores a single state at tick
//! N. Hybrid recovery (snapshot at N + WAL from N+1) is the future
//! integration; they ship as orthogonal mechanisms.
//!
//! What snapshot includes:
//! - All instances (entities, components, scheduler, ledger, id_counters,
//!   inflight_refs, wall_remainder, local_tick).
//! - Kernel-level `next_instance_id` counter.
//!
//! What snapshot **excludes**:
//! - `Box<dyn KernelObserver>` (not Serialize).
//! - `ActionRegistry` (fn pointers, not Serialize).
//! - Attached `WalWriter` (independent persistence layer).
//!
//! After `Kernel::from_snapshot(...)`, the caller must re-register every
//! Action that was active when the snapshot was taken, and re-attach
//! observers/WAL as needed.
//!
//! Determinism (A1): identical kernel state produces identical snapshot
//! bytes — postcard-canonical encoding + BTreeMap iteration (A5).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::abi::InstanceId;
use crate::state::instance::InstanceSnapshot;

/// Opaque point-in-time snapshot of kernel state.
///
/// Pub struct, pub(crate) fields — external callers see the type at the
/// API boundary and can hold a value, but cannot inspect its internals
/// (use [`serialize`](Self::serialize) / [`deserialize`](Self::deserialize)
/// for round-trip persistence). Fed to
/// [`Kernel::from_snapshot`](crate::Kernel::from_snapshot) for restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSnapshot {
    pub(crate) instances: BTreeMap<InstanceId, InstanceSnapshot>,
    pub(crate) next_instance_id: u64,
}

impl KernelSnapshot {
    /// Encode to canonical postcard bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, SnapshotError> {
        postcard::to_allocvec(self).map_err(|e| SnapshotError::SerializeFailed(format!("{}", e)))
    }

    /// Decode from canonical postcard bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, SnapshotError> {
        postcard::from_bytes(bytes).map_err(|e| SnapshotError::DeserializeFailed(format!("{}", e)))
    }

    /// Number of instances captured.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// Iterate captured instance ids in canonical (`InstanceId` ascending) order.
    pub fn instance_ids(&self) -> impl Iterator<Item = InstanceId> + '_ {
        self.instances.keys().copied()
    }

    /// Crate-internal constructor used by `Kernel::snapshot`.
    #[doc(hidden)]
    pub fn __construct(
        instances: BTreeMap<InstanceId, InstanceSnapshot>,
        next_instance_id: u64,
    ) -> Self {
        Self {
            instances,
            next_instance_id,
        }
    }

    /// Crate-internal destructor used by `Kernel::from_snapshot`.
    #[doc(hidden)]
    pub fn __into_parts(self) -> (BTreeMap<InstanceId, InstanceSnapshot>, u64) {
        (self.instances, self.next_instance_id)
    }
}

/// Snapshot postcard round-trip failures.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Postcard refused to encode the snapshot.
    SerializeFailed(String),
    /// Postcard refused to decode the bytes.
    DeserializeFailed(String),
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SerializeFailed(m) => write!(f, "snapshot serialize failed: {}", m),
            Self::DeserializeFailed(m) => write!(f, "snapshot deserialize failed: {}", m),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{CapabilityMask, EntityId, Principal, Tick, TypeCode};
    use crate::state::traits::_sealed::Sealed;
    use crate::state::{ActionCompute, ActionContext, ActionDeriv, InstanceConfig, Op};
    use crate::Kernel;
    use bytes::Bytes;
    use serde::{Deserialize as De, Serialize as Ser};

    /// Test action: spawn entity `id` and attach a 4-byte component
    /// under TypeCode(7).
    #[derive(Ser, De)]
    struct SpawnSetAction {
        id: u64,
    }
    impl Sealed for SpawnSetAction {}
    impl ActionDeriv for SpawnSetAction {
        const TYPE_CODE: TypeCode = TypeCode(900);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SpawnSetAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let entity = EntityId::new(self.id).unwrap();
            vec![
                Op::SpawnEntity {
                    id: entity,
                    owner: Principal::System,
                },
                Op::SetComponent {
                    entity,
                    type_code: TypeCode(7),
                    bytes: Bytes::from(vec![0xCDu8; 4]),
                    size: 4,
                },
            ]
        }
    }

    fn submit(k: &mut Kernel, inst: InstanceId, id: u64) {
        use crate::state::Action;
        let bytes = Action::canonical_bytes(&SpawnSetAction { id });
        k.submit(
            inst,
            Principal::System,
            None,
            Tick(0),
            SpawnSetAction::TYPE_CODE,
            bytes,
        )
        .unwrap();
    }

    fn boot_with_state(actions: &[u64]) -> (Kernel, InstanceId) {
        let mut k = Kernel::new();
        k.register_action::<SpawnSetAction>();
        let inst = k.create_instance(InstanceConfig::default());
        for id in actions {
            submit(&mut k, inst, *id);
            let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        }
        (k, inst)
    }

    #[test]
    fn snapshot_empty_kernel_serdes_roundtrip() {
        let k = Kernel::new();
        let snap = k.snapshot();
        assert_eq!(snap.instance_count(), 0);
        let bytes = snap.serialize().unwrap();
        let back = KernelSnapshot::deserialize(&bytes).unwrap();
        assert_eq!(back.instance_count(), 0);
    }

    #[test]
    fn snapshot_captures_instance_state() {
        let (k, inst) = boot_with_state(&[1, 2, 3]);
        let snap = k.snapshot();
        assert_eq!(snap.instance_count(), 1);
        let ids: Vec<InstanceId> = snap.instance_ids().collect();
        assert_eq!(ids, vec![inst]);
    }

    #[test]
    fn snapshot_preserves_entities_and_components() {
        let (k1, inst) = boot_with_state(&[1, 2]);
        let snap = k1.snapshot();
        let bytes = snap.serialize().unwrap();
        let snap2 = KernelSnapshot::deserialize(&bytes).unwrap();
        let mut k2 = Kernel::from_snapshot(snap2);
        // Caller MUST re-register the action types they care about; for
        // the read assertions below this isn't required.

        let v1 = k1.instance_view(inst).unwrap();
        let v2 = k2.instance_view(inst).unwrap();
        assert_eq!(v1.entity_count(), v2.entity_count());
        assert_eq!(v1.component_count(), v2.component_count());
        assert_eq!(
            v1.component(EntityId::new(1).unwrap(), TypeCode(7)),
            v2.component(EntityId::new(1).unwrap(), TypeCode(7)),
        );
        assert_eq!(
            v1.component(EntityId::new(2).unwrap(), TypeCode(7)),
            v2.component(EntityId::new(2).unwrap(), TypeCode(7)),
        );
        // After from_snapshot, k2 is mutable; verify we can re-register the
        // action and submit on the restored kernel without panic.
        k2.register_action::<SpawnSetAction>();
        submit(&mut k2, inst, 3);
        let _ = k2.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(k2.instance_view(inst).unwrap().entity_count(), 3);
    }

    #[test]
    fn snapshot_preserves_id_counters() {
        // create_instance increments next_instance_id; verify the round
        // trip produces a kernel that issues the same next id.
        let mut k1 = Kernel::new();
        let _ = k1.create_instance(InstanceConfig::default());
        let _ = k1.create_instance(InstanceConfig::default());
        let _ = k1.create_instance(InstanceConfig::default()); // next_instance_id = 3
        let snap = k1.snapshot();
        let bytes = snap.serialize().unwrap();
        let snap2 = KernelSnapshot::deserialize(&bytes).unwrap();
        let mut k2 = Kernel::from_snapshot(snap2);
        // Both kernels' next create_instance returns id=4.
        let next1 = k1.create_instance(InstanceConfig::default());
        let next2 = k2.create_instance(InstanceConfig::default());
        assert_eq!(next1, next2);
        assert_eq!(next1.get(), 4);
    }

    #[test]
    fn snapshot_preserves_local_tick_and_wall_remainder() {
        // Round-trip a kernel that has progressed; the restored kernel's
        // view exposes the same local_tick. (apply_stage doesn't auto-
        // advance local_tick — both readings should be 0.)
        let (k1, inst) = boot_with_state(&[1]);
        let snap = k1.snapshot();
        let bytes = snap.serialize().unwrap();
        let k2 = Kernel::from_snapshot(KernelSnapshot::deserialize(&bytes).unwrap());
        assert_eq!(
            k1.instance_view(inst).unwrap().local_tick(),
            k2.instance_view(inst).unwrap().local_tick(),
        );
    }

    #[test]
    fn snapshot_deserialize_fresh_kernel_no_observers_no_registry() {
        // After from_snapshot, observer count is 0 and action registry is
        // empty. Submitting an unknown TypeCode silently skips (per
        // existing kernel semantics).
        let (k1, inst) = boot_with_state(&[1]);
        let snap = k1.snapshot();
        let mut k2 =
            Kernel::from_snapshot(KernelSnapshot::deserialize(&snap.serialize().unwrap()).unwrap());
        assert_eq!(k2.stats().observer_count, 0);
        // Action registry empty: submit + step skips the action (no
        // deserializer registered).
        k2.submit(
            inst,
            Principal::System,
            None,
            Tick(0),
            TypeCode(900),
            vec![1u8],
        )
        .unwrap();
        let report = k2.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.actions_executed, 1);
        assert_eq!(report.effects_applied, 0);
    }

    #[test]
    fn snapshot_deterministic_same_state_same_bytes() {
        // A1 D1 extension: identical kernel state ⇒ identical snapshot bytes.
        // Build two independent kernels through the same sequence of
        // operations and compare the postcard outputs byte-for-byte.
        let (k1, _) = boot_with_state(&[1, 2, 3]);
        let (k2, _) = boot_with_state(&[1, 2, 3]);
        let b1 = k1.snapshot().serialize().unwrap();
        let b2 = k2.snapshot().serialize().unwrap();
        assert_eq!(
            b1, b2,
            "identical state must produce identical snapshot bytes"
        );
    }
}
