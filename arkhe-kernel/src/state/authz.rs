//! Authorization phantom-typed Effect (A8 + A19).
//!
//! `Effect<'i, S: AuthState>` carries:
//! - `S` — authorization state at the type level (Unverified or Authorized).
//! - `'i` — invariant-lifetime brand (GhostCell pattern, A19) preventing
//!   cross-instance reuse of authorized effects.
//!
//! `authorize()` is the sole constructor for `Effect<'i, Authorized>` —
//! external code cannot fabricate an `Authorized` value because the
//! struct fields are `pub(crate)` and the path through `authorize()`
//! is the only audited gate.

use crate::abi::{CapabilityMask, InstanceId, Principal};
use core::marker::PhantomData;

use super::op::Op;

/// Invariant lifetime — both contravariant and covariant in `'i`.
/// Standard GhostCell pattern (Yanovski et al., ICFP 2021). Do not change.
pub(crate) type InvariantLifetime<'i> = PhantomData<fn(&'i ()) -> &'i ()>;

mod seal {
    pub trait Sealed {}
}

/// Uninhabited tag — Effect has not been authorized.
#[derive(Debug)]
pub enum Unverified {}

/// Uninhabited tag — Effect has been validated by `authorize()`.
#[derive(Debug)]
pub enum Authorized {}

impl seal::Sealed for Unverified {}
impl seal::Sealed for Authorized {}

/// Sealed marker — only `Unverified` and `Authorized` may implement.
pub trait AuthState: seal::Sealed {}
impl AuthState for Unverified {}
impl AuthState for Authorized {}

/// Phantom-typed Effect — carries `Op` payload + `Principal` origin tag.
///
/// `instance_id` is the runtime witness retained against brand-erasure
/// at WAL boundaries (replay reconstructs a fresh `'j`-branded scope and
/// uses the witness to verify the instance binding survives).
#[derive(Debug)]
pub struct Effect<'i, S: AuthState> {
    pub(crate) instance_id: InstanceId,
    pub(crate) principal: Principal,
    pub(crate) op: Op,
    _state: PhantomData<S>,
    _brand: InvariantLifetime<'i>,
}

impl<'i> Effect<'i, Unverified> {
    /// Construct an unauthorized Effect. `pub(crate)` because external
    /// code submits Effects through `Kernel::submit`.
    pub(crate) fn new(instance_id: InstanceId, principal: Principal, op: Op) -> Self {
        Self {
            instance_id,
            principal,
            op,
            _state: PhantomData,
            _brand: PhantomData,
        }
    }
}

impl<'i, S: AuthState> Effect<'i, S> {
    /// `InstanceId` this effect is bound to. Survives the brand-erasure
    /// boundary at WAL serialize/deserialize.
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }
}

/// Reason an effect was denied during authorization.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// `CapabilityMask` lacks the bit required by the principal/op pair.
    CapabilityDenied,
    /// Effect's branded instance does not match the authorize call site.
    InstanceMismatch,
    /// Op type is restricted under the current policy (reserved for
    /// future per-op deny refinement).
    OperationRestricted,
    /// Authorization path not yet wired for this op variant.
    NotImplemented,
}

impl core::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CapabilityDenied => write!(f, "capability denied"),
            Self::InstanceMismatch => write!(f, "instance mismatch"),
            Self::OperationRestricted => write!(f, "operation restricted"),
            Self::NotImplemented => write!(f, "authorize not implemented"),
        }
    }
}

impl std::error::Error for DenyReason {}

/// Authorize an unverified Effect against a capability mask.
///
/// Policy (per-entity ownership refinement deferred):
/// - `Principal::System`            — all Ops permitted.
/// - `Principal::Unauthenticated`   — denied (no read/write paths yet).
/// - `Principal::External(_)`       — `SYSTEM` cap grants all; otherwise
///   per-Op cap match (`match_op_cap`).
pub(crate) fn authorize<'i>(
    caps: CapabilityMask,
    effect: Effect<'i, Unverified>,
) -> Result<Effect<'i, Authorized>, DenyReason> {
    match &effect.principal {
        Principal::System => { /* pass — kernel-internal origin */ }
        Principal::Unauthenticated => return Err(DenyReason::CapabilityDenied),
        Principal::External(_) => {
            if !caps.contains(CapabilityMask::SYSTEM) && !match_op_cap(&effect.op, caps) {
                return Err(DenyReason::CapabilityDenied);
            }
        }
    }
    Ok(Effect {
        instance_id: effect.instance_id,
        principal: effect.principal,
        op: effect.op,
        _state: PhantomData,
        _brand: PhantomData,
    })
}

/// Per-Op capability matching. Per-entity ownership and finer-grained
/// cap bits are reserved (deferred).
fn match_op_cap(op: &Op, caps: CapabilityMask) -> bool {
    match op {
        // Basic state mutations: open to External in v0.13.
        Op::SpawnEntity { .. }
        | Op::DespawnEntity { .. }
        | Op::SetComponent { .. }
        | Op::RemoveComponent { .. }
        | Op::EmitEvent { .. } => true,
        // Scheduler/IPC require SYSTEM cap.
        Op::ScheduleAction { .. } | Op::SendSignal { .. } => caps.contains(CapabilityMask::SYSTEM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{EntityId, ExternalId, RouteId, Tick, TypeCode};
    use bytes::Bytes;

    fn inst() -> InstanceId {
        InstanceId::new(1).unwrap()
    }
    fn ent() -> EntityId {
        EntityId::new(1).unwrap()
    }

    #[test]
    fn unverified_is_uninhabited() {
        fn _proof(x: Unverified) -> ! {
            match x {}
        }
    }

    #[test]
    fn authorized_is_uninhabited() {
        fn _proof(x: Authorized) -> ! {
            match x {}
        }
    }

    #[test]
    fn effect_carries_instance_id_and_op() {
        let e: Effect<'_, Unverified> = Effect::new(
            inst(),
            Principal::System,
            Op::SpawnEntity {
                id: ent(),
                owner: Principal::System,
            },
        );
        assert_eq!(e.instance_id().get(), 1);
    }

    #[test]
    fn auth_state_seal_blocks_external_impl() {
        fn assert_authstate<T: AuthState>() {}
        assert_authstate::<Unverified>();
        assert_authstate::<Authorized>();
    }

    #[test]
    fn deny_reason_display_and_error() {
        assert_eq!(
            format!("{}", DenyReason::CapabilityDenied),
            "capability denied"
        );
        assert_eq!(
            format!("{}", DenyReason::OperationRestricted),
            "operation restricted"
        );
        fn assert_err<E: std::error::Error>() {}
        assert_err::<DenyReason>();
    }

    // ---- authorize() body tests ----

    fn spawn_op() -> Op {
        Op::SpawnEntity {
            id: ent(),
            owner: Principal::System,
        }
    }
    fn schedule_op() -> Op {
        Op::ScheduleAction {
            at: Tick(0),
            actor: None,
            action_type_code: TypeCode(0),
            action_bytes: Bytes::new(),
            action_principal: Principal::System,
        }
    }
    fn signal_op() -> Op {
        Op::SendSignal {
            target: inst(),
            route: RouteId(1),
            payload: Bytes::new(),
        }
    }

    #[test]
    fn system_principal_authorized_for_all_ops() {
        for op in [spawn_op(), schedule_op(), signal_op()] {
            let e = Effect::new(inst(), Principal::System, op);
            let result = authorize(CapabilityMask::default(), e);
            assert!(result.is_ok(), "System principal must always pass");
        }
    }

    #[test]
    fn unauthenticated_principal_always_denied() {
        let e = Effect::new(inst(), Principal::Unauthenticated, spawn_op());
        let result = authorize(CapabilityMask::SYSTEM, e);
        assert_eq!(result.unwrap_err(), DenyReason::CapabilityDenied);
    }

    #[test]
    fn external_with_system_cap_authorized() {
        let e = Effect::new(inst(), Principal::External(ExternalId(7)), schedule_op());
        let result = authorize(CapabilityMask::SYSTEM, e);
        assert!(result.is_ok());
    }

    #[test]
    fn external_without_cap_denied_for_schedule() {
        let e = Effect::new(inst(), Principal::External(ExternalId(7)), schedule_op());
        let result = authorize(CapabilityMask::default(), e);
        assert_eq!(result.unwrap_err(), DenyReason::CapabilityDenied);
    }

    #[test]
    fn external_without_cap_denied_for_send_signal() {
        let e = Effect::new(inst(), Principal::External(ExternalId(7)), signal_op());
        let result = authorize(CapabilityMask::default(), e);
        assert_eq!(result.unwrap_err(), DenyReason::CapabilityDenied);
    }

    #[test]
    fn external_with_basic_cap_authorized_for_state_op() {
        let e = Effect::new(inst(), Principal::External(ExternalId(7)), spawn_op());
        let result = authorize(CapabilityMask::default(), e);
        assert!(
            result.is_ok(),
            "External with basic state op (no SYSTEM) is allowed in MVP"
        );
    }
}
