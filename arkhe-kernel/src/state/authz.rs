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

/// Resolve the effective capabilities an action runs under, from the
/// instance's configured `default_caps`, the action's `principal`, and the
/// `ceiling` it inherited (an external submission's granted caps, or a
/// scheduling parent's effective caps). Authority is the *intersection* of
/// config and ceiling on every authenticated path (min-of-bounds, like the
/// A10 quota reduction): `Principal::System` is bounded by `default_caps &
/// ceiling` exactly as `External` is — it is NOT an unconditional bypass and
/// NOT exempt from the ceiling. System is privileged only insofar as
/// `default_caps` grants AND the ceiling permits, so a submission or a
/// scheduled child of ANY principal can never exceed either bound and
/// privilege only narrows across a schedule (a scheduled child's ceiling is
/// the parent's effective caps, captured at schedule time, so a later-raised
/// operator session ceiling cannot re-widen the child — no time-shift
/// escalation). `Unauthenticated` is always empty.
pub(crate) fn effective_caps(
    default_caps: CapabilityMask,
    principal: &Principal,
    ceiling: CapabilityMask,
) -> CapabilityMask {
    match principal {
        Principal::System | Principal::External(_) => default_caps & ceiling,
        Principal::Unauthenticated => CapabilityMask::empty(),
    }
}

/// Authorize an unverified Effect against the already-resolved
/// `effective_caps` (see [`effective_caps`]) for its (instance, principal,
/// ceiling) — intersected by the caller with any operator session ceiling.
///
/// Policy (per-entity ownership refinement deferred):
/// - `Principal::Unauthenticated`   — denied (no read/write paths yet).
/// - `Principal::System` / `External(_)` — gated identically by
///   `effective_caps`: the `SYSTEM` bit grants all Ops, otherwise per-Op
///   cap match (`match_op_cap`). System holds authority only when the
///   instance's `default_caps` grant it — there is no blanket bypass.
pub(crate) fn authorize<'i>(
    caps: CapabilityMask,
    effect: Effect<'i, Unverified>,
) -> Result<Effect<'i, Authorized>, DenyReason> {
    match &effect.principal {
        Principal::Unauthenticated => return Err(DenyReason::CapabilityDenied),
        Principal::System | Principal::External(_) => {
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
        // Basic state mutations: open to External in v0.14.
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
    fn system_principal_gated_by_effective_caps_not_blanket_bypass() {
        // System is NOT an unconditional bypass: under empty effective caps a
        // SYSTEM-gated op (schedule/signal) is denied; under SYSTEM caps all
        // ops pass. (Basic state ops remain open to any non-empty principal.)
        for op in [schedule_op(), signal_op()] {
            let denied = authorize(CapabilityMask::empty(), Effect::new(inst(), Principal::System, op));
            assert_eq!(
                denied.unwrap_err(),
                DenyReason::CapabilityDenied,
                "System with empty caps must NOT pass a SYSTEM-gated op"
            );
        }
        for op in [spawn_op(), schedule_op(), signal_op()] {
            let ok = authorize(CapabilityMask::SYSTEM, Effect::new(inst(), Principal::System, op));
            assert!(ok.is_ok(), "System with SYSTEM caps passes every op");
        }
    }

    #[test]
    fn effective_caps_intersects_config_and_ceiling_for_authenticated_principals() {
        // Effective caps = default_caps ∩ ceiling (min-of-bounds) for BOTH
        // System and External — System is not exempt from the ceiling.
        let full = CapabilityMask::all();
        let none = CapabilityMask::empty();
        let ext = Principal::External(ExternalId(7));
        let sys = Principal::System;
        assert_eq!(effective_caps(full, &ext, none), none, "ceiling caps to none");
        assert_eq!(effective_caps(none, &ext, full), none, "config caps to none");
        assert_eq!(effective_caps(full, &ext, full), full);
        // System obeys the ceiling exactly like External (monotone narrowing).
        assert_eq!(
            effective_caps(full, &sys, none),
            none,
            "System is bounded by the ceiling — a low ceiling narrows it (no bypass)"
        );
        assert_eq!(effective_caps(none, &sys, full), none, "System bounded by config");
        assert_eq!(effective_caps(full, &sys, full), full);
        // Unauthenticated = empty always.
        assert_eq!(
            effective_caps(full, &Principal::Unauthenticated, full),
            none
        );
    }

    #[test]
    fn scheduled_system_child_cannot_rewiden_past_caps_ceiling() {
        // The core no-time-shift-escalation invariant for System children: a
        // child whose caps_ceiling (= the parent's narrowed effective caps) is
        // a strict subset of default_caps stays bounded by that ceiling even if
        // default_caps (or a later session) would permit more. Pre-fix this
        // returned `default_caps`, silently re-widening the child.
        let full = CapabilityMask::all();
        let parent_effective = CapabilityMask::SYSTEM; // parent ran narrowed
        let child = effective_caps(full, &Principal::System, parent_effective);
        assert_eq!(
            child, parent_effective,
            "System child is locked to the parent's effective caps, never default_caps"
        );
        assert!(
            child.bits() <= parent_effective.bits(),
            "child authority is a subset of the scheduling parent's"
        );
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
