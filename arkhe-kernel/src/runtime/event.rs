//! `KernelEvent` and supporting enums.
//!
//! `#[non_exhaustive]` everywhere: external matchers cannot wildcard-match,
//! so adding a variant is not breaking for external consumers. The
//! `clippy::wildcard_enum_match_arm = deny` lint enforces this within
//! the crate as well.

use bitflags::bitflags;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, InstanceId, RouteId, Tick, TypeCode};
use crate::state::ScheduledActionId;

/// Top-level kernel-emitted event. Routed through observer filters and
/// recorded in WAL (chunks 3b/c+).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KernelEvent {
    /// An action completed dispatch successfully.
    ActionExecuted {
        /// Instance where the action ran.
        instance: InstanceId,
        /// Type code of the executed action.
        action_type: TypeCode,
        /// Tick at which `step()` processed the action.
        at: Tick,
    },
    /// Action `compute()` failed (panic or error). `reason` is opaque bytes.
    ActionFailed {
        /// Instance where the action was attempted.
        instance: InstanceId,
        /// Type code of the failing action.
        action_type: TypeCode,
        /// Opaque failure reason — kernel does not interpret.
        reason: Bytes,
    },
    /// Effect application failed during dispatcher.
    EffectFailed {
        /// Instance where the effect was being applied.
        instance: InstanceId,
        /// Opaque failure reason (e.g. `b"budget_exceeded"` from
        /// memory-budget enforcement).
        reason: Bytes,
    },
    /// Observer panicked during `on_event`. Bounded payload —
    /// `observer_index` only, no panic message (covert channel closed).
    ObserverPanic {
        /// Index of the panicking observer in the registry.
        observer_index: u16,
    },
    /// First-panic eviction (A22).
    ObserverEvicted {
        /// Index of the evicted observer.
        observer_index: u16,
        /// Sequence number of the event that triggered the panic.
        panic_at_seq: u64,
        /// Panic count before eviction (always `1` under the
        /// first-panic policy).
        panic_count_before_eviction: u32,
    },
    /// Cross-instance signal dropped (reserved variant for the
    /// `SendSignal` rate-limit (deferred); constructible today for tests).
    SignalDropped {
        /// Target instance the signal was destined for.
        target: InstanceId,
        /// Route discriminant.
        route: RouteId,
        /// Why the kernel dropped the signal.
        reason: SignalDropReason,
    },
    /// Module force-unloaded via `force_unload` cap path.
    ModuleForceUnloaded {
        /// Route id whose `inflight_refs` were drained.
        route_id: RouteId,
        /// Sum of live refs that were dropped across instances.
        live_refs_at_unload: u32,
    },
    /// Action deferred to the next tick (reserved variant).
    ActionDeferredToNextTick {
        /// Id of the deferred scheduled action.
        action_id: ScheduledActionId,
        /// Why the action was deferred.
        reason: DeferReason,
    },
    /// `BestEffort` durability barrier flushed pending observer events.
    ObserversFlushed {
        /// Caller-supplied barrier ticket.
        barrier_ticket: u64,
        /// Number of events drained at this barrier.
        event_count: u32,
    },
    /// Domain `Op::EmitEvent` produced an event payload.
    DomainEventEmitted {
        /// Instance that emitted the event.
        instance: InstanceId,
        /// Optional originating entity.
        actor: Option<EntityId>,
        /// Event type discriminant.
        event_type_code: TypeCode,
        /// Canonical bytes of the event payload.
        bytes: Bytes,
    },
}

/// Why a `SendSignal` op was dropped before delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignalDropReason {
    /// Target instance's IPC queue was full.
    QueueFull,
    /// Target instance does not exist (or has been despawned).
    TargetNotFound,
    /// Sender cancelled the signal before delivery.
    Cancelled,
}

/// Why a scheduled action was deferred to the next tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeferReason {
    /// Per-step scheduler dispatch budget was reached.
    SchedulerBusy,
    /// Per-instance resource budget would be exceeded by running this
    /// action now.
    BudgetExceeded,
}

/// Stable observer registration handle returned by `Kernel::register_observer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObserverHandle(
    /// Monotonic registry index assigned at registration.
    pub u16,
);

bitflags! {
    /// Event-class filter for observer registration. One bit per
    /// `KernelEvent` variant; an observer registered with a mask only
    /// receives events whose variant bit is set. `EventMask::ALL`
    /// (the `Default`) matches every variant — backward-compatible with
    /// the unfiltered `Kernel::register_observer` path.
    ///
    /// Bit assignments are part of the public surface; new variants
    /// must take the next free bit (no repurposing).
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, serde::Serialize, serde::Deserialize)]
    pub struct EventMask: u32 {
        /// Match [`KernelEvent::ActionExecuted`].
        const ACTION_EXECUTED       = 1 << 0;
        /// Match [`KernelEvent::ActionFailed`].
        const ACTION_FAILED         = 1 << 1;
        /// Match [`KernelEvent::EffectFailed`].
        const EFFECT_FAILED         = 1 << 2;
        /// Match [`KernelEvent::ObserverPanic`].
        const OBSERVER_PANIC        = 1 << 3;
        /// Match [`KernelEvent::ObserverEvicted`].
        const OBSERVER_EVICTED      = 1 << 4;
        /// Match [`KernelEvent::SignalDropped`].
        const SIGNAL_DROPPED        = 1 << 5;
        /// Match [`KernelEvent::ModuleForceUnloaded`].
        const MODULE_FORCE_UNLOADED = 1 << 6;
        /// Match [`KernelEvent::ActionDeferredToNextTick`].
        const ACTION_DEFERRED       = 1 << 7;
        /// Match [`KernelEvent::ObserversFlushed`].
        const OBSERVERS_FLUSHED     = 1 << 8;
        /// Match [`KernelEvent::DomainEventEmitted`].
        const DOMAIN_EVENT_EMITTED  = 1 << 9;
        /// Match every variant — equivalent to `Default`.
        const ALL                   = 0x3FF;
    }
}

impl Default for EventMask {
    fn default() -> Self {
        Self::ALL
    }
}

impl EventMask {
    /// Whether this mask wants to be notified of `event`.
    pub(crate) fn matches(&self, event: &KernelEvent) -> bool {
        match event {
            KernelEvent::ActionExecuted { .. } => self.contains(Self::ACTION_EXECUTED),
            KernelEvent::ActionFailed { .. } => self.contains(Self::ACTION_FAILED),
            KernelEvent::EffectFailed { .. } => self.contains(Self::EFFECT_FAILED),
            KernelEvent::ObserverPanic { .. } => self.contains(Self::OBSERVER_PANIC),
            KernelEvent::ObserverEvicted { .. } => self.contains(Self::OBSERVER_EVICTED),
            KernelEvent::SignalDropped { .. } => self.contains(Self::SIGNAL_DROPPED),
            KernelEvent::ModuleForceUnloaded { .. } => self.contains(Self::MODULE_FORCE_UNLOADED),
            KernelEvent::ActionDeferredToNextTick { .. } => self.contains(Self::ACTION_DEFERRED),
            KernelEvent::ObserversFlushed { .. } => self.contains(Self::OBSERVERS_FLUSHED),
            KernelEvent::DomainEventEmitted { .. } => self.contains(Self::DOMAIN_EVENT_EMITTED),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_event_all_variants_constructible() {
        let inst = InstanceId::new(1).unwrap();
        let route = RouteId(1);
        let _ = KernelEvent::ActionExecuted {
            instance: inst,
            action_type: TypeCode(1),
            at: Tick(0),
        };
        let _ = KernelEvent::ActionFailed {
            instance: inst,
            action_type: TypeCode(1),
            reason: Bytes::from_static(b"r"),
        };
        let _ = KernelEvent::EffectFailed {
            instance: inst,
            reason: Bytes::new(),
        };
        let _ = KernelEvent::ObserverPanic { observer_index: 0 };
        let _ = KernelEvent::ObserverEvicted {
            observer_index: 0,
            panic_at_seq: 1,
            panic_count_before_eviction: 1,
        };
        let _ = KernelEvent::SignalDropped {
            target: inst,
            route,
            reason: SignalDropReason::QueueFull,
        };
        let _ = KernelEvent::ModuleForceUnloaded {
            route_id: route,
            live_refs_at_unload: 0,
        };
        let _ = KernelEvent::ActionDeferredToNextTick {
            action_id: ScheduledActionId::new(1).unwrap(),
            reason: DeferReason::SchedulerBusy,
        };
        let _ = KernelEvent::ObserversFlushed {
            barrier_ticket: 0,
            event_count: 0,
        };
    }

    #[test]
    fn signal_drop_reason_copy_eq() {
        let r1 = SignalDropReason::QueueFull;
        let r2 = r1;
        assert_eq!(r1, r2);
        assert_ne!(r1, SignalDropReason::TargetNotFound);
    }

    #[test]
    fn defer_reason_copy_distinct() {
        let r1 = DeferReason::SchedulerBusy;
        let r2 = DeferReason::BudgetExceeded;
        assert_ne!(r1, r2);
    }

    #[test]
    fn observer_handle_total_order() {
        let h1 = ObserverHandle(1);
        let h2 = ObserverHandle(2);
        assert!(h1 < h2);
        assert_eq!(h1, ObserverHandle(1));
    }
}
