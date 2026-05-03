//! BTreeMap-based scheduler with immediate-remove cancellation.
//!
//! Three indexed tables maintained in lockstep:
//! - `ready: BTreeMap<SchedKey, ScheduledEntry>` — primary execution queue,
//!   ordered by `(at, seq, id)`.
//! - `by_id: BTreeMap<ScheduledActionId, SchedKey>` — O(log n) cancel lookup.
//! - `by_actor: BTreeMap<EntityId, BTreeSet<ScheduledActionId>>` — O(k log n)
//!   actor-scoped cancel.
//!
//! No tombstones — `cancel` immediately removes from all three tables.
//! Determinism: BTreeMap iteration order is total over `SchedKey`, and
//! `seq` is monotonic per kernel lifetime, so identical schedule sequences
//! produce identical pop_due streams (deterministic).

use core::num::NonZeroU64;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::abi::{EntityId, Principal, Tick, TypeCode};

/// Sentinel-free scheduled-action handle (A6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScheduledActionId(pub NonZeroU64);

impl ScheduledActionId {
    /// Returns `Some(_)` iff `v != 0`.
    #[inline]
    pub const fn new(v: u64) -> Option<Self> {
        match NonZeroU64::new(v) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// Underlying non-zero `u64`.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Total-ordered key — `(at, seq, id)`. Tick first; same-tick FIFO by `seq`;
/// final disambiguator by `id` (defensive — `seq` alone is unique).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct SchedKey {
    pub at: Tick,
    pub seq: u64,
    pub id: ScheduledActionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScheduledEntry {
    pub id: ScheduledActionId,
    pub at: Tick,
    pub actor: Option<EntityId>,
    pub principal: Principal,
    pub action_type_code: TypeCode,
    /// Canonical bytes (postcard); deserialization through `ActionRegistry`
    /// happens at dispatch time.
    pub action_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Scheduler {
    ready: BTreeMap<SchedKey, ScheduledEntry>,
    by_id: BTreeMap<ScheduledActionId, SchedKey>,
    by_actor: BTreeMap<EntityId, BTreeSet<ScheduledActionId>>,
    /// Monotonic per kernel lifetime; same-tick FIFO discriminator.
    next_seq: u64,
    /// Monotonic ID counter (NonZeroU64 starts at 1).
    next_id: u64,
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        Self {
            ready: BTreeMap::new(),
            by_id: BTreeMap::new(),
            by_actor: BTreeMap::new(),
            next_seq: 0,
            next_id: 0,
        }
    }

    /// Insert into `ready` + `by_id` + `by_actor` atomically.
    pub(crate) fn schedule(
        &mut self,
        at: Tick,
        actor: Option<EntityId>,
        principal: Principal,
        type_code: TypeCode,
        bytes: Vec<u8>,
    ) -> ScheduledActionId {
        self.next_id += 1;
        let id = ScheduledActionId(
            NonZeroU64::new(self.next_id).expect("next_id incremented before use; never zero"),
        );

        let seq = self.next_seq;
        self.next_seq += 1;

        let key = SchedKey { at, seq, id };
        let entry = ScheduledEntry {
            id,
            at,
            actor,
            principal,
            action_type_code: type_code,
            action_bytes: bytes,
        };

        self.ready.insert(key, entry);
        self.by_id.insert(id, key);
        if let Some(actor_id) = actor {
            self.by_actor.entry(actor_id).or_default().insert(id);
        }

        id
    }

    /// Schedule with a caller-provided `id` (e.g. when Kernel pre-allocates
    /// the ScheduledActionId so it can be returned from `submit`). Internal
    /// `next_id` is bumped so future auto-allocations stay monotonic.
    pub(crate) fn schedule_with_id(
        &mut self,
        id: ScheduledActionId,
        at: Tick,
        actor: Option<EntityId>,
        principal: Principal,
        type_code: TypeCode,
        bytes: Vec<u8>,
    ) {
        if id.get() > self.next_id {
            self.next_id = id.get();
        }

        let seq = self.next_seq;
        self.next_seq += 1;

        let key = SchedKey { at, seq, id };
        let entry = ScheduledEntry {
            id,
            at,
            actor,
            principal,
            action_type_code: type_code,
            action_bytes: bytes,
        };

        self.ready.insert(key, entry);
        self.by_id.insert(id, key);
        if let Some(actor_id) = actor {
            self.by_actor.entry(actor_id).or_default().insert(id);
        }
    }

    /// Immediate cancel — three-table consistent removal.
    /// Returns the removed entry, or `None` if `id` was not scheduled
    /// (collapsed `CancelMiss` semantics — never-scheduled,
    /// already-executed, already-cancelled all return `None`).
    pub(crate) fn cancel(&mut self, id: ScheduledActionId) -> Option<ScheduledEntry> {
        let key = self.by_id.remove(&id)?;
        let entry = self
            .ready
            .remove(&key)
            .expect("ready/by_id consistency violated");
        if let Some(actor_id) = entry.actor {
            if let Some(set) = self.by_actor.get_mut(&actor_id) {
                set.remove(&id);
                if set.is_empty() {
                    self.by_actor.remove(&actor_id);
                }
            }
        }
        Some(entry)
    }

    /// Bulk-cancel every entry owned by `actor`. Returns removed entries
    /// in scheduler order (BTreeSet iteration over IDs is ascending).
    /// Production wiring (entity-despawn cascade) lands with the
    /// per-entity ownership refinement (deferred).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn cancel_by_actor(&mut self, actor: EntityId) -> Vec<ScheduledEntry> {
        let Some(ids) = self.by_actor.remove(&actor) else {
            return Vec::new();
        };
        let mut cancelled = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(key) = self.by_id.remove(&id) {
                if let Some(entry) = self.ready.remove(&key) {
                    cancelled.push(entry);
                }
            }
        }
        cancelled
    }

    /// Pop the earliest-due entry whose `at <= now`. Returns `None` if the
    /// queue is empty or the head is in the future.
    pub(crate) fn pop_due(&mut self, now: Tick) -> Option<ScheduledEntry> {
        let (&key, _) = self.ready.first_key_value()?;
        if key.at > now {
            return None;
        }
        let entry = self
            .ready
            .remove(&key)
            .expect("first_key_value just returned this key");
        self.by_id.remove(&entry.id);
        if let Some(actor_id) = entry.actor {
            if let Some(set) = self.by_actor.get_mut(&actor_id) {
                set.remove(&entry.id);
                if set.is_empty() {
                    self.by_actor.remove(&actor_id);
                }
            }
        }
        Some(entry)
    }

    // Test-only observability accessors. Production introspection wiring
    // lands with the future IntrospectHandle interface (deferred).
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.ready.len()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{EntityId, Tick, TypeCode};

    fn p() -> Principal {
        Principal::System
    }
    fn tc() -> TypeCode {
        TypeCode(1)
    }

    #[test]
    fn empty_state() {
        let s = Scheduler::new();
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn schedule_then_pop_due_single() {
        let mut s = Scheduler::new();
        let id = s.schedule(Tick(5), None, p(), tc(), vec![1, 2, 3]);
        assert_eq!(s.len(), 1);
        let entry = s.pop_due(Tick(5)).expect("entry due");
        assert_eq!(entry.id, id);
        assert_eq!(entry.at, Tick(5));
        assert_eq!(entry.action_bytes, vec![1, 2, 3]);
        assert!(s.is_empty());
    }

    #[test]
    fn pop_due_before_time_returns_none() {
        let mut s = Scheduler::new();
        s.schedule(Tick(10), None, p(), tc(), vec![]);
        assert!(s.pop_due(Tick(9)).is_none());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn pop_due_at_exact_tick_pops() {
        let mut s = Scheduler::new();
        let id = s.schedule(Tick(5), None, p(), tc(), vec![]);
        assert_eq!(s.pop_due(Tick(5)).unwrap().id, id);
    }

    #[test]
    fn pop_due_ordering_by_tick() {
        let mut s = Scheduler::new();
        let id_late = s.schedule(Tick(20), None, p(), tc(), vec![]);
        let id_early = s.schedule(Tick(5), None, p(), tc(), vec![]);
        let id_mid = s.schedule(Tick(10), None, p(), tc(), vec![]);
        assert_eq!(s.pop_due(Tick(100)).unwrap().id, id_early);
        assert_eq!(s.pop_due(Tick(100)).unwrap().id, id_mid);
        assert_eq!(s.pop_due(Tick(100)).unwrap().id, id_late);
    }

    #[test]
    fn pop_due_tiebreak_by_seq() {
        let mut s = Scheduler::new();
        let id1 = s.schedule(Tick(5), None, p(), tc(), vec![1]);
        let id2 = s.schedule(Tick(5), None, p(), tc(), vec![2]);
        let id3 = s.schedule(Tick(5), None, p(), tc(), vec![3]);
        assert_eq!(s.pop_due(Tick(5)).unwrap().id, id1);
        assert_eq!(s.pop_due(Tick(5)).unwrap().id, id2);
        assert_eq!(s.pop_due(Tick(5)).unwrap().id, id3);
    }

    #[test]
    fn cancel_removes_entry() {
        let mut s = Scheduler::new();
        let id = s.schedule(Tick(5), None, p(), tc(), vec![]);
        let cancelled = s.cancel(id).expect("found");
        assert_eq!(cancelled.id, id);
        assert!(s.is_empty());
        assert!(s.pop_due(Tick(100)).is_none());
    }

    #[test]
    fn cancel_unknown_returns_none() {
        let mut s = Scheduler::new();
        let bogus = ScheduledActionId::new(999).unwrap();
        assert!(s.cancel(bogus).is_none());
    }

    #[test]
    fn cancel_by_actor_removes_all() {
        let mut s = Scheduler::new();
        let actor = EntityId::new(1).unwrap();
        let other = EntityId::new(2).unwrap();
        let _ = s.schedule(Tick(5), Some(actor), p(), tc(), vec![]);
        let _ = s.schedule(Tick(10), Some(actor), p(), tc(), vec![]);
        let id_other = s.schedule(Tick(7), Some(other), p(), tc(), vec![]);
        assert_eq!(s.len(), 3);
        let cancelled = s.cancel_by_actor(actor);
        assert_eq!(cancelled.len(), 2);
        assert_eq!(s.len(), 1);
        assert_eq!(s.pop_due(Tick(100)).unwrap().id, id_other);
    }

    #[test]
    fn cancel_by_actor_unknown_returns_empty() {
        let mut s = Scheduler::new();
        let actor = EntityId::new(99).unwrap();
        assert!(s.cancel_by_actor(actor).is_empty());
    }

    #[test]
    fn schedule_id_monotonic() {
        let mut s = Scheduler::new();
        let id1 = s.schedule(Tick(0), None, p(), tc(), vec![]);
        let id2 = s.schedule(Tick(0), None, p(), tc(), vec![]);
        let id3 = s.schedule(Tick(0), None, p(), tc(), vec![]);
        assert!(id1 < id2);
        assert!(id2 < id3);
        assert_eq!(id1.get(), 1);
        assert_eq!(id3.get(), 3);
    }

    #[test]
    fn no_tombstones() {
        // After cancel, len decrements immediately — no lazy deletion.
        let mut s = Scheduler::new();
        let id1 = s.schedule(Tick(5), None, p(), tc(), vec![]);
        let _id2 = s.schedule(Tick(5), None, p(), tc(), vec![]);
        assert_eq!(s.len(), 2);
        s.cancel(id1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn determinism_same_sequence() {
        fn run() -> Vec<u64> {
            let mut s = Scheduler::new();
            s.schedule(Tick(3), None, p(), tc(), vec![]);
            s.schedule(Tick(1), None, p(), tc(), vec![]);
            s.schedule(Tick(2), None, p(), tc(), vec![]);
            s.schedule(Tick(1), None, p(), tc(), vec![]);
            let mut out = Vec::new();
            while let Some(e) = s.pop_due(Tick(100)) {
                out.push(e.id.get());
            }
            out
        }
        assert_eq!(run(), run());
    }
}
