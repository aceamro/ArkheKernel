//! `KernelObserver` trait + panic-resilient `ObserverRegistry`.
//!
//! Observer panic policy: first panic evicts. Eviction is recorded
//! in `evicted` set so subsequent deliveries skip the handle even if a
//! pathological observer were re-inserted with the same handle (it cannot
//! be — `next_handle` is monotonic).

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::runtime::event::{EventMask, KernelEvent, ObserverHandle};

/// Sink for [`KernelEvent`]s. Implementations are invoked in
/// `BTreeMap<ObserverHandle, _>` order during the post-commit drain
/// of `Kernel::step`. Panics inside `on_event` are caught and result
/// in first-panic eviction of the observer (A22).
///
/// Implementors must be `Send + Sync` because the kernel may move
/// observers across threads in higher-level setups (e.g. for
/// off-thread fan-out); the kernel itself remains single-threaded.
pub trait KernelObserver: Send + Sync {
    /// Receive one kernel event. Filtered by
    /// [`super::event::EventMask`] when registered via
    /// [`super::kernel::Kernel::register_observer_filtered`];
    /// `register_observer` is the unfiltered shorthand.
    fn on_event(&self, event: &KernelEvent);
}

struct ObserverSlot {
    observer: Box<dyn KernelObserver>,
    mask: EventMask,
}

pub(crate) struct ObserverRegistry {
    slots: BTreeMap<ObserverHandle, ObserverSlot>,
    evicted: BTreeSet<ObserverHandle>,
    next_handle: u16,
}

impl ObserverRegistry {
    pub(crate) fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            evicted: BTreeSet::new(),
            next_handle: 0,
        }
    }

    /// Register with `EventMask::ALL` (every variant delivered).
    pub(crate) fn register(&mut self, obs: Box<dyn KernelObserver>) -> ObserverHandle {
        self.register_filtered(obs, EventMask::ALL)
    }

    /// Register with an event-class filter — only events whose variant
    /// bit is set in `mask` are delivered.
    pub(crate) fn register_filtered(
        &mut self,
        obs: Box<dyn KernelObserver>,
        mask: EventMask,
    ) -> ObserverHandle {
        let h = ObserverHandle(self.next_handle);
        self.next_handle = self.next_handle.saturating_add(1);
        self.slots.insert(
            h,
            ObserverSlot {
                observer: obs,
                mask,
            },
        );
        h
    }

    /// Deliver `event` to every non-evicted observer whose mask matches.
    /// Panics are caught and the offending observer is evicted. Returns
    /// the handles of any observers newly evicted by this call.
    pub(crate) fn deliver(&mut self, event: &KernelEvent) -> Vec<ObserverHandle> {
        let mut newly_evicted = Vec::new();
        let keys: Vec<ObserverHandle> = self.slots.keys().copied().collect();
        for handle in keys {
            if self.evicted.contains(&handle) {
                continue;
            }
            let slot = match self.slots.get(&handle) {
                Some(s) => s,
                None => continue,
            };
            if !slot.mask.matches(event) {
                continue;
            }
            let result = catch_unwind(AssertUnwindSafe(|| slot.observer.on_event(event)));
            if result.is_err() {
                self.evicted.insert(handle);
                self.slots.remove(&handle);
                newly_evicted.push(handle);
            }
        }
        newly_evicted
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_evicted(&self, h: ObserverHandle) -> bool {
        self.evicted.contains(&h)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{InstanceId, Tick, TypeCode};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct CountingObserver {
        count: Arc<AtomicU32>,
    }
    impl KernelObserver for CountingObserver {
        fn on_event(&self, _event: &KernelEvent) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PanicObserver;
    impl KernelObserver for PanicObserver {
        fn on_event(&self, _event: &KernelEvent) {
            panic!("intentional");
        }
    }

    fn evt() -> KernelEvent {
        KernelEvent::ActionExecuted {
            instance: InstanceId::new(1).unwrap(),
            action_type: TypeCode(1),
            at: Tick(0),
        }
    }

    #[test]
    fn register_and_len() {
        let mut r = ObserverRegistry::new();
        let count = Arc::new(AtomicU32::new(0));
        let _h = r.register(Box::new(CountingObserver {
            count: count.clone(),
        }));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn deliver_increments_observer_count() {
        let mut r = ObserverRegistry::new();
        let count = Arc::new(AtomicU32::new(0));
        r.register(Box::new(CountingObserver {
            count: count.clone(),
        }));
        r.deliver(&evt());
        r.deliver(&evt());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn first_panic_evicts_observer() {
        let mut r = ObserverRegistry::new();
        let h = r.register(Box::new(PanicObserver));
        let evicted = r.deliver(&evt());
        assert_eq!(evicted, vec![h]);
        assert!(r.is_evicted(h));
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn evicted_observer_does_not_receive_subsequent_events() {
        let mut r = ObserverRegistry::new();
        let count = Arc::new(AtomicU32::new(0));
        r.register(Box::new(PanicObserver));
        r.register(Box::new(CountingObserver {
            count: count.clone(),
        }));
        r.deliver(&evt());
        r.deliver(&evt());
        // Counting observer received both; PanicObserver evicted on first.
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn handles_are_monotonic() {
        let mut r = ObserverRegistry::new();
        let count = Arc::new(AtomicU32::new(0));
        let h0 = r.register(Box::new(CountingObserver {
            count: count.clone(),
        }));
        let h1 = r.register(Box::new(CountingObserver {
            count: count.clone(),
        }));
        assert!(h0 < h1);
    }
}
