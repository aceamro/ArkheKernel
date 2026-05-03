//! L0 runtime stratum.
//!
//! Kernel-level event types, transactional `StepStage` (10 buckets),
//! the Kernel orchestrator, dispatcher, action registry, and the
//! panic-resilient observer chain. Depends on `abi` and
//! `state`.

pub mod apply;
pub mod dispatch;
pub mod event;
pub mod kernel;
pub mod observer;
pub mod registry;
pub mod stage;
pub mod view;

pub use kernel::{Kernel, Stats, StepReport};
pub use observer::KernelObserver;
pub use view::InstanceView;
