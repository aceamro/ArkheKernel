//! L0 state stratum.
//!
//! Per-instance state, sealed-trait declarations, authorization phantom
//! types, and the GhostCell brand handle. Depends only on `abi` (no
//! dependency on `runtime` or `persist`).

pub mod authz;
pub mod config;
pub mod context;
pub mod instance;
pub mod ledger;
pub mod op;
pub mod quota;
pub mod scheduler;
pub mod scope;
pub mod traits;

pub use authz::{AuthState, Authorized, DenyReason, Effect, Unverified};
pub use config::InstanceConfig;
pub use context::ActionContext;
pub use op::Op;
pub use quota::{apply_quota_reduction, QuotaReductionError, QuotaReductionPolicy};
pub use scope::InstanceScope;
pub use traits::{Action, ActionCompute, ActionDeriv, Component, DeserializeError, Event};

pub use instance::EntityMeta;
pub(crate) use instance::Instance;
pub(crate) use scheduler::{ScheduledActionId, ScheduledEntry};
