//! L1 dice example — A1 D1-Total proof carrier.
//!
//! Two stages:
//!   Stage 1: roll N times against a `Kernel::new_with_wal(...)` instance.
//!            Capture each roll outcome and the final WAL chain tip.
//!   Stage 2: hand the exported WAL to a fresh kernel of the same shape and
//!            `replay_into` it. Compare:
//!              - reconstructed chain tip  ==  Stage 1 chain tip
//!              - per-roll outcomes recovered from the WAL records  (D1-Total)
//!
//! "Deterministic" here means *every* bit of the WAL chain — the BLAKE3
//! keyed digest over `prev || postcard(record_body)` — matches across runs.
//! If a single byte of the action body, principal, tick, or step-stage
//! ordering varied, the chain tips would diverge.
//!
//! Demo source intentionally uses `unwrap` / `expect` / `panic` for
//! legibility; the workspace clippy deny is locally relaxed here so the
//! example reads as tutorial code rather than production-grade error
//! wiring. A library or shell using the same surface must not copy this
//! style.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use arkhe_kernel::abi::{CapabilityMask, EntityId, InstanceId, Principal, Tick, TypeCode};
use arkhe_kernel::persist::replay_into;
use arkhe_kernel::state::{Action, ActionCompute, ActionContext, InstanceConfig, Op};
use arkhe_kernel::{ArkheAction, Kernel, KernelEvent, KernelObserver, Wal};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

const WORLD_ID: [u8; 32] = [0x42u8; 32];
const MANIFEST_DIGEST: [u8; 32] = [0x9Au8; 32];

const DICE_EVENT_TC: TypeCode = TypeCode(8001);

// ---------------------------------------------------------------------------
// Domain payloads
// ---------------------------------------------------------------------------

/// Outcome event — emitted as `Op::EmitEvent` after each roll.
/// Includes the BLAKE3 digest of (instance_seed || tick || nonce) so any
/// non-determinism in the inputs would surface as a hash mismatch on replay.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct DiceRolled {
    nonce: u64,
    /// Three faces 1..=6, derived deterministically from `entropy_digest`.
    dice: [u8; 3],
    sum: u8,
    target_sum: u8,
    won: bool,
    entropy_digest: [u8; 32],
}

/// Roll action. `seed` carries the instance entropy seed so the action body
/// is self-contained (replay does not need to consult instance state).
#[derive(Debug, Serialize, Deserialize, Clone, ArkheAction)]
#[arkhe(type_code = 8000, schema_version = 1)]
struct RollAction {
    seed: [u8; 32],
    nonce: u64,
    target_sum: u8,
}

impl RollAction {
    /// Deterministic outcome derivation. Same inputs → same output, always.
    fn roll(&self, at: Tick) -> DiceRolled {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.seed);
        hasher.update(&at.0.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        let digest = hasher.finalize();
        let bytes: [u8; 32] = *digest.as_bytes();

        let d1 = (bytes[0] % 6) + 1;
        let d2 = (bytes[1] % 6) + 1;
        let d3 = (bytes[2] % 6) + 1;
        let sum = d1 + d2 + d3;

        DiceRolled {
            nonce: self.nonce,
            dice: [d1, d2, d3],
            sum,
            target_sum: self.target_sum,
            won: sum >= self.target_sum,
            entropy_digest: bytes,
        }
    }
}

impl ActionCompute for RollAction {
    fn compute(&self, ctx: &ActionContext) -> Vec<Op> {
        let outcome = self.roll(ctx.now);
        let event_bytes = postcard::to_allocvec(&outcome)
            .map(Bytes::from)
            .expect("postcard encode DiceRolled");

        // Spawn one entity per roll so apply_stage exercises the SpawnEntity
        // → ledger path on every record (D1-Total over a non-trivial state op).
        let entity_id = EntityId::new(ctx.entities_len() as u64 + 1).expect("next entity id > 0");

        vec![
            Op::SpawnEntity {
                id: entity_id,
                owner: Principal::System,
            },
            Op::EmitEvent {
                actor: Some(entity_id),
                event_type_code: DICE_EVENT_TC,
                event_bytes,
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// Observer — captures roll outcomes for verification.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RollLog {
    outcomes: Vec<DiceRolled>,
}

struct CaptureObserver {
    log: Arc<Mutex<RollLog>>,
}

impl KernelObserver for CaptureObserver {
    fn on_event(&self, event: &KernelEvent) {
        if let KernelEvent::DomainEventEmitted {
            event_type_code,
            bytes,
            ..
        } = event
        {
            if *event_type_code == DICE_EVENT_TC {
                if let Ok(outcome) = postcard::from_bytes::<DiceRolled>(bytes) {
                    self.log.lock().expect("log mutex").outcomes.push(outcome);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Driver helpers
// ---------------------------------------------------------------------------

fn fresh_kernel_with_wal() -> (Kernel, InstanceId, Arc<Mutex<RollLog>>) {
    let mut kernel = Kernel::new_with_wal(WORLD_ID, MANIFEST_DIGEST);
    kernel.register_action::<RollAction>();
    let log = Arc::new(Mutex::new(RollLog::default()));
    let _h = kernel.register_observer(Box::new(CaptureObserver { log: log.clone() }));

    let config = InstanceConfig {
        max_entities: 1024,
        max_scheduled: 1024,
        memory_budget_bytes: 1 << 20,
        ..Default::default()
    };

    let inst = kernel.create_instance(config);
    (kernel, inst, log)
}

/// One-line outcome formatter used by both phases for direct visual diff.
fn fmt_outcome(o: &DiceRolled) -> String {
    let digest_prefix: String = o
        .entropy_digest
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();
    format!(
        "  nonce={:>3} dice={:?} sum={:>2} target>={:>2} won={} digest=0x{}",
        o.nonce, o.dice, o.sum, o.target_sum, o.won, digest_prefix
    )
}

fn roll_n(kernel: &mut Kernel, inst: InstanceId, seed: [u8; 32], n: u64, target_sum: u8) {
    use arkhe_kernel::state::ActionDeriv;
    for nonce in 0..n {
        let action = RollAction {
            seed,
            nonce,
            target_sum,
        };
        let bytes = Action::canonical_bytes(&action);
        let at = Tick(nonce);
        kernel
            .submit(
                inst,
                Principal::System,
                None,
                at,
                RollAction::TYPE_CODE,
                bytes,
            )
            .expect("submit ok");
        let _ = kernel.step(at, CapabilityMask::SYSTEM);
    }
}

fn fmt_chain_tip(tip: &[u8; 32]) -> String {
    tip.iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

fn main() {
    println!("┌──────────────────────────────────────────────────┐");
    println!("│   ArkheKernel demo — dice                        │");
    println!("│   D1-Total proof: WAL replay → bit-identical     │");
    println!("└──────────────────────────────────────────────────┘");

    let seed: [u8; 32] = [0x5Au8; 32];
    let n_rolls: u64 = 5;
    let target_sum: u8 = 12;

    // ---- Stage 1: original run ----
    println!("\n[phase 1] roll {n_rolls} times against fresh kernel + WAL");
    let (mut k1, inst1, log1) = fresh_kernel_with_wal();
    roll_n(&mut k1, inst1, seed, n_rolls, target_sum);
    let original_tip = k1.wal_chain_tip().expect("wal attached");
    let original_records = k1.wal_record_count().expect("wal attached");
    let original_outcomes = log1.lock().unwrap().outcomes.clone();

    for o in &original_outcomes {
        println!("{}", fmt_outcome(o));
    }
    println!(
        "  records={} chain_tip=0x{}…",
        original_records,
        fmt_chain_tip(&original_tip)
    );

    let wal: Wal = k1.export_wal().expect("wal attached");

    // ---- Stage 2: replay into a fresh kernel ----
    println!("\n[phase 2] replay WAL into fresh kernel of same shape");
    let mut k2 = Kernel::new_with_wal(WORLD_ID, MANIFEST_DIGEST);
    k2.register_action::<RollAction>();
    let replay_log = Arc::new(Mutex::new(RollLog::default()));
    let _h = k2.register_observer(Box::new(CaptureObserver {
        log: replay_log.clone(),
    }));
    let config = InstanceConfig {
        max_entities: 1024,
        max_scheduled: 1024,
        memory_budget_bytes: 1 << 20,
        ..Default::default()
    };
    let _inst2 = k2.create_instance(config); // caller pre-creates instance; snapshot integration will fold this

    let report = replay_into(&mut k2, &wal).expect("replay ok");
    let replayed_tip = k2.wal_chain_tip().expect("wal attached");
    let replayed_outcomes = replay_log.lock().unwrap().outcomes.clone();

    for o in &replayed_outcomes {
        println!("{}", fmt_outcome(o));
    }
    println!(
        "  records_replayed={} chain_tip=0x{}…",
        report.records_replayed,
        fmt_chain_tip(&replayed_tip),
    );

    // ---- Verdict ----
    println!("\n────────────────────────────────────────────────────");
    let chain_match = replayed_tip == original_tip;
    let outcome_match = replayed_outcomes == original_outcomes;
    let count_match = report.records_replayed as usize == original_records;

    println!(
        "  chain_tip_match    : {}",
        if chain_match { "YES" } else { "NO " }
    );
    println!(
        "  outcome_match      : {}",
        if outcome_match { "YES" } else { "NO " }
    );
    println!(
        "  record_count_match : {}",
        if count_match { "YES" } else { "NO " }
    );

    if chain_match && outcome_match && count_match {
        println!("\n  ✓ A1 D1-Total verified: WAL replay is bit-identical.");
    } else {
        println!("\n  ✗ INTEGRITY BREACH: replay diverged from original run.");
        std::process::exit(1);
    }
    println!("────────────────────────────────────────────────────");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roll_action_round_trips_via_canonical_bytes() {
        use arkhe_kernel::state::ActionDeriv;
        let a = RollAction {
            seed: [3u8; 32],
            nonce: 42,
            target_sum: 12,
        };
        let bytes = Action::canonical_bytes(&a);
        let back = <RollAction as Action>::from_bytes(RollAction::SCHEMA_VERSION, &bytes).unwrap();
        assert_eq!(back.seed, [3u8; 32]);
        assert_eq!(back.nonce, 42);
        assert_eq!(back.target_sum, 12);
    }

    #[test]
    fn roll_is_deterministic_for_same_inputs() {
        let a = RollAction {
            seed: [7u8; 32],
            nonce: 99,
            target_sum: 10,
        };
        let o1 = a.roll(Tick(5));
        let o2 = a.roll(Tick(5));
        assert_eq!(o1, o2);
    }

    #[test]
    fn roll_differs_when_tick_changes() {
        let a = RollAction {
            seed: [7u8; 32],
            nonce: 1,
            target_sum: 10,
        };
        let o1 = a.roll(Tick(0));
        let o2 = a.roll(Tick(1));
        assert_ne!(o1.entropy_digest, o2.entropy_digest);
    }

    #[test]
    fn replay_reconstructs_chain_tip_and_outcomes() {
        // Stage 1
        let (mut k1, inst1, log1) = fresh_kernel_with_wal();
        roll_n(&mut k1, inst1, [0xA5u8; 32], 4, 11);
        let original_tip = k1.wal_chain_tip().unwrap();
        let original_records = k1.wal_record_count().unwrap();
        let original = log1.lock().unwrap().outcomes.clone();
        let wal = k1.export_wal().unwrap();

        // Stage 2
        let mut k2 = Kernel::new_with_wal(WORLD_ID, MANIFEST_DIGEST);
        k2.register_action::<RollAction>();
        let replay_log = Arc::new(Mutex::new(RollLog::default()));
        let _h = k2.register_observer(Box::new(CaptureObserver {
            log: replay_log.clone(),
        }));
        let cfg = InstanceConfig {
            max_entities: 1024,
            max_scheduled: 1024,
            memory_budget_bytes: 1 << 20,
            ..Default::default()
        };
        let _ = k2.create_instance(cfg);

        let report = replay_into(&mut k2, &wal).unwrap();
        let replayed_tip = k2.wal_chain_tip().unwrap();
        let replayed = replay_log.lock().unwrap().outcomes.clone();

        assert_eq!(report.records_replayed as usize, original_records);
        assert_eq!(replayed_tip, original_tip);
        assert_eq!(replayed, original);
    }
}
