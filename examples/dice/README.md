# 🎲 Dice Temple Domain

**Dice Temple** is a high-integrity proof-of-concept domain for **ArkheKernel**. It demonstrates the kernel's ability to enforce mathematical causality and perform bit-level deterministic replays.

## 🏛️ Concept
In a traditional centralized application, "Randomness" is often a black box controlled by the server admin. In **Dice Temple**, randomness is a deterministic function of the **Global Seed** and **Historical Context**. This makes every roll verifiable, auditable, and perfectly reproducible.

## 🚀 Key Features

### 1. Cryptographic Entropy Derivation
- Uses the **BLAKE3** hash function to derive 3D6 results.
- Entropy Source: `blake3(action.seed || tick || nonce)` — every input is
  carried in the action body, so replay is independent of instance state.
- Prevents "Timing Attacks" by anchoring the outcome to kernel-managed time.

### 2. State Lifecycle Management
- **`Op::SpawnEntity`**: Atomic allocation of digital actors.
- **`Op::EmitEvent`**: Deterministic outcome emission, captured by the
  observer pipeline and recorded in the WAL.

### 3. Fault-Tolerance & Reconstruction (A1 D1-Total)
- First pass runs N rolls against a `Kernel::new_with_wal(...)` instance and
  exports the resulting `Wal`.
- Second pass hands that `Wal` to a fresh kernel of the same shape via
  `persist::replay_into`.
- Both the BLAKE3 keyed chain tip and every captured outcome must match
  bit-for-bit. If a single byte of the action body, principal, tick, or
  step-stage ordering varied, the chain tips would diverge.

## 🛠️ Execution
To run the Dice Temple simulation and witness the integrity verification:

```bash
cargo run -p dice-domain
```

## 📊 Evaluation Results
The following invariants are guaranteed by this domain:
- **Provable Fairness**: Every dice roll can be audited against the master seed.
- **Perfect Continuity**: Any world destroyed in Tick $N$ can be perfectly resurrected from Tick $0$.
- **Zero Variance**: The replayed history is bit-for-bit identical to the original execution.

---
*Powered by ArkheKernel - Enforcing Causality across Virtual Worlds.*
