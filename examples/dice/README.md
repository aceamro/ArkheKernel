# Dice Temple Domain

`dice-domain` is a small ArkheKernel example domain that exercises the
deterministic-replay path with a 3D6 dice roller. It is shipped as an
illustrative integration test for the kernel's WAL + replay machinery, not
as a production gambling primitive.

## What it demonstrates

### Deterministic entropy

- 3D6 outcomes are derived from a BLAKE3 hash of the action body
  (`blake3(action.seed || tick || nonce)`).
- Every input is carried in the action body, so replay is independent of
  instance state and free of clock or RNG side effects.

### Action surface

- `Op::SpawnEntity` — atomic actor allocation.
- `Op::EmitEvent` — outcome emission, captured by the observer pipeline and
  recorded in the WAL.

### A1 D1-Total replay check

- First pass runs N rolls against a `Kernel::new_with_wal(...)` instance and
  exports the resulting `Wal`.
- Second pass hands that `Wal` to a fresh kernel of the same shape via
  `persist::replay_into`.
- The BLAKE3 keyed chain tip and every captured outcome must match
  bit-for-bit. A single byte of divergence in the action body, principal,
  tick, or step-stage ordering changes the chain tip.

## Running

```bash
cargo run -p dice-domain
```

The binary prints the rolls produced by the first pass, replays them on a
fresh kernel, and asserts chain-tip + outcome equality.
