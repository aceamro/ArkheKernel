# arkhe-macros

**L0 derive macros for [`arkhe-kernel`](../arkhe-kernel).**

Three procedural derives, one shared shape. Pair the derive with
`serde::{Serialize, Deserialize}`; the kernel provides canonical postcard
encoding by default.

## Layer

Companion proc-macro crate for the L0 kernel. Not intended for direct use
outside of kernel consumers — the derives resolve paths inside
`::arkhe_kernel::state::traits::*`.

## Derives

- `#[derive(ArkheAction)]` — emits `Sealed` + `ActionDeriv`. Pair with a
  hand-written `impl ActionCompute for T`; the kernel supplies the
  `canonical_bytes` / `from_bytes` / `approx_size` blanket.
- `#[derive(ArkheComponent)]` — emits `Sealed` + `Component`. No user method
  required beyond serde derives.
- `#[derive(ArkheEvent)]` — same shape as Component; requires `Debug` + serde.

Every derive expects `#[arkhe(type_code = N, schema_version = M)]`.
`schema_version` defaults to `1`; `type_code` is mandatory.

## Quick start

```rust
use arkhe_kernel::{ArkheComponent, ArkheEvent};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 5001, schema_version = 1)]
struct CounterComponent { value: u64 }

#[derive(Debug, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 8001)]
struct PostCreatedEvent { author: u64, body: String }
```

## Documentation

- Book: <https://aceamro.github.io/ArkheKernel/book/>
- API reference: <https://docs.rs/arkhe-macros>
- Repository: <https://github.com/aceamro/ArkheKernel>

## License

Dual-licensed under MIT OR Apache-2.0 at your option.
