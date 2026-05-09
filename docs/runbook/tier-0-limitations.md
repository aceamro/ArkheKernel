# Tier-0 Threat Surface — `software-kek` In-Memory Key Window

**Policy restatement**: Tier-0 is **dev / pre-production only**. Operating Tier-0 in any environment that serves real user data (subject to GDPR or equivalent) is **prohibited** — this is a compliance requirement, not a recommendation. Only Tier-1 (KMS free-tier) or above qualifies as a production path.

---

## 1. Problem — Plaintext KEK in Process Memory

Under Tier-0 (`[audit.dek_backend = "software-kek"]`, `runtime_max ≤ "0.15"`) the master Key-Encryption-Key (KEK) lives in process memory as plaintext. That KEK wraps / unwraps every per-user DEK, so any leak of the KEK means:

- Every live user's DEK becomes decryptable → PII plaintext is recoverable.
- DEK shred loses its effect — GDPR Art.17 "effective erasure" is no longer satisfied.
- The audit log / attestation paths are independent, so they only record the compromise after the fact.

Tier-1+ moves the KEK into an HSM / KMS (FIPS 140-3 certified boundary), out of process memory entirely, which removes this threat class.

---

## 2. Limits of the Process Protection FFI

`arkhe-forge-platform::process_protection` mitigates the exposure window with three syscalls but **does not eliminate it**.

| Primitive | Linux | macOS | Windows | Effect |
|---|---|---|---|---|
| `lock_memory` | `mlockall(MCL_CURRENT \| MCL_FUTURE)` | **Unsupported** (Darwin lacks `mlockall`) | `SetProcessWorkingSetSizeEx` HARDWS_MIN_ENABLE | Blocks swap / pagefile writes |
| `disable_core_dump` | `prctl(PR_SET_DUMPABLE, 0)` | `setrlimit(RLIMIT_CORE, 0)` | `SetErrorMode(SEM_NOGPFAULTERRORBOX)` | Blocks crash-dump file creation |
| `disable_ptrace` | `prctl(PR_SET_PTRACER, 0)` + yama probe | `ptrace(PT_DENY_ATTACH)` | `IsDebuggerPresent` + warn | Blocks non-privileged debugger attach |

Attack paths that each primitive **cannot** block:

- **Root / `CAP_SYS_PTRACE` processes**: on Linux, root (or any process holding `CAP_SYS_PTRACE`) can read `/proc/<pid>/mem` directly and extract the KEK. `PR_SET_PTRACER` only stops **non-privileged** tracers.
- **Kernel module / rootkit**: kernel-space code bypasses every user-space mitigation.
- **Cold-boot / DMA**: Thunderbolt / PCIe DMA dumps RAM regardless of `mlockall`.
- **Hypervisor escape / VMM introspection**: in virtualised environments the host can read guest RAM at will.
- **macOS `lock_memory` Unsupported**: Darwin has no `mlockall`, so Runtime returns `Unsupported`. Tier-0 on macOS cannot block swap at all — a significantly wider exposure window.

→ Tier-0 process protection is a defence against "ordinary user-process attackers". It is not protection against privileged attackers.

---

## 3. Attack scenarios — examples

### 3.1 Root-level memory read

```
# After attacker acquires root:
sudo cat /proc/$(pgrep arkhe-runtime)/mem | grep -a -A1 "SECRET-KEY-HEADER"
# or
gdb -p $(pgrep arkhe-runtime)
(gdb) dump memory /tmp/dump /start /end
```

`mlockall` only stops pagefile writes — it does not stop root's `/proc/<pid>/mem` read.

### 3.2 Coredump leak

```
ulimit -c unlimited                 # or systemd default core_pattern
kill -SEGV $(pgrep arkhe-runtime)   # crash the process
# /var/lib/systemd/coredump/... now contains a dump with the KEK — unless `disable_core_dump` is active.
```

With `disable_core_dump` the above path is blocked, but a systemd-coredump / ABRT pre-process intercept requires additional measures.

### 3.3 Container escape

A broken container boundary lets the host's root attacker reuse path §3.1. Tier-0 deploys without cgroup / seccomp / user-namespace isolation expose themselves to other tenants on the shared host.

---

## 4. **Minimum mitigation checklist** for Tier-0

Operators must verify every item before each deploy. Each missed item drives the risk sharply higher.

### 4.1 OS / kernel hardening

- [ ] **`ulimit -c 0`** explicit (systemd unit: `LimitCORE=0`).
- [ ] **`NoNewPrivileges=yes`** under systemd / container — blocks privilege escalation.
- [ ] **SELinux (enforcing) or AppArmor (enforce)** — restricts non-root `/proc/<pid>/mem` access.
- [ ] **`kernel.yama.ptrace_scope=2`** (admin-only) — system-wide ptrace block (the runtime's `linux.rs` probe only warns).
- [ ] **`kernel.dmesg_restrict=1` + `kernel.kptr_restrict=2`** — blocks kernel info leaks.

### 4.2 Container / VM isolation

- [ ] **User-namespace isolation** — host root ≠ container root.
- [ ] **Read-only root filesystem** — e.g. `ReadOnlyPaths=/` + `ReadWritePaths=/var/lib/arkhe`.
- [ ] **seccomp profile** — block `ptrace` / `process_vm_readv` syscalls.
- [ ] **cgroup memory limit + swap off** — disable swap entirely (`/proc/sys/vm/swappiness=0`).
- [ ] **No host sharing** — Tier-0 runs on a dedicated host / VM. Shared-tenant Tier-0 is strictly forbidden.

### 4.3 Runtime configuration

- [ ] **Manifest `runtime_max = "0.15"`** observed — v0.16+ binaries emit `ManifestError::SoftwareKekNotPermitted` at parse time.
- [ ] **`arkhe_runtime_software_kek_alpha_mode=1` metric** permanently visible on the dashboard — if someone turns it off, that's the signal that Tier-0 → Tier-1 promotion is required.
- [ ] **Tier-0 retention window** — cap the pre-production duration (recommended: ≤ 30 days, then Tier-1 promote or re-evaluate).
- [ ] **Ed25519 signing keys** stay on HW keys (YubiKey / NitroKey) even under Tier-0 — `software-kek` only covers the DEK KEK, never signing keys.

### 4.4 Network / access paths

- [ ] **SSH / admin port access control** — bastion / VPN only; never expose Tier-0 host on a public IP.
- [ ] **L4 adapter TLS compulsory** — plain telnet is allowed on Tier-0 only when the host itself terminates TLS or sits inside a VPN.
- [ ] **Prometheus endpoint authentication** — public endpoint forbidden (telemetry privacy).

### 4.5 Incident response

- [ ] **Suspected KEK compromise → kill the process immediately and scrap the whole deploy** — wipe every record encrypted with that KEK using the full-erasure path.
- [ ] **Tier-1 promotion in waiting** — operator-side promotion procedure.

---

## 5. Why Tier-1+ is a production requirement (summary)

| Axis | Tier-0 software-kek | Tier-1 KMS / Tier-2 HSM |
|---|---|---|
| KEK storage | process memory | HSM / KMS boundary (FIPS 140-3) |
| Root / `/proc/<pid>/mem` attack | **exposed** | not possible (key material lives outside the process) |
| Coredump leak | mitigated by process_protection only | not possible (not in memory) |
| DMA / cold-boot | exposed | not possible |
| Kernel rootkit | exposed | HSM is a separate device — kernel compromise alone does not expose the KEK |
| GDPR compliance | **insufficient** | sufficient (ICO / EDPB accepted) |
| Cost | $0 | $0-$50/month on AWS KMS free-tier |
| Ed25519 signing key | HW (unchanged) | HW (unchanged) |

→ Tier-0 exists as a **zero-dep development path for CI / integration testing / early prototyping**. The moment real users arrive, Tier-1 promotion is mandatory.

---

## 6. References

- Linux `mlockall(2)` / `prctl(2)` man pages.
- FIPS 140-3 cryptographic module validation — Tier-1/2 foundation.

---

*This runbook is a repo baseline. Operators must physically verify §4 before each deploy. `software-kek` never reaches production — if it does, rollback and redeploy under Tier-1 immediately.*
