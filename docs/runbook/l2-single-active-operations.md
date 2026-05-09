# Single-Active L2 Operations Runbook — SLO Suspension Policy

**Purpose**: specify the SLO suspension convention so that SLO alerts (e.g., `projection_lag_seconds` p99 < 30s) do not fire as false positives during the **failover / promote / upgrade** periods of active-passive L2 operations.

---

## 1. Single-Active operation model

- **Single active L2 writer** + **N passive readers** (standby).
- On active failure, passive → active promotion (operator-initiated by default; if `kms_auto_promote` is enabled, automatic after 60 minutes via the HF2 Auto-Promote trust model).
- During promotion, **projection stop / replay / rebuild** is unavoidable — SLO violations for several minutes.

---

## 2. SLO Suspension Trigger

SLO alerts are **temporarily suspended** in the following cases:

| Event | Suspension scope | Duration |
|---|---|---|
| Operator-initiated failover (`runtime-doctor failover`) | `projection_lag_seconds` / `observer_restart_total` | start → promote complete + 5 min settle |
| Auto-promote (after_60min) | Same as above | auto trigger → promote complete + 5 min |
| Upgrade (binary swap) | Above + `action_duration_seconds` | drain → binary swap → replay → rebuild + 5 min settle |
| HSM degraded mode | `hsm_unavailable_total` retained, only `projection_lag_seconds` | degraded start → healthy recovery |

**Alerts outside suspension are retained** — critical severity (e.g., `chain_tip_signature` verification fail / `RuntimeInitError::ProcessProtectionUnavailable`) is not subject to suspension. Suspension is limited to **operator-known downtime**.

---

## 3. Suspension mechanism

### 3.1 Alertmanager inhibit rule

The following inhibit rule in `alertmanager.yml`:

```yaml
inhibit_rules:
  - source_matchers:
      - severity = "info"
      - event = "failover-in-progress"
    target_matchers:
      - alertname =~ "ProjectionLag|ObserverRestart"
    equal: ["instance_id"]

  - source_matchers:
      - severity = "info"
      - event = "upgrade-in-progress"
    target_matchers:
      - alertname =~ "ProjectionLag|ObserverRestart|ActionDuration"
    equal: ["instance_id"]
```

### 3.2 Event metric — `arkhe_runtime_operation_in_progress`

When the runtime starts a failover / upgrade, it emits the following metric:

- `arkhe_runtime_operation_in_progress{operation="failover", instance_id="..."} 1`
- `arkhe_runtime_operation_in_progress{operation="upgrade", instance_id="..."} 1`

After completion + 5 min settle, reset to `0` — the alertmanager inhibit rule is automatically released.

### 3.3 Operator CLI

```bash
# At the start of failover, runtime-doctor automatically emits a suspension event.
runtime-doctor failover --to standby-region-2
# Internal: arkhe_runtime_operation_in_progress{operation="failover"} = 1

# Manual suspension (maintenance window) — when the operator pre-announces.
runtime-doctor suspend-slo --duration 30m --reason "planned maintenance"
```

---

## 4. Settle Period — 5 min buffer

A **5 min buffer** immediately after completion of failover / upgrade / degraded recovery:

- During this period, `projection_lag_seconds` is catching up on the existing backlog (catch-up replay), so the probability of SLO violation is high.
- Alertmanager releases the inhibit, but actual alert firing is after a **5 min rolling window**.

---

## 5. Suspension Log — audit trail

All suspension events are append-only entries in `runtime_doctor_journal`:

```
{
  "event": "slo-suspension-start",
  "operation": "failover",
  "initiator": "operator-ed25519-pubkey-<8b>",
  "reason": "primary region us-east-1 unhealthy",
  "started_at_tick": 1234567,
  "expected_duration_minutes": 15
}
```

At suspension end, a corresponding `slo-suspension-end` entry. **Cumulative suspension duration per quarter** is aggregated → operator escalation when the SLO budget is exceeded.

---

## 6. Production Threshold — Suspension Budget

**Alpha goal**:
- Total suspension / quarter ≤ **2 hours** (120 min).
- Individual suspension maximum 30 min (escalation to operator if exceeded).

**Beta goal** (production target):
- Total suspension / quarter ≤ **30 min**.
- Individual suspension maximum 15 min.

If exceeded → (a) failover procedure needs improvement / (b) consider zero-downtime failover in a Multi-active L2 model.

---

## 7. Related Alert Rules (reference)

`alert_rules.yml` (actually written at the KMS integration stage):

```yaml
- alert: ProjectionLagHigh
  expr: arkhe_runtime_projection_lag_seconds > 30
  for: 5m
  labels:
    severity: high
  annotations:
    summary: "L2 projection lag p99 > 30s"
    runbook: "docs/runbook/projection-lag.md"
    # Subject to suspension.

- alert: ChainTipSignatureFailed
  expr: increase(arkhe_runtime_chain_tip_verify_failed_total[5m]) > 0
  labels:
    severity: critical
  annotations:
    summary: "Chain tip signature verification fail"
    # Not subject to suspension — critical always fires.
```

---

---

*This runbook document is the repo baseline. The actual alertmanager rules + metric emission are implemented after the L2 services stage.*
