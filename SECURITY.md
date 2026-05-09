# Security policy

ArkheKernel is a deterministic L0 kernel library with first-class
cryptographic surfaces (BLAKE3-keyed WAL chains, Ed25519 record signatures,
Hybrid PQC Ed25519 + ML-DSA 65 signers, sealed traits across the
capability + host-import boundary). Vulnerabilities affecting any of these
surfaces — or the determinism axioms (A1, A11, A12, A22) that depend on
them — are treated as security issues.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to:

- **Email**: aceamro@gmail.com

Encrypt sensitive payloads if you have a public key for the maintainer; an
unencrypted initial contact requesting a key is also acceptable.

Please include:

1. The affected version (commit hash or crates.io version) and target
   triple.
2. A minimal reproduction (test, snippet, or repro project).
3. The observed vs. expected behaviour, and the security impact you
   believe applies (e.g., chain-integrity bypass, sealed-trait escape,
   determinism break, signature forgery, denial-of-service vector).
4. Optional: a suggested remediation or patch.

Please **do not** open a public GitHub issue, pull request, or
discussion thread for an unfixed vulnerability. Public reports that name
a concrete bypass or chain-integrity defect will be triaged the same as
private reports, but the disclosure window above no longer applies.

## Response expectations

- **Acknowledgement**: within 5 business days.
- **Triage**: within 14 days the report is either confirmed, declined, or
  marked needing-more-info.
- **Fix window**: depends on severity and surface. Security-critical
  defects in a kernel-sealed surface (Layer A invariants A1, A11, A12,
  A22; sealed-trait escape; signature forgery; chain-integrity bypass)
  are prioritised over functional bugs. Coordinated public disclosure is
  agreed with the reporter once a fix is ready.

## Scope

In-scope:

- `arkhe-kernel` (the L0 kernel crate).
- `arkhe-macros` (the derive crate that supplies the sealed `Action`
  byte-path blanket impl).
- The CI/lint gates that protect the seals — `verify-l0-baseline.sh`,
  `verify-axiom-cite.sh`, the `cargo-modules` layer-DAG gate.

Out of scope (please report to the relevant repository):

- ArkheForge runtime / hook host / capability linker — sibling repository.
- Domain shells (BBS, dice, etc.) using ArkheKernel — those repositories
  carry their own security policies.

## Versioning

The kernel ships under a single fixed version (currently v0.13). Security
fixes land on the published version; downstream consumers pinning the
exact version should re-pull after a security release. The version is
intentionally not bumped for routine fixes — see `CHANGELOG.md` for the
release narrative.

## Cryptographic acknowledgements

Cryptographic primitives used by the kernel:

- **BLAKE3** (`blake3` crate) — keyed chain hashing for WAL records.
- **Ed25519** (`ed25519-dalek`) — record signatures (RFC 8032).
- **ML-DSA 65** (`ml-dsa = "=0.1.0-rc.9"`, NIST FIPS 204 / Dilithium-3) —
  PQC signer half of the hybrid Ed25519 + ML-DSA 65 path.

Reports about these crates' upstream defects belong with the upstream
maintainers; reports about how ArkheKernel uses them belong here.
