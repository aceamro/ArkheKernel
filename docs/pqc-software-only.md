# PQC software-only signer (operator caveat)

ArkheKernel ships PQC Hybrid signing (Ed25519 + ML-DSA 65, NIST FIPS 204) as a **software-only signer** — `SoftwareMlDsa65Signer` holds key material in process memory exclusively. HSM / KMS provider integrations are a future extension behind the sealed `PqcSigner` / `PqcVerifier` trait abstractions.

This document is the operator-facing caveat. The kernel's [`SignatureClass::Hybrid`](../arkhe-kernel/src/persist/signature.rs) constructor accepts a 32-byte ML-DSA 65 seed; the resulting signing key never leaves the process boundary.

## Software signer rationale

- Hybrid (Ed25519 + ML-DSA 65) is the default for new WALs (write-side strict mode). The classical Ed25519 leg preserves chain-anchor continuity; the post-quantum ML-DSA 65 leg provides forward security against future CRQC adversaries (CNSA 2.0 transition spec).
- HSM / KMS integration is non-trivial: vendor-specific PQC algorithm support is still emerging (most HSMs do not expose ML-DSA primitives). Keeping the in-tree signer software-only avoids a forced choice between (a) early HSM lock-in to a single vendor or (b) blocking PQC adoption on universal HSM availability.
- The `PqcSigner` trait is sealed — by design, `SoftwareMlDsa65Signer` is the only in-tree impl. Future HSM / KMS provider impls integrate through the same trait contract, so adoption is a drop-in `Box<dyn PqcSigner>` swap with no kernel-side changes.

## Key material handling guide

`SoftwareMlDsa65Signer` carries the signing key in process memory:

- **Never serialize the signing key.** The kernel's WAL writer pins only the *verifying* key bytes in the WAL header (`verifying_key_pqc`); the signing key never appears in WAL bytes. `SoftwareMlDsa65Signer` derives `Debug` with the signing key field redacted.
- **Hold the signer behind a process boundary.** Run the kernel with `mlock_all()` to prevent paging / swap residue (Tier-0 process protection guidance in `docs/runbook/tier-0-limitations.md`).
- **Air-gap recommended for high-stakes deployments.** Software-only signers are vulnerable to host-OS-level memory inspection. Internet isolation reduces the adversary surface to physical access.
- **Rotate keys periodically.** ML-DSA 65 has no theoretical lifetime limit (FIPS 204), but operational rotation reduces the impact of any single signing-key compromise. Built-in rotation tooling is not provided; rotation requires a fresh `SoftwareMlDsa65Signer::from_seed(new_seed)` and a new WAL.
- **Seed entropy is critical.** Use a CSPRNG (e.g., `getrandom::getrandom`) to generate the 32-byte seed before passing it to `SignatureClass::new_hybrid_from_secrets`. Do not derive seeds from low-entropy sources (passwords, timestamps).

## Deployment tier matrix

ArkheKernel software-only signer suitability by deployment context:

| Tier | Context | Recommendation |
|---|---|---|
| **Tier 0 — personal dev / prototype** | Local development, testing, demos | **Software signer OK.** No real users, no compliance scope. |
| **Tier 1 — general SaaS** | Public-facing apps with ordinary user data | **Software signer + air-gap signing recommended.** Sign WALs in an isolated process / VM; verify on the public service. Use the ML-DSA 65 chain-anchor as the trust root for downstream consumers. |
| **Tier 2 — regulated industries** | Finance, healthcare, government (HIPAA / PCI / FedRAMP) | **Wait for an HSM-backed deployment path.** A software-only signer does not meet FIPS 140 hardware-token requirements. Operate Tier-0 dev environments to evaluate the kernel; defer production deployment until an HSM provider integration is available. |

## HSM / KMS forward-compat

When HSM / KMS providers are added behind the `PqcSigner` seam, four categories of additional implementation work are expected:

1. **Provider-specific `PqcSigner` impls.** Each HSM vendor (e.g., Thales Luna, Entrust nShield, AWS CloudHSM) exposes PQC primitives via PKCS#11 or vendor SDKs. The `PqcSigner` trait is the integration seam — provider impls wrap the vendor API and satisfy the trait contract. The kernel itself requires no changes beyond unsealing the trait.
2. **Operator key-attestation flow.** Production HSMs emit attestation statements proving that a signing key was generated inside the secure boundary. Attestation verification integrates into the kernel boot sequence via a `RuntimeBootstrap` event extension.
3. **Multi-region / multi-HSM redundancy.** High-availability deployments need quorum signing or cross-HSM key replication. A `PqcSignerQuorum<N>` wrapper composing multiple `Box<dyn PqcSigner>` providers covers this; kernel `SignatureClass::Hybrid` composes orthogonally.
4. **Migration tooling.** Operators running the software signer in production (Tier 0 / Tier 1) will need a migration path to HSM-backed signers. The intended shape is `arkhe-runtime-doctor pqc-migrate-software-to-hsm`: an offline batch that re-signs the chain tip under the new HSM key and emits a `SignatureClassPolicy` event documenting the transition.

## References

- [`arkhe-kernel/src/persist/signature.rs`](../arkhe-kernel/src/persist/signature.rs) — `PqcSigner` / `PqcVerifier` traits + `SoftwareMlDsa65Signer` / `SoftwareMlDsa65Verifier` impl + `SignatureClass::Hybrid` constructor.
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA, Dilithium-3 = ML-DSA 65). <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>
- NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0, Hybrid transition spec (Ed25519 + ML-DSA 65 dual-sign for 2026-2030 transition window). <https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3148990/>
- RustCrypto `ml-dsa` crate — <https://github.com/RustCrypto/signatures/tree/master/ml-dsa>
