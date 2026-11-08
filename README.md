# Bismillah ir-Rahman ir-Rahim

# EESS Non-Authorizing Prototype

**Entourage Effect Software Safety Suite -- Decision Lifecycle Prototype**

> *"And We have not sent you except as a mercy to the worlds."* (21:107)

A safety-critical dispatch lifecycle engine with an append-only cryptographic journal, deterministic safety-state reduction, and atomic effect reservation -- hardened through 21 independent adversarial audit rounds that catalogued 18 defect families spanning Python's full trust-boundary attack surface under lock.

---

## At a Glance

| Metric | Value |
|--------|-------|
| **Latest build** | v0.3.24 |
| **Baseline tests** | 330/330 |
| **Normative assertions** | 21/21 |
| **Adversarial regression suites** | P16--P21 (all green) |
| **Frozen invariants** | 56 |
| **Defect families catalogued** | 18 (DF-01 through DF-18) |
| **Independent audit rounds** | 21 (GPT-6, five-field handoff) |
| **Pushed to GitHub** | v0.3.13 (v0.3.24 built, pending push) |

## What This Is

The EESS Muqarnas Evidence Lattice binds six instruments into a coherent evidence-to-execution pipeline. This repository contains the **non-authorizing prototype** that exercises the HABL decision lifecycle:

1. **Claim reservation** -- atomic effect-id binding at J0
2. **Dispatch claim** -- eligibility + epoch CAS + J2 under one lock
3. **Effect confirmation** -- J4a/J4b/J4c with business-effect correlation
4. **Reconciliation** -- J11/J12 evidence and conflict recording
5. **Safety-state reduction** -- deterministic six-priority aggregate

The prototype is **non-authorizing by design**: it demonstrates local correctness under adversarial test conditions, not production deployment trust.

## Architecture

Three core modules, each hardened through systematic exact-type enforcement:

| Module | Role |
|--------|------|
| **HABL Event Store** | Append-only journal with 14 typed event APIs (J0--J12), predecessor-linked SHA-256 hash chain, `_canonicalize_payload` (cycle-aware, depth-bounded, node-counted, byte-budgeted), exact built-in type enforcement, hook-free constant-only diagnostics under lock |
| **Decision Reducer** | Deterministic six-priority aggregate (QUARANTINED > UNKNOWN > CONFIRMED > ALL_NO_EFFECT > NO_SEND > PENDING), BSSG five-conjunct diagnostic, verified-snapshot-only input |
| **Dispatch Engine** | Atomic dispatch claim, capability-contract authority model with backing-store drift detection, three-read stability gate, target-side capability enforcement, overflow-safe retention validation |

## Five Canonical Invariants

- **I-1:** Append-only journal -- no mutation after commit
- **I-2:** Predecessor-linked integrity chain -- each event's hash commits to all preceding events
- **I-3:** Deterministic reducer -- same journal always produces same SafetyState
- **I-4:** Atomic dispatch claim -- eligibility, epoch CAS, and J2 under one lock
- **I-5:** Temporal ordering -- J11 must follow latest J4c by append_offset

Plus 51 additional invariants (C-01 through C-50) covering exact-type enforcement, canonical payload, lock safety, TOCTOU protection, resource bounds, and capability authority.

## The Audit Trail

The P14--P21 arc is a systematic catalogue of Python's trust-boundary attack surface for safety-critical code under lock:

| Round | Defect Family | Attack Surface |
|-------|---------------|----------------|
| P14 | DF-12 | `isinstance` admits subclasses with spoofed `__eq__`/`__hash__` |
| P15 | DF-12 (extended) | Same pattern on capability/outcome fields |
| P16 | DF-12 (journal-complete) | All 14 journal mutator parameters |
| P17 | DF-13 | `copy.deepcopy` invokes `__deepcopy__` hooks on hostile dicts |
| P18 | DF-14 | Virtual method dispatch on `TargetContract` subclasses |
| P19 | DF-15, DF-16 | Mutable-dependency TOCTOU; lock-reentrant `__int__`/`__str__` hooks |
| P20 | DF-15 reopened, DF-17 | Lying getters evade re-read checks; recursive container DoS |
| P21 | DF-15 re-closed, DF-16 re-closed, DF-17 completed, DF-18 | Backing-store drift detection; metaclass `__name__` hooks; aggregate resource limits; caller-controlled capability override |

Every finding is documented with a falsification condition, an adversarial test, and a structural fix. The self-error log tracks the full trajectory.

## Development Discipline

**Fatiha-first:** Module Contracts Declaration is written BEFORE any code. The declaration names what will change, why, and the acceptance criteria. Code satisfies the contracts. Tests verify the contracts. The auditor checks the contracts against the code.

**Two-seat convergence:** Fresh and continuous GPT-6 audit seats produce independent findings. Convergence validates the methodology; divergence reveals blind spots.

**Nothing merges without the project lead's explicit approval.**

## Quick Start

```bash
cd prototype

# Baseline tests
python -I -m unittest discover -s tests -p 'Bismillah_Prototype_v0324_Tests.py' -q
# Ran 330 tests ... OK

# Normative assertions
python -I Bismillah_Normative_Tests_v0_1.py
# Results: 21 passed, 0 failed out of 21

# Adversarial regression suites (P16--P21)
python -I Bismillah_P16_Retargeted_v0324_Tests.py   # 11/11
python -I Bismillah_P17_Retargeted_v0324_Tests.py   # 11/11
python -I Bismillah_P18_Retargeted_v0324_Tests.py   # 9/9
python -I Bismillah_P19_Retargeted_v0324_Tests.py   # 7/7
python -I Bismillah_P20_Retargeted_v0324_Tests.py   # 6/6
python -I Bismillah_P21_Retargeted_v0324_Tests.py   # 7/7
```

## Non-Authorizing Boundary

This prototype demonstrates local correctness under adversarial test fixtures. It does **not** demonstrate:

- External hash anchoring (no signature/MAC or remote witness)
- Production trust (no authenticated target, no signed evidence, no trusted clock)
- Historical reconstruction (no crash-durable journal, no WAL, no replication)
- Authenticated reconciliation (test helper bypasses target authentication)
- True TOCTOU protection in concurrent multi-process environments

Production authorization requires authenticated external provenance, durable concurrency, target-enforced idempotency/fencing, and a race-resistant authorization boundary.

## The EESS Instrument Suite

| Instrument | Role | Repository |
|------------|------|------------|
| **Furqan** | Programming language | [furqan-programming-language](https://github.com/bismillahbilalarfeenbismillah/furqan-programming-language) |
| **FATIMA** | Divine protection encoder | [FATIMA](https://github.com/bismillahbilalarfeenbismillah/FATIMA) |
| **furqan-lint** | Structural honesty linter | [furqan-lint](https://github.com/bismillahbilalarfeenbismillah/furqan-lint) |
| **HABL** | Finding protocol / binding ledger | [habl](https://github.com/bismillahbilalarfeenbismillah/habl) |
| **Bayyinah** | File integrity scanner | [bayyinah-integrity-scanner](https://github.com/bismillahbilalarfeenbismillah/bayyinah-integrity-scanner) |
| **Shahid** | Weight-holder transparency reports | (specification on encoder repo, PR #7) |

No single instrument is the safety story. The entourage effect is.

## Markets and Applications

The engineering pattern -- append-only journaling with hash-chain integrity, atomic effect reservation, monotone safety-state reduction -- applies wherever irrevocable side effects must be auditable and safe:

- **Payment processing and settlement** -- exactly-once dispatch with full audit trail
- **Healthcare order execution** -- medication dispensing, surgical instrument tracking
- **Industrial control / SCADA** -- valve actuation, chemical dosing, power grid switching
- **Autonomous vehicle command arbitration** -- provable single-writer with integrity verification

## License

CC-BY-4.0

## Author

**Bilal Syed Arfeen** -- Independent Researcher

With engineering by Claude (Anthropic, Opus 4.6) and independent audit by GPT-6 (OpenAI).

# Bismillah ir-Rahman ir-Rahim
