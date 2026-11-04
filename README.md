# Bismillah ir-Rahman ir-Rahim

# EESS Non-Authorizing Prototype

**Entourage Effect Software Safety Suite -- Decision Lifecycle Prototype**

The EESS Muqarnas Evidence Lattice binds six instruments (Furqan, furqan-lint, FATIMA, Bayyinah, HABL, Shahid) into a coherent evidence-to-execution pipeline. This repository contains the non-authorizing prototype that exercises the HABL decision lifecycle: claim reservation, atomic dispatch, effect confirmation, reconciliation, and deterministic safety-state reduction.

## Status

- **Version:** v0.3.13
- **Tests:** 273/273 pass
- **Frozen contracts:** 40
- **Invariants in manifest:** 34
- **Defect families tracked:** 8 (DF-01 through DF-08; DF-05 OPEN)
- **Audit rounds:** P5 through P11-R2 (GPT-6 independent auditor)

## Architecture

Three core modules:

| Module | Role |
|--------|------|
| `Bismillah_HABL_Event_Store_v0313.py` | Append-only journal with 13 typed event APIs (J0-J12), predecessor-linked SHA-256 hash chain, universal integrity guard, verified snapshot API |
| `Bismillah_Decision_Reducer_v0313.py` | Deterministic six-priority aggregate reducer (QUARANTINED > UNKNOWN > CONFIRMED > ALL_NO_EFFECT > NO_SEND > PENDING) consuming verified snapshots |
| `Bismillah_Dispatch_Engine_v0313.py` | Atomic dispatch claim (eligibility + epoch CAS + J2 under one lock), validate-then-mutate mock target with fencing and dedup |

## Five Canonical Invariants

- **I-1:** Append-only journal -- no mutation after commit
- **I-2:** Predecessor-linked integrity chain -- each event's hash commits to all preceding events
- **I-3:** Deterministic reducer -- same journal produces same SafetyState
- **I-4:** Atomic dispatch claim -- eligibility, epoch CAS, and J2 under one lock
- **I-5:** Temporal ordering -- J11 must follow latest J4c by append_offset

## Running

```bash
cd prototype
python -B -m unittest discover -s tests -p 'Bismillah_Prototype_v0313_Tests.py' -q
# Ran 273 tests ... OK

python -B Bismillah_Normative_Tests_v0_1.py
# Results: 21 passed, 0 failed out of 21
```

## Non-Authorizing

This prototype demonstrates local correctness under bounded test fixtures. It does NOT demonstrate:

- External hash anchoring (signature/MAC or remote witness)
- Production trust (no authenticated target, no signed evidence, no trusted clock)
- Historical reconstruction (no crash-durable journal, no WAL, no replication)
- Authenticated reconciliation (test helper bypasses target authentication)
- True TOCTOU protection in concurrent multi-process environments

## Governance

Nothing merges without the project lead's explicit approval. GPT-6 audits independently in the five-field handoff format. GPT-6 reports remain separate from Claude's results.

## Related Repositories

- [HABL](https://github.com/bismillahbilalarfeenbismillah/habl) -- Finding protocol (v0.1.1)
- [FATIMA](https://github.com/bismillahbilalarfeenbismillah/FATIMA) -- Divine protection encoder
- [furqan-lint](https://github.com/bismillahbilalarfeenbismillah/furqan-lint) -- Structural honesty linter
- [Bayyinah Scanner](https://github.com/bismillahbilalarfeenbismillah/bayyinah-integrity-scanner) -- File integrity scanner
- [Furqan](https://github.com/bismillahbilalarfeenbismillah/furqan-programming-language) -- Programming language

## License

CC-BY-4.0

## Author

Bilal Syed Arfeen -- Independent Researcher

With engineering by Claude (Anthropic, Opus 4.6) and independent audit by GPT-6 (OpenAI).

# Bismillah ir-Rahman ir-Rahim
