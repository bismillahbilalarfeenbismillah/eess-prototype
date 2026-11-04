# Bismillah ir-Rahman ir-Rahim
# EESS Self-Error Pattern Log -- v0.3.13

## Purpose

Track recurrent defect families across audit rounds to detect structural patterns
and close them at their root cause rather than instance by instance.

## Defect Families

### DF-01: Integrity-Guard-Per-API

- **First seen:** P5
- **Recurred:** P6, P7, P8
- **Closed:** P9 (invariant-by-interface matrix adopted)
- **Pattern:** Each audit round discovered one more public API missing an integrity check. The root cause was that integrity verification was opt-in per method rather than structurally required.
- **Structural fix:** Universal integrity guard (`_require_integrity()`) on all 13 typed mutators; status readers return `None`/`True`/`False`/`[]` on corruption.

### DF-02: Input-Validation-Boundary

- **First seen:** P7
- **Recurred:** P8, P9, P10
- **Closed:** P10 (validate-then-mutate established as architectural pattern)
- **Pattern:** Each round found one more input type the mock/engine accepted without validation. Bool epochs (P7), empty effect_id (P8), non-string J11 tx_id (P8), whitespace effect_id (P9), float epoch (P10), empty hash (P10).
- **Structural fix:** All validation checks precede any state mutation. Single-point-of-mutation pattern in `_record_effect()`.

### DF-03: SHA-256-Representation

- **First seen:** P10
- **Recurred:** P11 (J12 call site missed in P10 fix)
- **Closed:** P11 (all call sites now use `_validate_sha256_hex()`)
- **Pattern:** `int(value, 16)` accepted non-hex-64 strings. P10 fixed the validator but missed the J12 `record_evidence_conflict()` call site which still used the old pattern.
- **Structural fix:** `re.fullmatch(r'[0-9a-fA-F]{64}', value)` in `_validate_sha256_hex()`, called from ALL hash-valued field validations including J12. No raw `int(..., 16)` remains in any hash validation path.

### DF-04: Fencing-State-Mutation-Timing

- **First seen:** P10
- **Closed:** P10
- **Pattern:** `_seen_epochs` was advanced during validation, before the request was accepted. A rejected invalid request could "poison" the epoch state and block subsequent valid requests.
- **Structural fix:** Validate-then-mutate -- `_record_effect()` is the single mutation point, called only after all checks pass.

### DF-05: Trust-Boundary-Contracts

- **First seen:** P8
- **Recurred:** P9
- **Status:** OPEN (deferred to production integration)
- **Pattern:** Test-only reconciliation helper does not authenticate target responses. J11 "not-found" can lead to J4b without verified no-effect window. This is an integration trust contract, not a prototype defect.
- **Expected resolution:** Production executor with authenticated evidence provider.

## Convergence Analysis

| Round | Total Findings | Confirmed | Contract | Boundary | New Families | Closed Families |
|-------|---------------|-----------|----------|----------|-------------|-----------------|
| P5    | 22 gaps       | --        | --       | --       | DF-01       | --              |
| P6    | 27 (broader)  | 8         | --       | --       | --          | --              |
| P7    | 12            | 8         | --       | --       | DF-02       | --              |
| P8    | 9             | 2         | 7        | --       | DF-05       | --              |
| P9    | 12            | 2         | 9        | 1        | --          | DF-01           |
| P10   | 12            | 3 families| --       | --       | DF-03, DF-04| DF-02, DF-03, DF-04 |
| P11   | 4             | 4         | --       | --       | DF-06, DF-07| DF-03 (re-closed), DF-06, DF-07 |

### DF-06: Fail-Open-on-Journal-Error

- **First seen:** P11
- **Closed:** P11
- **Pattern:** Dispatch engine swallowed J3 integrity failure (`except ValueError: pass`) and continued to call the target. The general pattern: exception handling that silences a safety-relevant error and continues to the side-effect.
- **Structural fix:** J3 failure is a no-send halt. Any exception from `record_attempt_observed()` returns BLOCKED without calling the target. Post-J3 revocation re-check added before `target.call()`.

### DF-07: Contract-Claims-Exceed-Implementation

- **First seen:** P11
- **Closed:** P11
- **Pattern:** Contract C07 and invariant I-2 claimed "prev_hash linking" (cryptographic hash chain) but the implementation used independent per-event hashes with no predecessor linkage.
- **Structural fix:** Added `prev_hash` field to `HABLEvent`. `compute_hash()` includes `prev_hash` in hash input. `verify_head()` and `_verify_integrity_under_lock()` check chain linkage. Contract C07 now accurately describes the implementation.

## Trajectory

Defect severity continues the convergent trend. P11 found 4 findings (all confirmed, all same-round closable). Two new defect families emerged:
- DF-06 (fail-open on error) is a cousin of DF-01 (integrity-guard-per-API) -- both involve a missing safety check at a boundary. DF-06 is at the exception-handling level rather than the API validation level.
- DF-07 (contract exceeds implementation) is a NEW family -- the first time the contract documentation overstated what the code actually does. Previous defects were missing code; this is correct code described with a stronger claim than it deserved.

The remaining open item is DF-05 (trust-boundary contracts) which requires production integration.

# Bismillah ir-Rahman ir-Rahim

### DF-08: Negative-Predicate-Authorization-Check

- **First seen:** P11-R2
- **Closed:** P11-R2
- **Pattern:** Post-J3 authorization gate checked `== "REVOKED"` (negative predicate, missing EXPIRED and other non-VALID states) instead of `!= "VALID"` (positive predicate). The pre-J3 guard at line 555 used the correct positive predicate; the post-J3 guard at line 620 did not match it.
- **Structural fix:** Both gates now use `!= "VALID"` (positive authorization predicate). Post-J3 gate also checks `safety == QUARANTINED` for integrity failures injected between the pre-J3 verify and the post-J3 reduce.
- **Related:** DF-06 (fail-open on journal error) -- both are incomplete error-path handling at the dispatch boundary.

