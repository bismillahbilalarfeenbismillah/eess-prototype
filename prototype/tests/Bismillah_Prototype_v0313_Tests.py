# Bismillah ir-Rahman ir-Rahim
"""
EESS Prototype v0.3.13 Test Suite -- Immutable ownership + universal integrity.

Tests organized by finding:
  1. Core journal lockdown (append is private)
  2. P4-F01: Validate-then-commit -- no partial state on serialization failure
  3. P4-F02: Reconciliation always UNKNOWN; test helper for authenticated recon
  4. P4-F03: Strict J4 type validation (evidence_hash, no_effect_evidence, TX ID)
  5. P4-F04: MockTarget request-hash enforcement + effect-level hash validation
  6. P4-F05: Strict capability enum (only canonical values accepted)
  7. P4-F06: J12 business_effect_id must match J2 binding
  8. P4-F07: Global attempt_id uniqueness across decisions
  9. P4-F08: Request hash validated as 64-character hexadecimal SHA-256
 10. P3-R1: Typed J6/J7 with ownership validation (regression)
 11. Full dispatch lifecycle (regression + updated for new constraints)
 12. Reducer tests (carried forward)
 13. Journal integrity (regression)
 14. Concurrent dispatch (regression)
 -- P5 FINDINGS (carried forward) --
 15. P5-F01: Deep copy + tamper rejection
 16. P5-F02: Evidence validation hardened
 17. P5-F03: Mock dedup full operation binding
 18. P5-F04: Malformed target response handling
 19. P5-F05: Strict scalar/enum validation on identifiers
 20. P5-F06: NaN/Infinity rejection in payloads
 21. P5-F07: Dedup retention validation
 22. P5-F08: J12 duplicate conflict deduplication
 23. P5-F09: J11 query_result validation
 24. P5-F10: Test-only reconciliation boundary
 25. P5 additional regressions
 -- NEW P6 FINDINGS --
 26. P6-F01: Immutable event ownership (payload alias, returned event alias)
 27. P6-F02: Universal integrity guard on ALL 13 typed paths
 28. P6-F03: decision_id validation at all write entry points
 29. P6-F04: Reconciliation sequence enforcement (J4c -> J11 -> J4a/J4b)
 30. P6-F05: Adapter retention required
 31. P6-F06: Atomic reader snapshots
 32. P6-F07: Empty decision filter scope

NON-AUTHORIZING PROTOTYPE.
"""

import sys
import os
import hashlib
import math
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Bismillah_HABL_Event_Store_v0313 import (
    HABLJournal, EventType, HABLEvent, VALID_CAPABILITIES, VALID_CLOSE_REASONS)
from Bismillah_Decision_Reducer_v0313 import (
    DecisionReducer, SafetyState, BusinessEffect, AttemptState)
from Bismillah_Dispatch_Engine_v0313 import (
    DispatchEngine, MockTarget, TargetContract, TargetCapability, DispatchResult)


# ===========================================================================
# Test hash constants -- all 64-char hex (P4-F08 compliance)
# ===========================================================================

HASH_A = hashlib.sha256(b"test_hash_a").hexdigest()
HASH_B = hashlib.sha256(b"test_hash_b").hexdigest()
HASH_C = hashlib.sha256(b"test_hash_c").hexdigest()
HASH_D = hashlib.sha256(b"test_hash_d").hexdigest()
HASH_WRONG = hashlib.sha256(b"wrong_hash").hexdigest()
EVIDENCE_HASH = hashlib.sha256(b"evidence").hexdigest()
CONFLICT_HASH = "a" * 64


# ===========================================================================
# Helpers
# ===========================================================================

def make_journal():
    return HABLJournal()


def commit_j0(journal, decision_id="D-1", target="TARGET-1",
              business_effect_id="EFF-1", claim_id="CLM-1"):
    return journal.reserve_effect_and_commit_decision(
        decision_id=decision_id,
        business_effect_id=business_effect_id,
        payload={
            "claim_id": claim_id, "action": "SEND_EMAIL",
            "target": target, "policy_version": "POL-1",
            "approval_ref": "APR-1", "business_effect_id": business_effect_id})


def dispatch_and_resolve(journal, decision_id="D-1", target="TARGET-1",
                         effect_id="EFF-1", attempt_id="ATT-1",
                         outcome="confirm"):
    """Helper: J0 + atomic dispatch + target call + J4a/J4b + release."""
    commit_j0(journal, decision_id, target, effect_id)
    j1, j2 = journal.atomic_dispatch_claim(
        decision_id=decision_id, target=target,
        worker_id="w1", attempt_id=attempt_id,
        request_hash=HASH_A, idempotency_key="KEY-1",
        target_capability="TARGET_DEDUP_ENFORCED",
        business_effect_id=effect_id)
    epoch = j1.payload["epoch"]
    journal.record_attempt_observed(decision_id, attempt_id)
    if outcome == "confirm":
        journal.record_effect_confirmed(
            decision_id, attempt_id,
            target_transaction_id="TX-1",
            request_hash=HASH_A, evidence_hash=EVIDENCE_HASH,
            business_effect_id=effect_id)
    elif outcome == "no_effect":
        journal.record_no_effect(
            decision_id, attempt_id,
            target_transaction_id="TX-1",
            request_hash=HASH_A,
            no_effect_evidence="rejected by target",
            business_effect_id=effect_id)
    journal.release_lease(decision_id, target, "w1", epoch)
    return j1, j2


# ===========================================================================
# 1. CORE JOURNAL LOCKDOWN
# ===========================================================================

class TestJournalLockdown(unittest.TestCase):

    def test_no_public_append(self):
        j = make_journal()
        self.assertFalse(hasattr(j, 'append'))

    def test_j0_requires_typed_api(self):
        j = make_journal()
        commit_j0(j)
        evts = j.get_events(event_type=EventType.DECISION_COMMITTED)
        self.assertEqual(len(evts), 1)

    def test_j1_j2_requires_typed_api(self):
        j = make_journal()
        commit_j0(j)
        j1, j2 = j.atomic_dispatch_claim(
            "D-1", "TARGET-1", "w1", "ATT-1", HASH_A, "KEY-1",
            "TARGET_DEDUP_ENFORCED", "EFF-1")
        self.assertEqual(j1.event_type, EventType.LEASE_ACQUIRED)
        self.assertEqual(j2.event_type, EventType.SEND_INTENT_COMMITTED)

    def test_all_event_types_via_typed_apis(self):
        """Every event type J0-J12 is created via typed API."""
        j = make_journal()
        commit_j0(j)
        j1, j2 = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                          HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_attempt_observed("D-1", "ATT-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        j.release_lease("D-1", "TARGET-1", "w1", j1.payload["epoch"])
        j.record_human_review("D-1", reason="test")
        j.record_authorization_revoked("D-1")
        j.record_evidence_conflict("D-1", "ATT-1", "REF", CONFLICT_HASH)
        events = j.replay()
        types = {e.event_type for e in events}
        for expected in [EventType.DECISION_COMMITTED, EventType.LEASE_ACQUIRED,
                         EventType.SEND_INTENT_COMMITTED, EventType.ATTEMPT_OBSERVED,
                         EventType.TARGET_EFFECT_CONFIRMED, EventType.HUMAN_REVIEW_REQUESTED,
                         EventType.LEASE_RELEASED, EventType.AUTHORIZATION_REVOKED,
                         EventType.EVIDENCE_CONFLICT]:
            self.assertIn(expected, types)


# ===========================================================================
# 2. P4-F01: VALIDATE-THEN-COMMIT
# ===========================================================================

class TestValidateThenCommit(unittest.TestCase):

    def test_malformed_worker_no_state_mutation(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", object(), "ATT-1",
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self.assertEqual(j.get_epoch_floor("D-1", "TARGET-1"), 0)
        events = j.get_events()
        self.assertEqual(len(events), 1)
        self.assertTrue(j.verify_head()[0])

    def test_malformed_worker_does_not_block_next_claim(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", object(), "ATT-1",
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j1, j2 = j.atomic_dispatch_claim("D-1", "TARGET-1", "good_worker", "ATT-2",
                                          HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self.assertEqual(j1.payload["epoch"], 1)

    def test_nonserializable_capability_no_state_mutation(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", {"bad": object()}, "EFF-1")
        self.assertEqual(j.get_epoch_floor("D-1", "TARGET-1"), 0)

    def test_j0_serialization_failure_no_reservation(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision("D-1", "EFF-1",
                {"claim_id": "C1", "action": "SEND", "target": "T1",
                 "policy_version": "P1", "approval_ref": "A1",
                 "business_effect_id": "EFF-1", "bad_field": object()})
        self.assertIsNone(j.is_effect_reserved("EFF-1"))

    def test_j6_release_atomic(self):
        j = make_journal()
        commit_j0(j)
        j1, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                         HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        epoch = j1.payload["epoch"]
        j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                           no_effect_evidence="rejected",
                           business_effect_id="EFF-1")
        j.release_lease("D-1", "TARGET-1", "w1", epoch)
        j1b, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w2", "ATT-2",
                                          HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self.assertEqual(j1b.payload["epoch"], 2)

    def test_replay_equivalence_after_valid_claim(self):
        j = make_journal()
        commit_j0(j)
        j1, j2 = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                          HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self.assertEqual(j.get_epoch_floor("D-1", "TARGET-1"), j1.payload["epoch"])
        events = j.get_events()
        self.assertEqual(len(events), 3)
        self.assertTrue(j.verify_head()[0])


# ===========================================================================
# 3. P4-F02: RECONCILIATION ALWAYS UNKNOWN
# ===========================================================================

class TestReconciliationTrustBoundary(unittest.TestCase):

    def test_reconciliation_always_returns_unknown(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior="timeout", target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        recon = eng.record_reconciliation(
            "D-1", result.attempt_id, "TX found in target", tx_id="TX-99")
        self.assertEqual(recon.outcome, "UNKNOWN")

    def test_reconciliation_no_definitive_param(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        import inspect
        sig = inspect.signature(eng.record_reconciliation)
        self.assertNotIn("definitive", sig.parameters)
        self.assertNotIn("effect_confirmed", sig.parameters)

    def test_reconciliation_not_found_stays_unknown(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior="timeout", target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        recon = eng.record_reconciliation("D-1", result.attempt_id, "not found")
        self.assertEqual(recon.outcome, "UNKNOWN")
        agg = r.reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.UNKNOWN)

    def test_test_helper_simulated_confirm(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior="timeout", target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        # v0.3.13: J4c exists, so J11 is needed before J4a via test helper
        recon = eng._test_simulate_authenticated_reconciliation(
            "D-1", result.attempt_id, "TX found", tx_id="TX-RECON", effect_confirmed=True)
        self.assertTrue(recon.success)
        self.assertEqual(recon.outcome, "CONFIRMED")
        agg = r.reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.TERMINAL_CONFIRMED)

    def test_test_helper_simulated_no_effect(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior="timeout", target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        # v0.3.13: test helper records J11 internally before J4b
        recon = eng._test_simulate_authenticated_reconciliation(
            "D-1", result.attempt_id, "not found", effect_confirmed=False)
        self.assertTrue(recon.success)
        self.assertEqual(recon.outcome, "NO_EFFECT")


# ===========================================================================
# 4. P4-F03: STRICT J4 TYPE VALIDATION
# ===========================================================================

class TestJ4StrictTypes(unittest.TestCase):

    def _j4_ready_journal(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        return j

    def test_j4a_empty_evidence_hash_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash="")

    def test_j4a_valid_evidence_hash_accepted(self):
        j = self._j4_ready_journal()
        e = j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash=EVIDENCE_HASH,
                                       business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.TARGET_EFFECT_CONFIRMED)

    def test_j4b_boolean_tx_id_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", True, HASH_A)

    def test_j4b_numeric_tx_id_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", 12345, HASH_A)

    def test_j4b_list_no_effect_evidence_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                                no_effect_evidence=["false"])

    def test_j4b_dict_no_effect_evidence_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                                no_effect_evidence={"reason": "none"})

    def test_j4b_bool_no_effect_evidence_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                                no_effect_evidence=False)

    def test_j4b_valid_string_accepted(self):
        j = self._j4_ready_journal()
        e = j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                                no_effect_evidence="rejected by target",
                                business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.TARGET_NO_EFFECT)


# ===========================================================================
# 5. P4-F04: MOCKTARGET REQUEST-HASH ENFORCEMENT
# ===========================================================================

class TestMockTargetHashEnforcement(unittest.TestCase):

    def test_empty_request_hash_rejected(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        r = mt.call({"idempotency_key": "K1", "request_hash": "",
                      "business_effect_id": "E1", "decision_id": "D1", "epoch": 1})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_effect_dedup_different_hash_rejected(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        r1 = mt.call({"idempotency_key": "K1", "request_hash": HASH_A,
                       "business_effect_id": "E1", "decision_id": "D1", "epoch": 1})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = mt.call({"idempotency_key": "K2", "request_hash": HASH_B,
                       "business_effect_id": "E1", "decision_id": "D2", "epoch": 1})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")

    def test_effect_dedup_same_hash_accepted(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        r1 = mt.call({"idempotency_key": "K1", "request_hash": HASH_A,
                       "business_effect_id": "E1", "decision_id": "D1", "epoch": 1})
        tx1 = r1[1]
        r2 = mt.call({"idempotency_key": "K2", "request_hash": HASH_A,
                       "business_effect_id": "E1", "decision_id": "D2", "epoch": 1})
        self.assertEqual(r2[0], "DEFINITIVE_EFFECT")
        self.assertEqual(r2[1], tx1)

    def test_request_key_conflict_still_works(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        mt.call({"idempotency_key": "K1", "request_hash": HASH_A,
                  "business_effect_id": "E1", "decision_id": "D1", "epoch": 1})
        r = mt.call({"idempotency_key": "K1", "request_hash": HASH_B,
                      "business_effect_id": "E1", "decision_id": "D1", "epoch": 2})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_callable_response_tx_for_dedup(self):
        real_tx = "REAL-TX-FROM-TARGET"
        def custom(req):
            return ("DEFINITIVE_EFFECT", real_tx, "Custom")
        mt = MockTarget(behavior=custom, capability="TARGET_DEDUP_ENFORCED")
        r1 = mt.call({"idempotency_key": "K1", "request_hash": HASH_A,
                       "business_effect_id": "E1", "decision_id": "D1", "epoch": 1})
        self.assertEqual(r1[1], real_tx)
        r2 = mt.call({"idempotency_key": "K1", "request_hash": HASH_A,
                       "business_effect_id": "E1", "decision_id": "D1", "epoch": 2})
        self.assertEqual(r2[1], real_tx)


# ===========================================================================
# 6-9. P4-F05/F06/F07/F08 (capability, J12 binding, attempt uniqueness, hash)
# ===========================================================================

class TestCapabilityEnum(unittest.TestCase):

    def test_arbitrary_capability_denied(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", "MAGIC_CAPABILITY", "EFF-1")

    def test_none_capability_denied(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", None, "EFF-1")

    def test_empty_capability_denied(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", "", "EFF-1")

    def test_unsupported_denied(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", "UNSUPPORTED", "EFF-1")

    def test_valid_capabilities_accepted(self):
        for cap in sorted(VALID_CAPABILITIES):
            j = make_journal()
            commit_j0(j, decision_id=f"D-{cap}", claim_id=f"C-{cap}")
            j1, j2 = j.atomic_dispatch_claim(
                f"D-{cap}", "TARGET-1", "w1", f"ATT-{cap}",
                HASH_A, f"K-{cap}", cap, "EFF-1")
            self.assertEqual(j2.payload["target_capability"], cap)


class TestJ12EffectBinding(unittest.TestCase):

    def test_j12_wrong_effect_id_denied(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        with self.assertRaises(ValueError):
            j.record_evidence_conflict("D-1", "ATT-1", "REF-1", CONFLICT_HASH,
                                        business_effect_id="DIFFERENT-EFFECT")

    def test_j12_correct_effect_id_accepted(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        e = j.record_evidence_conflict("D-1", "ATT-1", "REF-1", CONFLICT_HASH,
                                        business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.EVIDENCE_CONFLICT)

    def test_j12_omitted_effect_id_binds_from_j2(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        e = j.record_evidence_conflict("D-1", "ATT-1", "REF-1", CONFLICT_HASH)
        self.assertEqual(e.payload["business_effect_id"], "EFF-1")


class TestGlobalAttemptUniqueness(unittest.TestCase):

    def test_same_attempt_id_different_decisions_denied(self):
        j = make_journal()
        commit_j0(j, decision_id="D-1", business_effect_id="EFF-1")
        commit_j0(j, decision_id="D-2", business_effect_id="EFF-2", claim_id="CLM-2")
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-SHARED",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-2", "TARGET-1", "w2", "ATT-SHARED",
                                    HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-2")

    def test_different_attempt_ids_accepted(self):
        j = make_journal()
        commit_j0(j, decision_id="D-1", business_effect_id="EFF-1")
        commit_j0(j, decision_id="D-2", business_effect_id="EFF-2", claim_id="CLM-2")
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.atomic_dispatch_claim("D-2", "TARGET-1", "w2", "ATT-2",
                                HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-2")
        self.assertEqual(len(j.get_events(event_type=EventType.SEND_INTENT_COMMITTED)), 2)


class TestRequestHashFormat(unittest.TestCase):

    def test_short_hash_denied(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    "abc123", "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_non_hex_hash_denied(self):
        j = make_journal()
        commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    "g" * 64, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_valid_64_hex_accepted(self):
        j = make_journal()
        commit_j0(j)
        j1, j2 = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                          HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self.assertEqual(j2.payload["request_hash"], HASH_A)

    def test_j4a_short_hash_denied(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.record_effect_confirmed("D-1", "ATT-1", "TX-1", "short")

    def test_j4b_short_hash_denied(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "TX-1", "short")


# ===========================================================================
# 10. LEASE OWNERSHIP (REGRESSION)
# ===========================================================================

class TestLeaseOwnership(unittest.TestCase):

    def test_j6_wrong_worker_denied(self):
        j = make_journal()
        commit_j0(j)
        j1, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "legit", "ATT-1",
                                         HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.release_lease("D-1", "TARGET-1", "intruder", j1.payload["epoch"])

    def test_j6_wrong_epoch_denied(self):
        j = make_journal()
        commit_j0(j)
        j1, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                         HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.release_lease("D-1", "TARGET-1", "w1", j1.payload["epoch"] + 5)

    def test_j7_wrong_epoch_denied(self):
        j = make_journal()
        commit_j0(j)
        j1, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                         HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.expire_lease("D-1", "TARGET-1", j1.payload["epoch"] + 5)

    def test_valid_release_then_new_claim(self):
        j = make_journal()
        commit_j0(j)
        j1, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                         HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                           no_effect_evidence="rejected",
                           business_effect_id="EFF-1")
        j.release_lease("D-1", "TARGET-1", "w1", j1.payload["epoch"])
        j1b, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w2", "ATT-2",
                                          HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self.assertEqual(j1b.payload["epoch"], 2)


# ===========================================================================
# 11. FULL DISPATCH LIFECYCLE
# ===========================================================================

class TestDispatchLifecycle(unittest.TestCase):

    def _make_engine(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        return j, r, eng

    def test_happy_path_confirm(self):
        j, r, eng = self._make_engine()
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertTrue(result.success)
        self.assertEqual(result.outcome, "CONFIRMED")
        agg = r.reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.TERMINAL_CONFIRMED)

    def test_happy_path_reject(self):
        j, r, eng = self._make_engine()
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior="reject", target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertFalse(result.success)
        self.assertEqual(result.outcome, "NO_EFFECT")

    def test_happy_path_timeout(self):
        j, r, eng = self._make_engine()
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior="timeout", target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "UNKNOWN")

    def test_close_no_send(self):
        j, r, eng = self._make_engine()
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.close_no_send("D-1", "BUDGET_EXHAUSTED")
        self.assertTrue(result.success)
        self.assertEqual(result.outcome, "NO_SEND")
        agg = r.reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.TERMINAL_NO_SEND)

    def test_target_mismatch_blocked(self):
        j, r, eng = self._make_engine()
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(target_id="TARGET-WRONG"),
            TargetContract("TARGET-WRONG", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_double_dispatch_terminal_blocked(self):
        j, r, eng = self._make_engine()
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        r1 = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertTrue(r1.success)
        r2 = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertFalse(r2.success)

    def test_conflict_quarantines(self):
        j, r, eng = self._make_engine()
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        r1 = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        cr = eng.record_conflict("D-1", r1.attempt_id, "external-audit", "b" * 64)
        self.assertEqual(cr.outcome, "QUARANTINED")
        agg = r.reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.QUARANTINED)


# ===========================================================================
# 12. REDUCER
# ===========================================================================

class TestReducer(unittest.TestCase):

    def test_empty_decision(self):
        j = make_journal()
        r = DecisionReducer(j)
        agg = r.reduce("D-NONE")
        self.assertEqual(agg.safety, SafetyState.PENDING)
        self.assertFalse(agg.dispatchable)

    def test_pending_dispatchable(self):
        j = make_journal()
        r = DecisionReducer(j)
        commit_j0(j)
        agg = r.reduce("D-1")
        self.assertTrue(agg.dispatchable)

    def test_revoked_not_dispatchable(self):
        j = make_journal()
        r = DecisionReducer(j)
        commit_j0(j)
        j.record_authorization_revoked("D-1")
        agg = r.reduce("D-1")
        self.assertEqual(agg.authorization_state, "REVOKED")
        self.assertFalse(agg.dispatchable)

    def test_no_send_terminal(self):
        j = make_journal()
        r = DecisionReducer(j)
        commit_j0(j)
        j.close_no_send_atomic("D-1", "BUDGET_EXHAUSTED", "w1")
        agg = r.reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.TERMINAL_NO_SEND)


# ===========================================================================
# 13. JOURNAL INTEGRITY (REGRESSION)
# ===========================================================================

class TestJournalIntegrity(unittest.TestCase):

    def test_monotonic_offsets(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        for i, e in enumerate(j.replay()):
            self.assertEqual(e.append_offset, i)

    def test_hash_tamper_detection(self):
        j = make_journal()
        commit_j0(j)
        j._events[0].payload["TAMPERED"] = True
        valid, _, _ = j.verify_head()
        self.assertFalse(valid)

    def test_effect_reservation_cross_decision(self):
        j = make_journal()
        commit_j0(j, decision_id="D-1", business_effect_id="EFF-1")
        with self.assertRaises(ValueError):
            commit_j0(j, decision_id="D-2", business_effect_id="EFF-1", claim_id="CLM-2")

    def test_effect_released_on_j10(self):
        j = make_journal()
        commit_j0(j)
        j.close_no_send_atomic("D-1", "BUDGET_EXHAUSTED", "w1")
        commit_j0(j, decision_id="D-2", business_effect_id="EFF-1", claim_id="CLM-2")
        self.assertEqual(len(j.get_events(decision_id="D-2",
                            event_type=EventType.DECISION_COMMITTED)), 1)

    def test_revoked_blocks_dispatch_claim(self):
        j = make_journal()
        commit_j0(j)
        j.record_authorization_revoked("D-1")
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_quarantined_blocks_dispatch_claim(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        j.record_evidence_conflict("D-1", "ATT-1", "REF", "e" * 64)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w2", "ATT-2",
                                    HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_duplicate_attempt_denied(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                           no_effect_evidence="rejected",
                           business_effect_id="EFF-1")
        j.release_lease("D-1", "TARGET-1", "w1", 1)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w2", "ATT-1",
                                    HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_exclusive_lease(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w2", "ATT-2",
                                    HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-1")


# ===========================================================================
# 14. CONCURRENT DISPATCH (REGRESSION)
# ===========================================================================

class TestConcurrentDispatch(unittest.TestCase):

    def test_20_run_8_worker_single_call(self):
        for run in range(20):
            j = make_journal()
            r = DecisionReducer(j)
            j.reserve_effect_and_commit_decision("D-1", "EFF-1",
                {"claim_id": "C1", "action": "SEND_EMAIL", "target": "TARGET-1",
                 "policy_version": "P1", "approval_ref": "A1",
                 "business_effect_id": "EFF-1"})
            mt = MockTarget(target_id="TARGET-1", behavior="confirm")
            tc = TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600)
            engines = [DispatchEngine(j, r) for _ in range(8)]
            gate = threading.Barrier(8)
            outcomes = []
            def work(e):
                gate.wait()
                outcomes.append(e.dispatch("D-1", mt, tc).outcome)
            threads = [threading.Thread(target=work, args=(e,)) for e in engines]
            for t in threads: t.start()
            for t in threads: t.join(timeout=5)
            self.assertFalse(any(t.is_alive() for t in threads),
                             f"Deadlock on run {run}")
            self.assertEqual(mt.call_count, 1,
                             f"Run {run}: expected 1 call, got {mt.call_count}")

    def test_concurrent_effect_reservation(self):
        j = make_journal()
        gate = threading.Barrier(8)
        results = []
        def worker(n):
            gate.wait()
            try:
                j.reserve_effect_and_commit_decision(
                    f"D-{n}", "SHARED-EFF",
                    {"claim_id": f"C{n}", "action": "SEND", "target": "T1",
                     "policy_version": "P1", "approval_ref": "A1",
                     "business_effect_id": "SHARED-EFF"})
                results.append("accepted")
            except ValueError:
                results.append("rejected")
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("rejected"), 7)


# ===========================================================================
# 15-25. P5 FINDINGS (carried forward, updated for v0.3.13 behavior)
# ===========================================================================

class TestIntegrityBoundOps(unittest.TestCase):
    """P5-F01 + P6-F01: Deep copy and tamper rejection."""

    def test_get_events_returns_deep_copies(self):
        j = make_journal()
        commit_j0(j)
        events = j.get_events()
        events[0].payload["action"] = "ALTERED"
        self.assertTrue(j.verify_head()[0])

    def test_replay_returns_deep_copies(self):
        j = make_journal()
        commit_j0(j)
        events = j.replay()
        events[0].payload["target"] = "ALTERED"
        self.assertTrue(j.verify_head()[0])

    def test_tamper_j0_blocks_dispatch_claim(self):
        j = make_journal()
        commit_j0(j)
        j._events[0].payload["action"] = "altered"
        self.assertFalse(j.verify_head()[0])
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_tamper_j2_blocks_effect_confirmed(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j._events[2].payload["idempotency_key"] = "altered"
        with self.assertRaises(ValueError):
            j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A, EVIDENCE_HASH)

    def test_tamper_j0_blocks_reserve_effect(self):
        j = make_journal()
        commit_j0(j, decision_id="D-1", business_effect_id="EFF-1")
        j._events[0].payload["action"] = "altered"
        with self.assertRaises(ValueError):
            commit_j0(j, decision_id="D-2", business_effect_id="EFF-2", claim_id="CLM-2")


class TestEvidenceValidation(unittest.TestCase):
    """P5-F02"""

    def _j4_ready_journal(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        return j

    def test_j4b_empty_no_effect_evidence_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "", HASH_A, no_effect_evidence="")

    def test_j4b_whitespace_no_effect_evidence_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "", HASH_A, no_effect_evidence="   ")

    def test_j4a_arbitrary_text_evidence_hash_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash="arbitrary-text")

    def test_j4a_non_hex_64char_evidence_hash_denied(self):
        j = self._j4_ready_journal()
        with self.assertRaises(ValueError):
            j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash="g" * 64)

    def test_j4a_valid_sha256_evidence_hash_accepted(self):
        j = self._j4_ready_journal()
        e = j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash=EVIDENCE_HASH,
                                       business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.TARGET_EFFECT_CONFIRMED)


class TestMockDedupBinding(unittest.TestCase):
    """P5-F03"""

    def test_same_key_different_effect_id_conflict(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        r1 = mt.call({"decision_id": "D1", "idempotency_key": "K",
                       "business_effect_id": "E1", "request_hash": HASH_A, "epoch": 1})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = mt.call({"decision_id": "D2", "idempotency_key": "K",
                       "business_effect_id": "E2", "request_hash": HASH_A, "epoch": 1})
        self.assertNotEqual(r2[0], "DEFINITIVE_EFFECT")

    def test_same_key_same_effect_id_dedup(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        r1 = mt.call({"decision_id": "D1", "idempotency_key": "K",
                       "business_effect_id": "E1", "request_hash": HASH_A, "epoch": 1})
        r2 = mt.call({"decision_id": "D2", "idempotency_key": "K",
                       "business_effect_id": "E1", "request_hash": HASH_A, "epoch": 1})
        self.assertEqual(r2[0], "DEFINITIVE_EFFECT")
        self.assertEqual(r2[1], r1[1])


class TestMalformedTargetResponse(unittest.TestCase):
    """P5-F04"""

    def _dispatch_with_behavior(self, behavior):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        return eng.dispatch("D-1",
            MockTarget(behavior=behavior, target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))

    def test_none_response_unknown(self):
        result = self._dispatch_with_behavior(lambda req: None)
        self.assertEqual(result.outcome, "UNKNOWN")

    def test_numeric_detail_unknown(self):
        result = self._dispatch_with_behavior(lambda req: ("DEFINITIVE_EFFECT", "TX", 123))
        self.assertEqual(result.outcome, "UNKNOWN")

    def test_wrong_arity_unknown(self):
        result = self._dispatch_with_behavior(lambda req: ("DEFINITIVE_EFFECT", "TX"))
        self.assertEqual(result.outcome, "UNKNOWN")

    def test_non_tuple_unknown(self):
        result = self._dispatch_with_behavior(lambda req: "DEFINITIVE_EFFECT")
        self.assertEqual(result.outcome, "UNKNOWN")

    def test_numeric_detail_lease_released(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior=lambda req: ("DEFINITIVE_EFFECT", "TX", 123),
                       target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "UNKNOWN")
        unknowns = j.get_events(decision_id="D-1", event_type=EventType.OUTCOME_UNKNOWN)
        self.assertGreaterEqual(len(unknowns), 1)


class TestScalarEnumValidation(unittest.TestCase):
    """P5-F05"""

    def test_j2_boolean_attempt_id_denied(self):
        j = make_journal(); commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", True,
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_j2_boolean_idempotency_key_denied(self):
        j = make_journal(); commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, True, "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_j2_list_attempt_id_typed_denial(self):
        j = make_journal(); commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", ["x"],
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_j2_dict_idempotency_key_typed_denial(self):
        j = make_journal(); commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, {"x": 1}, "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_blank_worker_id_denied(self):
        j = make_journal(); commit_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "   ", "ATT-1",
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")

    def test_j10_invalid_close_reason_denied(self):
        j = make_journal(); commit_j0(j)
        with self.assertRaises(ValueError):
            j.close_no_send_atomic("D-1", "INVENTED_REASON", "w1")

    def test_j10_valid_close_reasons_accepted(self):
        for reason in sorted(VALID_CLOSE_REASONS):
            j = make_journal()
            commit_j0(j, decision_id=f"D-{reason}", claim_id=f"C-{reason}",
                      business_effect_id=f"E-{reason}")
            j.close_no_send_atomic(f"D-{reason}", reason, "w1")
            self.assertTrue(j.verify_head()[0])


class TestNanRejection(unittest.TestCase):
    """P5-F06"""

    def test_j0_nan_in_payload_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision("D-1", "EFF-1",
                {"claim_id": "C1", "action": "SEND", "target": "T1",
                 "policy_version": "P1", "approval_ref": "A1",
                 "business_effect_id": "EFF-1", "extra": float("nan")})

    def test_j0_infinity_in_payload_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision("D-1", "EFF-1",
                {"claim_id": "C1", "action": "SEND", "target": "T1",
                 "policy_version": "P1", "approval_ref": "A1",
                 "business_effect_id": "EFF-1", "extra": float("inf")})

    def test_j3_nan_transport_metadata_denied(self):
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        with self.assertRaises(ValueError):
            j.record_attempt_observed("D-1", "ATT-1", float("nan"))

    def test_j0_nested_nan_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision("D-1", "EFF-1",
                {"claim_id": "C1", "action": "SEND", "target": "T1",
                 "policy_version": "P1", "approval_ref": "A1",
                 "business_effect_id": "EFF-1",
                 "nested": {"deep": [1, 2, float("nan")]}})


class TestRetentionValidation(unittest.TestCase):
    """P5-F07"""

    def _make_dispatch_engine(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        return j, r, eng

    def test_nan_retention_blocked(self):
        j, r, eng = self._make_dispatch_engine()
        result = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", float("nan")))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_boolean_retention_blocked(self):
        j, r, eng = self._make_dispatch_engine()
        result = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", True))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_zero_retention_blocked(self):
        j, r, eng = self._make_dispatch_engine()
        result = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 0))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_adapter_retention_mismatch_blocked(self):
        j, r, eng = self._make_dispatch_engine()
        mt = MockTarget(target_id="TARGET-1"); mt.dedup_retention = 0
        result = eng.dispatch("D-1", mt,
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_valid_retention_accepted(self):
        j, r, eng = self._make_dispatch_engine()
        result = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "CONFIRMED")


class TestJ12Deduplication(unittest.TestCase):
    """P5-F08"""

    def test_duplicate_identical_j12_denied(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        j.record_evidence_conflict("D-1", "ATT-1", "ref", CONFLICT_HASH)
        with self.assertRaises(ValueError):
            j.record_evidence_conflict("D-1", "ATT-1", "ref", CONFLICT_HASH)

    def test_different_j12_evidence_accepted(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        j.record_evidence_conflict("D-1", "ATT-1", "ref-A", CONFLICT_HASH)
        e = j.record_evidence_conflict("D-1", "ATT-1", "ref-B", "b" * 64)
        self.assertEqual(e.event_type, EventType.EVIDENCE_CONFLICT)

    def test_j12_evidence_marked_unverified(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        e = j.record_evidence_conflict("D-1", "ATT-1", "ref", CONFLICT_HASH)
        self.assertFalse(e.payload.get("evidence_verified", True))


class TestJ11QueryResultValidation(unittest.TestCase):
    """P5-F09"""

    def _j11_ready_journal(self):
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        return j

    def test_empty_query_result_denied(self):
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1", "")

    def test_whitespace_query_result_denied(self):
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1", "   ")

    def test_non_string_query_result_denied(self):
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1", {"x": object()})

    def test_dict_query_result_denied(self):
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1", {"result": "found"})

    def test_valid_query_result_accepted(self):
        j = self._j11_ready_journal()
        e = j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "transaction found in target ledger")
        self.assertEqual(e.event_type, EventType.RECONCILIATION_EVIDENCE)


class TestReconciliationBoundary(unittest.TestCase):
    """P5-F10"""

    def test_public_reconciliation_stays_unknown(self):
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(behavior="timeout", target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        recon = eng.record_reconciliation("D-1", result.attempt_id, "not found")
        self.assertEqual(recon.outcome, "UNKNOWN")
        agg = r.reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.UNKNOWN)

    def test_j11_alone_never_grants_effect(self):
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                         "effect success", target_transaction_id="TX")
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.UNKNOWN)


class TestP5Regressions(unittest.TestCase):

    def test_confirmed_effect_blocks_repeat_claim(self):
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w2", "ATT-2",
                                    HASH_B, "K2", "TARGET_DEDUP_ENFORCED", "EFF-1")
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.TERMINAL_CONFIRMED)

    def test_conflict_quarantines_confirmed_decision(self):
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        j.record_evidence_conflict("D-1", "ATT-1", "ref", CONFLICT_HASH)
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.QUARANTINED)

    def test_fencing_only_target_blocked(self):
        j = make_journal(); r = DecisionReducer(j); eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1",
            MockTarget(target_id="TARGET-1", capability="TARGET_FENCING_ENFORCED"),
            TargetContract("TARGET-1", "TARGET_FENCING_ENFORCED", 3600))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_different_actual_target_blocked(self):
        j = make_journal(); r = DecisionReducer(j); eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1", MockTarget(target_id="OTHER"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_verify_head_catches_direct_tamper(self):
        j = make_journal(); commit_j0(j)
        j._events[0].payload["target"] = "ALTERED"
        self.assertFalse(j.verify_head()[0])


# ===========================================================================
# 26. P6-F01: IMMUTABLE EVENT OWNERSHIP (payload alias, returned event alias)
# ===========================================================================

class TestImmutableEventOwnership(unittest.TestCase):

    def test_caller_payload_mutation_does_not_corrupt_journal(self):
        """P6-MUT-01: Mutating the original payload dict after J0 commit
        must NOT corrupt the journal's internal events."""
        j = make_journal()
        payload = {"claim_id": "C1", "action": "SEND", "target": "T1",
                   "policy_version": "P1", "approval_ref": "A1",
                   "business_effect_id": "EFF-1"}
        j.reserve_effect_and_commit_decision("D-1", "EFF-1", payload)
        payload["target"] = "MUTATED"
        self.assertTrue(j.verify_head()[0])

    def test_returned_j0_event_mutation_does_not_corrupt(self):
        """P6-MUT-02: Mutating the returned J0 event must NOT corrupt journal."""
        j = make_journal()
        j0 = commit_j0(j)
        j0.payload["target"] = "MUTATED_VIA_RETURN"
        self.assertTrue(j.verify_head()[0])

    def test_returned_j1_j2_mutation_does_not_corrupt(self):
        """P6-F01: Mutating returned J1/J2 events must NOT corrupt journal."""
        j = make_journal(); commit_j0(j)
        j1, j2 = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                          HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j1.payload["epoch"] = 999
        j2.payload["attempt_id"] = "MUTATED"
        self.assertTrue(j.verify_head()[0])

    def test_returned_j4a_mutation_does_not_corrupt(self):
        """P6-F01: Mutating returned J4a event must NOT corrupt journal."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j4a = j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                         evidence_hash=EVIDENCE_HASH,
                                         business_effect_id="EFF-1")
        j4a.payload["target_transaction_id"] = "MUTATED"
        self.assertTrue(j.verify_head()[0])

    def test_get_events_deep_copy_positive(self):
        """P6-MUT-03: get_events deep copy confirmed working."""
        j = make_journal(); commit_j0(j)
        copies = j.get_events()
        copies[0].payload["target"] = "CHANGED"
        self.assertTrue(j.verify_head()[0])


# ===========================================================================
# 27. P6-F02: UNIVERSAL INTEGRITY GUARD ON ALL TYPED PATHS
# ===========================================================================

class TestUniversalIntegrityGuard(unittest.TestCase):
    """P6-I-01..15: ALL typed mutators must deny after journal tampering."""

    def _tamper_j0(self, j):
        """Corrupt the journal via internal reference to simulate tampering."""
        j._events[0].payload["claim_id"] = "TAMPERED"

    def test_integrity_J3_denied(self):
        """P6-I-01: J3 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_attempt_observed("D-1", "ATT-1")

    def test_integrity_J4a_denied(self):
        """P6-I-02/15: J4a after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A, EVIDENCE_HASH, "EFF-1")

    def test_integrity_J4b_denied(self):
        """P6-I-03: J4b after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                               no_effect_evidence="rejected", business_effect_id="EFF-1")

    def test_integrity_J4c_denied(self):
        """P6-I-04: J4c after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_outcome_unknown("D-1", "ATT-1", "ambiguous")

    def test_integrity_J5_denied(self):
        """P6-I-05: J5 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_human_review("D-1", "ATT-1", "investigate")

    def test_integrity_J6_denied(self):
        """P6-I-06: J6 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j1, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                         HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        epoch = j1.payload["epoch"]
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.release_lease("D-1", "TARGET-1", "w1", epoch)

    def test_integrity_J7_denied(self):
        """P6-I-07: J7 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j1, _ = j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                         HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        epoch = j1.payload["epoch"]
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.expire_lease("D-1", "TARGET-1", epoch)

    def test_integrity_J8_denied(self):
        """P6-I-08: J8 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_authorization_revoked("D-1")

    def test_integrity_J9_denied(self):
        """P6-I-09: J9 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_authorization_expired("D-1")

    def test_integrity_J10_denied(self):
        """P6-I-11: J10 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.close_no_send_atomic("D-1", "CANCELLED", "w1")

    def test_integrity_J11_denied(self):
        """P6-I-10: J11 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1", "pending")

    def test_integrity_J12_denied(self):
        """P6-I-12: J12 after tamper must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.record_evidence_conflict("D-1", "ATT-1", "ref", CONFLICT_HASH)

    def test_integrity_J0_positive(self):
        """P6-I-13: J0 on tampered journal must be denied."""
        j = make_journal(); commit_j0(j)
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            commit_j0(j, decision_id="D-2", business_effect_id="EFF-2", claim_id="CLM-2")

    def test_integrity_J1J2_positive(self):
        """P6-I-14: J1+J2 on tampered journal must be denied."""
        j = make_journal(); commit_j0(j)
        self._tamper_j0(j)
        with self.assertRaises(ValueError):
            j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                    HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")


# ===========================================================================
# 28. P6-F03: DECISION_ID VALIDATION AT ALL WRITE ENTRY POINTS
# ===========================================================================

class TestDecisionIdValidation(unittest.TestCase):

    def test_empty_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision("", "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_whitespace_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision("  ", "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_bool_true_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision(True, "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_bool_false_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision(False, "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_int_zero_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision(0, "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_int_one_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision(1, "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_list_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision([], "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_dict_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision({}, "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_none_decision_id_denied(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision(None, "EFF-1",
                {"claim_id": "C", "action": "A", "target": "T",
                 "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})

    def test_valid_decision_id_accepted(self):
        j = make_journal()
        j0 = j.reserve_effect_and_commit_decision("D1", "EFF-1",
            {"claim_id": "C", "action": "A", "target": "T",
             "policy_version": "P", "approval_ref": "R", "business_effect_id": "EFF-1"})
        self.assertEqual(j0.event_type, EventType.DECISION_COMMITTED)


# ===========================================================================
# 29. P6-F04: RECONCILIATION SEQUENCE ENFORCEMENT
# ===========================================================================

class TestReconciliationSequence(unittest.TestCase):

    def test_j4a_after_j4c_without_j11_denied(self):
        """P6-REC-01: J4c -> direct J4a without J11 must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        with self.assertRaises(ValueError):
            j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")

    def test_j4b_after_j4c_without_j11_denied(self):
        """P6-REC-02: J4c -> direct J4b without J11 must be denied."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                               no_effect_evidence="not found", business_effect_id="EFF-1")

    def test_j4a_after_j4c_with_j11_accepted(self):
        """P6-REC-03: J4c -> J11 -> J4a must be accepted."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                         "confirmed by target", target_transaction_id="TX-1",
                                         business_effect_id="EFF-1")
        e = j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.TARGET_EFFECT_CONFIRMED)
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.TERMINAL_CONFIRMED)

    def test_j4a_without_j4c_accepted(self):
        """Original target callback without prior J4c must be accepted."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        e = j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.TARGET_EFFECT_CONFIRMED)


# ===========================================================================
# 30. P6-F05: ADAPTER RETENTION REQUIRED
# ===========================================================================

class TestAdapterRetentionRequired(unittest.TestCase):

    def test_adapter_without_retention_blocked(self):
        """P6-TGT-01: Adapter without dedup_retention must be BLOCKED."""
        j = make_journal()
        r = DecisionReducer(j)
        eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")

        class BareTarget:
            target_id = "TARGET-1"
            capability = "TARGET_DEDUP_ENFORCED"
            def call(self, r): return ("DEFINITIVE_EFFECT", "TX", "done")

        result = eng.dispatch("D-1", BareTarget(),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "BLOCKED")

    def test_adapter_with_matching_retention_confirmed(self):
        """P6-TGT-02: Adapter with matching retention must work."""
        j = make_journal(); r = DecisionReducer(j); eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        result = eng.dispatch("D-1", MockTarget(target_id="TARGET-1"),
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "CONFIRMED")

    def test_adapter_insufficient_retention_blocked(self):
        """Adapter with less retention than contract must be BLOCKED."""
        j = make_journal(); r = DecisionReducer(j); eng = DispatchEngine(j, r)
        eng.commit_decision("D-1", "CLM-1", "SEND", "TARGET-1",
                            "POL-1", "APR-1", business_effect_id="EFF-1")
        mt = MockTarget(target_id="TARGET-1"); mt.dedup_retention = 100
        result = eng.dispatch("D-1", mt,
            TargetContract("TARGET-1", "TARGET_DEDUP_ENFORCED", 3600))
        self.assertEqual(result.outcome, "BLOCKED")


# ===========================================================================
# 31. P6-F06: ATOMIC READER SNAPSHOTS
# ===========================================================================

class TestAtomicReaderSnapshots(unittest.TestCase):

    def test_get_events_acquires_lock_basic(self):
        """P6-F06: Verify get_events acquires lock (basic non-deadlock test)."""
        j = make_journal(); commit_j0(j)
        events = j.get_events(decision_id="D-1")
        self.assertEqual(len(events), 1)


# ===========================================================================
# 32. P6-F07: EMPTY DECISION FILTER SCOPE
# ===========================================================================

class TestQueryScope(unittest.TestCase):

    def test_empty_decision_id_returns_zero(self):
        """P6-QRY-01: get_events(decision_id='') must NOT return all events."""
        j = make_journal()
        commit_j0(j, decision_id="D-1", business_effect_id="EFF-1")
        commit_j0(j, decision_id="D-2", business_effect_id="EFF-2", claim_id="CLM-2")
        empty_results = j.get_events(decision_id="")
        self.assertEqual(len(empty_results), 0)

    def test_none_decision_id_returns_all(self):
        """get_events(decision_id=None) returns all events (unscoped)."""
        j = make_journal()
        commit_j0(j, decision_id="D-1", business_effect_id="EFF-1")
        commit_j0(j, decision_id="D-2", business_effect_id="EFF-2", claim_id="CLM-2")
        all_results = j.get_events(decision_id=None)
        self.assertEqual(len(all_results), 2)

    def test_invalid_type_decision_id_raises(self):
        """get_events(decision_id=123) must raise ValueError."""
        j = make_journal(); commit_j0(j)
        with self.assertRaises(ValueError):
            j.get_events(decision_id=123)


# ===========================================================================
# 33. P7-F01: VERIFIED SNAPSHOT FOR REDUCER
# ===========================================================================

class TestVerifiedSnapshotReducer(unittest.TestCase):
    """P7-F01: Reducer must return QUARANTINED for corrupt journals."""

    def test_corrupt_j0_reducer_quarantines(self):
        """P7-20: Corrupt J0 -> reducer returns QUARANTINED, not dispatchable."""
        j = make_journal(); commit_j0(j)
        j._events[0].payload["target"] = "TAMPERED"
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.QUARANTINED)
        self.assertFalse(agg.dispatchable)

    def test_corrupt_j4a_reducer_quarantines(self):
        """P7-21: Corrupt J4a -> reducer returns QUARANTINED, not TERMINAL_CONFIRMED."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        j._events[-1].payload["target_transaction_id"] = "FORGED"
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.QUARANTINED)
        self.assertFalse(agg.dispatchable)

    def test_clean_journal_reducer_returns_expected(self):
        """Positive control: clean journal -> expected state."""
        j = make_journal(); commit_j0(j)
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.PENDING)
        self.assertTrue(agg.dispatchable)

    def test_verified_snapshot_raises_on_corrupt(self):
        """verified_snapshot() raises ValueError on corrupt journal."""
        j = make_journal(); commit_j0(j)
        j._events[0].payload["target"] = "TAMPERED"
        with self.assertRaises(ValueError):
            j.verified_snapshot(decision_id="D-1")

    def test_verified_snapshot_or_quarantine_returns_false_on_corrupt(self):
        """verified_snapshot_or_quarantine() returns (False, ...) on corrupt."""
        j = make_journal(); commit_j0(j)
        j._events[0].payload["target"] = "TAMPERED"
        result = j.verified_snapshot_or_quarantine(decision_id="D-1")
        self.assertIs(result[0], False)
        self.assertEqual(result[1], "CORRUPT")

    def test_verified_snapshot_returns_events_on_clean(self):
        """verified_snapshot() returns events on clean journal."""
        j = make_journal(); commit_j0(j)
        events, head_offset, head_hash = j.verified_snapshot(decision_id="D-1")
        self.assertEqual(len(events), 1)
        self.assertEqual(head_offset, 1)
        self.assertTrue(len(head_hash) > 0)


# ===========================================================================
# 34. P7-F02: TEMPORAL J11 ORDERING
# ===========================================================================

class TestTemporalJ11Ordering(unittest.TestCase):
    """P7-F02: Stale J11 predating J4c cannot resolve later uncertainty."""

    def test_stale_j11_before_j4c_denied(self):
        """P7-24: J11 before J4c -> J4c -> J4b must be DENIED (stale J11)."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        # J11 recorded BEFORE J4c
        j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                         "query before timeout")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        # Stale J11 should NOT satisfy reconciliation guard
        with self.assertRaises(ValueError):
            j.record_no_effect("D-1", "ATT-1", "", HASH_A,
                               no_effect_evidence="no effect", business_effect_id="EFF-1")

    def test_stale_j11_before_j4c_then_fresh_j11_accepted(self):
        """P7-24 fix: J11 before J4c -> J4c -> new J11 after J4c -> J4a accepted."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        # Stale J11
        j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                         "query before timeout")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        # Fresh J11 AFTER J4c
        j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                         "confirmed after timeout")
        # Now J4a should be accepted
        e = j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.TARGET_EFFECT_CONFIRMED)

    def test_j4c_then_j11_then_j4a_normal_flow(self):
        """Positive: J4c -> J11 -> J4a is normal reconciliation flow."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                         "confirmed by target")
        e = j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                       evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        self.assertEqual(e.event_type, EventType.TARGET_EFFECT_CONFIRMED)
        agg = DecisionReducer(j).reduce("D-1")
        self.assertEqual(agg.safety, SafetyState.TERMINAL_CONFIRMED)


# ===========================================================================
# 35. P7-F03: J4c AFTER DEFINITIVE BLOCKED
# ===========================================================================

class TestJ4cAfterDefinitiveBlocked(unittest.TestCase):
    """P7-F03: J4c after J4a/J4b must be rejected."""

    def test_j4c_after_j4a_denied(self):
        """P7-28: J4c after confirmed J4a is illegal."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        with self.assertRaises(ValueError):
            j.record_outcome_unknown("D-1", "ATT-1", "late observation")

    def test_j4c_after_j4b_denied(self):
        """P7-29: J4c after no-effect J4b is illegal."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_no_effect("D-1", "ATT-1", "TX-1", HASH_A,
                           no_effect_evidence="rejected by target",
                           business_effect_id="EFF-1")
        with self.assertRaises(ValueError):
            j.record_outcome_unknown("D-1", "ATT-1", "late observation")

    def test_j4c_without_prior_definitive_accepted(self):
        """Positive: J4c alone (no prior definitive) is accepted."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        e = j.record_outcome_unknown("D-1", "ATT-1", "ambiguous response")
        self.assertEqual(e.event_type, EventType.OUTCOME_UNKNOWN)


# ===========================================================================
# 36. P7-F04: EFFECTIVE ATTEMPT OUTCOME
# ===========================================================================

class TestEffectiveAttemptOutcome(unittest.TestCase):
    """P7-F04: get_attempt_outcome returns effective state matching reducer."""

    def test_j4c_j11_j4a_returns_confirmed(self):
        """P7-30: After J4c -> J11 -> J4a, outcome is CONFIRMED not J4c."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                         "confirmed by target")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        outcome = j.get_attempt_outcome("D-1", "ATT-1")
        self.assertEqual(outcome, EventType.TARGET_EFFECT_CONFIRMED)

    def test_j4c_alone_returns_unknown(self):
        """J4c alone: outcome is OUTCOME_UNKNOWN."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        outcome = j.get_attempt_outcome("D-1", "ATT-1")
        self.assertEqual(outcome, EventType.OUTCOME_UNKNOWN)

    def test_j4a_alone_returns_confirmed(self):
        """J4a alone (no J4c): outcome is TARGET_EFFECT_CONFIRMED."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH, business_effect_id="EFF-1")
        outcome = j.get_attempt_outcome("D-1", "ATT-1")
        self.assertEqual(outcome, EventType.TARGET_EFFECT_CONFIRMED)


# ===========================================================================
# 37. P7-F05: FENCING+DEDUP SAME-EPOCH RETRY
# ===========================================================================

class TestFencingDedupRetry(unittest.TestCase):
    """P7-F05: Combined fencing+dedup same-epoch retry semantics."""

    def test_fencing_and_dedup_same_epoch_identical_retry_dedup(self):
        """P7-32: Same-epoch identical retry -> DEFINITIVE_EFFECT with same TX."""
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED")
        req = {"decision_id": "D", "business_effect_id": "E",
               "request_hash": HASH_A, "idempotency_key": "KEY", "epoch": 1}
        r1 = mt.call(req)
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = mt.call(dict(req))  # exact same request
        self.assertEqual(r2[0], "DEFINITIVE_EFFECT")
        self.assertEqual(r2[1], r1[1])  # same TX ID

    def test_fencing_and_dedup_stale_epoch_fenced(self):
        """Stale epoch retry -> DEFINITIVE_NO_EFFECT (fenced)."""
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED")
        req1 = {"decision_id": "D", "business_effect_id": "E",
                "request_hash": HASH_A, "idempotency_key": "KEY1", "epoch": 2}
        mt.call(req1)
        req2 = {"decision_id": "D", "business_effect_id": "E2",
                "request_hash": HASH_B, "idempotency_key": "KEY2", "epoch": 1}
        r2 = mt.call(req2)
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")
        self.assertIn("fenced", r2[2].lower())

    def test_dedup_only_same_key_retry_returns_same_tx(self):
        """Positive: DEDUP_ENFORCED same-key retry -> same TX (unchanged)."""
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        req = {"decision_id": "D", "business_effect_id": "E",
               "request_hash": HASH_A, "idempotency_key": "KEY", "epoch": 1}
        r1 = mt.call(req)
        r2 = mt.call(dict(req))
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        self.assertEqual(r2[0], "DEFINITIVE_EFFECT")
        self.assertEqual(r2[1], r1[1])


# ===========================================================================
# 38. P7-F06: ROBUST INTEGRITY CHECK
# ===========================================================================

class TestRobustIntegrityCheck(unittest.TestCase):
    """P7-F06: Corrupt unserializable payload handled as typed failure."""

    def test_set_payload_verify_head_returns_false(self):
        """P7-23: Corrupt payload with set -> verify_head returns False."""
        j = make_journal(); commit_j0(j)
        j._events[0].payload["bad"] = {1, 2, 3}
        valid, _, _ = j.verify_head()
        self.assertFalse(valid)

    def test_set_payload_require_integrity_raises_valueerror(self):
        """P7-23: Corrupt payload with set -> _require_integrity raises ValueError."""
        j = make_journal(); commit_j0(j)
        j._events[0].payload["bad"] = {1, 2}
        with self.assertRaises(ValueError):
            j.record_authorization_revoked("D-1", "rev")


# ===========================================================================
# 39. P7-F07: TAIL DELETION DETECTION
# ===========================================================================

class TestTailDeletionDetection(unittest.TestCase):
    """P7-F07: Tail deletion detected by verify_head and require_integrity."""

    def test_tail_deletion_verify_head_false(self):
        """P7-22/35: Deleting last event -> verify_head returns False."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j._events.pop()  # Delete J2
        valid, _, _ = j.verify_head()
        self.assertFalse(valid)

    def test_tail_deletion_blocks_append(self):
        """Tail deletion -> subsequent append refused."""
        j = make_journal(); commit_j0(j)
        j._events.pop()
        with self.assertRaises(ValueError):
            commit_j0(j, decision_id="D-2", business_effect_id="EFF-2", claim_id="CLM-2")

    def test_normal_journal_verify_head_true(self):
        """Positive: Normal journal -> verify_head returns True."""
        j = make_journal(); commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        valid, head, _ = j.verify_head()
        self.assertTrue(valid)
        self.assertEqual(head, 3)


# ===========================================================================
# 40. P8-F01: VERIFIED STATUS READERS
# ===========================================================================

class TestVerifiedStatusReaders(unittest.TestCase):
    """P8-F01: Public status-reader APIs must fail-closed on corrupt journal."""

    def _make_confirmed_journal(self):
        """Create a journal with J0 + J1/J2 + J4a confirmed."""
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_effect_confirmed("D-1", "ATT-1", "TX-1", HASH_A,
                                   evidence_hash=EVIDENCE_HASH,
                                   business_effect_id="EFF-1")
        return j

    def test_corrupt_get_attempt_outcome_returns_none(self):
        """P8-22: Corrupt journal -> get_attempt_outcome returns None, not CONFIRMED."""
        j = self._make_confirmed_journal()
        j._events[0].payload["target"] = "TAMPERED"
        self.assertFalse(j.verify_head()[0])
        outcome = j.get_attempt_outcome("D-1", "ATT-1")
        self.assertIsNone(outcome)

    def test_corrupt_has_conflict_returns_true(self):
        """P8-F01: Corrupt journal -> has_conflict returns True (fail-closed)."""
        j = self._make_confirmed_journal()
        j._events[0].payload["target"] = "TAMPERED"
        self.assertTrue(j.has_conflict("D-1"))

    def test_corrupt_has_j2_returns_false(self):
        """P8-F01: Corrupt journal -> has_j2 returns False (fail-closed)."""
        j = self._make_confirmed_journal()
        j._events[0].payload["target"] = "TAMPERED"
        self.assertFalse(j.has_j2("D-1"))

    def test_corrupt_get_attempts_returns_empty(self):
        """P8-F01: Corrupt journal -> get_attempts returns [] (fail-closed)."""
        j = self._make_confirmed_journal()
        j._events[0].payload["target"] = "TAMPERED"
        self.assertEqual(j.get_attempts("D-1"), [])

    def test_clean_get_attempt_outcome_returns_confirmed(self):
        """Positive: Clean journal -> get_attempt_outcome returns correct state."""
        j = self._make_confirmed_journal()
        outcome = j.get_attempt_outcome("D-1", "ATT-1")
        self.assertEqual(outcome, EventType.TARGET_EFFECT_CONFIRMED)


# ===========================================================================
# 41. P8-F02: J11 TARGET_TRANSACTION_ID TYPE VALIDATION
# ===========================================================================

class TestJ11TransactionIdValidation(unittest.TestCase):
    """P8-F02: J11 target_transaction_id must be a string."""

    def _j11_ready_journal(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        return j

    def test_j11_integer_tx_id_denied(self):
        """P8-28: Integer target_transaction_id must be rejected."""
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "query result", target_transaction_id=42)

    def test_j11_boolean_tx_id_denied(self):
        """Boolean target_transaction_id must be rejected."""
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "query result", target_transaction_id=True)

    def test_j11_list_tx_id_denied(self):
        """List target_transaction_id must be rejected."""
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "query result", target_transaction_id=["x"])

    def test_j11_empty_string_tx_id_accepted(self):
        """Empty string target_transaction_id accepted (means no TX known)."""
        j = self._j11_ready_journal()
        e = j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "query result", target_transaction_id="")
        self.assertEqual(e.event_type, EventType.RECONCILIATION_EVIDENCE)


# ===========================================================================
# 42. P8-C01: GET_EVENTS UNVERIFIED READER
# ===========================================================================

class TestGetEventsUnverifiedReader(unittest.TestCase):
    """P8-C01: get_events() is an unverified general reader --
    returns events even on corrupt journal (documented behavior)."""

    def test_corrupt_get_events_still_returns_events(self):
        """P8-23: get_events returns copied but unverified records from tampered journal."""
        j = make_journal()
        commit_j0(j)
        j._events[0].payload["claim_id"] = "TAMPERED"
        events = j.get_events(decision_id="D-1")
        self.assertEqual(len(events), 1)  # Still returns data


# ===========================================================================
# 43. P8-C02: J11 BEFORE J4C PERMITTED
# ===========================================================================

class TestJ11BeforeJ4cPermitted(unittest.TestCase):
    """P8-C02: J11 before any J4c is permitted as an early observation."""

    def test_j11_before_j4c_accepted(self):
        """P8-24: Record J11 before any J4c -> accepted."""
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        # No J4c recorded yet -- J11 is an early observation
        e = j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "early observation result")
        self.assertEqual(e.event_type, EventType.RECONCILIATION_EVIDENCE)


# ===========================================================================
# 44. P8-C04: MOCK TARGET VALIDATES EFFECT IDENTITY
# ===========================================================================

class TestMockTargetEffectIdentity(unittest.TestCase):
    """P8-C04: Mock target rejects missing business_effect_id for dedup targets."""

    def test_empty_effect_id_rejected(self):
        """P8-34: Empty business_effect_id -> DEFINITIVE_NO_EFFECT."""
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        r = mt.call({"decision_id": "D1", "idempotency_key": "K1",
                      "business_effect_id": "", "request_hash": HASH_A, "epoch": 1})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_valid_effect_id_accepted(self):
        """Positive: valid business_effect_id -> DEFINITIVE_EFFECT."""
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED")
        r = mt.call({"decision_id": "D1", "idempotency_key": "K1",
                      "business_effect_id": "EFF-1", "request_hash": HASH_A, "epoch": 1})
        self.assertEqual(r[0], "DEFINITIVE_EFFECT")


# ===========================================================================
# 45. P8-C05: MOCK TARGET VALIDATES EPOCH TYPE
# ===========================================================================

class TestMockTargetEpochValidation(unittest.TestCase):
    """P8-C05: Mock target type-checks epoch (no TypeError on string epoch)."""

    def test_string_epoch_rejected(self):
        """P8-35: String epoch -> DEFINITIVE_NO_EFFECT, not TypeError."""
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED")
        r = mt.call({"decision_id": "D1", "idempotency_key": "K1",
                      "business_effect_id": "E1", "request_hash": HASH_A, "epoch": "bad"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_boolean_epoch_rejected(self):
        """Boolean epoch -> DEFINITIVE_NO_EFFECT."""
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED")
        r = mt.call({"decision_id": "D1", "idempotency_key": "K1",
                      "business_effect_id": "E1", "request_hash": HASH_A, "epoch": True})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")


# ===========================================================================
# 46. P9-F01: MOCK DEDUP EMPTY-HASH BYPASS CLOSED
# ===========================================================================

class TestMockDedupEmptyHashBypass(unittest.TestCase):
    """P9-F01: Empty request_hash on replay must not bypass dedup conflict check."""

    def test_same_key_empty_hash_replay_rejected(self):
        """P9-37: Same idem key, valid first hash, empty second hash -> NO_EFFECT."""
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="TARGET-1")
        r1 = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                       "target": "TARGET-1", "idempotency_key": "KEY",
                       "request_hash": HASH_A})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                       "target": "TARGET-1", "idempotency_key": "KEY",
                       "request_hash": ""})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")
        self.assertEqual(mt._tx_counter, 1)

    def test_same_key_valid_hash_replay_deduped(self):
        """Positive: Same key + same hash -> DEFINITIVE_EFFECT (dedup replay)."""
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="TARGET-1")
        r1 = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                       "target": "TARGET-1", "idempotency_key": "KEY",
                       "request_hash": HASH_A})
        tx1 = r1[1]
        r2 = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                       "target": "TARGET-1", "idempotency_key": "KEY",
                       "request_hash": HASH_A})
        self.assertEqual(r2[0], "DEFINITIVE_EFFECT")
        self.assertEqual(r2[1], tx1)

    def test_fencing_dedup_empty_hash_replay_rejected(self):
        """P9-54: Combined fencing+dedup, same key, empty hash -> NO_EFFECT."""
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED", target_id="TARGET-1")
        r1 = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                       "target": "TARGET-1", "idempotency_key": "KEY",
                       "request_hash": HASH_A})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                       "target": "TARGET-1", "idempotency_key": "KEY",
                       "request_hash": ""})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")


# ===========================================================================
# 47. P9-F02: J11 NONE/WHITESPACE TARGET_TRANSACTION_ID REJECTED
# ===========================================================================

class TestJ11NoneWhitespaceTxId(unittest.TestCase):
    """P9-F02: J11 rejects None and whitespace-only target_transaction_id."""

    def _j11_ready_journal(self):
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim("D-1", "TARGET-1", "w1", "ATT-1",
                                HASH_A, "K1", "TARGET_DEDUP_ENFORCED", "EFF-1")
        j.record_outcome_unknown("D-1", "ATT-1", "timeout")
        return j

    def test_none_tx_id_rejected(self):
        """P9-20: None target_transaction_id -> ValueError."""
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "query result", target_transaction_id=None)

    def test_whitespace_only_tx_id_rejected(self):
        """P9-21: Whitespace-only target_transaction_id -> ValueError."""
        j = self._j11_ready_journal()
        with self.assertRaises(ValueError):
            j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "query result", target_transaction_id="   ")

    def test_empty_string_tx_id_accepted(self):
        """Positive: Empty string is the explicit absence marker."""
        j = self._j11_ready_journal()
        e = j.record_reconciliation_evidence("D-1", "ATT-1", HASH_A, "K1",
                                             "query result", target_transaction_id="")
        self.assertEqual(e.event_type, EventType.RECONCILIATION_EVIDENCE)


# ===========================================================================
# 48. P9-C39: MOCK TARGET TYPED REFUSAL FOR NON-DICT INPUT
# ===========================================================================

class TestMockTargetTypedRefusal(unittest.TestCase):
    """P9-C39: MockTarget.call(None) returns typed refusal, not exception."""

    def test_none_input_typed_refusal(self):
        mt = MockTarget()
        r = mt.call(None)
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_string_input_typed_refusal(self):
        mt = MockTarget()
        r = mt.call("not a dict")
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_list_input_typed_refusal(self):
        mt = MockTarget()
        r = mt.call([1, 2, 3])
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")


# ===========================================================================
# 49. P9-C46: MOCK MISSING IDEMPOTENCY KEY REJECTED
# ===========================================================================

class TestMockMissingIdempotencyKey(unittest.TestCase):
    """P9-C46: Dedup-capable mock rejects missing/non-string idempotency key."""

    def test_missing_idempotency_key_rejected(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_empty_idempotency_key_rejected(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": ""})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_valid_idempotency_key_accepted(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": "KEY"})
        self.assertEqual(r[0], "DEFINITIVE_EFFECT")


# ===========================================================================
# 50. P9-C47: MOCK WHITESPACE EFFECT ID REJECTED
# ===========================================================================

class TestMockWhitespaceEffectId(unittest.TestCase):
    """P9-C47: Whitespace-only business_effect_id rejected for dedup targets."""

    def test_whitespace_effect_id_rejected(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "  ",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")


# ===========================================================================
# 51. P9-C48: MOCK BOOLEAN REQUEST HASH REJECTED
# ===========================================================================

class TestMockBooleanRequestHash(unittest.TestCase):
    """P9-C48: Boolean request_hash rejected."""

    def test_boolean_request_hash_rejected(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": True, "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")


# ===========================================================================
# 52. P9-C49: MOCK TARGET MISMATCH REJECTED
# ===========================================================================

class TestMockTargetMismatch(unittest.TestCase):
    """P9-C49: Request target field mismatching adapter target_id -> rejected."""

    def test_target_mismatch_rejected(self):
        mt = MockTarget(target_id="T-1", capability="TARGET_DEDUP_ENFORCED")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T-OTHER", "request_hash": HASH_A,
                      "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_matching_target_accepted(self):
        mt = MockTarget(target_id="T-1", capability="TARGET_DEDUP_ENFORCED")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T-1", "request_hash": HASH_A,
                      "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_EFFECT")


# ===========================================================================
# 53. P9-C34/C36: MOCK EPOCH VALIDATION FOR FENCING TARGETS
# ===========================================================================

class TestMockFencingEpochValidation(unittest.TestCase):
    """P9-C34/C36: Non-positive and non-integer epochs rejected for fencing."""

    def test_epoch_zero_rejected(self):
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 0, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_epoch_fractional_rejected(self):
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 0.5, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_epoch_negative_rejected(self):
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": -1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_epoch_positive_integer_accepted(self):
        mt = MockTarget(capability="TARGET_FENCING_AND_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_EFFECT")


# ===========================================================================
# 54. P9-C51: MOCK CALL RECORDS DEEP-COPIED
# ===========================================================================

class TestMockCallRecordsCopied(unittest.TestCase):
    """P9-C51: Mutating caller dict after call does not change mock.calls."""

    def test_call_records_are_copies(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="T")
        req = {"epoch": 1, "decision_id": "D", "business_effect_id": "E",
               "target": "T", "request_hash": HASH_A, "idempotency_key": "K"}
        mt.call(req)
        req["decision_id"] = "MUTATED"
        self.assertEqual(mt.calls[0]["decision_id"], "D")

    def test_valid_mock_call_positive(self):
        mt = MockTarget(capability="TARGET_DEDUP_ENFORCED", target_id="T")
        r = mt.call({"epoch": 1, "decision_id": "D", "business_effect_id": "E",
                      "target": "T", "request_hash": HASH_A, "idempotency_key": "K"})
        self.assertEqual(r[0], "DEFINITIVE_EFFECT")
        self.assertEqual(mt.call_count, 1)


# ===========================================================================
# P10 FINDINGS -- Validate-then-mutate fencing + strict epoch + SHA-256 grammar
# ===========================================================================

class TestP10F01EpochPoisoning(unittest.TestCase):
    """P10-F01: Rejected requests must NOT advance _seen_epochs."""

    def test_empty_hash_does_not_poison_epoch(self):
        """Empty request_hash rejection must not advance fencing epoch."""
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r1 = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                      "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        self.assertEqual(t._seen_epochs.get("D1"), 1)
        r2 = t.call({"decision_id": "D1", "epoch": 2, "idempotency_key": "K2",
                      "request_hash": "", "business_effect_id": "E2", "target": "T1"})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")
        self.assertEqual(t._seen_epochs.get("D1"), 1,
                         "Epoch poisoned by rejected request")

    def test_whitespace_hash_does_not_poison_epoch(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r1 = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                      "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = t.call({"decision_id": "D1", "epoch": 2, "idempotency_key": "K2",
                      "request_hash": "   ", "business_effect_id": "E2", "target": "T1"})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")
        self.assertEqual(t._seen_epochs.get("D1"), 1)

    def test_missing_effect_id_does_not_poison_epoch(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r1 = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                      "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = t.call({"decision_id": "D1", "epoch": 2, "idempotency_key": "K2",
                      "request_hash": HASH_B, "business_effect_id": "", "target": "T1"})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")
        self.assertEqual(t._seen_epochs.get("D1"), 1)

    def test_valid_request_after_rejected_succeeds(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r1 = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                      "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        r2 = t.call({"decision_id": "D1", "epoch": 2, "idempotency_key": "K2",
                      "request_hash": "", "business_effect_id": "E2", "target": "T1"})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")
        r3 = t.call({"decision_id": "D1", "epoch": 2, "idempotency_key": "K3",
                      "request_hash": HASH_B, "business_effect_id": "E3", "target": "T1"})
        self.assertEqual(r3[0], "DEFINITIVE_EFFECT")
        self.assertEqual(t._seen_epochs.get("D1"), 2)

    def test_fencing_only_target_not_poisoned(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_ENFORCED)
        r1 = t.call({"decision_id": "D1", "epoch": 1, "target": "T1"})
        self.assertEqual(r1[0], "DEFINITIVE_EFFECT")
        self.assertEqual(t._seen_epochs.get("D1"), 1)
        r2 = t.call({"decision_id": "D1", "epoch": 2, "target": "WRONG"})
        self.assertEqual(r2[0], "DEFINITIVE_NO_EFFECT")
        self.assertEqual(t._seen_epochs.get("D1"), 1,
                         "Fencing epoch poisoned by target mismatch")

    def test_dedup_keys_not_recorded_on_rejection(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r1 = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                      "request_hash": HASH_A, "business_effect_id": "", "target": "T1"})
        self.assertEqual(r1[0], "DEFINITIVE_NO_EFFECT")
        self.assertNotIn("K1", t._seen_keys)

    def test_effect_ids_not_recorded_on_rejection(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r1 = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                      "request_hash": "", "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r1[0], "DEFINITIVE_NO_EFFECT")
        self.assertNotIn("E1", t._seen_effects)


class TestP10F02StrictEpochType(unittest.TestCase):
    """P10-F02: Fencing epoch must be type(epoch) is int, positive."""

    def test_float_epoch_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": 1.0, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")
        self.assertIn("positive integer", r[2])

    def test_bool_true_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": True, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")
        self.assertIn("bool", r[2])

    def test_bool_false_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": False, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_negative_int_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": -1, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_zero_epoch_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": 0, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_string_epoch_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": "1", "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_none_epoch_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": None, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_positive_int_accepted(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_EFFECT")

    def test_large_float_epoch_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "D1", "epoch": 100.0, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")


class TestP10F03SHA256Grammar(unittest.TestCase):
    """P10-F03: SHA-256 validator must use re.fullmatch, not int(v,16)."""

    def test_valid_sha256_accepted(self):
        j = make_journal()
        j._validate_sha256_hex(HASH_A, "test")

    def test_0x_prefix_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("0x" + "a" * 62, "test")

    def test_leading_space_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex(" " + "a" * 63, "test")

    def test_trailing_space_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("a" * 63 + " ", "test")

    def test_plus_sign_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("+" + "a" * 63, "test")

    def test_underscore_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("a" * 32 + "_" + "a" * 31, "test")

    def test_uppercase_hex_accepted(self):
        j = make_journal()
        j._validate_sha256_hex("A" * 64, "test")

    def test_mixed_case_accepted(self):
        j = make_journal()
        j._validate_sha256_hex("aAbBcCdDeEfF" * 5 + "aAbB", "test")

    def test_short_hash_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("a" * 63, "test")

    def test_long_hash_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("a" * 65, "test")

    def test_empty_string_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("", "test")

    def test_newline_in_hash_rejected(self):
        j = make_journal()
        with self.assertRaises(ValueError):
            j._validate_sha256_hex("a" * 32 + "\n" + "a" * 31, "test")


class TestP10OpenMockInputHardening(unittest.TestCase):
    """P10-OPEN: Remaining mock input hardening observations."""

    def test_whitespace_only_idempotency_key_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.DEDUP_ENFORCED)
        r = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "   ",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")
        self.assertIn("idempotency_key", r[2])

    def test_whitespace_only_request_hash_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.DEDUP_ENFORCED)
        r = t.call({"decision_id": "D1", "epoch": 1, "idempotency_key": "K1",
                     "request_hash": "   ", "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")

    def test_missing_decision_id_rejected_for_dedup(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.DEDUP_ENFORCED)
        r = t.call({"epoch": 1, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")
        self.assertIn("decision_id", r[2])

    def test_whitespace_decision_id_rejected(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_AND_DEDUP)
        r = t.call({"decision_id": "   ", "epoch": 1, "idempotency_key": "K1",
                     "request_hash": HASH_A, "business_effect_id": "E1", "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")
        self.assertIn("decision_id", r[2])

    def test_empty_decision_id_rejected_for_fencing(self):
        t = MockTarget(target_id="T1", capability=TargetCapability.FENCING_ENFORCED)
        r = t.call({"decision_id": "", "epoch": 1, "target": "T1"})
        self.assertEqual(r[0], "DEFINITIVE_NO_EFFECT")
        self.assertIn("decision_id", r[2])


# ===========================================================================
# P11 FINDINGS -- J12 hash grammar, hash chain, revocation interlock, fail-closed J3
# ===========================================================================

class TestP11F01J12HashGrammar(unittest.TestCase):
    """P11-F01: J12 record_evidence_conflict() must use canonical SHA-256 validator.
    # FALSIFICATION: If any noncanonical 64-char string (+ prefix, space prefix,
    # 0x prefix, underscore separator) is accepted as competing_evidence_hash,
    # the validator is incomplete and the invariant is broken."""

    def _journal_with_confirmed(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        return j

    def test_j12_rejects_plus_prefix_hash(self):
        j = self._journal_with_confirmed()
        with self.assertRaises(ValueError):
            j.record_evidence_conflict("D-1", "ATT-1", "ref", "+" + "a" * 63, "EFF-1")

    def test_j12_rejects_space_prefix_hash(self):
        j = self._journal_with_confirmed()
        with self.assertRaises(ValueError):
            j.record_evidence_conflict("D-1", "ATT-1", "ref", " " + "a" * 63, "EFF-1")

    def test_j12_rejects_0x_prefix_hash(self):
        j = self._journal_with_confirmed()
        with self.assertRaises(ValueError):
            j.record_evidence_conflict("D-1", "ATT-1", "ref", "0x" + "a" * 62, "EFF-1")

    def test_j12_rejects_underscore_hash(self):
        j = self._journal_with_confirmed()
        with self.assertRaises(ValueError):
            j.record_evidence_conflict("D-1", "ATT-1", "ref", "a" * 32 + "_" + "a" * 31, "EFF-1")

    def test_j12_accepts_valid_lowercase_hash(self):
        j = self._journal_with_confirmed()
        e = j.record_evidence_conflict("D-1", "ATT-1", "ref", "a" * 64, "EFF-1")
        self.assertEqual(e.event_type, EventType.EVIDENCE_CONFLICT)

    def test_j12_accepts_valid_uppercase_hash(self):
        j = self._journal_with_confirmed()
        e = j.record_evidence_conflict("D-1", "ATT-1", "ref", "A" * 64, "EFF-1")
        self.assertEqual(e.event_type, EventType.EVIDENCE_CONFLICT)


class TestP11F02HashChain(unittest.TestCase):
    """P11-F02: Events carry prev_hash linking each to its predecessor.
    # FALSIFICATION: If rewriting one event's payload and recomputing only that
    # event's hash does not cause verify_head() to return False, the chain is
    # not predecessor-linked and the invariant is broken."""

    def test_genesis_event_has_empty_prev_hash(self):
        j = make_journal()
        commit_j0(j)
        events = j.get_events("D-1")
        self.assertEqual(events[0].prev_hash, "")

    def test_second_event_chains_to_first(self):
        j = make_journal()
        commit_j0(j)
        j1, j2 = j.atomic_dispatch_claim(
            "D-1", "TARGET-1", "w1", "ATT-1", HASH_A, "KEY-1",
            "TARGET_DEDUP_ENFORCED", "EFF-1")
        events = j.get_events("D-1")
        # J1 (second event) should chain to J0 (first event)
        self.assertEqual(events[1].prev_hash, events[0].integrity_hash)

    def test_atomic_j1_j2_chain_linked(self):
        j = make_journal()
        commit_j0(j)
        j1, j2 = j.atomic_dispatch_claim(
            "D-1", "TARGET-1", "w1", "ATT-1", HASH_A, "KEY-1",
            "TARGET_DEDUP_ENFORCED", "EFF-1")
        # J2.prev_hash should equal J1.integrity_hash
        self.assertEqual(j2.prev_hash, j1.integrity_hash)

    def test_rewrite_j0_breaks_chain(self):
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        ok_before, _, _ = j.verify_head()
        self.assertTrue(ok_before)
        # Rewrite J0 payload and recompute only J0's hash
        j._events[0].payload["claim_id"] = "ALTERED"
        j._events[0].integrity_hash = j._events[0].compute_hash()
        ok_after, offset, msg = j.verify_head()
        self.assertFalse(ok_after)
        self.assertIn("Chain break", msg)

    def test_rewrite_j0_recompute_breaks_despite_valid_per_event_hash(self):
        """Positive control: after rewriting J0 and recomputing its hash,
        J0's own per-event hash IS valid. The chain link is what catches it."""
        j = make_journal()
        commit_j0(j)
        j.atomic_dispatch_claim(
            "D-1", "TARGET-1", "w1", "ATT-1", HASH_A, "KEY-1",
            "TARGET_DEDUP_ENFORCED", "EFF-1")
        j._events[0].payload["claim_id"] = "TAMPERED"
        j._events[0].integrity_hash = j._events[0].compute_hash()
        # J0 per-event hash is valid (recomputed matches stored)
        self.assertEqual(j._events[0].compute_hash(), j._events[0].integrity_hash)
        # But chain is broken: J1.prev_hash != J0.integrity_hash
        self.assertNotEqual(j._events[1].prev_hash, j._events[0].integrity_hash)
        ok, _, msg = j.verify_head()
        self.assertFalse(ok)

    def test_full_journal_chain_integrity(self):
        """Build a 7+ event journal and verify every event's prev_hash."""
        j = make_journal()
        dispatch_and_resolve(j, outcome="confirm")
        j.record_evidence_conflict("D-1", "ATT-1", "ref", "b" * 64, "EFF-1")
        events_raw = j._events
        self.assertGreaterEqual(len(events_raw), 7)
        # Genesis
        self.assertEqual(events_raw[0].prev_hash, "")
        # Every subsequent event chains to predecessor
        for i in range(1, len(events_raw)):
            self.assertEqual(
                events_raw[i].prev_hash, events_raw[i - 1].integrity_hash,
                f"Chain break at offset {i}")
        ok, _, _ = j.verify_head()
        self.assertTrue(ok)


class TestP11F03RevocationInterlock(unittest.TestCase):
    """P11-F03: Revocation interleaved after J3 but before target call blocks dispatch.
    # FALSIFICATION: If a revocation recorded between record_attempt_observed()
    # and target.call() still results in target.call_count == 1, the interlock
    # is missing and the invariant is broken."""

    def test_revocation_after_j3_blocks_target(self):
        j = HABLJournal()
        r = DecisionReducer(j)
        engine = DispatchEngine(j, r)
        engine.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                               business_effect_id="E-1")
        orig = j.record_attempt_observed

        def interposed(*a, **kw):
            val = orig(*a, **kw)
            j.record_authorization_revoked("D-1", "interleaved before target call")
            return val
        j.record_attempt_observed = interposed

        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = engine.dispatch("D-1", t,
                                 TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 0)
        self.assertEqual(result.outcome, "BLOCKED")
        self.assertEqual(r.reduce("D-1").authorization_state, "REVOKED")

    def test_normal_dispatch_without_revocation_still_works(self):
        """Positive control: dispatch without interposition completes."""
        j = HABLJournal()
        r = DecisionReducer(j)
        engine = DispatchEngine(j, r)
        engine.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                               business_effect_id="E-1")
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = engine.dispatch("D-1", t,
                                 TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 1)
        self.assertEqual(result.outcome, "CONFIRMED")

    def test_revocation_before_dispatch_blocks_at_eligibility(self):
        j = HABLJournal()
        r = DecisionReducer(j)
        engine = DispatchEngine(j, r)
        engine.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                               business_effect_id="E-1")
        j.record_authorization_revoked("D-1", "revoked before dispatch")
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = engine.dispatch("D-1", t,
                                 TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 0)
        self.assertIn(result.outcome, ("BLOCKED", "NOT_DISPATCHABLE"))


class TestP11F04FailClosedJ3(unittest.TestCase):
    """P11-F04: Failed J3 (integrity failure) halts dispatch -- target NOT called.
    # FALSIFICATION: If corrupting the journal before record_attempt_observed()
    # still results in target.call_count == 1, the fail-closed guard is missing
    # and the invariant is broken."""

    def test_j3_integrity_failure_blocks_target(self):
        j = HABLJournal()
        r = DecisionReducer(j)
        engine = DispatchEngine(j, r)
        engine.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                               business_effect_id="E-1")
        orig = j.record_attempt_observed

        def tamper_before_j3(*a, **kw):
            j._events[0].payload["claim_id"] = "CORRUPTED"
            return orig(*a, **kw)
        j.record_attempt_observed = tamper_before_j3

        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = engine.dispatch("D-1", t,
                                 TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 0, "Target must NOT be called when J3 fails")
        self.assertEqual(result.outcome, "BLOCKED")

    def test_j3_success_allows_target(self):
        """Positive control: normal J3 allows target call."""
        j = HABLJournal()
        r = DecisionReducer(j)
        engine = DispatchEngine(j, r)
        engine.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                               business_effect_id="E-1")
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = engine.dispatch("D-1", t,
                                 TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 1)
        self.assertEqual(result.outcome, "CONFIRMED")

    def test_j3_failure_preserves_j2(self):
        """After J3 failure, J2 event should still be in journal (not erased)."""
        j = HABLJournal()
        r = DecisionReducer(j)
        engine = DispatchEngine(j, r)
        engine.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                               business_effect_id="E-1")
        orig = j.record_attempt_observed

        def tamper_before_j3(*a, **kw):
            j._events[0].payload["claim_id"] = "CORRUPTED"
            return orig(*a, **kw)
        j.record_attempt_observed = tamper_before_j3

        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        engine.dispatch("D-1", t,
                        TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        # J2 should still exist even though dispatch was blocked
        events = j.get_events("D-1")
        j2_events = [e for e in events
                     if e.event_type == EventType.SEND_INTENT_COMMITTED]
        self.assertEqual(len(j2_events), 1, "J2 must be preserved after J3 failure")


# ===========================================================================
# P11-R2 FINDINGS -- Positive auth predicate + quarantine gate at post-J3
# ===========================================================================

class TestP11R2F05ExpirationBlocksPostJ3(unittest.TestCase):
    """P11-R2-F05: Expiration after J3 must block target call.
    # FALSIFICATION: If authorization_state == 'EXPIRED' at the post-J3
    # gate and target.call_count > 0, the positive auth predicate is broken."""

    def test_expiration_after_j3_blocks_target(self):
        """Inject J9 (expiration) after J3 -- target must not be called."""
        j = HABLJournal(); r = DecisionReducer(j)
        e = DispatchEngine(j, r)
        e.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                          business_effect_id="E-1")
        orig = j.record_attempt_observed
        def expire(*a, **kw):
            val = orig(*a, **kw)
            j.record_authorization_expired("D-1", "injected after J3")
            return val
        j.record_attempt_observed = expire
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = e.dispatch("D-1", t,
                            TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 0)
        self.assertEqual(result.outcome, "BLOCKED")
        self.assertEqual(r.reduce("D-1").authorization_state, "EXPIRED")

    def test_normal_dispatch_without_expiration_works(self):
        """Positive control: dispatch without interposition completes."""
        j = HABLJournal(); r = DecisionReducer(j)
        e = DispatchEngine(j, r)
        e.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                          business_effect_id="E-1")
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = e.dispatch("D-1", t,
                            TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 1)
        self.assertEqual(result.outcome, "CONFIRMED")


class TestP11R2F06QuarantineBlocksPostJ3(unittest.TestCase):
    """P11-R2-F06: Quarantine at post-J3 reducer must block target call.
    # FALSIFICATION: If reducer reports QUARANTINED at the post-J3 gate
    # and target.call_count > 0, the quarantine gate is broken."""

    def test_quarantine_at_post_j3_blocks_target(self):
        """Inject corruption just before the post-J3 reducer call."""
        j = HABLJournal(); r = DecisionReducer(j)
        e = DispatchEngine(j, r)
        e.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                          business_effect_id="E-1")
        original_reduce = r.reduce
        counter = [0]
        def inject(*a, **kw):
            counter[0] += 1
            if counter[0] == 2:
                j._events[0].payload["claim_id"] = "TAMPERED AT POST-J3"
            return original_reduce(*a, **kw)
        r.reduce = inject
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = e.dispatch("D-1", t,
                            TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 0)
        self.assertEqual(result.outcome, "BLOCKED")
        self.assertIn("quarantine", result.detail.lower())

    def test_clean_journal_at_post_j3_allows_dispatch(self):
        """Positive control: clean journal at post-J3 allows target call."""
        j = HABLJournal(); r = DecisionReducer(j)
        e = DispatchEngine(j, r)
        e.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                          business_effect_id="E-1")
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = e.dispatch("D-1", t,
                            TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 1)
        self.assertEqual(result.outcome, "CONFIRMED")


class TestP11R2C26LinearizationPolicy(unittest.TestCase):
    """C-26 linearization: the post-J3 snapshot is the linearization point.
    Events interleaved AFTER this snapshot and BEFORE target.call() are a
    known residual race. This test documents the boundary, not a defect.
    # FALSIFICATION: If C-26 claims to block ALL revocations between J3
    # and target.call() (including those after the snapshot), the claim
    # exceeds the implementation."""

    def test_revocation_at_snapshot_blocked(self):
        """Revocation visible at the post-J3 snapshot is blocked."""
        j = HABLJournal(); r = DecisionReducer(j)
        e = DispatchEngine(j, r)
        e.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                          business_effect_id="E-1")
        orig = j.record_attempt_observed
        def revoke(*a, **kw):
            val = orig(*a, **kw)
            j.record_authorization_revoked("D-1", "visible at snapshot")
            return val
        j.record_attempt_observed = revoke
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = e.dispatch("D-1", t,
                            TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 0)
        self.assertEqual(result.outcome, "BLOCKED")

    def test_revocation_after_snapshot_is_residual_race(self):
        """Revocation injected AFTER the post-J3 reducer read is a known
        residual TOCTOU race. The target is called. This is the declared
        limitation, not a defect -- C-26 is scoped to the snapshot."""
        j = HABLJournal(); r = DecisionReducer(j)
        e = DispatchEngine(j, r)
        e.commit_decision("D-1", "C-1", "SEND", "T-1", "P-1", "A-1",
                          business_effect_id="E-1")
        original_reduce = r.reduce
        counter = [0]
        def inject_after(*a, **kw):
            counter[0] += 1
            result = original_reduce(*a, **kw)
            if counter[0] == 2:
                j.record_authorization_revoked("D-1", "after snapshot")
            return result
        r.reduce = inject_after
        t = MockTarget(target_id="T-1", capability=TargetCapability.DEDUP_ENFORCED)
        result = e.dispatch("D-1", t,
                            TargetContract("T-1", TargetCapability.DEDUP_ENFORCED, 3600))
        # This is the known residual race -- target IS called
        self.assertEqual(t.call_count, 1)
        self.assertEqual(result.outcome, "CONFIRMED")
        self.assertEqual(r.reduce("D-1").authorization_state, "REVOKED")


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
