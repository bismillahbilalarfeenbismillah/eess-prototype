# Bismillah ir-Rahman ir-Rahim
"""
EESS Normative Verifier Tests v0.1.4
Adversarial and positive fixtures invoking the reference verifier v0.4.
All calls go through verify_pipeline (sole public API per G4D-R1).
"""

import sys
import os
import hashlib
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from Bismillah_Reference_Verifier_v0_13 import verify_pipeline

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "Bismillah_Evidence_Receipt_v0_3_1_DRAFT.schema.json")
with open(SCHEMA_PATH) as f:
    SCHEMA = json.load(f)


def _content_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _make_eval_record(evaluation_id, claim_id, claim_revision_id,
                      claim_text, evaluator_lineage_id,
                      tested_property="SHA-256 hash verification",
                      observed_result="hash matched",
                      claim_relevance="direct_test",
                      outcome_type="PASS",
                      execution_evidence_id=None,
                      method_name="sha256sum"):
    content_hash = _content_hash(claim_text)
    rec = {
        "evaluation_id": evaluation_id,
        "claim_id": claim_id,
        "claim_revision_id": claim_revision_id,
        "claim_content_hash": content_hash,
        "evaluator_lineage_id": evaluator_lineage_id,
        "tested_property": tested_property,
        "observed_result": observed_result,
        "claim_relevance": claim_relevance,
        "outcome_type": outcome_type,
        "method_name": method_name,
        "assessment_timestamp": "2026-11-01T12:00:00Z",
        "record_content_hash": "placeholder"
    }
    if execution_evidence_id:
        rec["execution_evidence_id"] = execution_evidence_id
    hashable = {k: v for k, v in rec.items() if k != "record_content_hash"}
    rec["record_content_hash"] = hashlib.sha256(
        json.dumps(hashable, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()
    return rec


CLAIM_TEXT = "File X has SHA-256 hash Y"
CLAIM_HASH = _content_hash(CLAIM_TEXT)
DEFAULT_TARGET = "test-target"


def make_full_receipt(status="VERIFIED", claim_id="CLAIM-001",
                      eval_record_id="EVAL-001", evaluator="EVAL-LAB",
                      producer="PROD-A", claim_relevance="direct_test",
                      observed_result="hash matched",
                      action="no_action", auth=None,
                      review_auth=None, revisions=None,
                      independence_assessment="independent",
                      extra_evidence=None):
    eval_rec = _make_eval_record(
        eval_record_id, claim_id, "REV-001", CLAIM_TEXT,
        evaluator, observed_result=observed_result,
        claim_relevance=claim_relevance,
        execution_evidence_id="EXEC-001"
    )

    evidence = {
        "evidence_id": "E-001",
        "source_id": "SRC-001",
        "locator": "file:///evidence/hash.txt",
        "kind": "recomputed_measurement",
        "independence": "external",
        "verification_state": "reproduced",
        "evaluation_record_id": eval_record_id,
        "evaluator_binding": {
            "claim_id": claim_id,
            "claim_revision_id": "REV-001",
            "claim_content_hash": CLAIM_HASH,
            "tested_property": "SHA-256 hash verification",
            "observed_result": observed_result,
            "claim_relevance": claim_relevance,
            "assessed_by": evaluator,
            "assessment_timestamp": "2026-11-01T12:00:00Z"
        }
    }

    if extra_evidence:
        evidence.update(extra_evidence)

    receipt = {
        "schema_version": "0.3.1-draft",
        "claim_id": claim_id,
        "claim": CLAIM_TEXT,
        "claim_content_hash": CLAIM_HASH,
        "claim_type": "computation",
        "tier": "Tier 1",
        "status": status,
        "source_evidence": [evidence],
        "evidence_independence": "external",
        "independence_provenance": {
            "producer_lineage_id": producer,
            "evaluator_lineage_id": evaluator,
            "assessment": independence_assessment,
            "organizational_relationship": "independent"
        },
        "method": {
            "name": "sha256sum",
            "version": "coreutils 9.4",
            "scope": "file integrity",
            "execution_evidence_id": "EXEC-001"
        },
        "allowed_action": action,
        "review": {"reviewer": "Human Reviewer", "date": "2026-11-01"},
        "limitations": ["Single hash verification only"],
        "evaluation_records": [eval_rec],
        "revision_history": revisions or []
    }

    if review_auth is not None:
        receipt["review"]["authorization"] = review_auth
    if auth is not None:
        receipt["effect_authorization"] = auth
    return receipt


def make_registry(producer="PROD-A", evaluator="EVAL-LAB"):
    """Registry with affirmative lineage data per G4D-R5. G4I-R4: structured graphCoverage."""
    return {
        "graphCoverage": {"status": "complete", "claim_scope": "CLAIM-001", "policy_version": "1.0"},
        "lineages": {
            producer: {
                "parent_lineage_id": None,
                "registration_date": "2026-01-01",
                "registration_evidence_id": "REG-PROD-001",
                "organization": "Producer Corp",
                "lineage_type": "producer"
            },
            evaluator: {
                "parent_lineage_id": None,
                "registration_date": "2026-01-01",
                "registration_evidence_id": "REG-EVAL-001",
                "organization": "Independent Eval Lab",
                "lineage_type": "evaluator"
            }
        }
    }


def make_evidence_snapshot(eval_record_id="EVAL-001", eval_rec=None):
    if eval_rec is None:
        eval_rec = _make_eval_record(
            eval_record_id, "CLAIM-001", "REV-001", CLAIM_TEXT, "EVAL-LAB",
            execution_evidence_id="EXEC-001"
        )
    return {
        "evaluation_records": {eval_record_id: eval_rec},
        "execution_records": {
            "EXEC-001": {
                "execution_id": "EXEC-001",
                "method_name": "sha256sum",
                "timestamp": "2026-11-01T11:00:00Z",
                "status": "completed",
                "claim_id": "CLAIM-001",
                "claim_revision_id": "REV-001"
            }
        }
    }


def make_policy_snapshot(approval_id=None, approval_rec=None, policies=None):
    snap = {
        "applicability_policies": policies or {},
        "approval_records": {}
    }
    if approval_id and approval_rec:
        snap["approval_records"][approval_id] = approval_rec
    return snap


def make_valid_approval(approval_id="A-001", action="bounded_effect",
                        target=None):
    if target is None:
        target = DEFAULT_TARGET
    return {
        "approval_id": approval_id,
        "approving_principal": "bilal",
        "approved_action": action,
        "approved_target": target,
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2040-01-01T00:00:00Z",
        "revocation_status": "active"
    }


def make_verification_context(timestamp="2026-11-02T12:00:00Z",
                               target=None):
    if target is None:
        target = DEFAULT_TARGET
    return {
        "verification_timestamp": timestamp,
        "requested_target": target
    }


# ============================================================
# TESTS
# ============================================================

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  PASS  {name}")
        passed += 1
    else:
        print(f"  FAIL  {name}: {detail}")
        failed += 1


def test_01_genuinely_assured():
    """POSITIVE: Full pipeline -- external evaluator, authenticated record."""
    print("\nT-NV-01: Genuinely ASSURED case")
    receipt = make_full_receipt(status="VERIFIED")
    registry = make_registry()
    evidence = make_evidence_snapshot()
    policy = make_policy_snapshot()

    result = verify_pipeline(receipt, SCHEMA, registry, policy, evidence)
    check("conformance is CONFORMANT", result["claim_conformance"]["overall"] == "CONFORMANT",
          result["claim_conformance"]["overall"])
    check("assurance is ASSURED", result["claim_assurance"]["overall"] == "ASSURED",
          result["claim_assurance"]["overall"])
    check("execution not requested", result["action_authorization"]["execution_permission"] == "NOT_REQUESTED")


def test_02_fabricated_evaluator():
    """NEGATIVE: evaluation_record_id references missing record in snapshot."""
    print("\nT-NV-02: Fabricated evaluator -- missing record in snapshot")
    receipt = make_full_receipt(status="VERIFIED", eval_record_id="EVAL-FAKE")
    registry = make_registry()
    evidence = make_evidence_snapshot(eval_record_id="EVAL-REAL")
    policy = make_policy_snapshot()

    result = verify_pipeline(receipt, SCHEMA, registry, policy, evidence)
    check("assurance is NOT ASSURED or UNCERTIFIED",
          result["claim_assurance"]["overall"] in ("NOT_ASSURED", "UNCERTIFIED"),
          result["claim_assurance"]["overall"])


def test_03_self_produced_only():
    """NEGATIVE: Self-produced evidence only."""
    print("\nT-NV-03: Self-produced evidence only")
    receipt = make_full_receipt(status="VERIFIED", producer="PROD-A", evaluator="PROD-A")
    registry = make_registry(producer="PROD-A", evaluator="PROD-A")
    evidence = make_evidence_snapshot()
    policy = make_policy_snapshot()

    result = verify_pipeline(receipt, SCHEMA, registry, policy, evidence)
    check("independence FAIL", result["claim_assurance"]["witness_independence"] == "FAIL",
          result["claim_assurance"]["witness_independence"])
    check("assurance is NOT_ASSURED", result["claim_assurance"]["overall"] == "NOT_ASSURED",
          result["claim_assurance"]["overall"])


def test_04_missing_provenance():
    """NEGATIVE: Missing independence provenance."""
    print("\nT-NV-04: Missing independence provenance")
    receipt = make_full_receipt(status="VERIFIED")
    del receipt["independence_provenance"]
    receipt["evidence_independence"] = "external"
    registry = make_registry()
    evidence = make_evidence_snapshot()

    result = verify_pipeline(receipt, SCHEMA, registry, None, evidence)
    check("independence FAIL", result["claim_assurance"]["witness_independence"] == "FAIL",
          result["claim_assurance"]["witness_independence"])


def test_05_failed_observed_result():
    """NEGATIVE: Evaluator observed failure."""
    print("\nT-NV-05: Failed observed result in evaluation record")
    receipt = make_full_receipt(status="VERIFIED", observed_result="failed to reproduce")
    eval_rec = _make_eval_record(
        "EVAL-001", "CLAIM-001", "REV-001", CLAIM_TEXT, "EVAL-LAB",
        observed_result="failed to reproduce"
    )
    evidence = make_evidence_snapshot(eval_rec=eval_rec)
    registry = make_registry()

    result = verify_pipeline(receipt, SCHEMA, registry, None, evidence)
    check("relevance FAIL", result["claim_assurance"]["evidence_relevance"] == "FAIL",
          result["claim_assurance"]["evidence_relevance"])
    check("assurance NOT_ASSURED", result["claim_assurance"]["overall"] == "NOT_ASSURED",
          result["claim_assurance"]["overall"])


def test_06_stale_revision():
    """NEGATIVE: Evaluation record bound to old revision -- content hash mismatch."""
    print("\nT-NV-06: Stale claim revision -- content hash mismatch")
    old_text = "Old claim text that has been superseded"
    new_text = "New claim text after revision"
    new_hash = _content_hash(new_text)

    eval_rec = _make_eval_record(
        "EVAL-001", "CLAIM-001", "REV-001", old_text, "EVAL-LAB"
    )

    receipt = make_full_receipt(status="VERIFIED")
    receipt["claim"] = new_text
    receipt["claim_content_hash"] = new_hash

    evidence = make_evidence_snapshot(eval_rec=eval_rec)
    registry = make_registry()

    result = verify_pipeline(receipt, SCHEMA, registry, None, evidence)
    check("relevance UNCERTIFIED or FAIL (stale binding)",
          result["claim_assurance"]["evidence_relevance"] in ("UNCERTIFIED", "FAIL"),
          result["claim_assurance"]["evidence_relevance"])


def test_07_bounded_effect_unknown():
    """NEGATIVE: Bounded effect with UNKNOWN authorization check."""
    print("\nT-NV-07: Bounded effect with UNKNOWN authorization")
    auth = {
        "contract_match": "TRUE", "effect_type_allowed": "TRUE",
        "target_allowed": "UNKNOWN", "witness_healthy": "TRUE",
        "evidence_current": "TRUE", "approval_record_id": "A-001"
    }
    receipt = make_full_receipt(status="VERIFIED", action="bounded_effect", auth=auth)
    registry = make_registry()
    evidence = make_evidence_snapshot()
    policy = make_policy_snapshot("A-001", make_valid_approval())
    ctx = make_verification_context()

    result = verify_pipeline(receipt, SCHEMA, registry, policy, evidence, ctx)
    check("authorization FAIL", result["action_authorization"]["authorization_consistency"] == "FAIL",
          result["action_authorization"]["authorization_consistency"])
    check("execution DENIED", result["action_authorization"]["execution_permission"] == "DENIED",
          result["action_authorization"]["execution_permission"])


def test_08_human_approval_nonconformant():
    """NEGATIVE: Human approval on non-conformant receipt (NV-21 fail-closed)."""
    print("\nT-NV-08: Human approval on non-conformant receipt")
    auth = {
        "contract_match": "TRUE", "effect_type_allowed": "TRUE",
        "target_allowed": "TRUE", "witness_healthy": "TRUE",
        "evidence_current": "TRUE", "approval_record_id": "A-001"
    }
    receipt = make_full_receipt(status="VERIFIED", action="bounded_effect",
                               auth=auth, review_auth="approved")
    receipt["source_evidence"] = []
    receipt["evidence_independence"] = "unknown"
    del receipt["independence_provenance"]

    registry = make_registry()
    policy = make_policy_snapshot("A-001", make_valid_approval())
    evidence = make_evidence_snapshot()
    ctx = make_verification_context()

    result = verify_pipeline(receipt, SCHEMA, registry, policy, evidence, ctx)
    check("conformance NON_CONFORMANT",
          result["claim_conformance"]["overall"] == "NON_CONFORMANT",
          result["claim_conformance"]["overall"])
    check("execution DENIED despite approval",
          result["action_authorization"]["execution_permission"] == "DENIED",
          result["action_authorization"]["execution_permission"])


def test_09_cyclic_revisions():
    """NEGATIVE: Cyclic revision history."""
    print("\nT-NV-09: Cyclic revision history")
    revisions = [
        {"revision_id": "R1", "relation": "supersedes", "prior_revision_id": "R2",
         "status": "VERIFIED", "timestamp": "2026-11-01T01:00:00Z"},
        {"revision_id": "R2", "relation": "supersedes", "prior_revision_id": "R1",
         "status": "VERIFIED", "timestamp": "2026-11-01T02:00:00Z"},
    ]
    receipt = make_full_receipt(status="VERIFIED", revisions=revisions)
    registry = make_registry()
    evidence = make_evidence_snapshot()

    result = verify_pipeline(receipt, SCHEMA, registry, None, evidence)
    check("revision integrity FAIL",
          result["claim_conformance"]["revision_integrity"] == "FAIL",
          result["claim_conformance"]["revision_integrity"])
    check("conformance NON_CONFORMANT",
          result["claim_conformance"]["overall"] == "NON_CONFORMANT",
          result["claim_conformance"]["overall"])


def test_10_honestly_unknown():
    """POSITIVE: Honestly UNKNOWN receipt is CONFORMANT."""
    print("\nT-NV-10: Honestly UNKNOWN receipt")
    receipt = {
        "schema_version": "0.3.1-draft",
        "claim_id": "CLAIM-UNK",
        "claim": "Unverified hypothesis",
        "claim_type": "inference",
        "tier": "Tier 3",
        "status": "UNKNOWN",
        "source_evidence": [],
        "evidence_independence": "unknown",
        "method": {"name": "manual", "version": "1.0", "scope": "hypothesis"},
        "allowed_action": "no_action",
        "review": {"reviewer": "Human Reviewer", "date": "2026-11-01"},
        "limitations": ["No independent evidence available"],
    }

    result = verify_pipeline(receipt, SCHEMA)
    check("conformance CONFORMANT",
          result["claim_conformance"]["overall"] == "CONFORMANT",
          result["claim_conformance"]["overall"])
    check("execution NOT_REQUESTED",
          result["action_authorization"]["execution_permission"] == "NOT_REQUESTED")


def test_11_not_applicable_with_policy():
    """POSITIVE: NOT_APPLICABLE authorization with valid, scope-matched policy."""
    print("\nT-NV-11: NOT_APPLICABLE with valid scoped policy")
    auth = {
        "contract_match": "TRUE", "effect_type_allowed": "TRUE",
        "target_allowed": "NOT_APPLICABLE", "witness_healthy": "TRUE",
        "evidence_current": "TRUE", "approval_record_id": "A-001",
        "exception_policy": "POLICY-TARGET-EXEMPT-2026"
    }
    policy = make_policy_snapshot(
        policies={
            "POLICY-TARGET-EXEMPT-2026": {
                "scope": "internal-only",
                "allowed_checks": ["target_allowed"],
                "approved_action": "bounded_effect"
            }
        },
        approval_id="A-001",
        approval_rec=make_valid_approval()
    )
    receipt = make_full_receipt(status="VERIFIED", action="bounded_effect", auth=auth)
    registry = make_registry()
    evidence = make_evidence_snapshot()
    ctx = make_verification_context()

    result = verify_pipeline(receipt, SCHEMA, registry, policy, evidence, ctx)
    check("authorization not FAIL",
          result["action_authorization"]["authorization_consistency"] != "FAIL",
          result["action_authorization"]["authorization_consistency"])


def test_12_not_applicable_without_policy():
    """NEGATIVE: NOT_APPLICABLE without exception_policy."""
    print("\nT-NV-12: NOT_APPLICABLE without policy")
    auth = {
        "contract_match": "TRUE", "effect_type_allowed": "TRUE",
        "target_allowed": "NOT_APPLICABLE", "witness_healthy": "TRUE",
        "evidence_current": "TRUE", "approval_record_id": "A-001",
        "exception_policy": None
    }
    receipt = make_full_receipt(status="VERIFIED", action="bounded_effect", auth=auth)
    registry = make_registry()
    evidence = make_evidence_snapshot()
    policy = make_policy_snapshot("A-001", make_valid_approval())
    ctx = make_verification_context()

    result = verify_pipeline(receipt, SCHEMA, registry, policy, evidence, ctx)
    check("authorization FAIL (no policy)",
          result["action_authorization"]["authorization_consistency"] == "FAIL",
          result["action_authorization"]["authorization_consistency"])
    check("execution DENIED",
          result["action_authorization"]["execution_permission"] == "DENIED")


# ============================================================
# RUN ALL
# ============================================================

if __name__ == "__main__":
    test_01_genuinely_assured()
    test_02_fabricated_evaluator()
    test_03_self_produced_only()
    test_04_missing_provenance()
    test_05_failed_observed_result()
    test_06_stale_revision()
    test_07_bounded_effect_unknown()
    test_08_human_approval_nonconformant()
    test_09_cyclic_revisions()
    test_10_honestly_unknown()
    test_11_not_applicable_with_policy()
    test_12_not_applicable_without_policy()

    total = passed + failed
    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed out of {total}")
    if failed == 0:
        print("All normative tests passed.")
    else:
        print("SOME TESTS FAILED.")
        sys.exit(1)
# Bismillah ir-Rahman ir-Rahim
