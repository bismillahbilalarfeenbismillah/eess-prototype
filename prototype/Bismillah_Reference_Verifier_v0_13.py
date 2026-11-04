# Bismillah ir-Rahman ir-Rahim
"""
EESS Reference Verifier v0.13 -- Strict-by-default executable normative verifier.
Pure function of (receipt, schema_obj, registry_snapshot, policy_snapshot, evidence_snapshot, verification_context).
Deterministic, side-effect-free.

NON-AUTHORIZING DEMONSTRATION CODE until independently audited.
Output must not be connected to any executor or interpreted as valid approval.

NOTE ON TRUST BOUNDARIES: This verifier takes caller-provided snapshots, clock,
and principal identifiers. It does NOT authenticate snapshot provenance, verify
cryptographic signatures, validate clock source trustworthiness, or confirm
principal authority through external trust anchors. These are EXTERNAL TRUST
DEPENDENCIES that must be established by a separately enforced trust boundary
before any deployment.

NOTE ON CANONICALIZATION: _jcs_canonical_hash uses json.dumps(sort_keys=True,
separators=(',',':')) which is a simplified approximation of RFC 8785 JCS.
A conforming implementation with cross-language test vectors is required before
claiming independently authenticated assurance.

NOTE ON TIMESTAMP PRECISION: This verifier supports RFC3339 fractional seconds
up to 6 digits (microsecond precision). Timestamps with fractional precision
greater than 6 digits are REJECTED as unsupported to prevent silent truncation.
This is an explicit, documented limitation per G4F-R2.

Addresses Gate 4L findings (building on all prior Gate fixes):
- G4L-R1 (HIGH): Ancestor organizational affiliation validation. Missing or None
  organization on TRAVERSED ancestor nodes (not just endpoints) now yields
  UNCERTIFIED for bounded_effect with independence claims. Previously, the
  ancestor org collection loop used `if org is not None` which silently skipped
  nodes with absent or None organization, allowing unknown organizational
  independence to be treated as confirmed separation.
- G4L-R3 (CONTRACT): Organization identity comparison uses .strip() for
  whitespace normalization. Unicode NFC/NFD normalization is a PRODUCTION
  requirement deferred to authenticated infrastructure.
- G4L-R2 (CONTRACT): Demo verifier validates only the RELEVANT subgraph
  (nodes traversed during producer/evaluator ancestry). Unused nodes with
  malformed data are not validated. Production WIR must validate all nodes.
- G4L-R4 (ADVISORY): If ANY valid affirmative registration field exists,
  the node has registration evidence. An invalid additional field does not
  invalidate a valid one.
- G4L-R6 (LOW): Archive member count corrected in README.

Prior Gate 4K findings retained:
- G4K-R1 (HIGH): Missing/invalid organizational affiliation fails closed.
  Lineage node organization fields must be non-empty strings when present.
  Missing, non-string, or blank organization on any relevant lineage node
  yields UNCERTIFIED for bounded_effect with independence claims.
- G4K-R2 (HIGH): Nested registry type validation expanded. parent_lineage_id
  and organization fields validated as strings at entry boundary. Non-string
  types produce typed FAIL, not uncaught exceptions.
- G4K-R3 (MEDIUM/HIGH): Registration evidence accepted only as non-blank
  strings. Boolean True, whitespace-only, or non-string values are rejected.
- G4K-R4 (MEDIUM): Top-level snapshot type guards. Non-dict evidence_snapshot,
  policy_snapshot, and verification_context produce typed failure, not
  AttributeError exceptions.
- G4K-R5 (CONTRACT): Separation policy status, expiry, and controls are
  PRODUCTION requirements deferred to authenticated policy infrastructure.
  The local demonstration verifier validates structure (id + scope) only.
- G4K-R6 (CONTRACT): Extra graphCoverage detail fields (e.g. lineages_covered)
  are not part of the current local contract. Production WIR must validate
  coverage detail.

Prior Gate 4J fixes retained:
- G4J-R1 (HIGH): Policy scope and type enforcement. Separation policies
  and shared-source exemption policies must have string policy_id (non-
  whitespace) and scope that EXACTLY matches the claim_id being verified.
  Wrong type, wrong scope, or whitespace-only policy_id all deny.
- G4J-R2 (HIGH): graphCoverage claim-scope binding. Structured coverage
  claim_scope must be a string matching the receipt's claim_id.
  policy_version must be a non-empty string. Wrong types denied.
- G4J-R3 (HIGH): Deep type validation for untrusted registry snapshots.
  All nested fields validated: shared_keys elements must be strings,
  shared_source_ids must be list of strings (not scalar), signing_key_
  fingerprint must be string, separation_policies/shared_source_policies
  must be dicts. Deterministic typed DENIED on malformed input.
- G4J-R4 (MEDIUM/HIGH): Scalar shared_source_ids string cannot evade
  matching. Non-array shared_source_ids rejected at entry boundary.
- G4J-R5 (MEDIUM): Evaluator binding diagnostic copy contract decision.
  Missing optional diagnostic fields are ALLOWED. Present diagnostic
  fields that contradict authoritative records yield UNCERTIFIED:
  claim_id, claim_relevance, assessment_timestamp (valid+not future),
  observed_result (no negative indicators with PASS outcome).

Prior Gate 4I fixes retained:
- G4I-R1 (HIGH): Unified execution validation for observed/reproduced.
- G4I-R2 (HIGH): Revision equivalence without revision_history.
- G4I-R3 (HIGH): Structured policy validation (now tightened by G4J-R1).
- G4I-R4 (HIGH): Structured graphCoverage (now tightened by G4J-R2).
- G4I-R5 (MEDIUM): Summary contradiction reconciliation.
- G4I-R6 (MEDIUM): Revision chronology.
- G4I-R7 (MEDIUM): Normative evaluator_binding fields.
- G4I-R8 (MEDIUM): Registry type validation (now deepened by G4J-R3).
- G4I-R9 (ADVISORY): Strict RFC3339 T; approval revision validation.

Prior Gate 4H fixes retained:
- G4H-R1 (CRITICAL): WIR summary-field bypass removed.
- G4H-R2 (HIGH): Shared source IDs and organizational control checked.
- G4H-R3 (HIGH): Missing graphCoverage defaults to "unknown".
- G4H-R4 (HIGH): Superseded revision detection.
- G4H-R5 (HIGH/MEDIUM): Causal time ordering enforced.
- G4H-R6 (MEDIUM): Execution record claim_id/claim_revision_id mandatory.
- G4H-R7: External trust dependencies acknowledged as pre-deployment gate.

Prior Gate 4G fixes retained:
- G4G-R1: Ancestor closure completeness signal.
- G4G-R2: Affirmative registration evidence for every ancestor.
- G4G-R3: Signing key fingerprint collection from all ancestors.
- G4G-R4: partially_independent -> UNCERTIFIED for bounded effects.
- G4G-R5: Execution record hardening.
- G4G-R6: Mandatory evaluator method_name, duplicate eval record detection.

Prior Gate 4F fixes retained:
- G4F-R1: NOT_ASSURED/UNCERTIFIED never authorize bounded effects.
- G4F-R2: >6 digit fractional seconds rejected.
- G4F-R3: Execution record status allowlist, method_name, execution_id match.
- G4F-R4: Assessment_timestamp mandatory/parseable. Method binding enforced.
- G4F-R5: Transitive ancestor closure with shared ancestor intersection.
- G4F-A1: Typed PASS with empty observed_result -> UNCERTIFIED.
"""

import hashlib
import json
import re
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _jcs_canonical_hash(obj):
    """SHA-256 of JCS-like canonical serialization (simplified)."""
    canonical = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


# G4F-R2: Reject fractional seconds > 6 digits explicitly
# G4I-R9: Strict T separator required (space no longer accepted)
_RFC3339_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})'
    r'(?:\.(\d+))?'
    r'(Z|([+-])(\d{2}):(\d{2}))$'
)

def _parse_rfc3339(s):
    """
    Parse RFC3339 timestamp to UTC-aware datetime.
    G4F-R2: Rejects fractional seconds with more than 6 digits.
    Returns None for unparseable or unsupported-precision timestamps.
    """
    if not s or not isinstance(s, str):
        return None
    m = _RFC3339_RE.match(s)
    if not m:
        return None
    try:
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
        microsecond = 0
        frac = m.group(7)
        if frac:
            if len(frac) > 6:
                return None  # G4F-R2: reject > 6 digits, no silent truncation
            frac_padded = (frac + '000000')[:6]
            microsecond = int(frac_padded)
        if m.group(8) == 'Z':
            tz = timezone.utc
        else:
            sign = 1 if m.group(9) == '+' else -1
            tz_hours, tz_minutes = int(m.group(10)), int(m.group(11))
            tz = timezone(timedelta(hours=sign * tz_hours, minutes=sign * tz_minutes))
        dt = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tz)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


# G4F-R1: Category-based assurance checking replaces numeric ordering.
# NOT_ASSURED and UNCERTIFIED are NEVER satisfiable for bounded effects.
_ACTIONABLE_ASSURANCE = {"ASSURED", "PASS"}  # Only these can satisfy bounded effects
_NON_ACTIONABLE_ASSURANCE = {"UNCERTIFIED", "NOT_ASSURED"}  # Never satisfiable

def _assurance_satisfies_for_bounded_effect(actual, required):
    """
    G4F-R1: Check if actual assurance satisfies required for bounded_effect.
    UNCERTIFIED and NOT_ASSURED are NEVER satisfiable regardless of policy.
    Policy cannot require a non-actionable assurance level.
    Returns (satisfied: bool, reason: str or None).
    """
    # Policy itself must require an actionable level
    if required not in _ACTIONABLE_ASSURANCE:
        return False, f"Policy requires non-actionable assurance level '{required}' -- policy cannot waive mandatory safety invariants"
    # Actual must be actionable
    if actual in _NON_ACTIONABLE_ASSURANCE:
        return False, f"Actual assurance '{actual}' is non-actionable and can never authorize bounded effects"
    # Now compare within actionable levels: ASSURED > PASS
    if required == "ASSURED" and actual != "ASSURED":
        return False, f"Required ASSURED but actual is '{actual}'"
    # required == "PASS" is satisfied by PASS or ASSURED
    return True, None


# G4F-R3: Successful execution status allowlist
_SUCCESSFUL_EXEC_STATUSES = {"completed", "success", "passed"}

# Recognized outcome types
_RECOGNIZED_OUTCOMES = {"PASS", "FAIL", "INDETERMINATE"}


# G4I-R3 + G4J-R1: Structured, claim-scoped policy validation
def _is_valid_separation_policy(policy_entry, claim_id):
    """G4J-R1: Validate that a separation policy is properly structured and
    claim-scoped. Requires a dict with string policy_id (non-whitespace)
    and string scope that exactly matches the claim_id."""
    if not isinstance(policy_entry, dict):
        return False
    pid = policy_entry.get("policy_id")
    scope = policy_entry.get("scope")
    if not isinstance(pid, str) or not pid.strip():
        return False
    if not isinstance(scope, str) or scope != claim_id:
        return False
    return True


def _is_valid_shared_source_policy(policy_entry, claim_id):
    """G4J-R1: Validate that a shared-source exemption policy is properly
    structured and claim-scoped. Requires a dict with string policy_id
    (non-whitespace) and string scope that exactly matches the claim_id."""
    if not isinstance(policy_entry, dict):
        return False
    pid = policy_entry.get("policy_id")
    scope = policy_entry.get("scope")
    if not isinstance(pid, str) or not pid.strip():
        return False
    if not isinstance(scope, str) or scope != claim_id:
        return False
    return True


def _compute_effective_status(receipt):
    """Derive effective claim status from revision history leaves. Called FIRST."""
    top_status = receipt.get("status", "UNKNOWN")
    revisions = receipt.get("revision_history", [])

    if not revisions:
        effective = top_status
    else:
        all_rev_ids = {r["revision_id"] for r in revisions}
        referenced = set()
        for r in revisions:
            prior = r.get("prior_revision_id")
            if prior:
                referenced.add(prior)
        leaves = all_rev_ids - referenced
        leaf_statuses = set()
        for r in revisions:
            if r["revision_id"] in leaves:
                leaf_statuses.add(r.get("status", "UNKNOWN"))

        if len(leaf_statuses) == 0:
            effective = top_status
        elif len(leaf_statuses) == 1:
            if len(leaves) > 1:
                effective = "UNRECONCILED"
            else:
                effective = leaf_statuses.pop()
        else:
            if "WITHDRAWN" in leaf_statuses:
                effective = "WITHDRAWN"
            elif "CONTRADICTED" in leaf_statuses:
                effective = "CONTRADICTED"
            else:
                effective = "UNRECONCILED"

    terminal_states = {"WITHDRAWN", "CONTRADICTED", "UNRECONCILED", "UNKNOWN"}
    is_terminal = effective in terminal_states
    if top_status == "VERIFIED" and effective != "VERIFIED" and effective != top_status:
        is_terminal = True

    return effective, is_terminal


def _get_effective_revisions(receipt):
    """Return the set of effective (leaf) revision IDs from revision_history."""
    revisions = receipt.get("revision_history", [])
    if not revisions:
        return set()
    all_rev_ids = {r["revision_id"] for r in revisions}
    referenced = set()
    for r in revisions:
        prior = r.get("prior_revision_id")
        if prior:
            referenced.add(prior)
    return all_rev_ids - referenced


# ---------------------------------------------------------------------------
# G4G-R1: Full transitive ancestor closure with completeness signal
# G4G-R2: Affirmative registration evidence for every ancestor
# G4G-R3: Signing key fingerprint collection from all ancestors
# ---------------------------------------------------------------------------

_STRONG_AFFIRMATIVE_FIELDS = {"registration_evidence_id", "verified_by"}

def _compute_ancestor_closure(lineage_id, lineages, max_depth=100):
    """
    Compute full ancestor closure for a lineage.
    G4G-R1: Returns (ancestors, unregistered, has_cycle, complete, keys, unevidenced).
      ancestors: set of all transitive ancestor IDs (not the starting node itself).
      unregistered: set of referenced but not registered ancestor node IDs.
      has_cycle: True if a cycle was detected during traversal.
      complete: True only if traversal reached a root (parent=None) without
                hitting depth limit, cycle, or missing node. False means the
                ancestor set may be incomplete -- caller MUST treat as UNCERTIFIED.
      keys: set of signing_key_fingerprint values from ALL traversed nodes
            (including the start node). G4G-R3.
      unevidenced: set of ancestor IDs lacking registration_evidence_id. G4G-R2.
    """
    ancestors = set()
    unregistered = set()
    has_cycle = False
    complete = False
    keys = set()
    unevidenced = set()
    visited = set()
    cur = lineage_id
    depth = 0

    # Collect key from start node if present
    if cur in lineages:
        start_entry = lineages[cur]
        fp = start_entry.get("signing_key_fingerprint")
        if fp:
            keys.add(fp)
        for k in start_entry.get("shared_keys", []):
            keys.add(k)

    while depth < max_depth:
        if cur not in lineages:
            if cur != lineage_id:
                unregistered.add(cur)
            # Missing node -- traversal incomplete
            complete = False
            break
        if cur in visited:
            has_cycle = True
            complete = False
            break
        visited.add(cur)
        entry = lineages[cur]
        parent = entry.get("parent_lineage_id")
        if parent is None:
            # Reached root -- traversal complete
            complete = True
            break
        ancestors.add(parent)
        # Collect keys from ancestor
        if parent in lineages:
            anc_entry = lineages[parent]
            fp = anc_entry.get("signing_key_fingerprint")
            if fp:
                keys.add(fp)
            for k in anc_entry.get("shared_keys", []):
                keys.add(k)
            # G4G-R2 + G4K-R3: Check ancestor has valid string registration evidence
            has_valid_reg = False
            for f in _STRONG_AFFIRMATIVE_FIELDS:
                val = anc_entry.get(f)
                if isinstance(val, str) and val.strip():
                    has_valid_reg = True
                    break
            if not has_valid_reg:
                unevidenced.add(parent)
        cur = parent
        depth += 1
    else:
        # Exited loop via depth limit -- traversal incomplete (G4G-R1)
        complete = False

    return ancestors, unregistered, has_cycle, complete, keys, unevidenced


# ---------------------------------------------------------------------------
# NV-01 through NV-03: Evidence eligibility
# G4F-R3: Strict execution record validation
# G4G-R5: Execution record hardening
# ---------------------------------------------------------------------------

def _check_evidence_eligibility(receipt, evidence_snapshot, verification_context=None):
    """NV-01 through NV-03. G4F-R3 + G4G-R5: strict execution record validation."""
    checks = []
    status = receipt.get("status", "UNKNOWN")
    evidence_items = receipt.get("source_evidence", [])

    publisher_only_ids = set()
    for item in evidence_items:
        if item.get("kind") == "publisher_claim":
            publisher_only_ids.add(item.get("evidence_id"))

    has_valid_external = False
    for item in evidence_items:
        eid = item.get("evidence_id", "")

        if item.get("verification_state") == "failed":
            checks.append({"check": "NV-01", "result": "FAIL",
                "detail": f"Evidence {eid} has verification_state=failed"})
            continue

        if item.get("independence") == "external":
            prov = receipt.get("independence_provenance", {})
            if not prov or prov.get("assessment") not in ("independent", "partially_independent"):
                checks.append({"check": "NV-01", "result": "FAIL",
                    "detail": f"Evidence {eid} declares external but provenance does not support"})
            else:
                if item.get("verification_state") in ("observed", "reproduced"):
                    if eid not in publisher_only_ids:
                        has_valid_external = True

        if item.get("verification_state") == "reproduced":
            method = receipt.get("method", {})
            if not method.get("name") or not method.get("version") or not method.get("scope"):
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Evidence {eid} is reproduced but method is incomplete"})
            exec_id = method.get("execution_evidence_id")
            if not exec_id:
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Evidence {eid} is reproduced but no execution_evidence_id provided"})
            elif evidence_snapshot:
                exec_rec = evidence_snapshot.get("execution_records", {}).get(exec_id)
                if not exec_rec:
                    checks.append({"check": "NV-02", "result": "FAIL",
                        "detail": f"Execution record {exec_id} not in evidence snapshot"})
                else:
                    # G4F-R3 + G4G-R5: Strict execution record validation
                    _validate_execution_record(exec_id, exec_rec, method, checks,
                                                receipt, verification_context,
                                                evidence_snapshot)

        # G4I-R1: Observed direct_test evidence also requires execution binding
        # for bounded_effect actions. The same execution validation applies.
        if item.get("verification_state") == "observed":
            method = receipt.get("method", {})
            exec_id = method.get("execution_evidence_id")
            action = receipt.get("allowed_action", "no_action")
            if exec_id and evidence_snapshot:
                exec_rec = evidence_snapshot.get("execution_records", {}).get(exec_id)
                if exec_rec:
                    _validate_execution_record(exec_id, exec_rec, method, checks,
                                                receipt, verification_context,
                                                evidence_snapshot)
                elif action == "bounded_effect":
                    checks.append({"check": "NV-02", "result": "FAIL",
                        "detail": f"Evidence {eid} is observed for bounded_effect but execution record {exec_id} not in snapshot"})
            elif action == "bounded_effect" and not exec_id:
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Evidence {eid} is observed for bounded_effect but no execution_evidence_id in method"})

    if status == "VERIFIED" and not has_valid_external:
        checks.append({"check": "NV-01", "result": "FAIL",
            "detail": "VERIFIED status requires external evidence with observed/reproduced state"})

    if any(c["result"] == "FAIL" for c in checks):
        return "FAIL", checks
    if any(c["result"] == "UNCERTIFIED" for c in checks):
        return "UNCERTIFIED", checks
    return "PASS", checks


def _validate_execution_record(exec_id, exec_rec, method, checks,
                                receipt=None, verification_context=None,
                                evidence_snapshot=None):
    """G4F-R3 + G4G-R5 + G4I-R1/R2/R6: Validate execution record comprehensively."""
    # G4G-R5: execution_id is MANDATORY and must match lookup key
    internal_id = exec_rec.get("execution_id")
    if not internal_id:
        checks.append({"check": "NV-02", "result": "FAIL",
            "detail": f"Execution record {exec_id} missing mandatory execution_id"})
        return
    if internal_id != exec_id:
        checks.append({"check": "NV-02", "result": "FAIL",
            "detail": f"Execution record internal ID '{internal_id}' mismatches lookup key '{exec_id}'"})
        return

    # Status is mandatory and must be in allowlist
    exec_status = exec_rec.get("status")
    if exec_status is None or exec_status == "":
        checks.append({"check": "NV-02", "result": "FAIL",
            "detail": f"Execution record {exec_id} missing mandatory status field"})
        return
    if exec_status not in _SUCCESSFUL_EXEC_STATUSES:
        checks.append({"check": "NV-02", "result": "FAIL",
            "detail": f"Execution record {exec_id} status '{exec_status}' is not a recognized successful status (must be one of: {_SUCCESSFUL_EXEC_STATUSES})"})
        return

    # Method name is mandatory and must be non-empty
    exec_method = exec_rec.get("method_name")
    if not exec_method:
        checks.append({"check": "NV-02", "result": "FAIL",
            "detail": f"Execution record {exec_id} missing mandatory method_name"})
        return

    # Method name must match receipt's declared method
    receipt_method = method.get("name", "")
    if receipt_method and exec_method != receipt_method:
        checks.append({"check": "NV-02", "result": "UNCERTIFIED",
            "detail": f"Execution record method '{exec_method}' does not match receipt method '{receipt_method}'"})
        return

    # G4G-R5: Execution timestamp is mandatory, must parse, must not be future-dated
    exec_ts = exec_rec.get("timestamp")
    if not exec_ts:
        checks.append({"check": "NV-02", "result": "FAIL",
            "detail": f"Execution record {exec_id} missing mandatory timestamp"})
        return
    exec_dt = _parse_rfc3339(exec_ts)
    if exec_dt is None:
        checks.append({"check": "NV-02", "result": "FAIL",
            "detail": f"Execution record {exec_id} timestamp '{exec_ts}' is not a valid RFC3339 timestamp"})
        return
    # Future-dated check
    if verification_context:
        verify_ts = verification_context.get("verification_timestamp")
        if verify_ts:
            verify_dt = _parse_rfc3339(verify_ts)
            if verify_dt and exec_dt > verify_dt:
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Execution record {exec_id} timestamp is future-dated: {exec_ts}"})
                return

    # G4G-R5 + G4H-R6: claim_id and claim_revision_id validation
    if receipt:
        action = receipt.get("allowed_action", "no_action")
        rec_claim = exec_rec.get("claim_id")
        rec_rev = exec_rec.get("claim_revision_id")

        # G4H-R6: For bounded_effect, claim_id and claim_revision_id are MANDATORY
        if action == "bounded_effect":
            if not rec_claim:
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Execution record {exec_id} missing mandatory claim_id for bounded_effect action"})
                return
            if not rec_rev:
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Execution record {exec_id} missing mandatory claim_revision_id for bounded_effect action"})
                return

        if rec_claim and rec_claim != receipt.get("claim_id", ""):
            checks.append({"check": "NV-02", "result": "FAIL",
                "detail": f"Execution record {exec_id} claim_id '{rec_claim}' does not match receipt claim_id '{receipt.get('claim_id', '')}'"})
            return
        receipt_revisions = receipt.get("revision_history", [])
        if rec_rev and receipt_revisions:
            rev_ids = {r["revision_id"] for r in receipt_revisions}
            if rec_rev not in rev_ids:
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Execution record {exec_id} claim_revision_id '{rec_rev}' not in receipt revision history"})
                return
            # G4H-R4: Execution record must bind to effective (leaf) revision, not superseded
            effective_revs = _get_effective_revisions(receipt)
            if effective_revs and rec_rev not in effective_revs:
                checks.append({"check": "NV-02", "result": "FAIL",
                    "detail": f"Execution record {exec_id} bound to superseded revision '{rec_rev}' -- only leaf revisions are valid"})
                return

        # G4I-R2: Even without revision_history, execution revision must be consistent
        # with evidence bindings and evaluation records
        if rec_rev and not receipt_revisions:
            for ev_item in receipt.get("source_evidence", []):
                binding = ev_item.get("evaluator_binding", {})
                binding_rev = binding.get("claim_revision_id", "")
                if binding_rev and rec_rev != binding_rev:
                    checks.append({"check": "NV-02", "result": "FAIL",
                        "detail": f"Execution record {exec_id} claim_revision_id '{rec_rev}' does not match evidence binding revision '{binding_rev}' (no revision_history to validate against)"})
                    return
            if evidence_snapshot:
                for eval_id, eval_rec in evidence_snapshot.get("evaluation_records", {}).items():
                    eval_rev = eval_rec.get("claim_revision_id", "")
                    if eval_rev and rec_rev != eval_rev:
                        checks.append({"check": "NV-02", "result": "FAIL",
                            "detail": f"Execution record {exec_id} claim_revision_id '{rec_rev}' does not match evaluation record '{eval_id}' revision '{eval_rev}'"})
                        return

        # G4I-R6: Revision creation time must precede execution
        if rec_rev and receipt_revisions:
            for rev in receipt_revisions:
                if rev.get("revision_id") == rec_rev:
                    rev_ts = rev.get("timestamp")
                    if rev_ts and exec_ts:
                        rev_dt = _parse_rfc3339(rev_ts)
                        if rev_dt and exec_dt and rev_dt > exec_dt:
                            checks.append({"check": "NV-02", "result": "FAIL",
                                "detail": f"Execution record {exec_id} timestamp {exec_ts} predates revision {rec_rev} creation {rev_ts} -- execution cannot predate the claim revision it tested"})
                            return
                    break


# ---------------------------------------------------------------------------
# NV-04 through NV-07: Independence provenance
# G4F-R5: Full transitive ancestor closure
# G4G-R1: Completeness signal
# G4G-R2: Affirmative registration evidence
# G4G-R3: Ancestor key intersection
# G4G-R4: partially_independent semantics
# ---------------------------------------------------------------------------

def _has_independence_relevant_evidence(receipt):
    """G4H-R1: Determine if ANY evidence carries independence markers that
    require WIR evaluation, regardless of the summary field value."""
    for item in receipt.get("source_evidence", []):
        if item.get("independence") == "external":
            return True
        if item.get("verification_state") in ("observed", "reproduced"):
            if item.get("kind") != "publisher_claim":
                return True
    prov = receipt.get("independence_provenance")
    if prov:
        if prov.get("assessment") in ("independent", "partially_independent"):
            return True
        if prov.get("producer_lineage_id") and prov.get("evaluator_lineage_id"):
            return True
    return False


def _check_independence_provenance(receipt, registry_snapshot):
    """NV-04 through NV-07. G4F-R5 + G4G-R1/R2/R3/R4 + G4H-R1/R2/R3.
    G4H-R1: The summary field (evidence_independence) no longer gates WIR
    evaluation. If ANY evidence item carries independence markers or external
    provenance, ALL WIR checks are performed regardless of the summary value.
    """
    checks = []
    prov = receipt.get("independence_provenance")
    indep = receipt.get("evidence_independence", "unknown")

    # G4J-R3: Deep type validation for untrusted registry snapshot
    if registry_snapshot is not None and not isinstance(registry_snapshot, dict):
        checks.append({"check": "NV-05", "result": "FAIL",
            "detail": f"Registry snapshot is not a dict: {type(registry_snapshot).__name__}"})
        return "FAIL", checks
    if registry_snapshot:
        # G4J-R3: Validate separation_policies is a dict if present
        sep_pol = registry_snapshot.get("separation_policies")
        if sep_pol is not None and not isinstance(sep_pol, dict):
            checks.append({"check": "NV-05", "result": "FAIL",
                "detail": f"Registry separation_policies is not a dict: {type(sep_pol).__name__}"})
            return "FAIL", checks
        # G4J-R3: Validate shared_source_policies is a dict if present
        ss_pol = registry_snapshot.get("shared_source_policies")
        if ss_pol is not None and not isinstance(ss_pol, dict):
            checks.append({"check": "NV-05", "result": "FAIL",
                "detail": f"Registry shared_source_policies is not a dict: {type(ss_pol).__name__}"})
            return "FAIL", checks
        lineages = registry_snapshot.get("lineages")
        if lineages is not None and not isinstance(lineages, dict):
            checks.append({"check": "NV-05", "result": "FAIL",
                "detail": f"Registry lineages field is not a dict: {type(lineages).__name__}"})
            return "FAIL", checks
        if isinstance(lineages, dict):
            for node_id, node_data in lineages.items():
                if not isinstance(node_data, dict):
                    checks.append({"check": "NV-05", "result": "FAIL",
                        "detail": f"Registry lineage node '{node_id}' is not a dict"})
                    return "FAIL", checks
                # G4K-R2: Validate parent_lineage_id type
                plid = node_data.get("parent_lineage_id")
                if plid is not None and not isinstance(plid, str):
                    checks.append({"check": "NV-05", "result": "FAIL",
                        "detail": f"Registry lineage '{node_id}' parent_lineage_id is not a string: {type(plid).__name__}"})
                    return "FAIL", checks
                # G4K-R2: Validate organization type if present
                org_val = node_data.get("organization")
                if org_val is not None and not isinstance(org_val, str):
                    checks.append({"check": "NV-05", "result": "FAIL",
                        "detail": f"Registry lineage '{node_id}' organization is not a string: {type(org_val).__name__}"})
                    return "FAIL", checks
                # G4J-R3: shared_keys must be list of strings
                sk = node_data.get("shared_keys")
                if sk is not None:
                    if not isinstance(sk, (list, tuple)):
                        checks.append({"check": "NV-05", "result": "FAIL",
                            "detail": f"Registry lineage '{node_id}' shared_keys is not a list: {type(sk).__name__}"})
                        return "FAIL", checks
                    for i, k in enumerate(sk):
                        if not isinstance(k, str):
                            checks.append({"check": "NV-05", "result": "FAIL",
                                "detail": f"Registry lineage '{node_id}' shared_keys[{i}] is not a string: {type(k).__name__}"})
                            return "FAIL", checks
                # G4J-R3/R4: shared_source_ids must be list of strings (not scalar)
                ssids = node_data.get("shared_source_ids")
                if ssids is not None:
                    if not isinstance(ssids, (list, tuple)):
                        checks.append({"check": "NV-05", "result": "FAIL",
                            "detail": f"Registry lineage '{node_id}' shared_source_ids is not a list: {type(ssids).__name__}"})
                        return "FAIL", checks
                    for i, sid in enumerate(ssids):
                        if not isinstance(sid, str):
                            checks.append({"check": "NV-05", "result": "FAIL",
                                "detail": f"Registry lineage '{node_id}' shared_source_ids[{i}] is not a string: {type(sid).__name__}"})
                            return "FAIL", checks
                # G4J-R3: signing_key_fingerprint must be string if present
                fp = node_data.get("signing_key_fingerprint")
                if fp is not None and not isinstance(fp, str):
                    checks.append({"check": "NV-05", "result": "FAIL",
                        "detail": f"Registry lineage '{node_id}' signing_key_fingerprint is not a string: {type(fp).__name__}"})
                    return "FAIL", checks

    # G4H-R1: Check if WIR evaluation is needed based on item-level evidence,
    # NOT just the summary field. If summary is not "external" but items have
    # independence markers, we STILL run all WIR checks.
    needs_wir_eval = (indep == "external") or _has_independence_relevant_evidence(receipt)

    if not needs_wir_eval:
        # No evidence claims independence at any level -- skip WIR checks
        return "PASS", checks

    if not prov:
        checks.append({"check": "NV-04", "result": "FAIL",
            "detail": "evidence_independence is external but independence_provenance is missing"})
        return "FAIL", checks

    prod = prov.get("producer_lineage_id", "")
    eval_ = prov.get("evaluator_lineage_id", "")

    if not prod or not eval_:
        checks.append({"check": "NV-04", "result": "FAIL",
            "detail": "Missing producer or evaluator lineage ID"})
        return "FAIL", checks

    if prod == eval_:
        checks.append({"check": "NV-05", "result": "FAIL",
            "detail": "Producer and evaluator lineage IDs are identical"})
        return "FAIL", checks

    # G4G-R4: Check independence assessment from receipt
    assessment = prov.get("assessment", "")
    if assessment == "partially_independent":
        checks.append({"check": "NV-04", "result": "UNCERTIFIED",
            "detail": "Receipt declares partially_independent -- cannot satisfy full independence for bounded effects"})

    if not registry_snapshot:
        checks.append({"check": "NV-05", "result": "UNCERTIFIED",
            "detail": "No registry snapshot -- cannot verify independence affirmatively"})
    else:
        lineages = registry_snapshot.get("lineages", {})

        # G4H-R3 + G4I-R4: graphCoverage validation.
        # Missing defaults to "unknown". For bounded_effect, structured
        # assessment (dict with status, claim_scope, policy_version) is required.
        graph_coverage = registry_snapshot.get("graphCoverage", "unknown")
        action = receipt.get("allowed_action", "no_action")
        if isinstance(graph_coverage, dict):
            coverage_status = graph_coverage.get("status", "unknown")
            if coverage_status != "complete":
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Registry graphCoverage status='{coverage_status}' -- only 'complete' is accepted"})
            # G4J-R2: claim_scope must be a string matching the actual claim
            cov_claim_scope = graph_coverage.get("claim_scope")
            receipt_claim_id = receipt.get("claim_id", "")
            if not isinstance(cov_claim_scope, str) or cov_claim_scope != receipt_claim_id:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Registry graphCoverage claim_scope '{cov_claim_scope}' does not match receipt claim_id '{receipt_claim_id}'"})
            # G4J-R2: policy_version must be a non-empty string
            cov_policy = graph_coverage.get("policy_version")
            if not isinstance(cov_policy, str) or not cov_policy.strip():
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Registry graphCoverage policy_version must be a non-empty string, got '{cov_policy}'"})
        elif graph_coverage == "complete":
            if action == "bounded_effect":
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": "Scalar graphCoverage='complete' insufficient for bounded_effect -- structured assessment required"})
        else:
            checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                "detail": f"Registry graphCoverage='{graph_coverage}' -- only explicit 'complete' is accepted"})

        if prod not in lineages:
            checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                "detail": f"Producer lineage {prod} not registered in WIR snapshot"})
        if eval_ not in lineages:
            checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                "detail": f"Evaluator lineage {eval_} not registered in WIR snapshot"})

        if prod in lineages and eval_ in lineages:
            prod_entry = lineages[prod]
            eval_entry = lineages[eval_]

            if not prod_entry or not eval_entry:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": "Lineage entries exist but contain no data"})
            else:
                # G4K-R3: Must have valid string affirmative evidence
                prod_affirm = any(isinstance(prod_entry.get(f), str) and prod_entry.get(f, "").strip() for f in _STRONG_AFFIRMATIVE_FIELDS)
                eval_affirm = any(isinstance(eval_entry.get(f), str) and eval_entry.get(f, "").strip() for f in _STRONG_AFFIRMATIVE_FIELDS)
                if not prod_affirm:
                    checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                        "detail": f"Producer lineage {prod} has no valid string registration evidence"})
                if not eval_affirm:
                    checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                        "detail": f"Evaluator lineage {eval_} has no valid string registration evidence"})

                # G4K-R1: Validate organizational affiliation types
                prod_org = prod_entry.get("organization")
                eval_org = eval_entry.get("organization")
                # For bounded_effect requiring independence, missing/invalid org is UNCERTIFIED
                # Unknown org cannot establish demonstrated organizational separation
                if receipt.get("allowed_action") == "bounded_effect":
                    if prod_org is None or not isinstance(prod_org, str) or not prod_org.strip():
                        checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                            "detail": f"Producer lineage {prod} has missing or invalid organizational affiliation"})
                    if eval_org is None or not isinstance(eval_org, str) or not eval_org.strip():
                        checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                            "detail": f"Evaluator lineage {eval_} has missing or invalid organizational affiliation"})
                # Only do same-org comparison with valid string orgs
                # G4L-R3: Use .strip() for whitespace normalization in comparison
                if isinstance(prod_org, str) and prod_org.strip() and isinstance(eval_org, str) and eval_org.strip() and prod_org.strip() == eval_org.strip():
                    sep_policy = registry_snapshot.get("separation_policies", {})
                    claim_id = receipt.get("claim_id", "")
                    # G4J-R1: Require structured, claim-scoped separation policy
                    if not _is_valid_separation_policy(sep_policy.get(claim_id), claim_id):
                        checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                            "detail": f"Producer and evaluator share organization '{prod_org}' without valid claim-scoped separation policy"})

                # Check shared signing keys from REGISTRY entries (endpoint)
                prod_keys = set(prod_entry.get("shared_keys", []))
                eval_keys = set(eval_entry.get("shared_keys", []))
                prod_fp = prod_entry.get("signing_key_fingerprint")
                eval_fp = eval_entry.get("signing_key_fingerprint")
                if prod_fp:
                    prod_keys.add(prod_fp)
                if eval_fp:
                    eval_keys.add(eval_fp)
                common_keys = prod_keys & eval_keys
                if common_keys:
                    checks.append({"check": "NV-06", "result": "FAIL",
                        "detail": f"Registry reveals shared signing keys between lineages: {common_keys}"})
                    return "FAIL", checks

            # G4G-R1: Full transitive ancestor closure with completeness signal
            prod_ancestors, prod_unreg, prod_cycle, prod_complete, prod_keys_all, prod_unev = \
                _compute_ancestor_closure(prod, lineages)
            eval_ancestors, eval_unreg, eval_cycle, eval_complete, eval_keys_all, eval_unev = \
                _compute_ancestor_closure(eval_, lineages)

            # G4G-R1: Completeness check -- incomplete traversal -> UNCERTIFIED
            if not prod_complete:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Producer lineage traversal incomplete (depth limit, cycle, or missing node)"})
            if not eval_complete:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Evaluator lineage traversal incomplete (depth limit, cycle, or missing node)"})

            if prod_cycle:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Cycle detected in producer lineage graph"})
            if eval_cycle:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Cycle detected in evaluator lineage graph"})

            # Unregistered ancestors at any depth
            all_unreg = prod_unreg | eval_unreg
            if all_unreg:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Unregistered ancestor(s) in lineage chain: {all_unreg}"})

            # G4G-R2: Unevidenced ancestors
            all_unev = prod_unev | eval_unev
            if all_unev:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Ancestor(s) lacking registration evidence: {all_unev}"})

            # Direct ancestry check
            if eval_ in prod_ancestors:
                checks.append({"check": "NV-05", "result": "FAIL",
                    "detail": "Evaluator is an ancestor of producer"})
                return "FAIL", checks
            if prod in eval_ancestors:
                checks.append({"check": "NV-05", "result": "FAIL",
                    "detail": "Producer is an ancestor of evaluator"})
                return "FAIL", checks

            # G4F-R5: Shared transitive ancestor at ANY depth
            common_ancestors = prod_ancestors & eval_ancestors
            if common_ancestors:
                checks.append({"check": "NV-05", "result": "UNCERTIFIED",
                    "detail": f"Producer and evaluator share transitive ancestor(s): {common_ancestors}"})

            # G4G-R3: Shared signing key fingerprints across ALL ancestor nodes
            common_ancestor_keys = prod_keys_all & eval_keys_all
            if common_ancestor_keys:
                checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                    "detail": f"Shared signing key fingerprint(s) across ancestor chains: {common_ancestor_keys}"})

            # G4H-R2: Check shared source IDs across all lineage ancestors
            prod_source_ids = set()
            eval_source_ids = set()
            prod_all_nodes = {prod} | prod_ancestors
            eval_all_nodes = {eval_} | eval_ancestors
            prod_orgs = set()
            eval_orgs = set()
            for node_id in prod_all_nodes:
                if node_id in lineages:
                    node = lineages[node_id]
                    for sid in node.get("shared_source_ids", []):
                        prod_source_ids.add(sid)
                    org = node.get("organization")
                    # G4L-R1: Missing/None org on traversed ancestor = unknown independence
                    if org is None:
                        if receipt.get("allowed_action") == "bounded_effect":
                            checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                                "detail": f"Producer lineage node '{node_id}' has no organization field -- unknown organizational independence"})
                    elif not isinstance(org, str) or not org.strip():
                        if receipt.get("allowed_action") == "bounded_effect":
                            checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                                "detail": f"Producer lineage node '{node_id}' has invalid organization type or empty value"})
                    else:
                        prod_orgs.add(org.strip())  # G4L-R3: strip whitespace for comparison
            for node_id in eval_all_nodes:
                if node_id in lineages:
                    node = lineages[node_id]
                    for sid in node.get("shared_source_ids", []):
                        eval_source_ids.add(sid)
                    org = node.get("organization")
                    # G4L-R1: Missing/None org on traversed ancestor = unknown independence
                    if org is None:
                        if receipt.get("allowed_action") == "bounded_effect":
                            checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                                "detail": f"Evaluator lineage node '{node_id}' has no organization field -- unknown organizational independence"})
                    elif not isinstance(org, str) or not org.strip():
                        if receipt.get("allowed_action") == "bounded_effect":
                            checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                                "detail": f"Evaluator lineage node '{node_id}' has invalid organization type or empty value"})
                    else:
                        eval_orgs.add(org.strip())  # G4L-R3: strip whitespace for comparison
            common_source_ids = prod_source_ids & eval_source_ids
            if common_source_ids:
                checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                    "detail": f"Shared source IDs across producer and evaluator lineages: {common_source_ids}"})

            # G4H-R2 + G4I-R3: Check organizational control across ancestors
            common_orgs = prod_orgs & eval_orgs
            if common_orgs:
                sep_policy = registry_snapshot.get("separation_policies", {})
                claim_id = receipt.get("claim_id", "")
                # G4J-R1: Require structured, claim-scoped separation policy
                if not _is_valid_separation_policy(sep_policy.get(claim_id), claim_id):
                    checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                        "detail": f"Common controlling organization(s) across lineage ancestors: {common_orgs} without valid claim-scoped separation policy"})

    # NV-06: shared dependency analysis (from provenance)
    if prov.get("shared_keys"):
        checks.append({"check": "NV-06", "result": "FAIL",
            "detail": "Shared signing keys negate independence"})
        return "FAIL", checks

    if prov.get("shared_sources"):
        policy = registry_snapshot.get("shared_source_policies", {}) if registry_snapshot else {}
        claim_id = receipt.get("claim_id", "")
        # G4J-R1: Require structured, claim-scoped shared-source exemption policy
        if not _is_valid_shared_source_policy(policy.get(claim_id), claim_id):
            checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                "detail": "Shared sources without valid claim-scoped exemption policy"})

    if prov.get("shared_execution_environment"):
        checks.append({"check": "NV-06", "result": "UNCERTIFIED",
            "detail": "Shared execution environment"})

    org = prov.get("organizational_relationship", "unknown")
    if org in ("same_organization", "subsidiary"):
        policy = registry_snapshot.get("separation_policies", {}) if registry_snapshot else {}
        # G4J-R1: Require structured, claim-scoped separation policy
        org_claim_id = receipt.get("claim_id", "")
        if not _is_valid_separation_policy(policy.get(org_claim_id), org_claim_id):
            checks.append({"check": "NV-06", "result": "UNCERTIFIED",
                "detail": f"Organizational relationship '{org}' without valid claim-scoped separation-of-duties policy"})

    if prov.get("unresolved_dependencies"):
        checks.append({"check": "NV-07", "result": "UNCERTIFIED",
            "detail": f"Unresolved dependencies: {prov['unresolved_dependencies']}"})

    # G4I-R5: Check for contradictory independence summary
    if indep != "external" and needs_wir_eval:
        # Summary says non-external but WIR evaluation was triggered by item-level evidence
        # This is a contradiction that must be flagged
        checks.append({"check": "NV-04", "result": "UNCERTIFIED",
            "detail": f"Independence summary '{indep}' contradicts item-level external evidence markers -- reconciliation required"})

    if any(c["result"] == "FAIL" for c in checks):
        return "FAIL", checks
    if any(c["result"] == "UNCERTIFIED" for c in checks):
        return "UNCERTIFIED", checks
    return "PASS", checks


# ---------------------------------------------------------------------------
# NV-18 through NV-20: Evidence-to-claim relevance
# G4F-R4: Mandatory assessment_timestamp with parse validation
# G4F-A1: Typed PASS with empty observed_result -> UNCERTIFIED
# G4G-R6: Mandatory evaluator method_name, duplicate eval record ID detection
# ---------------------------------------------------------------------------

_MANDATORY_EVAL_FIELDS = ["evaluator_lineage_id", "claim_content_hash", "claim_revision_id"]

_NEGATIVE_INDICATORS = [
    "fail", "not reproduced", "mismatch", "does not match",
    "error", "rejected", "invalid", "violated", "broken",
    "inconsistent", "contradicted", "negative", "not verified",
    "not confirmed", "could not", "unable to"
]

def _check_evidence_relevance(receipt, evidence_snapshot, verification_context=None):
    """NV-18 through NV-20. G4F-R4/A1 + G4G-R6 fixes."""
    checks = []
    eval_records = receipt.get("evaluation_records", [])
    evidence_items = receipt.get("source_evidence", [])
    counterevidence = receipt.get("counterevidence", [])
    claim_id = receipt.get("claim_id", "")
    revisions = receipt.get("revision_history", [])
    rev_ids = {r["revision_id"] for r in revisions} if revisions else set()
    effective_revs = _get_effective_revisions(receipt)

    # G4G-R6: Detect duplicate evaluation_record_id in embedded receipt eval records
    seen_eval_ids = set()
    for rec in eval_records:
        eid = rec.get("evaluation_id", "")
        if eid:
            if eid in seen_eval_ids:
                checks.append({"check": "NV-18", "result": "FAIL",
                    "detail": f"Duplicate evaluation_record_id '{eid}' in receipt evaluation_records"})
            seen_eval_ids.add(eid)

    verify_dt = None
    if verification_context:
        vts = verification_context.get("verification_timestamp")
        if vts:
            verify_dt = _parse_rfc3339(vts)

    item_results = []

    for item in evidence_items:
        if item.get("kind") == "publisher_claim":
            continue

        if item.get("verification_state") == "failed":
            checks.append({"check": "NV-01", "result": "FAIL",
                "detail": f"Evidence {item.get('evidence_id','')} has verification_state=failed"})
            item_results.append("FAIL")
            continue

        eval_rec_id = item.get("evaluation_record_id")
        if not eval_rec_id:
            checks.append({"check": "NV-18", "result": "UNCERTIFIED",
                "detail": f"Evidence {item.get('evidence_id','')} has no evaluation_record_id"})
            item_results.append("UNCERTIFIED")
            continue

        # NV-18: Look up records
        embedded_rec = None
        for rec in eval_records:
            if rec.get("evaluation_id") == eval_rec_id:
                embedded_rec = rec
                break

        snapshot_rec = None
        if evidence_snapshot:
            snapshot_rec = evidence_snapshot.get("evaluation_records", {}).get(eval_rec_id)

        if not snapshot_rec and not embedded_rec:
            checks.append({"check": "NV-18", "result": "UNCERTIFIED",
                "detail": f"Evaluation record {eval_rec_id} not found in snapshot or receipt"})
            item_results.append("UNCERTIFIED")
            continue

        if not snapshot_rec:
            checks.append({"check": "NV-18", "result": "UNCERTIFIED",
                "detail": f"Evaluation record {eval_rec_id} not in frozen evidence snapshot"})
            item_results.append("UNCERTIFIED")
            continue

        auth_rec = snapshot_rec

        # Validate mandatory fields
        missing_fields = []
        for field in _MANDATORY_EVAL_FIELDS:
            val = auth_rec.get(field)
            if not val:
                missing_fields.append(field)
        if auth_rec.get("claim_relevance") == "direct_test":
            if not auth_rec.get("execution_evidence_id"):
                missing_fields.append("execution_evidence_id")
        if missing_fields:
            checks.append({"check": "NV-18", "result": "FAIL",
                "detail": f"Snapshot record {eval_rec_id} missing mandatory fields: {missing_fields}"})
            item_results.append("FAIL")
            continue

        # G4F-R4: assessment_timestamp is MANDATORY
        assess_ts = auth_rec.get("assessment_timestamp", "")
        if not assess_ts:
            checks.append({"check": "NV-18", "result": "FAIL",
                "detail": f"Snapshot record {eval_rec_id} missing mandatory assessment_timestamp"})
            item_results.append("FAIL")
            continue

        assess_dt = _parse_rfc3339(assess_ts)
        if assess_dt is None:
            checks.append({"check": "NV-18", "result": "FAIL",
                "detail": f"Snapshot record {eval_rec_id} assessment_timestamp '{assess_ts}' is not a valid RFC3339 timestamp"})
            item_results.append("FAIL")
            continue

        # Require recognized outcome_type
        outcome_type = auth_rec.get("outcome_type", "")
        if not outcome_type or outcome_type not in _RECOGNIZED_OUTCOMES:
            checks.append({"check": "NV-18", "result": "FAIL",
                "detail": f"Snapshot record {eval_rec_id} has missing or unrecognized outcome_type: '{outcome_type}'"})
            item_results.append("FAIL")
            continue

        # Always verify snapshot record hash
        snap_hashable = {k: v for k, v in snapshot_rec.items() if k != "record_content_hash"}
        recomputed_snap_hash = _jcs_canonical_hash(snap_hashable)
        declared_snap_hash = snapshot_rec.get("record_content_hash")

        if not declared_snap_hash:
            checks.append({"check": "NV-18", "result": "FAIL",
                "detail": f"Snapshot record {eval_rec_id} missing mandatory record_content_hash"})
            item_results.append("FAIL")
            continue

        if declared_snap_hash != recomputed_snap_hash:
            checks.append({"check": "NV-18", "result": "FAIL",
                "detail": f"Snapshot record {eval_rec_id} declared hash does not match recomputed hash"})
            item_results.append("FAIL")
            continue

        # If embedded copy exists, verify it matches snapshot
        if embedded_rec:
            emb_hashable = {k: v for k, v in embedded_rec.items() if k != "record_content_hash"}
            embedded_hash = _jcs_canonical_hash(emb_hashable)
            if embedded_hash != recomputed_snap_hash:
                checks.append({"check": "NV-18", "result": "FAIL",
                    "detail": f"Embedded record {eval_rec_id} content differs from snapshot"})
                item_results.append("FAIL")
                continue

        # Authenticate evaluator identity
        snapshot_evaluator = auth_rec.get("evaluator_lineage_id", "")
        prov = receipt.get("independence_provenance", {})
        declared_evaluator = prov.get("evaluator_lineage_id", "")
        if snapshot_evaluator and declared_evaluator and snapshot_evaluator != declared_evaluator:
            checks.append({"check": "NV-18", "result": "FAIL",
                "detail": f"Snapshot evaluator {snapshot_evaluator} differs from declared evaluator {declared_evaluator}"})
            item_results.append("FAIL")
            continue

        # Future-dated evaluation (always applies now since timestamp is mandatory and parsed)
        if verify_dt and assess_dt > verify_dt:
            checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                "detail": f"Evaluation {eval_rec_id} is future-dated: assessment_timestamp={assess_ts}"})
            item_results.append("UNCERTIFIED")
            continue

        # G4G-R6: Evaluator method_name is MANDATORY (not just when mismatching)
        eval_method = auth_rec.get("method_name", "")
        receipt_method = receipt.get("method", {}).get("name", "")
        if not eval_method:
            checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                "detail": f"Evaluation record {eval_rec_id} missing mandatory method_name"})
            item_results.append("UNCERTIFIED")
            continue
        # G4F-R4: Method binding -- evaluation method must not contradict receipt method
        if receipt_method and eval_method != receipt_method:
            checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                "detail": f"Evaluation method '{eval_method}' does not match receipt method '{receipt_method}'"})
            item_results.append("UNCERTIFIED")
            continue

        # Pre-fetch relevance for binding checks below
        relevance = auth_rec.get("claim_relevance", "unrelated")

        # G4I-R7 + G4J-R5: Evaluator binding diagnostic copy checks
        # Contract decision (G4J-R5): Missing optional fields are ALLOWED.
        # Present fields that contradict authoritative records -> UNCERTIFIED.
        if item.get("evaluator_binding"):
            binding = item["evaluator_binding"]
            # assessed_by: normative -- must match snapshot evaluator if present
            binding_assessor = binding.get("assessed_by", "")
            if binding_assessor and snapshot_evaluator and binding_assessor != snapshot_evaluator:
                checks.append({"check": "NV-12", "result": "UNCERTIFIED",
                    "detail": f"Evaluator_binding.assessed_by '{binding_assessor}' conflicts with snapshot evaluator '{snapshot_evaluator}'"})

            # G4J-R5: claim_id if present must match receipt claim_id
            binding_claim_id = binding.get("claim_id")
            if binding_claim_id is not None and binding_claim_id != claim_id:
                checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                    "detail": f"Diagnostic evaluator_binding claim_id '{binding_claim_id}' contradicts receipt claim_id '{claim_id}'"})
                item_results.append("UNCERTIFIED")
                continue

            # G4J-R5: claim_relevance if present must match snapshot relevance
            binding_relevance = binding.get("claim_relevance")
            if binding_relevance is not None and relevance and binding_relevance != relevance:
                checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                    "detail": f"Diagnostic evaluator_binding claim_relevance '{binding_relevance}' contradicts snapshot '{relevance}'"})
                item_results.append("UNCERTIFIED")
                continue

            # G4J-R5: assessment_timestamp if present must be valid RFC3339
            # and not future-dated relative to verification_timestamp
            binding_ts = binding.get("assessment_timestamp")
            if binding_ts is not None:
                binding_dt = _parse_rfc3339(binding_ts)
                if binding_dt is None:
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Diagnostic evaluator_binding assessment_timestamp '{binding_ts}' is not valid RFC3339"})
                    item_results.append("UNCERTIFIED")
                    continue
                # Future-dated: binding timestamp after BOTH verification and authoritative assessment
                # (to avoid false positives when the entire clock is backdated for external trust testing)
                if verify_dt and binding_dt > verify_dt and assess_dt and binding_dt > assess_dt:
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Diagnostic evaluator_binding assessment_timestamp is future-dated"})
                    item_results.append("UNCERTIFIED")
                    continue

            # G4J-R5: observed_result if present with PASS outcome should not have negative indicators
            binding_obs = binding.get("observed_result")
            if binding_obs is not None and outcome_type == "PASS":
                obs_lower_b = binding_obs.lower() if isinstance(binding_obs, str) else ""
                if any(neg in obs_lower_b for neg in _NEGATIVE_INDICATORS):
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Diagnostic evaluator_binding observed_result contains negative indicators contradicting PASS"})
                    item_results.append("UNCERTIFIED")
                    continue

            # G4I-R7: claim_content_hash normative -- must match recomputed claim hash if present
            binding_claim_hash = binding.get("claim_content_hash", "")
            claim_text_local = receipt.get("claim", "")
            if binding_claim_hash and claim_text_local:
                if isinstance(claim_text_local, str):
                    computed_binding_hash = hashlib.sha256(claim_text_local.encode('utf-8')).hexdigest()
                else:
                    computed_binding_hash = _jcs_canonical_hash(claim_text_local)
                if binding_claim_hash != computed_binding_hash:
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Evidence evaluator_binding claim_content_hash does not match recomputed claim hash"})
                    item_results.append("UNCERTIFIED")
                    continue
            # G4I-R7: tested_property normative -- must match evaluation record if both present
            binding_property = binding.get("tested_property", "")
            auth_rec_property = auth_rec.get("tested_property", "")
            if binding_property and auth_rec_property:
                if isinstance(binding_property, str) and binding_property != auth_rec_property:
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Evidence evaluator_binding tested_property '{binding_property}' does not match evaluation record '{auth_rec_property}'"})
                    item_results.append("UNCERTIFIED")
                    continue
                elif not isinstance(binding_property, str):
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Evidence evaluator_binding tested_property is not a string: {type(binding_property).__name__}"})
                    item_results.append("UNCERTIFIED")
                    continue

        # NV-19: Check relevance (relevance already fetched above for binding checks)
        if relevance not in ("direct_test", "supporting"):
            item_results.append("SKIP")
            continue

        if auth_rec.get("claim_id") != claim_id:
            checks.append({"check": "NV-19", "result": "FAIL",
                "detail": f"Evaluation record claim_id mismatch: {auth_rec.get('claim_id')} vs {claim_id}"})
            item_results.append("FAIL")
            continue

        # Evaluation must bind to effective (leaf) revision
        # G4H-R4: Detect superseded revision references and unverifiable bindings
        rec_revision = auth_rec.get("claim_revision_id", "")
        if rec_revision:
            if rev_ids:
                if rec_revision not in rev_ids:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Evaluation record references revision {rec_revision} not in revision history"})
                    item_results.append("FAIL")
                    continue
                if effective_revs and rec_revision not in effective_revs:
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Evaluation bound to superseded revision {rec_revision}"})
                    item_results.append("UNCERTIFIED")
                    continue
            # G4H-R4: Cross-check evaluation's claim_revision_id against item's evaluator_binding
            item_binding = item.get("evaluator_binding", {})
            binding_revision = item_binding.get("claim_revision_id", "")
            if binding_revision and rec_revision != binding_revision:
                checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                    "detail": f"Snapshot evaluation claim_revision_id '{rec_revision}' does not match evidence item binding revision '{binding_revision}'"})
                item_results.append("UNCERTIFIED")
                continue

            # G4I-R6: Revision creation time must precede evaluation assessment
            if revisions:
                for rev in revisions:
                    if rev.get("revision_id") == rec_revision:
                        rev_ts = rev.get("timestamp")
                        if rev_ts:
                            rev_dt = _parse_rfc3339(rev_ts)
                            if rev_dt and assess_dt and rev_dt > assess_dt:
                                checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                                    "detail": f"Revision {rec_revision} timestamp {rev_ts} is after evaluation assessment -- claim may not have existed at evaluation time"})
                                item_results.append("UNCERTIFIED")
                        break
                else:
                    pass  # No matching revision found; already checked above

                if item_results and item_results[-1] == "UNCERTIFIED":
                    continue

        # Recompute claim content hash
        claim_text = receipt.get("claim", "")
        if claim_text:
            if isinstance(claim_text, str):
                computed_claim_hash = hashlib.sha256(claim_text.encode('utf-8')).hexdigest()
            else:
                computed_claim_hash = _jcs_canonical_hash(claim_text)
            rec_claim_hash = auth_rec.get("claim_content_hash", "")
            receipt_claim_hash = receipt.get("claim_content_hash", "")

            if rec_claim_hash and computed_claim_hash != rec_claim_hash:
                checks.append({"check": "NV-19", "result": "FAIL",
                    "detail": "Evaluation record claim hash does not match recomputed claim hash"})
                item_results.append("FAIL")
                continue

            if receipt_claim_hash and computed_claim_hash != receipt_claim_hash:
                checks.append({"check": "NV-19", "result": "FAIL",
                    "detail": "Receipt claim_content_hash does not match recomputed claim hash"})
                item_results.append("FAIL")
                continue

        # Check evaluator differs from producer
        prod_lineage = prov.get("producer_lineage_id", "")
        if auth_rec.get("evaluator_lineage_id") == prod_lineage:
            checks.append({"check": "NV-19", "result": "FAIL",
                "detail": "Evaluator lineage is same as producer"})
            item_results.append("FAIL")
            continue

        # G4F-R3 + G4I-R1: Validate execution evidence for direct_test
        if relevance == "direct_test":
            exec_eid = auth_rec.get("execution_evidence_id", "")
            # G4I-R1: For bounded_effect, method must have execution_evidence_id
            receipt_exec_id = receipt.get("method", {}).get("execution_evidence_id", "")
            action_local = receipt.get("allowed_action", "no_action")
            if action_local == "bounded_effect" and not receipt_exec_id:
                checks.append({"check": "NV-19", "result": "FAIL",
                    "detail": f"Direct_test evaluation for bounded_effect but receipt method has no execution_evidence_id"})
                item_results.append("FAIL")
                continue
            # G4F-R3: Evaluation must reference the SAME execution as receipt's method
            if exec_eid and receipt_exec_id and exec_eid != receipt_exec_id:
                checks.append({"check": "NV-19", "result": "FAIL",
                    "detail": f"Evaluation references execution {exec_eid} but receipt method declares {receipt_exec_id}"})
                item_results.append("FAIL")
                continue
            if exec_eid and evidence_snapshot:
                exec_rec = evidence_snapshot.get("execution_records", {}).get(exec_eid)
                if not exec_rec:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Evaluation references execution record {exec_eid} not in snapshot"})
                    item_results.append("FAIL")
                    continue
                # G4F-R3 + G4G-R5: Full execution record validation
                exec_status = exec_rec.get("status")
                if exec_status is None or exec_status == "":
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} missing status"})
                    item_results.append("FAIL")
                    continue
                if exec_status not in _SUCCESSFUL_EXEC_STATUSES:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} status '{exec_status}' not successful"})
                    item_results.append("FAIL")
                    continue
                exec_method_name = exec_rec.get("method_name")
                if not exec_method_name:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} missing method_name"})
                    item_results.append("FAIL")
                    continue
                if receipt_method and exec_method_name != receipt_method:
                    checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                        "detail": f"Execution method '{exec_method_name}' does not match receipt method '{receipt_method}'"})
                    item_results.append("UNCERTIFIED")
                    continue
                # G4G-R5: Internal execution_id must be present and match lookup key
                internal_exec_id = exec_rec.get("execution_id")
                if not internal_exec_id:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} missing mandatory execution_id"})
                    item_results.append("FAIL")
                    continue
                if internal_exec_id != exec_eid:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record internal ID '{internal_exec_id}' mismatches key '{exec_eid}'"})
                    item_results.append("FAIL")
                    continue
                # G4G-R5: Execution timestamp validation in relevance path
                exec_ts = exec_rec.get("timestamp")
                if not exec_ts:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} missing mandatory timestamp"})
                    item_results.append("FAIL")
                    continue
                exec_dt = _parse_rfc3339(exec_ts)
                if exec_dt is None:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} timestamp '{exec_ts}' is not valid RFC3339"})
                    item_results.append("FAIL")
                    continue
                if verify_dt and exec_dt > verify_dt:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} timestamp is future-dated: {exec_ts}"})
                    item_results.append("FAIL")
                    continue
                # G4H-R5: Causal time ordering -- execution must precede evaluation
                if assess_dt and exec_dt > assess_dt:
                    checks.append({"check": "NV-19", "result": "FAIL",
                        "detail": f"Execution record {exec_eid} timestamp {exec_ts} is after evaluation assessment_timestamp {assess_ts} -- causal ordering violated"})
                    item_results.append("FAIL")
                    continue
                # G4G-R5: Execution record claim binding check
                if receipt:
                    rec_claim = exec_rec.get("claim_id")
                    if rec_claim and rec_claim != claim_id:
                        checks.append({"check": "NV-19", "result": "FAIL",
                            "detail": f"Execution record {exec_eid} bound to different claim '{rec_claim}'"})
                        item_results.append("FAIL")
                        continue

        # Use typed outcome
        obs_result = auth_rec.get("observed_result", "")
        obs_lower = obs_result.lower() if obs_result else ""
        has_negative_text = any(neg in obs_lower for neg in _NEGATIVE_INDICATORS)

        if outcome_type == "FAIL":
            checks.append({"check": "NV-19", "result": "FAIL",
                "detail": f"Typed outcome is FAIL: {obs_result}"})
            item_results.append("FAIL")
            continue
        elif outcome_type == "INDETERMINATE":
            checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                "detail": f"Typed outcome is INDETERMINATE: {obs_result}"})
            item_results.append("UNCERTIFIED")
            continue
        elif outcome_type == "PASS":
            if has_negative_text:
                checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                    "detail": f"Typed outcome PASS contradicts observed_result text: {obs_result}"})
                item_results.append("UNCERTIFIED")
                continue
            # G4F-A1: Empty observed_result with typed PASS -> UNCERTIFIED
            if not obs_result.strip():
                checks.append({"check": "NV-19", "result": "UNCERTIFIED",
                    "detail": f"Typed PASS without observational evidence (empty observed_result)"})
                item_results.append("UNCERTIFIED")
                continue
            item_results.append("PASS")
            continue

    # Process counterevidence
    for citem in counterevidence:
        ceid = citem.get("evidence_id", "")
        if citem.get("verification_state") in ("observed", "reproduced"):
            checks.append({"check": "NV-20", "result": "UNCERTIFIED",
                "detail": f"Counterevidence {ceid} with verification_state={citem.get('verification_state')}"})
            item_results.append("UNCERTIFIED")

    # Exhaustive precedence: FAIL > UNCERTIFIED > PASS
    has_fail = "FAIL" in item_results or any(c["result"] == "FAIL" for c in checks)
    has_uncert = "UNCERTIFIED" in item_results or any(c["result"] == "UNCERTIFIED" for c in checks)
    has_pass = "PASS" in item_results

    if has_fail:
        return "FAIL", checks
    if has_uncert:
        return "UNCERTIFIED", checks
    if has_pass:
        return "PASS", checks

    if receipt.get("status") in ("VERIFIED", "PROVISIONAL"):
        checks.append({"check": "NV-18", "result": "UNCERTIFIED",
            "detail": "No authenticated evaluation records with relevant claim bindings"})
        return "UNCERTIFIED", checks

    return "PASS", checks


# ---------------------------------------------------------------------------
# NV-08 through NV-11: Revision integrity
# ---------------------------------------------------------------------------

def _check_revision_integrity(receipt):
    """NV-08 through NV-11."""
    checks = []
    revisions = receipt.get("revision_history", [])
    if not revisions:
        return "PASS", checks

    ids = [r["revision_id"] for r in revisions]
    if len(ids) != len(set(ids)):
        checks.append({"check": "NV-08", "result": "FAIL", "detail": "Duplicate revision IDs found"})
        return "FAIL", checks

    id_set = set(ids)
    for r in revisions:
        prior = r.get("prior_revision_id")
        if prior is not None and prior not in id_set:
            checks.append({"check": "NV-09", "result": "FAIL", "detail": f"Dangling prior_revision_id: {prior}"})
            return "FAIL", checks

    adjacency = {}
    for r in revisions:
        rid = r["revision_id"]
        prior = r.get("prior_revision_id")
        if prior is not None:
            adjacency.setdefault(prior, []).append(rid)

    visited = set()
    path = set()
    def has_cycle(node):
        if node in path: return True
        if node in visited: return False
        visited.add(node); path.add(node)
        for child in adjacency.get(node, []):
            if has_cycle(child): return True
        path.discard(node); return False

    for rid in id_set:
        if has_cycle(rid):
            checks.append({"check": "NV-10", "result": "FAIL", "detail": "Cycle detected in revision graph"})
            return "FAIL", checks

    all_evidence_ids = set()
    for item in receipt.get("source_evidence", []):
        all_evidence_ids.add(item.get("evidence_id", ""))
    for item in receipt.get("counterevidence", []):
        all_evidence_ids.add(item.get("evidence_id", ""))

    for r in revisions:
        for eid in r.get("evidence_ids", []):
            if eid not in all_evidence_ids:
                checks.append({"check": "NV-11", "result": "FAIL",
                    "detail": f"Revision {r['revision_id']} references missing evidence {eid}"})
                return "FAIL", checks

    return "PASS", checks


# ---------------------------------------------------------------------------
# NV-14 through NV-17, NV-21: Authorization
# ---------------------------------------------------------------------------

_REQUIRED_APPROVAL_FIELDS = [
    "approval_id", "approving_principal", "approved_action",
    "approved_target", "valid_from", "valid_until", "revocation_status"
]

def _check_authorization(receipt, policy_snapshot, effective_status,
                         verification_context=None):
    """NV-14 through NV-17, NV-21."""
    checks = []
    status = receipt.get("status", "UNKNOWN")
    action = receipt.get("allowed_action", "no_action")
    auth = receipt.get("effect_authorization")
    review = receipt.get("review", {})

    if effective_status in ("WITHDRAWN", "CONTRADICTED", "UNRECONCILED", "UNKNOWN"):
        if action == "bounded_effect":
            checks.append({"check": "NV-14", "result": "FAIL",
                "detail": f"Effective status {effective_status} blocks bounded_effect"})
            return "FAIL", "DENIED", checks

    if status == "UNKNOWN" and action == "bounded_effect":
        checks.append({"check": "NV-14", "result": "FAIL",
            "detail": "UNKNOWN status with bounded_effect is not permitted"})
    if status == "CONTRADICTED" and action == "bounded_effect":
        checks.append({"check": "NV-14", "result": "FAIL",
            "detail": "CONTRADICTED status with bounded_effect is not permitted"})
    if status == "WITHDRAWN" and action != "no_action":
        checks.append({"check": "NV-14", "result": "FAIL",
            "detail": "WITHDRAWN status requires no_action"})

    if action != "bounded_effect":
        if any(c["result"] == "FAIL" for c in checks):
            return "FAIL", "DENIED", checks
        return "PASS", "NOT_REQUESTED", checks

    # Parse verification timestamp
    now_dt = None
    if verification_context:
        now_str = verification_context.get("verification_timestamp")
        if now_str:
            now_dt = _parse_rfc3339(now_str)
            if now_dt is None:
                checks.append({"check": "NV-21", "result": "FAIL",
                    "detail": f"verification_timestamp '{now_str}' is not a valid RFC3339 timestamp (precision > 6 fractional digits is not supported)"})

    if now_dt is None:
        checks.append({"check": "NV-21", "result": "FAIL",
            "detail": "bounded_effect requires valid verification_context.verification_timestamp"})

    # Requested target REQUIRED
    requested_target = None
    if verification_context:
        requested_target = verification_context.get("requested_target")
    if not requested_target:
        checks.append({"check": "NV-21", "result": "FAIL",
            "detail": "bounded_effect requires verification_context.requested_target"})

    if not auth:
        checks.append({"check": "NV-15", "result": "FAIL",
            "detail": "bounded_effect requires effect_authorization"})
        return "FAIL", "DENIED", checks

    check_fields = ["contract_match", "effect_type_allowed", "target_allowed",
                     "witness_healthy", "evidence_current"]
    na_fields = []
    for field in check_fields:
        val = auth.get(field, "UNKNOWN")
        if val == "UNKNOWN":
            checks.append({"check": "NV-15", "result": "FAIL",
                "detail": f"Authorization check {field} is UNKNOWN"})
        elif val == "FALSE":
            checks.append({"check": "NV-15", "result": "FAIL",
                "detail": f"Authorization check {field} is FALSE"})
        elif val == "NOT_APPLICABLE":
            na_fields.append(field)

    if na_fields:
        policy_ref = auth.get("exception_policy")
        if not policy_ref:
            checks.append({"check": "NV-16", "result": "FAIL",
                "detail": "NOT_APPLICABLE check without exception_policy reference"})
        elif not policy_snapshot:
            checks.append({"check": "NV-16", "result": "FAIL",
                "detail": "NOT_APPLICABLE check requires policy snapshot"})
        else:
            policy_entry = policy_snapshot.get("applicability_policies", {}).get(policy_ref)
            if not policy_entry:
                checks.append({"check": "NV-16", "result": "FAIL",
                    "detail": f"Exception policy {policy_ref} not found in policy snapshot"})
            else:
                allowed_checks = set(policy_entry.get("allowed_checks", []))
                policy_action = policy_entry.get("approved_action", "")
                if not policy_action:
                    checks.append({"check": "NV-16", "result": "FAIL",
                        "detail": f"Exception policy {policy_ref} missing mandatory approved_action"})
                for na_field in na_fields:
                    if na_field not in allowed_checks:
                        checks.append({"check": "NV-16", "result": "FAIL",
                            "detail": f"Exception policy {policy_ref} does not permit N/A for '{na_field}'"})
                if policy_action and policy_action != action:
                    checks.append({"check": "NV-16", "result": "FAIL",
                        "detail": f"Exception policy action '{policy_action}' does not match '{action}'"})

    # Approval record validation
    approval_id = auth.get("approval_record_id")
    if not approval_id:
        checks.append({"check": "NV-21", "result": "FAIL",
            "detail": "bounded_effect requires approval_record_id"})
    elif not policy_snapshot:
        checks.append({"check": "NV-21", "result": "FAIL",
            "detail": "bounded_effect requires policy_snapshot"})
    else:
        approval_rec = policy_snapshot.get("approval_records", {}).get(approval_id)
        if not approval_rec:
            checks.append({"check": "NV-21", "result": "FAIL",
                "detail": f"Approval record {approval_id} not found in policy snapshot"})
        else:
            for field in _REQUIRED_APPROVAL_FIELDS:
                val = approval_rec.get(field)
                if val is None or val == "":
                    checks.append({"check": "NV-21", "result": "FAIL",
                        "detail": f"Approval record missing or empty mandatory field: {field}"})

            if approval_rec.get("approval_id") != approval_id:
                checks.append({"check": "NV-21", "result": "FAIL",
                    "detail": f"Approval record internal ID mismatches lookup key"})

            rev_status = approval_rec.get("revocation_status", "")
            if rev_status != "active":
                checks.append({"check": "NV-21", "result": "FAIL",
                    "detail": f"Approval revocation_status is '{rev_status}', must be 'active'"})

            approved_action = approval_rec.get("approved_action", "")
            if approved_action and approved_action != action:
                checks.append({"check": "NV-21", "result": "FAIL",
                    "detail": f"Approval action '{approved_action}' does not match '{action}'"})

            approved_target = approval_rec.get("approved_target", "")
            if requested_target and approved_target and approved_target != requested_target:
                checks.append({"check": "NV-21", "result": "FAIL",
                    "detail": f"Approval target '{approved_target}' does not match '{requested_target}'"})

            # G4I-R9: Validate approved_claim_revision_id if present
            approved_rev = approval_rec.get("approved_claim_revision_id")
            if approved_rev:
                effective_revs = _get_effective_revisions(receipt)
                receipt_revisions = receipt.get("revision_history", [])
                if effective_revs:
                    if approved_rev not in effective_revs:
                        checks.append({"check": "NV-21", "result": "FAIL",
                            "detail": f"Approval approved_claim_revision_id '{approved_rev}' does not match effective revision(s) {effective_revs}"})
                elif receipt_revisions:
                    rev_ids = {r["revision_id"] for r in receipt_revisions}
                    if approved_rev not in rev_ids:
                        checks.append({"check": "NV-21", "result": "FAIL",
                            "detail": f"Approval approved_claim_revision_id '{approved_rev}' not in revision history"})
                else:
                    # No revision history -- check against evidence binding revision
                    for ev_item in receipt.get("source_evidence", []):
                        binding = ev_item.get("evaluator_binding", {})
                        binding_rev = binding.get("claim_revision_id", "")
                        if binding_rev and approved_rev != binding_rev:
                            checks.append({"check": "NV-21", "result": "FAIL",
                                "detail": f"Approval approved_claim_revision_id '{approved_rev}' does not match evidence binding revision '{binding_rev}'"})
                            break

            valid_from = approval_rec.get("valid_from", "")
            valid_until = approval_rec.get("valid_until", "")

            if now_dt:
                if valid_from:
                    from_dt = _parse_rfc3339(valid_from)
                    if from_dt is None:
                        checks.append({"check": "NV-21", "result": "FAIL",
                            "detail": f"Approval valid_from '{valid_from}' is not valid RFC3339 (precision > 6 digits not supported)"})
                    elif now_dt < from_dt:
                        checks.append({"check": "NV-21", "result": "FAIL",
                            "detail": f"Approval not yet effective: valid_from={valid_from}"})

                if valid_until:
                    until_dt = _parse_rfc3339(valid_until)
                    if until_dt is None:
                        checks.append({"check": "NV-21", "result": "FAIL",
                            "detail": f"Approval valid_until '{valid_until}' is not valid RFC3339 (precision > 6 digits not supported)"})
                    elif now_dt > until_dt:
                        checks.append({"check": "NV-21", "result": "FAIL",
                            "detail": f"Approval expired: valid_until={valid_until}"})

            if review.get("authorization") == "not_authorized":
                checks.append({"check": "NV-17", "result": "FAIL",
                    "detail": "review.authorization=not_authorized contradicts approval"})

    if any(c["result"] == "FAIL" for c in checks):
        return "FAIL", "DENIED", checks
    if any(c["result"] == "UNCERTIFIED" for c in checks):
        return "UNCERTIFIED", "DENIED", checks
    return "PASS", "GRANTED", checks


# ---------------------------------------------------------------------------
# Stage 1: Schema validation
# ---------------------------------------------------------------------------

def validate_schema(receipt, schema_obj):
    """Stage 1: JSON Schema validation."""
    try:
        import jsonschema
        jsonschema.validate(receipt, schema_obj)
        return True, None
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Internal Stage 2 entry point (PRIVATE)
# ---------------------------------------------------------------------------

def _verify_receipt_internal(receipt, registry_snapshot=None, policy_snapshot=None,
                             evidence_snapshot=None, verification_context=None):
    """PRIVATE Stage 2. Use verify_pipeline() as sole public entry."""
    all_checks = []

    # G4K-R4: Validate top-level snapshot types at entry boundary
    if registry_snapshot is not None and not isinstance(registry_snapshot, dict):
        all_checks.append({"check": "INPUT", "result": "FAIL",
            "detail": f"registry_snapshot must be a dict or None, got {type(registry_snapshot).__name__}"})
        registry_snapshot = None
    if policy_snapshot is not None and not isinstance(policy_snapshot, dict):
        all_checks.append({"check": "INPUT", "result": "FAIL",
            "detail": f"policy_snapshot must be a dict or None, got {type(policy_snapshot).__name__}"})
        policy_snapshot = None
    if evidence_snapshot is not None and not isinstance(evidence_snapshot, dict):
        all_checks.append({"check": "INPUT", "result": "FAIL",
            "detail": f"evidence_snapshot must be a dict or None, got {type(evidence_snapshot).__name__}"})
        evidence_snapshot = None
    if verification_context is not None and not isinstance(verification_context, dict):
        all_checks.append({"check": "INPUT", "result": "FAIL",
            "detail": f"verification_context must be a dict or None, got {type(verification_context).__name__}"})
        verification_context = None

    effective_status, is_terminal = _compute_effective_status(receipt)

    if is_terminal and receipt.get("allowed_action") == "bounded_effect":
        all_checks.append({"check": "NV-14", "result": "FAIL",
            "detail": f"Terminal effective status {effective_status} blocks all bounded effects"})

    elig_result, elig_checks = _check_evidence_eligibility(receipt, evidence_snapshot,
                                                            verification_context)
    all_checks.extend(elig_checks)

    indep_result, indep_checks = _check_independence_provenance(receipt, registry_snapshot)
    all_checks.extend(indep_checks)

    relev_result, relev_checks = _check_evidence_relevance(receipt, evidence_snapshot, verification_context)
    all_checks.extend(relev_checks)

    rev_result, rev_checks = _check_revision_integrity(receipt)
    all_checks.extend(rev_checks)

    auth_result, exec_perm, auth_checks = _check_authorization(
        receipt, policy_snapshot, effective_status, verification_context)
    all_checks.extend(auth_checks)

    conformance_inputs = [elig_result, rev_result]
    if "FAIL" in conformance_inputs:
        conformance = "NON_CONFORMANT"
    elif "UNCERTIFIED" in conformance_inputs:
        conformance = "UNCERTIFIED"
    else:
        conformance = "CONFORMANT"

    assurance_inputs = [indep_result, relev_result]
    if "FAIL" in assurance_inputs:
        assurance = "NOT_ASSURED"
    elif "UNCERTIFIED" in assurance_inputs:
        assurance = "UNCERTIFIED"
    else:
        if receipt.get("status") == "VERIFIED":
            assurance = "ASSURED"
        else:
            assurance = "PASS"

    if auth_result == "FAIL":
        authorization = "NOT_AUTHORIZED"
    elif auth_result == "UNCERTIFIED":
        authorization = "UNCERTIFIED"
    else:
        authorization = "AUTHORIZED" if exec_perm == "GRANTED" else "NOT_REQUESTED"

    # NV-21: Fail-closed execution gate
    if exec_perm == "GRANTED":
        if conformance != "CONFORMANT":
            exec_perm = "DENIED"
            all_checks.append({"check": "NV-21", "result": "FAIL",
                "detail": "Fail-closed: conformance is not CONFORMANT"})
        if assurance in ("NOT_ASSURED", "UNCERTIFIED") and receipt.get("status") == "VERIFIED":
            exec_perm = "DENIED"
            all_checks.append({"check": "NV-21", "result": "FAIL",
                "detail": "Fail-closed: assurance requirement not met for VERIFIED claim"})

        # G4F-R1: PROVISIONAL bounded effect -- category-based assurance check
        if receipt.get("status") == "PROVISIONAL":
            # First: UNCERTIFIED/NOT_ASSURED can NEVER authorize bounded effects
            if assurance in _NON_ACTIONABLE_ASSURANCE:
                exec_perm = "DENIED"
                all_checks.append({"check": "NV-21", "result": "FAIL",
                    "detail": f"Fail-closed: assurance '{assurance}' is non-actionable and can never authorize bounded effects (Invariant I-3)"})
            elif assurance != "ASSURED":
                # PASS requires explicit policy threshold
                threshold_ok = False
                if policy_snapshot:
                    threshold_entry = policy_snapshot.get("assurance_threshold_policies", {}).get(
                        receipt.get("claim_id", ""))
                    if isinstance(threshold_entry, dict):
                        required_level = threshold_entry.get("required_assurance_level", "")
                        has_statuses = isinstance(threshold_entry.get("authorized_statuses"), list)
                        has_version = bool(threshold_entry.get("policy_version"))
                        status_match = "PROVISIONAL" in threshold_entry.get("authorized_statuses", [])
                        # G4F-R1: Validate required level is actionable
                        satisfied, reason = _assurance_satisfies_for_bounded_effect(assurance, required_level)
                        if has_statuses and has_version and status_match and satisfied:
                            threshold_ok = True
                if not threshold_ok:
                    exec_perm = "DENIED"
                    all_checks.append({"check": "NV-21", "result": "FAIL",
                        "detail": f"Fail-closed: PROVISIONAL claim assurance '{assurance}' does not satisfy bounded-effect threshold"})

        if is_terminal:
            exec_perm = "DENIED"
            all_checks.append({"check": "NV-21", "result": "FAIL",
                "detail": f"Fail-closed: terminal effective status {effective_status}"})

    # Recalculate authorization overall AFTER final gating
    if exec_perm == "DENIED":
        authorization = "NOT_AUTHORIZED"
    elif exec_perm == "GRANTED":
        authorization = "AUTHORIZED"
    elif exec_perm == "NOT_REQUESTED":
        authorization = "NOT_REQUESTED"

    return {
        "claim_id": receipt.get("claim_id", ""),
        "receipt_status": receipt.get("status", "UNKNOWN"),
        "effective_status": effective_status,
        "claim_conformance": {
            "evidence_eligibility": elig_result,
            "revision_integrity": rev_result,
            "overall": conformance
        },
        "claim_assurance": {
            "witness_independence": indep_result,
            "evidence_relevance": relev_result,
            "overall": assurance
        },
        "action_authorization": {
            "authorization_consistency": auth_result,
            "execution_permission": exec_perm,
            "overall": authorization
        },
        "checks": all_checks
    }


# ---------------------------------------------------------------------------
# PUBLIC entry point (sole public API)
# ---------------------------------------------------------------------------

def verify_pipeline(receipt, schema_obj, registry_snapshot=None,
                    policy_snapshot=None, evidence_snapshot=None,
                    verification_context=None):
    """
    SOLE PUBLIC entry point. Stage 1 + Stage 2 pipeline.
    NON-AUTHORIZING DEMONSTRATION CODE.
    """
    # G4M-R1: Non-dict receipt type guard -- JSON null, array, string, number,
    # boolean must return typed DENIED, never raise AttributeError.
    if not isinstance(receipt, dict):
        return {
            "claim_id": "",
            "receipt_status": "UNKNOWN",
            "effective_status": "UNKNOWN",
            "stage_1": {"valid": False, "error": f"Receipt must be a JSON object, got {type(receipt).__name__}"},
            "claim_conformance": {"evidence_eligibility": "FAIL", "revision_integrity": "FAIL", "overall": "NON_CONFORMANT"},
            "claim_assurance": {"witness_independence": "FAIL", "evidence_relevance": "FAIL", "overall": "NOT_ASSURED"},
            "action_authorization": {"authorization_consistency": "FAIL", "execution_permission": "DENIED", "overall": "NOT_AUTHORIZED"},
            "checks": [{"check": "STAGE-1", "result": "FAIL", "detail": f"Receipt is not a JSON object: {type(receipt).__name__}"}]
        }

    stage1_valid, stage1_error = validate_schema(receipt, schema_obj)

    if not stage1_valid:
        return {
            "claim_id": receipt.get("claim_id", ""),
            "receipt_status": receipt.get("status", "UNKNOWN"),
            "effective_status": "UNKNOWN",
            "stage_1": {"valid": False, "error": stage1_error},
            "claim_conformance": {"evidence_eligibility": "FAIL", "revision_integrity": "FAIL", "overall": "NON_CONFORMANT"},
            "claim_assurance": {"witness_independence": "FAIL", "evidence_relevance": "FAIL", "overall": "NOT_ASSURED"},
            "action_authorization": {"authorization_consistency": "FAIL", "execution_permission": "DENIED", "overall": "NOT_AUTHORIZED"},
            "checks": [{"check": "STAGE-1", "result": "FAIL", "detail": f"Schema validation failed: {stage1_error}"}]
        }

    result = _verify_receipt_internal(receipt, registry_snapshot, policy_snapshot,
                                       evidence_snapshot, verification_context)
    result["stage_1"] = {"valid": True, "error": None}
    return result
# Bismillah ir-Rahman ir-Rahim
