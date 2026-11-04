# Bismillah ir-Rahman ir-Rahim
"""
EESS Dispatch Engine v0.3.13 -- Positive authorization predicate at post-J3 gate.

v0.3.13 hardening (P11-R2 findings):
- P11-R2-F05: Post-J3 gate now requires authorization_state == "VALID"
  (positive predicate) instead of checking only for "REVOKED" (negative
  predicate). This blocks EXPIRED, REVOKED, and any other non-VALID state.
- P11-R2-F06: Post-J3 gate checks reducer safety for QUARANTINED.
  Corruption injected between the pre-J3 integrity check and the post-J3
  reducer read now halts dispatch.
- C-26 linearization policy: The post-J3 read is a prototype interlock.
  Events interleaved AFTER this read and BEFORE target.call() are a known
  residual race. Production TOCTOU protection requires target-enforced
  fencing. C-26 is narrowed to: "revocation/expiration visible at the
  named post-J3 snapshot blocks dispatch."

Prior hardening carried forward:
- P11-F04 (J3 fail-closed), P11-F03 (revocation interlock), P11-F01 (J12 hash),
  P11-F02 (hash chain), P10-F01/F02/OPEN, P9-P5 fixes.

Prior hardening carried forward:
- P10-F01/F02/OPEN, P9-F01/C34-C51, P8-C04/C05, P7-F05, P6-F05, P5-F03/F04/F07/F10.

NON-AUTHORIZING PROTOTYPE.
"""

import copy
import hashlib
import math
import re
import threading
import uuid
from dataclasses import dataclass
from typing import Optional

from Bismillah_HABL_Event_Store_v0313 import HABLJournal, EventType, HABLEvent, VALID_CAPABILITIES
from Bismillah_Decision_Reducer_v0313 import DecisionReducer, SafetyState


class TargetCapability:
    FENCING_ENFORCED = "TARGET_FENCING_ENFORCED"
    DEDUP_ENFORCED = "TARGET_DEDUP_ENFORCED"
    FENCING_AND_DEDUP = "TARGET_FENCING_AND_DEDUP_ENFORCED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class TargetContract:
    target_id: str
    capability: str
    dedup_retention_seconds: int = 0
    api_version: str = "1.0"

    def supports_automated_dispatch(self) -> bool:
        return self.capability in (
            TargetCapability.DEDUP_ENFORCED,
            TargetCapability.FENCING_AND_DEDUP,
        )


@dataclass
class DispatchResult:
    success: bool
    decision_id: str
    attempt_id: str = ""
    outcome: str = ""
    detail: str = ""
    target_transaction_id: str = ""


# ---------------------------------------------------------------------------
# MockTarget v0.3.13: Validate-then-mutate fencing + strict epoch
# P10-F01: Epoch advance ONLY on accepted effect execution
# P10-F02: type(epoch) is int -- rejects float 1.0
# ---------------------------------------------------------------------------

class MockTarget:
    """
    v0.3.13 fixes:
    - P10-F01: _seen_epochs, _seen_keys, and _seen_effects are ONLY mutated
      on successful effect execution. Rejected requests leave all mock state
      unchanged. No epoch poisoning on invalid input.
    - P10-F02: Fencing epoch validated as `type(epoch) is int and epoch > 0`.
      Float 1.0 rejected. bool rejected (type is not int for bool).
    - P10-OPEN: Whitespace-only request_hash and idempotency_key rejected;
      missing decision_id rejected for fencing/dedup targets.
    """

    def __init__(self, behavior="confirm", target_id="TARGET-1",
                 capability="TARGET_DEDUP_ENFORCED", dedup_retention=3600):
        self.behavior = behavior
        self.target_id = target_id
        self.capability = capability
        self.dedup_retention = dedup_retention
        self.call_count = 0
        self.calls: list[dict] = []
        self._tx_counter = 0
        self._lock = threading.Lock()
        self._seen_keys: dict[str, dict] = {}
        self._seen_epochs: dict[str, int] = {}
        self._seen_effects: dict[str, dict] = {}

    def _check_request_key_dedup(self, idem_key, req_hash, effect_id):
        """Check request-key dedup with full operation binding.
        Returns (is_hit, response_tuple) or (False, None) if no hit.
        Does NOT mutate any state.
        """
        if not idem_key or idem_key not in self._seen_keys:
            return False, None
        existing = self._seen_keys[idem_key]
        existing_hash = existing.get("request_hash", "")
        existing_effect = existing.get("business_effect_id", "")

        # Different effect_id = conflict, not dedup
        if existing_effect and effect_id and existing_effect != effect_id:
            return True, ("DEFINITIVE_NO_EFFECT", "",
                          f"Operation binding conflict for key '{idem_key}' "
                          f"-- effect_id mismatch: "
                          f"'{existing_effect}' vs '{effect_id}'")

        # Different hash = payload conflict
        if existing_hash and req_hash and existing_hash != req_hash:
            return True, ("DEFINITIVE_NO_EFFECT", "",
                          f"Payload conflict for key '{idem_key}' "
                          f"-- rejected")

        # Exact match = safe dedup replay
        return True, ("DEFINITIVE_EFFECT",
                      existing["tx_id"],
                      f"Deduplicated -- same key '{idem_key}'")

    def _record_effect(self, tx_id, idem_key, req_hash, effect_id,
                       decision_id, epoch):
        """Record a successful effect in all tracking maps.
        P10-F01: This is the ONLY place _seen_epochs, _seen_keys,
        and _seen_effects are mutated."""
        # Advance fencing epoch
        if self.capability in (TargetCapability.FENCING_ENFORCED,
                               TargetCapability.FENCING_AND_DEDUP):
            self._seen_epochs[decision_id] = epoch
        # Record dedup keys
        if idem_key:
            self._seen_keys[idem_key] = {
                "tx_id": tx_id,
                "request_hash": req_hash,
                "business_effect_id": effect_id}
        if effect_id:
            self._seen_effects[effect_id] = {
                "tx_id": tx_id,
                "request_hash": req_hash}

    def call(self, request: dict) -> tuple[str, str, str]:
        with self._lock:
            # P9-C39: Non-dict request returns typed refusal
            if not isinstance(request, dict):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid request type: {type(request).__name__}")

            self.call_count += 1
            # P9-C51: Deep-copy call records to prevent aliasing
            self.calls.append(copy.deepcopy(request))

            idem_key = request.get("idempotency_key", "")
            epoch = request.get("epoch", 0)
            decision_id = request.get("decision_id", "")
            effect_id = request.get("business_effect_id", "")
            req_hash = request.get("request_hash", "")

            # -----------------------------------------------------------
            # Input validation -- ALL checks BEFORE any state mutation
            # P10-F01: No mutation on rejected requests
            # -----------------------------------------------------------

            # P10-F02 + P8-C05: Strict epoch type validation
            if isinstance(epoch, bool):
                return ("DEFINITIVE_NO_EFFECT", "",
                        "Invalid epoch type: bool")
            if not isinstance(epoch, (int, float)):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid epoch type: {type(epoch).__name__}")
            if isinstance(epoch, float) and (math.isnan(epoch) or math.isinf(epoch)):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Non-finite epoch: {epoch}")

            # P10-F02: Fencing targets require STRICT positive integer
            if self.capability in (TargetCapability.FENCING_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if type(epoch) is not int or epoch < 1:
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Epoch must be a positive integer for "
                            f"fencing targets, got {type(epoch).__name__}:{epoch}")

            # P9-C49: Request target mismatch
            req_target = request.get("target", "")
            if req_target and req_target != self.target_id:
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Request target '{req_target}' does not match "
                        f"adapter '{self.target_id}'")

            # P9-C48 + P10-OPEN: request_hash type and whitespace
            if isinstance(req_hash, bool):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid request_hash type: {type(req_hash).__name__}")
            if req_hash and not isinstance(req_hash, str):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid request_hash type: {type(req_hash).__name__}")

            # P8-C04 + P9-C47: business_effect_id validation
            if self.capability in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if not effect_id or not isinstance(effect_id, str) or not effect_id.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Missing or invalid business_effect_id -- rejected")

            # P9-C46 + P10-OPEN: idempotency_key mandatory + whitespace
            if self.capability in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if not idem_key or not isinstance(idem_key, str) or not idem_key.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Missing or invalid idempotency_key -- rejected")

            # P10-OPEN: decision_id mandatory for fencing/dedup targets
            if self.capability in (TargetCapability.FENCING_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP,
                                   TargetCapability.DEDUP_ENFORCED):
                if not decision_id or not isinstance(decision_id, str) or not decision_id.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Missing or invalid decision_id -- rejected")

            # P10-OPEN + P9-F01: request_hash must be non-empty non-whitespace
            if self.capability in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if not req_hash or not isinstance(req_hash, str) or not req_hash.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Empty or invalid request_hash -- rejected; "
                            "immutable operation identity required")

            # -----------------------------------------------------------
            # All input validation passed. Now check fencing and dedup.
            # P10-F01: State mutation happens ONLY in _record_effect()
            # at the end, after all checks pass.
            # -----------------------------------------------------------

            # Fencing check -- read-only, no state mutation
            if self.capability == TargetCapability.FENCING_ENFORCED:
                max_seen = self._seen_epochs.get(decision_id, 0)
                if epoch <= max_seen:
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Stale epoch {epoch} <= {max_seen} -- fenced")
                # Do NOT advance epoch here -- happens in _record_effect()

            elif self.capability == TargetCapability.FENCING_AND_DEDUP:
                max_seen = self._seen_epochs.get(decision_id, 0)

                if epoch < max_seen:
                    # Truly stale -- no state change
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Stale epoch {epoch} < {max_seen} -- fenced")

                if epoch == max_seen and max_seen > 0:
                    # Same epoch -- check dedup (read-only)
                    hit, response = self._check_request_key_dedup(
                        idem_key, req_hash, effect_id)
                    if hit:
                        return response
                    # Same epoch, unknown key -- fenced, no state change
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Same epoch {epoch} with unknown key -- fenced")

                # epoch > max_seen -- new epoch, continue to dedup/execute
                # Do NOT advance epoch here -- happens in _record_effect()

            # Layer 1: Request-key dedup (read-only check)
            if self.capability in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                hit, response = self._check_request_key_dedup(
                    idem_key, req_hash, effect_id)
                if hit:
                    return response

            # Layer 2: Cross-decision effect uniqueness (read-only check)
            if (effect_id and self.capability in
                    (TargetCapability.DEDUP_ENFORCED,
                     TargetCapability.FENCING_AND_DEDUP)):
                if effect_id in self._seen_effects:
                    existing = self._seen_effects[effect_id]
                    existing_hash = existing.get("request_hash", "")
                    if existing_hash and req_hash and existing_hash != req_hash:
                        return ("DEFINITIVE_NO_EFFECT", "",
                                f"Effect '{effect_id}' conflict -- "
                                f"different request hash; "
                                f"cannot certify prior effect matches")
                    return ("DEFINITIVE_EFFECT", existing["tx_id"],
                            f"Deduplicated by effect_id '{effect_id}'")

            # -----------------------------------------------------------
            # Execute effect -- ALL validation passed
            # P10-F01: _record_effect() is the ONLY place state mutates
            # -----------------------------------------------------------
            self._tx_counter += 1
            internal_tx_id = f"TX-{self.target_id}-{self._tx_counter}"

            if callable(self.behavior):
                result = self.behavior(request)
                outcome_type = result[0] if result else "AMBIGUOUS"
                response_tx_id = result[1] if len(result) > 1 and result[1] else internal_tx_id
                if outcome_type == "DEFINITIVE_EFFECT":
                    self._record_effect(response_tx_id, idem_key, req_hash,
                                        effect_id, decision_id, epoch)
                return result

            if self.behavior == "confirm":
                self._record_effect(internal_tx_id, idem_key, req_hash,
                                    effect_id, decision_id, epoch)
                return "DEFINITIVE_EFFECT", internal_tx_id, "Effect completed"
            elif self.behavior == "reject":
                return "DEFINITIVE_NO_EFFECT", internal_tx_id, "Rejected"
            elif self.behavior == "timeout":
                return "AMBIGUOUS", "", "Timeout"
            elif self.behavior == "error_after_effect":
                self._record_effect(internal_tx_id, idem_key, req_hash,
                                    effect_id, decision_id, epoch)
                return "AMBIGUOUS", "", "HTTP 500 after possible commit"
            elif self.behavior == "accepted_not_final":
                return "ACCEPTED_NOT_FINAL", internal_tx_id, "HTTP 202"
            else:
                return "AMBIGUOUS", "", f"Unknown: {self.behavior}"


# ---------------------------------------------------------------------------
# Retention validation helper
# ---------------------------------------------------------------------------

def _validate_retention(value, label="dedup_retention_seconds"):
    """Validate retention is a finite, positive, non-boolean number."""
    if isinstance(value, bool):
        raise ValueError(f"{label} must be numeric, got bool")
    if not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric, got {type(value).__name__}")
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{label} must be finite, got {value}")
    if value <= 0:
        raise ValueError(f"{label} must be positive, got {value}")


# ---------------------------------------------------------------------------
# Safe target response parsing
# ---------------------------------------------------------------------------

def _parse_target_response(raw_response):
    """Parse and type-check target adapter response.
    Returns (outcome_type: str, tx_id: str, detail: str) or raises ValueError.
    """
    if raw_response is None:
        raise ValueError("Target returned None")
    if not isinstance(raw_response, tuple):
        raise ValueError(f"Target response must be a tuple, got {type(raw_response).__name__}")
    if len(raw_response) != 3:
        raise ValueError(f"Target response must be a 3-tuple, got length {len(raw_response)}")

    outcome_type, tx_id, detail = raw_response

    if not isinstance(outcome_type, str):
        raise ValueError(f"Target outcome_type must be string, got {type(outcome_type).__name__}")
    if not isinstance(tx_id, str):
        raise ValueError(f"Target tx_id must be string, got {type(tx_id).__name__}")
    if not isinstance(detail, str):
        raise ValueError(f"Target detail must be string, got {type(detail).__name__}")

    return outcome_type, tx_id, detail


# ---------------------------------------------------------------------------
# Dispatch Engine v0.3.13 -- ZERO public append() calls
# ---------------------------------------------------------------------------

class DispatchEngine:

    def __init__(self, journal: HABLJournal, reducer: DecisionReducer):
        self._journal = journal
        self._reducer = reducer
        self._worker_id = f"worker-{uuid.uuid4().hex[:8]}"

    def commit_decision(self, decision_id: str, claim_id: str,
                        action: str, target_id: str,
                        policy_version: str, approval_ref: str,
                        evidence_hash: str = "",
                        business_effect_id: str = "") -> HABLEvent:
        """Step 1-2: Atomic effect reservation + J0 commit."""

        required = {"claim_id": claim_id, "action": action,
                     "target_id": target_id,
                     "policy_version": policy_version,
                     "approval_ref": approval_ref}
        for name, val in required.items():
            if not val or not isinstance(val, str) or not val.strip():
                raise ValueError(
                    f"commit_decision requires non-empty '{name}'")

        if (not business_effect_id or
                not isinstance(business_effect_id, str) or
                not business_effect_id.strip()):
            raise ValueError(
                "commit_decision requires non-empty 'business_effect_id'")

        return self._journal.reserve_effect_and_commit_decision(
            decision_id=decision_id,
            business_effect_id=business_effect_id,
            payload={
                "claim_id": claim_id, "action": action,
                "target": target_id,
                "policy_version": policy_version,
                "approval_ref": approval_ref,
                "evidence_hash": evidence_hash,
                "business_effect_id": business_effect_id,
            })

    def dispatch(self, decision_id: str, target,
                 target_contract: TargetContract) -> DispatchResult:
        """Steps 3-7 using atomic dispatch claim. ALL events via typed APIs."""

        # Validate inputs before any operation
        if not isinstance(target_contract, TargetContract):
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="target_contract must be a TargetContract instance")

        # Validate retention as finite positive non-boolean
        try:
            _validate_retention(target_contract.dedup_retention_seconds)
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=str(e))

        # Verify journal integrity
        valid, head, msg = self._journal.verify_head()
        if not valid:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Journal integrity check failed: {msg}")

        # Get J0 for binding validation
        j0_events = self._journal.get_events(
            decision_id=decision_id,
            event_type=EventType.DECISION_COMMITTED)
        if not j0_events:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="No J0 found for this decision")
        j0 = j0_events[0]
        j0_target = j0.payload.get("target", "")
        j0_effect = j0.payload.get("business_effect_id", "")

        # Validate target binding
        if j0_target != target_contract.target_id:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target mismatch: J0='{j0_target}' "
                       f"contract='{target_contract.target_id}'")
        if not j0_effect:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="J0 has no business_effect_id")

        # Require target adapter has mandatory fields (strict)
        target_id_attr = getattr(target, 'target_id', None)
        if not target_id_attr:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="Target adapter missing required target_id")
        target_cap_attr = getattr(target, 'capability', None)
        if not target_cap_attr:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="Target adapter missing required capability")

        # Validate actual target matches contract
        if target_id_attr != target_contract.target_id:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target identity mismatch: "
                       f"'{target_id_attr}' vs "
                       f"'{target_contract.target_id}'")
        if target_cap_attr != target_contract.capability:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target capability mismatch: "
                       f"'{target_cap_attr}' vs "
                       f"'{target_contract.capability}'")

        # Adapter retention is MANDATORY for dedup-capable targets.
        adapter_retention = getattr(target, 'dedup_retention', None)
        if adapter_retention is None:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="Target adapter must declare dedup_retention")
        try:
            _validate_retention(adapter_retention, "adapter dedup_retention")
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target adapter retention invalid: {e}")
        if adapter_retention < target_contract.dedup_retention_seconds:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Adapter retention {adapter_retention}s "
                       f"< contract {target_contract.dedup_retention_seconds}s")

        # Fencing-only blocked
        if not target_contract.supports_automated_dispatch():
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target capability "
                       f"'{target_contract.capability}' does not "
                       f"support automated dispatch")

        # Generate attempt identifiers
        attempt_id = f"ATT-{decision_id}-{uuid.uuid4().hex[:8]}"
        request_hash = hashlib.sha256(
            f"{decision_id}:{attempt_id}:"
            f"{target_contract.target_id}:{j0_effect}".encode()
        ).hexdigest()
        idempotency_key = (
            f"KEY-{decision_id}-{target_contract.target_id}-"
            f"{request_hash[:16]}")

        # ATOMIC dispatch claim -- eligibility + J1 + J2 under ONE lock
        try:
            j1, j2 = self._journal.atomic_dispatch_claim(
                decision_id=decision_id,
                target=target_contract.target_id,
                worker_id=self._worker_id,
                attempt_id=attempt_id,
                request_hash=request_hash,
                idempotency_key=idempotency_key,
                target_capability=target_contract.capability,
                business_effect_id=j0_effect)
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Atomic dispatch claim failed: {e}")

        new_epoch = j1.payload.get("epoch", 0)

        # Post-J2 auth revalidation
        agg_recheck = self._reducer.reduce(decision_id)
        if agg_recheck.safety == SafetyState.QUARANTINED:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason="quarantined_before_call")
            except ValueError:
                pass
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail="Quarantined before target call")

        if agg_recheck.authorization_state != "VALID":
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"authorization_"
                           f"{agg_recheck.authorization_state.lower()}"
                           f"_before_call")
            except ValueError:
                pass
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"Authorization is "
                       f"{agg_recheck.authorization_state}")

        # Last-moment journal integrity re-check
        valid2, _, msg2 = self._journal.verify_head()
        if not valid2:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"journal_integrity_failed: {msg2}")
            except ValueError:
                pass
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"Journal integrity failed at dispatch: {msg2}")

        # Step 5: Call target
        request = {
            "decision_id": decision_id,
            "attempt_id": attempt_id,
            "epoch": new_epoch,
            "request_hash": request_hash,
            "idempotency_key": idempotency_key,
            "target": target_contract.target_id,
            "business_effect_id": j0_effect,
        }

        # J3 observation -- P11-F04: FAIL CLOSED if J3 cannot commit
        try:
            self._journal.record_attempt_observed(
                decision_id, attempt_id, transport_metadata="mock_call")
        except (ValueError, Exception) as j3_err:
            # P11-F04: J3 failure is a no-send halt. Do NOT call target.
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"J3 pre-send observation failed: {j3_err}")

        # P11-R2-F05/F06: Post-J3 authorization and integrity gate.
        # Re-verify the FULL authorization predicate after J3 and before
        # target call. This is a prototype interlock, NOT a production
        # TOCTOU solution -- events interleaved AFTER this read and BEFORE
        # target.call() are a known residual race (see C-26 linearization
        # policy). Production TOCTOU protection requires target-enforced
        # fencing (the epoch check in the mock).
        post_j3_state = self._reducer.reduce(decision_id)

        # P11-R2-F06: If reducer reports QUARANTINED, halt immediately.
        # This catches corruption injected between the earlier integrity
        # check and this reducer call.
        if post_j3_state.safety == SafetyState.QUARANTINED:
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail="Journal quarantined at post-J3 gate")

        # P11-R2-F05 + P11-F03: Require VALID authorization at post-J3
        # gate. This blocks REVOKED (P11-F03), EXPIRED (P11-R2-F05),
        # and any other non-VALID state. Uses != "VALID" (positive
        # predicate) matching the pre-J3 guard at line 555, NOT the
        # v0.3.12 == "REVOKED" (negative predicate) that missed EXPIRED.
        if post_j3_state.authorization_state != "VALID":
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"authorization_{post_j3_state.authorization_state.lower()}"
                           f"_after_j3_before_send")
            except ValueError:
                pass
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"Authorization {post_j3_state.authorization_state} "
                       f"at post-J3 gate")

        # Wrap entire target call + response parsing in exception handler
        try:
            raw_response = target.call(request)
        except Exception as e:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"target_call_exception: {e}")
            except ValueError:
                pass
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail=f"Target exception: {e}")

        # Type-check the complete response before interpreting
        try:
            outcome_type, tx_id, detail = _parse_target_response(raw_response)
        except ValueError as e:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"malformed_target_response: {e}")
            except ValueError:
                pass
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail=f"Malformed target response: {e}")

        # Step 6: Record outcome via typed APIs
        if outcome_type == "DEFINITIVE_EFFECT":
            if not tx_id:
                try:
                    self._journal.record_outcome_unknown(
                        decision_id, attempt_id,
                        reason="definitive_effect_without_tx_id")
                except ValueError:
                    pass
                self._release_lease(decision_id, target_contract.target_id, new_epoch)
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail="Target reported effect but no TX ID")
            # J4a via typed API
            try:
                self._journal.record_effect_confirmed(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id,
                    request_hash=request_hash,
                    evidence_hash=hashlib.sha256(
                        detail.encode()).hexdigest(),
                    business_effect_id=j0_effect)
            except ValueError as e:
                try:
                    self._journal.record_outcome_unknown(
                        decision_id, attempt_id,
                        reason=f"j4a_validation_failed: {e}")
                except ValueError:
                    pass
                self._release_lease(decision_id, target_contract.target_id, new_epoch)
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"J4a validation failed: {e}")
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                True, decision_id, attempt_id=attempt_id,
                outcome="CONFIRMED", detail=detail,
                target_transaction_id=tx_id)

        elif outcome_type == "DEFINITIVE_NO_EFFECT":
            # J4b via typed API
            try:
                self._journal.record_no_effect(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id or "none",
                    request_hash=request_hash,
                    no_effect_evidence=detail or "no_effect_reported",
                    business_effect_id=j0_effect)
            except ValueError as e:
                try:
                    self._journal.record_outcome_unknown(
                        decision_id, attempt_id,
                        reason=f"j4b_validation_failed: {e}")
                except ValueError:
                    pass
                self._release_lease(decision_id, target_contract.target_id, new_epoch)
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"J4b validation failed: {e}")
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="NO_EFFECT", detail=detail,
                target_transaction_id=tx_id)

        else:
            # J4c via typed API
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"{outcome_type}: {detail}")
            except ValueError:
                pass
            self._release_lease(decision_id, target_contract.target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail=f"{outcome_type}: {detail}")

    def _release_lease(self, decision_id: str, target: str, epoch: int):
        """Use typed release_lease with ownership validation."""
        try:
            self._journal.release_lease(
                decision_id, target, self._worker_id, epoch)
        except ValueError:
            pass

    def close_no_send(self, decision_id: str,
                      reason: str = "BUDGET_EXHAUSTED") -> DispatchResult:
        """Atomic J10 + effect release via typed API."""
        try:
            self._journal.close_no_send_atomic(
                decision_id, reason, self._worker_id)
            return DispatchResult(
                True, decision_id, outcome="NO_SEND",
                detail=f"Closed without send: {reason}")
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="ERROR",
                detail=str(e))

    # -------------------------------------------------------------------
    # Reconciliation -- ALWAYS returns UNKNOWN.
    # -------------------------------------------------------------------

    def record_reconciliation(self, decision_id: str, attempt_id: str,
                              query_result: str, tx_id: str = ""
                              ) -> DispatchResult:
        """Record reconciliation (J11) via typed API with J2 binding validation.

        ALL reconciliation returns UNKNOWN. The caller cannot elevate to
        definitive J4a/J4b without an authenticated target adapter.
        """

        # Get J2 for binding data
        j2_events = [
            e for e in self._journal.get_events(
                decision_id=decision_id,
                event_type=EventType.SEND_INTENT_COMMITTED)
            if e.payload.get("attempt_id") == attempt_id]
        if not j2_events:
            raise ValueError(f"No J2 for attempt '{attempt_id}'")
        j2 = j2_events[0]

        j2_hash = j2.payload.get("request_hash", "")
        j2_key = j2.payload.get("idempotency_key", "")
        j2_effect = j2.payload.get("business_effect_id", "")

        # J11 via typed API -- journal validates bindings
        try:
            self._journal.record_reconciliation_evidence(
                decision_id=decision_id,
                attempt_id=attempt_id,
                request_hash=j2_hash,
                idempotency_key=j2_key,
                query_result=query_result,
                target_transaction_id=tx_id,
                business_effect_id=j2_effect)
        except ValueError as e:
            raise ValueError(f"J11 validation failed: {e}")

        # ALWAYS UNKNOWN. No caller-asserted definitiveness.
        return DispatchResult(
            False, decision_id, attempt_id=attempt_id,
            outcome="UNKNOWN",
            detail=f"Reconciliation observation recorded: {query_result}")

    def _test_simulate_authenticated_reconciliation(
            self, decision_id: str, attempt_id: str,
            query_result: str, tx_id: str = "",
            effect_confirmed: bool = False) -> DispatchResult:
        """TEST-ONLY: Simulate authenticated target reconciliation.

        This method BYPASSES the reconciliation trust boundary to allow
        testing the full J11 -> J4a/J4b pipeline. In production, this
        path requires an authenticated target adapter with defined
        consistency, complete-window semantics, and response authenticity.

        NOT for production use. NOT called by any non-test code path.
        """

        # Get J2 for binding
        j2_events = [
            e for e in self._journal.get_events(
                decision_id=decision_id,
                event_type=EventType.SEND_INTENT_COMMITTED)
            if e.payload.get("attempt_id") == attempt_id]
        if not j2_events:
            raise ValueError(f"No J2 for attempt '{attempt_id}'")
        j2 = j2_events[0]

        j2_hash = j2.payload.get("request_hash", "")
        j2_key = j2.payload.get("idempotency_key", "")
        j2_effect = j2.payload.get("business_effect_id", "")

        # Record J11
        self._journal.record_reconciliation_evidence(
            decision_id=decision_id,
            attempt_id=attempt_id,
            request_hash=j2_hash,
            idempotency_key=j2_key,
            query_result=query_result,
            target_transaction_id=tx_id,
            business_effect_id=j2_effect)

        if effect_confirmed:
            if not tx_id:
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail="Simulated reconciliation claims effect but no TX")
            try:
                self._journal.record_effect_confirmed(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id,
                    request_hash=j2_hash,
                    evidence_hash=hashlib.sha256(
                        query_result.encode()).hexdigest(),
                    business_effect_id=j2_effect)
            except ValueError as e:
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"Simulated reconciliation J4a failed: {e}")
            return DispatchResult(
                True, decision_id, attempt_id=attempt_id,
                outcome="CONFIRMED",
                detail=f"Simulated authenticated reconciliation: {query_result}",
                target_transaction_id=tx_id)
        else:
            try:
                self._journal.record_no_effect(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id or "recon-no-effect",
                    request_hash=j2_hash,
                    no_effect_evidence=query_result or "reconciliation_no_effect",
                    business_effect_id=j2_effect)
            except ValueError as e:
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"Simulated reconciliation J4b failed: {e}")
            return DispatchResult(
                True, decision_id, attempt_id=attempt_id,
                outcome="NO_EFFECT",
                detail=f"Simulated authenticated no-effect: {query_result}",
                target_transaction_id=tx_id)

    def record_conflict(self, decision_id: str, attempt_id: str,
                        competing_evidence: str,
                        competing_hash: str) -> DispatchResult:
        """Record J12 via typed API -- journal validates prior definitive + hex."""
        try:
            self._journal.record_evidence_conflict(
                decision_id, attempt_id,
                competing_evidence_ref=competing_evidence,
                competing_evidence_hash=competing_hash)
        except ValueError as e:
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="ERROR",
                detail=f"J12 validation failed: {e}")
        return DispatchResult(
            False, decision_id, attempt_id=attempt_id,
            outcome="QUARANTINED",
            detail="Evidence conflict -- decision quarantined")
# Bismillah ir-Rahman ir-Rahim
