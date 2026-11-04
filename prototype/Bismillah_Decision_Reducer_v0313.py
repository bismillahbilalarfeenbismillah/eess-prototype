# Bismillah ir-Rahman ir-Rahim
"""
EESS Decision Reducer v0.3.13 -- Deterministic six-priority aggregate.

v0.3.13 (P7 findings):
- P7-F01: Reducer consumes ONLY verified journal snapshots. Uses
  verified_snapshot_or_quarantine() instead of raw get_events().
  A corrupt journal produces QUARANTINED, never dispatchable=True
  or TERMINAL_CONFIRMED.

NON-AUTHORIZING PROTOTYPE.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from Bismillah_HABL_Event_Store_v0313 import HABLJournal, EventType


class SafetyState(Enum):
    QUARANTINED = 1
    UNKNOWN = 2
    TERMINAL_CONFIRMED = 3
    TERMINAL_NO_EFFECT = 4
    TERMINAL_NO_SEND = 5
    PENDING = 6


class BusinessEffect(Enum):
    CONFIRMED = "CONFIRMED"
    NO_EFFECT = "NO_EFFECT"
    NO_SEND = "NO_SEND"
    UNDETERMINED = "UNDETERMINED"
    QUARANTINED = "QUARANTINED"


class AttemptState(Enum):
    SEND_INTENT = "SEND_INTENT"
    ATTEMPTED = "ATTEMPTED"
    CONFIRMED = "CONFIRMED"
    NO_EFFECT = "NO_EFFECT"
    UNKNOWN = "UNKNOWN"


@dataclass
class AttemptRecord:
    attempt_id: str
    state: AttemptState
    epoch: int = 0
    target_transaction_id: Optional[str] = None
    has_j3: bool = False


@dataclass
class DecisionAggregate:
    decision_id: str
    safety: SafetyState
    business_effect: BusinessEffect
    dispatchable: bool
    attempt_count: int
    confirmed_effects: int
    unresolved_attempts: int
    conflicting_observations: int
    has_j10: bool
    authorization_state: str
    lease_epoch: int
    attempts: list[AttemptRecord] = field(default_factory=list)
    detail: str = ""


class DecisionReducer:
    """Deterministic six-priority aggregate reducer.
    P7-F01: Consumes only verified journal snapshots."""

    def __init__(self, journal: HABLJournal):
        self._journal = journal

    def reduce(self, decision_id: str) -> DecisionAggregate:
        # P7-F01: Use verified snapshot -- corrupt journal -> QUARANTINED
        result = self._journal.verified_snapshot_or_quarantine(decision_id)
        if result[0] is False:
            # Journal integrity failed -- return QUARANTINED, never dispatchable
            return DecisionAggregate(
                decision_id=decision_id, safety=SafetyState.QUARANTINED,
                business_effect=BusinessEffect.QUARANTINED, dispatchable=False,
                attempt_count=0, confirmed_effects=0, unresolved_attempts=0,
                conflicting_observations=0, has_j10=False,
                authorization_state="UNKNOWN", lease_epoch=0,
                detail=f"QUARANTINED: journal integrity failed -- {result[2]}")

        _, events, head_offset, head_hash = result

        if not events:
            return DecisionAggregate(
                decision_id=decision_id, safety=SafetyState.PENDING,
                business_effect=BusinessEffect.UNDETERMINED, dispatchable=False,
                attempt_count=0, confirmed_effects=0, unresolved_attempts=0,
                conflicting_observations=0, has_j10=False,
                authorization_state="UNKNOWN", lease_epoch=0,
                detail="No events found for this decision")

        attempts: dict[str, AttemptRecord] = {}
        has_j0 = False
        has_j10 = False
        conflict_count = 0
        max_epoch = 0
        auth_state = "UNKNOWN"
        confirmed_tx_ids: set[str] = set()

        for event in events:
            et = event.event_type
            p = event.payload

            if et == EventType.DECISION_COMMITTED:
                has_j0 = True
                if auth_state == "UNKNOWN":
                    auth_state = "VALID"
            elif et == EventType.LEASE_ACQUIRED:
                epoch = p.get("epoch", 0)
                if epoch > max_epoch:
                    max_epoch = epoch
            elif et == EventType.SEND_INTENT_COMMITTED:
                aid = p.get("attempt_id", "")
                epoch = p.get("epoch", 0)
                attempts[aid] = AttemptRecord(
                    attempt_id=aid, state=AttemptState.SEND_INTENT,
                    epoch=epoch)
            elif et == EventType.ATTEMPT_OBSERVED:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    attempts[aid].has_j3 = True
                    if attempts[aid].state == AttemptState.SEND_INTENT:
                        attempts[aid].state = AttemptState.ATTEMPTED
            elif et == EventType.TARGET_EFFECT_CONFIRMED:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    attempts[aid].state = AttemptState.CONFIRMED
                    tx_id = p.get("target_transaction_id", "")
                    if tx_id:
                        attempts[aid].target_transaction_id = tx_id
                        confirmed_tx_ids.add(tx_id)
            elif et == EventType.TARGET_NO_EFFECT:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    attempts[aid].state = AttemptState.NO_EFFECT
            elif et == EventType.OUTCOME_UNKNOWN:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    if attempts[aid].state not in (
                            AttemptState.CONFIRMED, AttemptState.NO_EFFECT):
                        attempts[aid].state = AttemptState.UNKNOWN
            elif et == EventType.EVIDENCE_CONFLICT:
                conflict_count += 1
            elif et == EventType.DISPATCH_CLOSED_NO_SEND:
                has_j10 = True
            elif et == EventType.AUTHORIZATION_REVOKED:
                auth_state = "REVOKED"
            elif et == EventType.AUTHORIZATION_EXPIRED:
                auth_state = "EXPIRED"

        attempt_list = list(attempts.values())
        attempt_count = len(attempt_list)
        unresolved = sum(
            1 for a in attempt_list
            if a.state in (AttemptState.SEND_INTENT,
                           AttemptState.ATTEMPTED,
                           AttemptState.UNKNOWN))
        confirmed_count = sum(
            1 for a in attempt_list if a.state == AttemptState.CONFIRMED)
        no_effect_count = sum(
            1 for a in attempt_list if a.state == AttemptState.NO_EFFECT)

        def _agg(safety, biz, disp, detail):
            return DecisionAggregate(
                decision_id=decision_id, safety=safety,
                business_effect=biz, dispatchable=disp,
                attempt_count=attempt_count,
                confirmed_effects=len(confirmed_tx_ids),
                unresolved_attempts=unresolved,
                conflicting_observations=conflict_count,
                has_j10=has_j10, authorization_state=auth_state,
                lease_epoch=max_epoch, attempts=attempt_list,
                detail=detail)

        # Priority 1: QUARANTINED
        if conflict_count > 0:
            return _agg(SafetyState.QUARANTINED,
                        BusinessEffect.QUARANTINED, False,
                        f"QUARANTINED: {conflict_count} J12 conflict(s)")
        if len(confirmed_tx_ids) > 1:
            return _agg(SafetyState.QUARANTINED,
                        BusinessEffect.QUARANTINED, False,
                        f"QUARANTINED: {len(confirmed_tx_ids)} distinct "
                        f"target transactions -- cardinality violation")

        # Priority 2: UNKNOWN
        if unresolved > 0:
            return _agg(SafetyState.UNKNOWN,
                        BusinessEffect.UNDETERMINED, False,
                        f"UNKNOWN: {unresolved} attempt(s) lack "
                        f"definitive resolution")

        # Priority 3: CONFIRMED
        if confirmed_count > 0 and unresolved == 0:
            return _agg(SafetyState.TERMINAL_CONFIRMED,
                        BusinessEffect.CONFIRMED, False,
                        f"CONFIRMED: {confirmed_count} attempt(s) "
                        f"confirmed effect")

        # Priority 4: ALL NO EFFECT (non-vacuous)
        if attempt_count > 0 and no_effect_count == attempt_count:
            return _agg(SafetyState.TERMINAL_NO_EFFECT,
                        BusinessEffect.NO_EFFECT, False,
                        f"NO_EFFECT: all {attempt_count} attempt(s) "
                        f"definitively no-effect")

        # Priority 5: NO SEND
        if has_j10 and attempt_count == 0:
            return _agg(SafetyState.TERMINAL_NO_SEND,
                        BusinessEffect.NO_SEND, False,
                        "NO_SEND: J10 terminal closure")

        # Priority 6: PENDING
        dispatchable = (has_j0 and auth_state == "VALID"
                        and attempt_count == 0)
        return _agg(SafetyState.PENDING,
                     BusinessEffect.UNDETERMINED, dispatchable,
                     "PENDING: eligible for dispatch"
                     if dispatchable else "PENDING: not yet dispatchable")
# Bismillah ir-Rahman ir-Rahim
