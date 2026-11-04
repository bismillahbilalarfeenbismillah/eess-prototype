# Bismillah ir-Rahman ir-Rahim
"""
EESS HABL Event Store v0.3.13 -- PREDECESSOR-LINKED HASH CHAIN.

Every event type goes through a typed API with full validation.
No public append method exists. No caller can create any HABL event
without the journal validating all invariants.

v0.3.13 (P11 findings):
- P11-F01: J12 record_evidence_conflict() now uses _validate_sha256_hex()
  instead of int(value, 16). Completes the P10-F03 correction across
  all hash-valued fields.
- P11-F02: Events now carry prev_hash linking each event to its
  predecessor's integrity_hash. compute_hash() includes prev_hash in
  the hash input. verify_head() checks chain linkage. Rewriting any
  earlier event invalidates all subsequent hashes.
  Note: chain is not externally anchored. Full-chain rewrite by a party
  with in-memory access remains possible. External anchoring is a
  production obligation.

Prior fixes carried forward:
- P10-F03, P9-F02, P8-F01/F02, P7-F01..F07 and all P4/P5/P6 fixes.

Architecture: v0.2.6a Section 8.4
NON-AUTHORIZING PROTOTYPE.
"""

import copy
import hashlib
import json
import math
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


class EventType(Enum):
    DECISION_COMMITTED = "J0"
    LEASE_ACQUIRED = "J1"
    SEND_INTENT_COMMITTED = "J2"
    ATTEMPT_OBSERVED = "J3"
    TARGET_EFFECT_CONFIRMED = "J4a"
    TARGET_NO_EFFECT = "J4b"
    OUTCOME_UNKNOWN = "J4c"
    HUMAN_REVIEW_REQUESTED = "J5"
    LEASE_RELEASED = "J6"
    LEASE_EXPIRED = "J7"
    AUTHORIZATION_REVOKED = "J8"
    AUTHORIZATION_EXPIRED = "J9"
    DISPATCH_CLOSED_NO_SEND = "J10"
    RECONCILIATION_EVIDENCE = "J11"
    EVIDENCE_CONFLICT = "J12"


# P4-F05: Canonical capability values -- the ONLY accepted values.
VALID_CAPABILITIES = frozenset({
    "TARGET_FENCING_ENFORCED",
    "TARGET_DEDUP_ENFORCED",
    "TARGET_FENCING_AND_DEDUP_ENFORCED",
})

# P5-F05: Canonical J10 close reasons
VALID_CLOSE_REASONS = frozenset({
    "BUDGET_EXHAUSTED",
    "POLICY_DENIED",
    "CANCELLED",
    "APPROVAL_WITHDRAWN",
    "TARGET_UNAVAILABLE",
    "DUPLICATE_DETECTED",
})


@dataclass
class HABLEvent:
    event_id: str
    event_type: EventType
    decision_id: str
    timestamp: str
    append_offset: int
    payload: dict = field(default_factory=dict)
    integrity_hash: str = ""
    prev_hash: str = ""  # P11-F02: predecessor-linked hash chain

    def compute_hash(self):
        """Compute SHA-256 over event fields INCLUDING prev_hash.
        P11-F02: This creates a cryptographic hash chain where each event
        commits to all preceding events. Rewriting any earlier event
        invalidates all subsequent hashes.
        Note: This is still not externally anchored. A party with full
        in-memory access can rewrite the entire chain. External anchoring
        (signature/MAC or remote witness) is a production obligation."""
        hashable = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "append_offset": self.append_offset,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
        }
        # P5-F06: Reject NaN/Infinity -- not valid JSON per RFC 8259
        canonical = json.dumps(hashable, sort_keys=True, separators=(',', ':'),
                               allow_nan=False)
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class HABLJournal:
    """
    v0.3.13: STRICT SHA-256 GRAMMAR + VERIFIED STATUS READERS.
    NO public append(). Every event type has its own typed, validated API.
    ALL state-mutating operations verify journal integrity under the lock.
    ALL inputs are deep-copied on ingestion; ALL returns are deep copies.
    ALL reader methods acquire the lock for atomic snapshots.
    P8-F01: Status-reader APIs verify integrity before returning
    authoritative state. get_events() is an unverified general reader.
    Reducer MUST consume events via verified_snapshot() or
    verified_snapshot_or_quarantine(), never via unverified get_events().
    """

    def __init__(self):
        self._events: list[HABLEvent] = []
        self._event_index: dict[str, HABLEvent] = {}
        self._lock = threading.Lock()
        self._epoch_floor: dict[tuple[str, str], int] = {}
        self._next_offset = 0
        self._active_leases: dict[tuple[str, str], tuple[str, int]] = {}
        self._effect_reservations: dict[str, str] = {}
        # P4-F07: Global attempt_id uniqueness tracking
        self._global_attempt_ids: set[str] = set()

    @property
    def head_offset(self) -> int:
        return self._next_offset

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # -------------------------------------------------------------------
    # PRIVATE: Validate-then-commit helpers -- caller MUST hold self._lock
    # -------------------------------------------------------------------

    def _build_event(self, event_type, decision_id, payload, event_id=None,
                     offset_delta=0):
        """Build a HABLEvent and compute its hash WITHOUT appending.
        P6-F01: Deep-copies input payload so callers cannot corrupt journal.
        P5-F06: Uses allow_nan=False via compute_hash() to reject NaN/Infinity.
        """
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise ValueError(f"Payload must be a dict, got {type(payload).__name__}")

        # P5-F06: Pre-check for non-finite numbers in payload before building
        self._reject_non_finite(payload, "payload")

        # P6-F01: Deep-copy payload to sever caller alias
        payload = copy.deepcopy(payload)

        if event_id is None:
            event_id = f"{decision_id}-{event_type.value}-{self._next_offset + offset_delta}"
        if event_id in self._event_index:
            raise ValueError(f"Duplicate event_id '{event_id}'")
        # P11-F02: Set prev_hash from the last committed event (or "" for genesis)
        # For atomic multi-event appends (J1+J2), offset_delta > 0 means
        # this event follows a not-yet-committed sibling. The caller must
        # set prev_hash explicitly after building the predecessor.
        prev_hash = ""
        effective_offset = self._next_offset + offset_delta
        if effective_offset > 0 and len(self._events) > 0 and offset_delta == 0:
            prev_hash = self._events[-1].integrity_hash

        event = HABLEvent(
            event_id=event_id, event_type=event_type,
            decision_id=decision_id, timestamp=self._now(),
            append_offset=effective_offset,
            payload=payload,
            prev_hash=prev_hash)
        try:
            event.integrity_hash = event.compute_hash()
        except TypeError as e:
            raise ValueError(f"Payload serialization failed: {e}")
        return event

    @staticmethod
    def _reject_non_finite(obj, path=""):
        """Recursively reject NaN and Infinity in nested structures.
        P5-F06: Catches non-finite numbers before json.dumps."""
        if isinstance(obj, float):
            if math.isnan(obj) or math.isinf(obj):
                raise ValueError(f"Non-finite number at {path}: {obj}")
        elif isinstance(obj, dict):
            for k, v in obj.items():
                HABLJournal._reject_non_finite(v, f"{path}.{k}")
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                HABLJournal._reject_non_finite(v, f"{path}[{i}]")

    def _commit_event(self, event):
        """Append a pre-built, pre-validated event. MUST hold self._lock."""
        self._events.append(event)
        self._event_index[event.event_id] = event
        self._next_offset += 1

    def _append_internal(self, event_type, decision_id, payload, event_id=None):
        """Single-event append: build + commit in one step.
        Caller MUST hold self._lock.
        P6-F01: Returns a deep copy of the committed event.
        """
        event = self._build_event(event_type, decision_id, payload, event_id)
        self._commit_event(event)
        return copy.deepcopy(event)

    # -------------------------------------------------------------------
    # P7-F06 / P7-F07: Integrity verification under lock
    # -------------------------------------------------------------------

    def _verify_integrity_under_lock(self):
        """Verify journal head integrity. MUST hold self._lock.
        P7-F07: Also checks len(_events) == _next_offset for tail deletion.
        P7-F06: Catches TypeError/ValueError from corrupt payloads.
        """
        # P7-F07: Tail deletion detection
        if len(self._events) != self._next_offset:
            return False
        # P7-F07: Event index consistency
        if len(self._event_index) != len(self._events):
            return False
        if not self._events:
            return True
        for i, event in enumerate(self._events):
            if event.append_offset != i:
                return False
            # P11-F02: Verify predecessor-linked hash chain
            expected_prev = "" if i == 0 else self._events[i - 1].integrity_hash
            if event.prev_hash != expected_prev:
                return False
            # P7-F06: Catch serialization errors from corrupt payloads
            try:
                recomputed = event.compute_hash()
            except (TypeError, ValueError):
                return False
            if recomputed != event.integrity_hash:
                return False
        return True

    def _require_integrity(self):
        """Require verified head before ANY append.
        MUST hold self._lock.
        P7-F07: Also checks structural consistency."""
        # P7-F07: Quick structural check before full hash verification
        if len(self._events) != self._next_offset:
            raise ValueError(
                "Journal structural integrity failed -- "
                f"event count {len(self._events)} != offset {self._next_offset}. "
                "Events may have been deleted.")
        if not self._verify_integrity_under_lock():
            raise ValueError(
                "Journal integrity check failed -- refusing operation. "
                "Events may have been tampered with.")

    # -------------------------------------------------------------------
    # P7-F01: Verified snapshot API for reducer
    # -------------------------------------------------------------------

    def verified_snapshot(self, decision_id=None):
        """P7-F01: Atomic verified event read for the reducer.
        Under self._lock: verifies integrity, then returns deep-copied events.
        Raises ValueError if journal is corrupt.
        Returns: (events_copy, head_offset, head_hash)
        """
        # P6-F07: Validate decision_id filter
        self._validate_decision_id_filter(decision_id)

        with self._lock:
            # P7-F01: Verify integrity first -- raises on corrupt
            self._require_integrity()

            # Compute head info
            if not self._events:
                head_offset = 0
                head_hash = ""
            else:
                last = self._events[-1]
                head_offset = last.append_offset + 1
                head_hash = last.integrity_hash

            # Deep-copy filtered events
            results = []
            for event in self._events:
                if decision_id is not None and event.decision_id != decision_id:
                    continue
                results.append(copy.deepcopy(event))

            return results, head_offset, head_hash

    def verified_snapshot_or_quarantine(self, decision_id=None):
        """P7-F01: Non-raising verified snapshot for reducer use.
        Returns (True, events_copy, head_offset, head_hash) on success,
        or (False, "CORRUPT", error_message, None) on integrity failure.
        The reducer should return QUARANTINED on False.
        """
        try:
            events, head_offset, head_hash = self.verified_snapshot(decision_id)
            return True, events, head_offset, head_hash
        except ValueError as e:
            return False, "CORRUPT", str(e), None

    # -------------------------------------------------------------------
    # PRIVATE helpers -- caller MUST hold self._lock
    # -------------------------------------------------------------------

    def _decision_events(self, decision_id):
        return [e for e in self._events if e.decision_id == decision_id]

    def _has_type(self, devts, et):
        return any(e.event_type == et for e in devts)

    def _get_j0(self, decision_id, devts=None):
        if devts is None:
            devts = self._decision_events(decision_id)
        for e in devts:
            if e.event_type == EventType.DECISION_COMMITTED:
                return e
        return None

    def _require_j0(self, decision_id, devts=None):
        j0 = self._get_j0(decision_id, devts)
        if not j0:
            raise ValueError(f"No J0 for decision '{decision_id}'")
        return j0

    def _find_j2(self, decision_id, attempt_id, devts=None):
        if devts is None:
            devts = self._decision_events(decision_id)
        for e in devts:
            if (e.event_type == EventType.SEND_INTENT_COMMITTED and
                e.payload.get("attempt_id") == attempt_id):
                return e
        return None

    def _require_j2(self, decision_id, attempt_id, devts=None):
        if not attempt_id:
            raise ValueError("attempt_id is required")
        j2 = self._find_j2(decision_id, attempt_id, devts)
        if not j2:
            raise ValueError(f"No J2 for attempt '{attempt_id}' in decision '{decision_id}'")
        return j2

    def _has_prior_definitive(self, decision_id, attempt_id, devts=None):
        if devts is None:
            devts = self._decision_events(decision_id)
        return any(
            e.event_type in (EventType.TARGET_EFFECT_CONFIRMED, EventType.TARGET_NO_EFFECT)
            and e.payload.get("attempt_id") == attempt_id
            for e in devts)

    def _require_no_prior_definitive(self, decision_id, attempt_id, devts=None):
        if self._has_prior_definitive(decision_id, attempt_id, devts):
            raise ValueError(f"Prior definitive outcome for attempt '{attempt_id}' -- use J12")

    # P7-F02: Temporal reconciliation sequence enforcement
    def _has_j4c_without_j11(self, decision_id, attempt_id, devts=None):
        """Return True if there is a J4c OUTCOME_UNKNOWN for this attempt
        but no J11 RECONCILIATION_EVIDENCE that FOLLOWS the latest J4c.
        P7-F02: Checks temporal ordering -- J11.append_offset must be >
        latest J4c.append_offset. A stale J11 predating a newer J4c
        cannot satisfy the reconciliation guard.
        P8-C02: J11 before J4c is permitted as an early observation record.
        The temporal guard only applies to definitives after J4c."""
        if devts is None:
            devts = self._decision_events(decision_id)

        # Find the LATEST J4c for this attempt
        latest_j4c_offset = -1
        for e in devts:
            if (e.event_type == EventType.OUTCOME_UNKNOWN
                    and e.payload.get("attempt_id") == attempt_id):
                if e.append_offset > latest_j4c_offset:
                    latest_j4c_offset = e.append_offset

        if latest_j4c_offset < 0:
            return False  # No J4c exists -- no reconciliation needed

        # Check if any J11 for this attempt follows the latest J4c
        has_subsequent_j11 = any(
            e.event_type == EventType.RECONCILIATION_EVIDENCE
            and e.payload.get("attempt_id") == attempt_id
            and e.append_offset > latest_j4c_offset
            for e in devts)

        return not has_subsequent_j11

    # P4-F08: SHA-256 hash format validation
    @staticmethod
    def _validate_sha256_hex(value, field_name):
        """Validate a value as a 64-character hexadecimal SHA-256 string.
        P10-F03: Uses re.fullmatch instead of int(value, 16) to reject
        non-hex syntax (0x prefix, spaces, signs, underscores)."""
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string, got {type(value).__name__}")
        if not re.fullmatch(r'[0-9a-fA-F]{64}', value):
            raise ValueError(
                f"{field_name} must be exactly 64 hexadecimal characters, "
                f"got {repr(value[:20])}{'...' if len(value) > 20 else ''}")

    # P4-F05: Capability validation
    @staticmethod
    def _validate_capability(capability):
        """Validate target capability is a canonical enum value."""
        if not capability or not isinstance(capability, str):
            raise ValueError(f"target_capability must be a non-empty string, got {type(capability).__name__ if not isinstance(capability, str) else repr(capability)}")
        if capability == "UNSUPPORTED":
            raise ValueError("Cannot dispatch with UNSUPPORTED target capability")
        if capability not in VALID_CAPABILITIES:
            raise ValueError(f"Unknown target_capability '{capability}'; must be one of {sorted(VALID_CAPABILITIES)}")

    # P5-F05: Strict string identifier validation
    @staticmethod
    def _validate_string_id(value, field_name):
        """Validate a value is a non-empty, non-bool, non-whitespace-only string."""
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must be a string, got bool")
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string, got {type(value).__name__}")
        if not value.strip():
            raise ValueError(f"{field_name} must be non-empty and non-whitespace")

    # P6-F07: Decision ID validation for query methods
    @staticmethod
    def _validate_decision_id_filter(value):
        """Validate decision_id for query use. None means 'no filter'.
        Any other value must be a valid non-empty string.
        P6-F07: Prevents truthiness-based unscoped queries."""
        if value is None:
            return  # None means no filter -- valid
        if isinstance(value, bool):
            raise ValueError(f"decision_id filter must be a string or None, got bool")
        if not isinstance(value, str):
            raise ValueError(f"decision_id filter must be a string or None, got {type(value).__name__}")

    # -------------------------------------------------------------------
    # J0: DECISION_COMMITTED -- atomic with effect reservation
    # -------------------------------------------------------------------

    def reserve_effect_and_commit_decision(self, decision_id, business_effect_id, payload):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            if not isinstance(payload, dict):
                raise ValueError("J0 payload must be a dict")
            for fld in ("claim_id", "action", "target", "policy_version", "approval_ref"):
                val = payload.get(fld)
                if not val or not isinstance(val, str) or not val.strip():
                    raise ValueError(f"J0 requires non-empty string '{fld}'")
            if not business_effect_id or not isinstance(business_effect_id, str) or not business_effect_id.strip():
                raise ValueError("J0 requires non-empty string business_effect_id")
            if payload.get("business_effect_id") != business_effect_id:
                raise ValueError("Payload business_effect_id must match reserved effect_id")

            if business_effect_id in self._effect_reservations:
                existing = self._effect_reservations[business_effect_id]
                if existing != decision_id:
                    raise ValueError(f"Effect '{business_effect_id}' already reserved by '{existing}'")

            devts = self._decision_events(decision_id)
            if self._has_type(devts, EventType.DECISION_COMMITTED):
                raise ValueError(f"Duplicate J0 for decision '{decision_id}'")

            j0_event = self._build_event(
                EventType.DECISION_COMMITTED, decision_id, payload)

            self._commit_event(j0_event)
            self._effect_reservations[business_effect_id] = decision_id
            return copy.deepcopy(j0_event)

    # -------------------------------------------------------------------
    # J1+J2: ATOMIC DISPATCH CLAIM
    # -------------------------------------------------------------------

    def atomic_dispatch_claim(self, decision_id, target, worker_id,
                               attempt_id, request_hash, idempotency_key,
                               target_capability, business_effect_id):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            devts = self._decision_events(decision_id)

            j0 = self._require_j0(decision_id, devts)
            j0_target = j0.payload.get("target", "")
            if j0_target and target != j0_target:
                raise ValueError(f"Target '{target}' does not match J0 target '{j0_target}'")
            j0_effect = j0.payload.get("business_effect_id", "")
            if j0_effect and business_effect_id != j0_effect:
                raise ValueError(f"Effect '{business_effect_id}' does not match J0 '{j0_effect}'")

            if self._has_type(devts, EventType.AUTHORIZATION_REVOKED):
                raise ValueError(f"Authorization revoked for '{decision_id}'")
            if self._has_type(devts, EventType.AUTHORIZATION_EXPIRED):
                raise ValueError(f"Authorization expired for '{decision_id}'")
            if self._has_type(devts, EventType.DISPATCH_CLOSED_NO_SEND):
                raise ValueError(f"Decision '{decision_id}' terminally closed")
            if self._has_type(devts, EventType.EVIDENCE_CONFLICT):
                raise ValueError(f"Decision '{decision_id}' quarantined")

            for j2_ev in (e for e in devts if e.event_type == EventType.SEND_INTENT_COMMITTED):
                j2_att = j2_ev.payload.get("attempt_id", "")
                if any(e.event_type == EventType.TARGET_EFFECT_CONFIRMED
                       and e.payload.get("attempt_id") == j2_att for e in devts):
                    raise ValueError(f"Decision '{decision_id}' already confirmed -- terminal")
                if not any(e.event_type in (EventType.TARGET_EFFECT_CONFIRMED, EventType.TARGET_NO_EFFECT)
                           and e.payload.get("attempt_id") == j2_att for e in devts):
                    raise ValueError(f"Unresolved J2 for attempt '{j2_att}'")

            if business_effect_id:
                if self._effect_reservations.get(business_effect_id) != decision_id:
                    raise ValueError(f"Effect '{business_effect_id}' not reserved by '{decision_id}'")

            self._validate_string_id(attempt_id, "attempt_id")
            self._validate_string_id(request_hash, "request_hash")
            self._validate_string_id(idempotency_key, "idempotency_key")
            self._validate_string_id(worker_id, "worker_id")
            self._validate_string_id(business_effect_id, "business_effect_id")

            self._validate_capability(target_capability)
            self._validate_sha256_hex(request_hash, "request_hash")

            if any(e.event_type == EventType.SEND_INTENT_COMMITTED
                   and e.payload.get("attempt_id") == attempt_id for e in devts):
                raise ValueError(f"Duplicate attempt_id '{attempt_id}' in decision '{decision_id}'")

            if attempt_id in self._global_attempt_ids:
                raise ValueError(f"attempt_id '{attempt_id}' already used in another decision")

            key = (decision_id, target)
            if key in self._active_leases:
                active_worker, active_epoch = self._active_leases[key]
                has_release = any(
                    e.decision_id == decision_id
                    and e.event_type in (EventType.LEASE_RELEASED, EventType.LEASE_EXPIRED)
                    and e.payload.get("epoch") == active_epoch
                    for e in self._events)
                if not has_release:
                    raise ValueError(f"Active lease held by '{active_worker}' at epoch {active_epoch}")

            current_floor = self._epoch_floor.get(key, 0)
            new_epoch = current_floor + 1

            j1_payload = {
                "worker_id": worker_id, "epoch": new_epoch, "target": target,
                "prior_epoch": current_floor}
            j2_payload = {
                "attempt_id": attempt_id, "epoch": new_epoch,
                "request_hash": request_hash, "idempotency_key": idempotency_key,
                "target_capability": target_capability, "target": target,
                "business_effect_id": business_effect_id}

            j1_event_id = f"{decision_id}-J1-epoch{new_epoch}"
            j2_event_id = f"{decision_id}-J2-{attempt_id}"

            j1_event = self._build_event(
                EventType.LEASE_ACQUIRED, decision_id, j1_payload,
                event_id=j1_event_id, offset_delta=0)
            j2_event = self._build_event(
                EventType.SEND_INTENT_COMMITTED, decision_id, j2_payload,
                event_id=j2_event_id, offset_delta=1)
            # P11-F02: Link J2 to J1 in the hash chain
            j2_event.prev_hash = j1_event.integrity_hash
            j2_event.integrity_hash = j2_event.compute_hash()

            self._epoch_floor[key] = new_epoch
            self._active_leases[key] = (worker_id, new_epoch)
            self._global_attempt_ids.add(attempt_id)

            self._commit_event(j1_event)
            self._commit_event(j2_event)

            return copy.deepcopy(j1_event), copy.deepcopy(j2_event)

    # -------------------------------------------------------------------
    # J3: ATTEMPT_OBSERVED
    # -------------------------------------------------------------------

    def record_attempt_observed(self, decision_id, attempt_id, transport_metadata=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            self._require_j0(decision_id)
            self._require_j2(decision_id, attempt_id)
            return self._append_internal(EventType.ATTEMPT_OBSERVED, decision_id,
                {"attempt_id": attempt_id, "transport_metadata": transport_metadata})

    # -------------------------------------------------------------------
    # J4a: TARGET_EFFECT_CONFIRMED
    # P7-F02: Temporal reconciliation sequence
    # -------------------------------------------------------------------

    def record_effect_confirmed(self, decision_id, attempt_id, target_transaction_id,
                                 request_hash, evidence_hash="", business_effect_id=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            devts = self._decision_events(decision_id)
            self._require_j0(decision_id, devts)
            j2 = self._require_j2(decision_id, attempt_id, devts)

            if not isinstance(target_transaction_id, str) or not target_transaction_id.strip():
                raise ValueError("J4a requires non-empty string target_transaction_id")
            if not isinstance(request_hash, str) or not request_hash:
                raise ValueError("J4a requires request_hash")

            self._validate_sha256_hex(request_hash, "J4a request_hash")

            j2_hash = j2.payload.get("request_hash", "")
            if j2_hash and request_hash != j2_hash:
                raise ValueError(f"J4a request_hash does not match J2")

            j2_effect = j2.payload.get("business_effect_id", "")
            if business_effect_id and j2_effect and business_effect_id != j2_effect:
                raise ValueError(f"J4a business_effect_id does not match J2")

            if not isinstance(evidence_hash, str):
                raise ValueError("J4a evidence_hash must be a string")
            self._validate_sha256_hex(evidence_hash, "J4a evidence_hash")

            self._require_no_prior_definitive(decision_id, attempt_id, devts)

            # P7-F02: Temporal reconciliation sequence enforcement
            if self._has_j4c_without_j11(decision_id, attempt_id, devts):
                raise ValueError(
                    "J4c exists without J11 reconciliation -- "
                    "direct definitive resolution after UNKNOWN requires J11 evidence")

            return self._append_internal(EventType.TARGET_EFFECT_CONFIRMED, decision_id,
                {"attempt_id": attempt_id, "target_transaction_id": target_transaction_id,
                 "request_hash": request_hash, "evidence_hash": evidence_hash,
                 "business_effect_id": business_effect_id or j2_effect})

    # -------------------------------------------------------------------
    # J4b: TARGET_NO_EFFECT
    # P7-F02: Temporal reconciliation sequence
    # -------------------------------------------------------------------

    def record_no_effect(self, decision_id, attempt_id, target_transaction_id,
                          request_hash, no_effect_evidence="", business_effect_id=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            devts = self._decision_events(decision_id)
            self._require_j0(decision_id, devts)
            j2 = self._require_j2(decision_id, attempt_id, devts)

            if not isinstance(request_hash, str) or not request_hash:
                raise ValueError("J4b requires request_hash")

            self._validate_sha256_hex(request_hash, "J4b request_hash")

            if not isinstance(target_transaction_id, str):
                raise ValueError(f"J4b target_transaction_id must be a string, got {type(target_transaction_id).__name__}")

            if not isinstance(no_effect_evidence, str):
                raise ValueError(f"J4b no_effect_evidence must be a string, got {type(no_effect_evidence).__name__}")
            if not no_effect_evidence.strip():
                raise ValueError("J4b requires non-empty no_effect_evidence")

            j2_hash = j2.payload.get("request_hash", "")
            if j2_hash and request_hash != j2_hash:
                raise ValueError("J4b request_hash does not match J2")

            j2_effect = j2.payload.get("business_effect_id", "")
            if business_effect_id and j2_effect and business_effect_id != j2_effect:
                raise ValueError("J4b business_effect_id does not match J2")

            self._require_no_prior_definitive(decision_id, attempt_id, devts)

            # P7-F02: Temporal reconciliation sequence enforcement
            if self._has_j4c_without_j11(decision_id, attempt_id, devts):
                raise ValueError(
                    "J4c exists without J11 reconciliation -- "
                    "direct definitive resolution after UNKNOWN requires J11 evidence")

            return self._append_internal(EventType.TARGET_NO_EFFECT, decision_id,
                {"attempt_id": attempt_id, "target_transaction_id": target_transaction_id or "",
                 "request_hash": request_hash, "no_effect_evidence": no_effect_evidence,
                 "business_effect_id": business_effect_id or j2_effect})

    # -------------------------------------------------------------------
    # J4c: OUTCOME_UNKNOWN
    # P7-F03: Block J4c after definitive J4a/J4b
    # -------------------------------------------------------------------

    def record_outcome_unknown(self, decision_id, attempt_id, reason=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            devts = self._decision_events(decision_id)
            self._require_j0(decision_id, devts)
            self._require_j2(decision_id, attempt_id, devts)

            # P7-F03: Block J4c after definitive J4a/J4b
            if self._has_prior_definitive(decision_id, attempt_id, devts):
                raise ValueError(
                    f"J4c illegal after definitive J4a/J4b for attempt '{attempt_id}'")

            return self._append_internal(EventType.OUTCOME_UNKNOWN, decision_id,
                {"attempt_id": attempt_id, "reason": reason})

    # -------------------------------------------------------------------
    # J5: HUMAN_REVIEW_REQUESTED
    # -------------------------------------------------------------------

    def record_human_review(self, decision_id, attempt_id="", reason="", escalation_ref=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            self._require_j0(decision_id)
            if attempt_id:
                self._require_j2(decision_id, attempt_id)
            return self._append_internal(EventType.HUMAN_REVIEW_REQUESTED, decision_id,
                {"attempt_id": attempt_id, "reason": reason, "escalation_ref": escalation_ref})

    # -------------------------------------------------------------------
    # J6: LEASE_RELEASED -- only current owner can release
    # -------------------------------------------------------------------

    def release_lease(self, decision_id, target, worker_id, epoch):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            self._require_j0(decision_id)
            key = (decision_id, target)
            if key not in self._active_leases:
                raise ValueError(f"No active lease for ({decision_id}, {target})")
            active_worker, active_epoch = self._active_leases[key]
            if active_worker != worker_id:
                raise ValueError(f"Worker '{worker_id}' is not the lease owner (owner: '{active_worker}')")
            if active_epoch != epoch:
                raise ValueError(f"Epoch {epoch} does not match active epoch {active_epoch}")

            event = self._build_event(EventType.LEASE_RELEASED, decision_id,
                {"epoch": epoch, "worker_id": worker_id, "target": target})

            del self._active_leases[key]
            self._commit_event(event)
            return copy.deepcopy(event)

    # -------------------------------------------------------------------
    # J7: LEASE_EXPIRED -- validated epoch
    # -------------------------------------------------------------------

    def expire_lease(self, decision_id, target, epoch, expiry_reason="timeout"):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            self._require_j0(decision_id)
            key = (decision_id, target)
            if key in self._active_leases:
                _, active_epoch = self._active_leases[key]
                if active_epoch != epoch:
                    raise ValueError(f"Cannot expire epoch {epoch} -- active is {active_epoch}")
            else:
                raise ValueError(f"No active lease to expire for ({decision_id}, {target})")

            event = self._build_event(EventType.LEASE_EXPIRED, decision_id,
                {"epoch": epoch, "expiry_reason": expiry_reason, "target": target})

            del self._active_leases[key]
            self._commit_event(event)
            return copy.deepcopy(event)

    # -------------------------------------------------------------------
    # J8: AUTHORIZATION_REVOKED
    # -------------------------------------------------------------------

    def record_authorization_revoked(self, decision_id, revocation_ref=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            self._require_j0(decision_id)
            return self._append_internal(EventType.AUTHORIZATION_REVOKED, decision_id,
                {"revocation_ref": revocation_ref})

    # -------------------------------------------------------------------
    # J9: AUTHORIZATION_EXPIRED
    # -------------------------------------------------------------------

    def record_authorization_expired(self, decision_id, approval_ref=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            self._require_j0(decision_id)
            return self._append_internal(EventType.AUTHORIZATION_EXPIRED, decision_id,
                {"approval_ref": approval_ref})

    # -------------------------------------------------------------------
    # J10: DISPATCH_CLOSED_NO_SEND -- atomic with effect release
    # -------------------------------------------------------------------

    def close_no_send_atomic(self, decision_id, reason, worker_id):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            devts = self._decision_events(decision_id)
            if not self._has_type(devts, EventType.DECISION_COMMITTED):
                raise ValueError(f"J10 requires J0 for decision '{decision_id}'")
            if self._has_type(devts, EventType.SEND_INTENT_COMMITTED):
                raise ValueError(f"J10 illegal: J2 exists for '{decision_id}'")
            if self._has_type(devts, EventType.DISPATCH_CLOSED_NO_SEND):
                raise ValueError(f"Duplicate J10 for '{decision_id}'")

            self._validate_string_id(reason, "J10 reason")
            if reason not in VALID_CLOSE_REASONS:
                raise ValueError(
                    f"J10 invalid close reason '{reason}'; "
                    f"must be one of {sorted(VALID_CLOSE_REASONS)}")

            self._validate_string_id(worker_id, "J10 worker_id")

            event = self._build_event(EventType.DISPATCH_CLOSED_NO_SEND, decision_id,
                {"reason": reason, "worker_id": worker_id})

            self._commit_event(event)

            for e in devts:
                if e.event_type == EventType.DECISION_COMMITTED:
                    eid = e.payload.get("business_effect_id")
                    if eid and self._effect_reservations.get(eid) == decision_id:
                        del self._effect_reservations[eid]
            return copy.deepcopy(event)

    # -------------------------------------------------------------------
    # J11: RECONCILIATION_EVIDENCE -- full J2 binding validation
    # P8-F02: target_transaction_id type validation
    # P8-C02: J11 before J4c is permitted as early observation
    # -------------------------------------------------------------------

    def record_reconciliation_evidence(self, decision_id, attempt_id,
                                        request_hash, idempotency_key,
                                        query_result, target_transaction_id="",
                                        business_effect_id=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            self._require_j0(decision_id)
            j2 = self._require_j2(decision_id, attempt_id)

            if not isinstance(query_result, str):
                raise ValueError(
                    f"J11 query_result must be a string, got {type(query_result).__name__}")
            if not query_result.strip():
                raise ValueError("J11 requires non-empty query_result")

            # P9-F02: Validate target_transaction_id as strict string type.
            # None is NOT a supported absence marker -- caller must pass ""
            # explicitly for unknown tx_id. Whitespace-only is also rejected.
            if isinstance(target_transaction_id, bool):
                raise ValueError(
                    "J11 target_transaction_id must be a string, got bool")
            if not isinstance(target_transaction_id, str):
                raise ValueError(
                    f"J11 target_transaction_id must be a string, "
                    f"got {type(target_transaction_id).__name__}")
            # P9-C (P9-21): Reject whitespace-only -- use "" for unknown
            if target_transaction_id.strip() == "" and target_transaction_id != "":
                raise ValueError(
                    "J11 target_transaction_id must not be whitespace-only; "
                    "use empty string for unknown")

            j2_hash = j2.payload.get("request_hash", "")
            if j2_hash and request_hash and request_hash != j2_hash:
                raise ValueError("J11 request_hash does not match J2")
            j2_key = j2.payload.get("idempotency_key", "")
            if j2_key and idempotency_key and idempotency_key != j2_key:
                raise ValueError("J11 idempotency_key does not match J2")
            j2_effect = j2.payload.get("business_effect_id", "")
            if business_effect_id and j2_effect and business_effect_id != j2_effect:
                raise ValueError("J11 business_effect_id does not match J2")

            # P8-C02: J11 before J4c is permitted as an early observation
            # record. The temporal guard (P7-F02) only applies when
            # definitives (J4a/J4b) are attempted after J4c.

            return self._append_internal(EventType.RECONCILIATION_EVIDENCE, decision_id,
                {"attempt_id": attempt_id, "request_hash": request_hash or j2_hash,
                 "idempotency_key": idempotency_key or j2_key,
                 "query_result": query_result,
                 "target_transaction_id": target_transaction_id,
                 "business_effect_id": business_effect_id or j2_effect})

    # -------------------------------------------------------------------
    # J12: EVIDENCE_CONFLICT
    # -------------------------------------------------------------------

    def record_evidence_conflict(self, decision_id, attempt_id,
                                  competing_evidence_ref, competing_evidence_hash,
                                  business_effect_id=""):
        with self._lock:
            self._require_integrity()
            self._validate_string_id(decision_id, "decision_id")

            devts = self._decision_events(decision_id)
            self._require_j0(decision_id, devts)
            j2 = self._require_j2(decision_id, attempt_id, devts)

            if not self._has_prior_definitive(decision_id, attempt_id, devts):
                raise ValueError(f"J12 requires prior definitive for attempt '{attempt_id}'")

            if not competing_evidence_ref or not isinstance(competing_evidence_ref, str) or not competing_evidence_ref.strip():
                raise ValueError("J12 requires non-empty competing_evidence_ref")
            # P11-F01: Use canonical SHA-256 grammar validator (not int(..., 16))
            self._validate_sha256_hex(competing_evidence_hash, "J12 competing_evidence_hash")

            j2_effect = j2.payload.get("business_effect_id", "")
            if business_effect_id and j2_effect and business_effect_id != j2_effect:
                raise ValueError(f"J12 business_effect_id '{business_effect_id}' does not match J2 '{j2_effect}'")

            for existing in devts:
                if (existing.event_type == EventType.EVIDENCE_CONFLICT
                    and existing.payload.get("attempt_id") == attempt_id
                    and existing.payload.get("competing_evidence_ref") == competing_evidence_ref
                    and existing.payload.get("competing_evidence_hash") == competing_evidence_hash):
                    raise ValueError(
                        f"Duplicate J12 conflict observation for attempt '{attempt_id}' "
                        f"with same evidence ref and hash")

            return self._append_internal(EventType.EVIDENCE_CONFLICT, decision_id,
                {"attempt_id": attempt_id,
                 "competing_evidence_ref": competing_evidence_ref,
                 "competing_evidence_hash": competing_evidence_hash,
                 "quarantine_disposition": "QUARANTINED",
                 "business_effect_id": business_effect_id or j2_effect,
                 "evidence_verified": False,
                 "verification_note": "PROTOTYPE: evidence reference not content-verified"})

    # -------------------------------------------------------------------
    # Query methods
    # P8-F01: Status-reader APIs verify integrity; fail-closed on corrupt.
    # P8-C01: get_events() is an unverified general reader. For
    #   authoritative status, use verified_snapshot() or the reducer.
    # P6-F06: All readers acquire self._lock for atomic snapshots.
    # P6-F07: decision_id filter uses `is not None` not truthiness.
    # P5-F01: get_events returns DEEP COPIES.
    # -------------------------------------------------------------------

    def is_effect_reserved(self, business_effect_id):
        return self._effect_reservations.get(business_effect_id)

    def get_epoch_floor(self, decision_id, target):
        return self._epoch_floor.get((decision_id, target), 0)

    def get_events(self, decision_id=None, event_type=None, from_offset=0):
        """Returns deep copies under lock for atomic snapshots.
        P8-C01: This is an UNVERIFIED general reader. It does NOT check
        journal integrity. For authoritative status decisions, use
        verified_snapshot(), verified_snapshot_or_quarantine(), or the
        reducer. This method is suitable for debugging, logging, and
        non-authoritative inspection only.
        P6-F07: decision_id=None means no filter; decision_id='' filters
        for empty (not unscoped). Non-string non-None raises ValueError.
        """
        self._validate_decision_id_filter(decision_id)

        with self._lock:
            results = []
            for event in self._events:
                if event.append_offset < from_offset:
                    continue
                if decision_id is not None and event.decision_id != decision_id:
                    continue
                if event_type is not None and event.event_type != event_type:
                    continue
                results.append(copy.deepcopy(event))
            return results

    def get_attempts(self, decision_id):
        """P8-F01: Verified reader -- returns empty list on corrupt journal.
        P6-F06: Locked reader snapshot."""
        with self._lock:
            # P8-F01: Verify integrity before returning authoritative data
            if not self._verify_integrity_under_lock():
                return []  # Corrupt -- no authoritative attempt list
            return [e.payload.get("attempt_id") for e in self._events
                    if e.decision_id == decision_id
                    and e.event_type == EventType.SEND_INTENT_COMMITTED
                    and e.payload.get("attempt_id")]

    def has_j2(self, decision_id):
        """P8-F01: Verified reader -- returns False (fail-closed) on
        corrupt journal. Cannot confirm dispatch occurred.
        P6-F06: Locked reader snapshot."""
        with self._lock:
            # P8-F01: Verify integrity before returning authoritative data
            if not self._verify_integrity_under_lock():
                return False  # Corrupt -- cannot confirm dispatch
            return any(e.decision_id == decision_id
                       and e.event_type == EventType.SEND_INTENT_COMMITTED
                       for e in self._events)

    def get_attempt_outcome(self, decision_id, attempt_id):
        """P8-F01: Verified reader -- returns None on corrupt journal.
        Never returns CONFIRMED or NO_EFFECT on a failed integrity check.
        P7-F04: Returns EFFECTIVE outcome matching reducer semantics.
        Scans all outcome events -- definitive J4a/J4b overrides J4c,
        J12 conflict returns None (quarantined). Returns the most
        definitive state, not the first chronological match.
        """
        with self._lock:
            # P8-F01: Verify integrity before returning authoritative status
            if not self._verify_integrity_under_lock():
                return None  # Corrupt journal -- no authoritative status

            has_j12 = any(
                e.decision_id == decision_id
                and e.event_type == EventType.EVIDENCE_CONFLICT
                and e.payload.get("attempt_id") == attempt_id
                for e in self._events)
            if has_j12:
                return None  # Quarantined -- no single effective outcome

            effective = None
            for event in self._events:
                if event.decision_id != decision_id:
                    continue
                if event.payload.get("attempt_id") != attempt_id:
                    continue
                if event.event_type == EventType.TARGET_EFFECT_CONFIRMED:
                    effective = EventType.TARGET_EFFECT_CONFIRMED
                elif event.event_type == EventType.TARGET_NO_EFFECT:
                    effective = EventType.TARGET_NO_EFFECT
                elif event.event_type == EventType.OUTCOME_UNKNOWN:
                    if effective is None:
                        effective = EventType.OUTCOME_UNKNOWN
            return effective

    def has_conflict(self, decision_id):
        """P8-F01: Verified reader -- returns True (fail-closed /
        quarantine-equivalent) on corrupt journal.
        P6-F06: Locked reader snapshot."""
        with self._lock:
            # P8-F01: Verify integrity -- fail-closed on corrupt
            if not self._verify_integrity_under_lock():
                return True  # Corrupt journal -- treat as conflicted
            return any(e.decision_id == decision_id
                       and e.event_type == EventType.EVIDENCE_CONFLICT
                       for e in self._events)

    def replay(self):
        """Locked reader snapshot. Returns deep copies."""
        with self._lock:
            return [copy.deepcopy(e) for e in self._events]

    def verify_head(self):
        """P7-F07: Includes tail deletion and index consistency checks."""
        with self._lock:
            # P7-F07: Structural consistency
            if len(self._events) != self._next_offset:
                return False, self._next_offset, \
                    f"Event count {len(self._events)} != offset {self._next_offset}"
            if len(self._event_index) != len(self._events):
                return False, self._next_offset, \
                    f"Index count {len(self._event_index)} != event count {len(self._events)}"
            if not self._events:
                return True, 0, ""
            for i, event in enumerate(self._events):
                if event.append_offset != i:
                    return False, i, "Non-monotonic offset"
                # P11-F02: Verify predecessor-linked hash chain
                expected_prev = "" if i == 0 else self._events[i - 1].integrity_hash
                if event.prev_hash != expected_prev:
                    return False, i, f"Chain break at offset {i}: prev_hash mismatch"
                # P7-F06: Catch serialization errors
                try:
                    recomputed = event.compute_hash()
                except (TypeError, ValueError):
                    return False, i, f"Unserializable payload at offset {i}"
                if recomputed != event.integrity_hash:
                    return False, i, f"Hash mismatch at offset {i}"
            last = self._events[-1]
            return True, last.append_offset + 1, last.integrity_hash
# Bismillah ir-Rahman ir-Rahim
