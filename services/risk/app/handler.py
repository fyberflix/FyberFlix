"""Pure request logic for risk-service (no web framework, so it is unit-testable anywhere)."""
from __future__ import annotations

import json
import logging
from typing import Any, Protocol

from .engine import Decision, RiskVerdict

log = logging.getLogger("fyberflix.risk")

MAX_EVENT_BYTES = 4096
# Only these specs may be evaluated over HTTP (spam_abuse etc. stay offline).
ALLOWED_SPECS = frozenset({"auth_risk", "login_fail"})


class Evaluator(Protocol):
    def evaluate(self, spec: str, event: dict[str, Any], subject_id: str) -> RiskVerdict: ...


class BadRequest(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def evaluate(engine: Evaluator, spec: str, event: Any, subject_id: str) -> dict[str, Any]:
    if spec not in ALLOWED_SPECS:
        raise BadRequest(422, "unknown spec")
    if not isinstance(event, dict):
        raise BadRequest(422, "event must be an object")
    if not isinstance(subject_id, str) or not 1 <= len(subject_id) <= 128:
        raise BadRequest(422, "subject_id must be 1-128 characters")
    if len(json.dumps(event)) > MAX_EVENT_BYTES:
        raise BadRequest(413, "event too large")
    try:
        v = engine.evaluate(spec, event, subject_id)
    except KeyError:
        raise BadRequest(422, "unknown spec")
    except Exception:
        log.exception("evaluate failed")
        v = RiskVerdict(Decision.STEP_UP, degraded=True)
    return {"decision": v.decision.value, "rule_ids": list(v.rule_ids),
            "reasons": list(v.reasons), "degraded": v.degraded}
