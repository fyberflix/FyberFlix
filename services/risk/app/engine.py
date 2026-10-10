"""Thin, fail-safe wrapper around zikriyon-prism for auth decisions."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from zikriyon_prism import RuleEngine

log = logging.getLogger("fyberflix.risk")


class Decision(str, Enum):
    ALLOW = "allow"
    STEP_UP = "step_up"  # require extra verification (e.g. face re-check)
    DENY = "deny"


# Prism action string -> auth decision. Unknown actions fail towards STEP_UP.
_ACTIONS = {
    "allow": Decision.ALLOW,
    "flag": Decision.ALLOW,   # logged, not blocking
    "warn": Decision.STEP_UP,
    "step_up": Decision.STEP_UP,
    "mute": Decision.STEP_UP,
    "block": Decision.DENY,
    "deny": Decision.DENY,
}


@dataclass(frozen=True)
class RiskVerdict:
    decision: Decision
    rule_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    degraded: bool = False  # True when the engine failed and we fell back


class RiskEngine:
    """Loads every rules/*.yaml once at startup; one engine per spec."""

    def __init__(self, rules_dir: str | Path):
        self._engines: dict[str, RuleEngine] = {}
        for path in sorted(Path(rules_dir).glob("*.yaml")):
            self._engines[path.stem] = RuleEngine.from_file(str(path))
        if not self._engines:
            raise RuntimeError(f"no rule files found in {rules_dir}")

    def evaluate(self, spec: str, event: dict[str, Any], subject_id: str) -> RiskVerdict:
        engine = self._engines.get(spec)
        if engine is None:
            raise KeyError(f"unknown rule spec: {spec}")
        try:
            result = engine.evaluate(event, subject_id=subject_id)
        except Exception:
            # Never allow silently and never hard-lock users because our
            # risk engine broke: ask for extra verification instead.
            log.exception("prism evaluation failed; degrading to step_up")
            return RiskVerdict(Decision.STEP_UP, degraded=True)

        decision = _ACTIONS.get(str(result.action).lower())
        if decision is None:
            log.warning("unknown prism action %r; using step_up", result.action)
            decision = Decision.STEP_UP
        matches = getattr(result, "matches", None) or []
        return RiskVerdict(
            decision=decision,
            rule_ids=tuple(m.rule_id for m in matches),
            reasons=tuple(m.reason for m in matches),
        )
