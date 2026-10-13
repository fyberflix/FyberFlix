"""Needs the real zikriyon-prism package; skipped where it is not installed."""
from pathlib import Path

import pytest

pytest.importorskip("zikriyon_prism")

from app.engine import Decision, RiskEngine  # noqa: E402

RULES = Path(__file__).resolve().parent.parent / "rules"
NORMAL = [120, 340, 90, 500, 210, 400]


def engine() -> RiskEngine:
    return RiskEngine(RULES)


def test_normal_signup_is_allowed():
    ev = {"signup": {"cable_name": "Arman_Films", "action_intervals": NORMAL}}
    assert engine().evaluate("auth_risk", ev, "sess-1").decision == Decision.ALLOW


def test_scripted_timing_needs_step_up():
    ev = {"signup": {"cable_name": "Arman_Films", "action_intervals": [100] * 6}}
    v = engine().evaluate("auth_risk", ev, "sess-2")
    assert v.decision == Decision.STEP_UP and "signup_bot_timing" in v.rule_ids


def test_phishing_like_name_needs_step_up():
    ev = {"signup": {"cable_name": "secure.wallet.verify", "action_intervals": NORMAL}}
    v = engine().evaluate("auth_risk", ev, "sess-3")
    assert v.decision == Decision.STEP_UP and "name_phishing_words" in v.rule_ids


def test_unknown_spec_raises():
    with pytest.raises(KeyError):
        engine().evaluate("nope", {}, "x")


def test_login_fail_denies_on_fifth_failure_per_subject():
    e, ev = engine(), {"auth": {"failed_login_count": 1}}
    for _ in range(4):
        assert e.evaluate("login_fail", ev, "ip:9.9.9.9").decision == Decision.ALLOW
    assert e.evaluate("login_fail", ev, "ip:9.9.9.9").decision == Decision.DENY
    # another subject has its own counter
    assert e.evaluate("login_fail", ev, "ip:8.8.8.8").decision == Decision.ALLOW
