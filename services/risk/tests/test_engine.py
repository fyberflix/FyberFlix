from pathlib import Path

from app.engine import Decision, RiskEngine

RULES = Path(__file__).resolve().parent.parent / "rules"


def engine() -> RiskEngine:
    return RiskEngine(RULES)


def test_normal_signup_is_allowed():
    ev = {"signup": {"cable_name": "Arman_Films",
                     "action_intervals": [120, 340, 90, 500, 210, 400]}}
    assert engine().evaluate("auth_risk", ev, "sess-1").decision == Decision.ALLOW


def test_scripted_timing_needs_step_up():
    ev = {"signup": {"cable_name": "Arman_Films", "action_intervals": [100] * 6}}
    v = engine().evaluate("auth_risk", ev, "sess-2")
    assert v.decision == Decision.STEP_UP
    assert "signup_bot_timing" in v.rule_ids


def test_phishing_like_name_needs_step_up():
    ev = {"signup": {"cable_name": "secure.wallet.verify", "action_intervals": [120, 340, 90, 500, 210, 400]}}
    v = engine().evaluate("auth_risk", ev, "sess-3")
    assert v.decision == Decision.STEP_UP
    assert "name_phishing_words" in v.rule_ids


def test_unknown_spec_raises():
    import pytest
    with pytest.raises(KeyError):
        engine().evaluate("nope", {}, "x")
