import pytest

from app import handler
from app.engine import Decision, RiskVerdict


class Fake:
    def __init__(self):
        self.calls, self.boom = [], False

    def evaluate(self, spec, event, subject_id):
        self.calls.append((spec, event, subject_id))
        if self.boom:
            raise RuntimeError("engine down")
        if event.get("signup", {}).get("cable_name") == "secure.wallet":
            return RiskVerdict(Decision.STEP_UP, ("name_phishing_words",), ("phishing-like",))
        return RiskVerdict(Decision.ALLOW)


EV = {"signup": {"cable_name": "Arman"}}


def test_allow_and_step_up():
    f = Fake()
    assert handler.evaluate(f, "auth_risk", EV, "s1")["decision"] == "allow"
    r = handler.evaluate(f, "auth_risk", {"signup": {"cable_name": "secure.wallet"}}, "s1")
    assert r["decision"] == "step_up" and r["rule_ids"] == ["name_phishing_words"] and not r["degraded"]


@pytest.mark.parametrize("spec,event,subject,status", [
    ("spam_abuse", EV, "s", 422),
    ("auth_risk", "nope", "s", 422),
    ("auth_risk", EV, "", 422),
    ("auth_risk", EV, "x" * 129, 422),
    ("auth_risk", {"x": "a" * 5000}, "s", 413),
])
def test_rejects_bad_input_before_engine(spec, event, subject, status):
    f = Fake()
    with pytest.raises(handler.BadRequest) as e:
        handler.evaluate(f, spec, event, subject)
    assert e.value.status == status and f.calls == []


def test_engine_crash_degrades_never_allows_silently():
    f = Fake()
    f.boom = True
    r = handler.evaluate(f, "login_fail", EV, "ip:1.2.3.4")
    assert r["decision"] == "step_up" and r["degraded"] is True
