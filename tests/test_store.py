import pytest

from security_seti.protocol import Fact, Finding, Hypothesis, Evidence
from security_seti.scope import Authorization, Scope, ScopeError
from security_seti.store import Store


def test_hypothesis_lifecycle():
    s = Store(":memory:")
    h = Hypothesis(goal_id="g1", statement="idea A", novelty=0.9)
    s.add_hypothesis(h)
    assert len(s.open_hypotheses("g1")) == 1
    s.set_hypothesis_status(h.id, "confirmed")
    assert len(s.open_hypotheses("g1")) == 0


def test_open_hypotheses_sorted_by_novelty():
    s = Store(":memory:")
    s.add_hypothesis(Hypothesis(goal_id="g", statement="low", novelty=0.1))
    s.add_hypothesis(Hypothesis(goal_id="g", statement="high", novelty=0.9))
    ordered = s.open_hypotheses("g")
    assert ordered[0]["statement"] == "high"


def test_fact_with_evidence_roundtrip():
    s = Store(":memory:")
    h = Hypothesis(goal_id="g", statement="x")
    s.add_hypothesis(h)
    f = Fact(hypothesis_id=h.id, statement="x->y", value={"p": 0.25},
             confidence=0.8, evidence=Evidence(tool="t", seed=3))
    s.add_fact(f)
    facts = s.facts_for(h.id)
    assert len(facts) == 1
    assert facts[0]["confidence"] == 0.8


def test_finding_scope_enforced():
    scope = Scope(Authorization(targets=["example.com"]))
    s = Store(":memory:", scope=scope)
    # in scope: ok
    s.add_finding(Finding(title="ok", target="api.example.com"))
    # out of scope: rejected
    with pytest.raises(ScopeError):
        s.add_finding(Finding(title="bad", target="evil.com"))
    assert len(s.findings()) == 1


def test_finding_without_target_bypasses_scope():
    scope = Scope(Authorization(targets=["example.com"]))
    s = Store(":memory:", scope=scope)
    # crypto findings have no network target; allowed
    s.add_finding(Finding(title="crypto", target=""))
    assert len(s.findings()) == 1
