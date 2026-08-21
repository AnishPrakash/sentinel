# tests/test_layer5.py
import json
import pytest
from layer5_risk.risk_scorer   import RiskScorer
from layer5_risk.playbook_engine import PlaybookEngine


def test_risk_scorer_critical():
    scorer = RiskScorer()
    with open("backend/data/topology.json") as f:
        topo = json.load(f)
    score = scorer.compute(0.95, "auth-server", topo, "WATCHLIST")
    assert score > 0.6   # High criticality host


def test_risk_scorer_low():
    scorer = RiskScorer()
    with open("backend/data/topology.json") as f:
        topo = json.load(f)
    score = scorer.compute(0.3, "honeypot-1", topo, "WATCHLIST")
    assert score < 0.5


def test_playbook_engine_loads():
    engine = PlaybookEngine("backend/data/playbooks")
    assert len(engine._playbooks) > 0


def test_playbook_returns_actions():
    engine = PlaybookEngine("backend/data/playbooks")
    actions = engine.get_actions(["T1059"], risk_score=0.9)
    assert len(actions) > 0
    assert any(a["id"] == "KILL_PROC" for a in actions)
