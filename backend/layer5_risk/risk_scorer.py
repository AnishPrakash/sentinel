# backend/layer5_risk/risk_scorer.py
"""
Composite risk scoring formula:
  Risk = (α × confidence) + (β × asset_criticality_norm) + (γ × blast_radius_norm) − (δ × disruption_cost)

All inputs normalised to [0, 1]. Final score clamped to [0, 1].
"""
import json
import networkx as nx
from typing import Dict
from config import ALPHA, BETA, GAMMA, DELTA, ASSET_JSON


class RiskScorer:

    def __init__(self, asset_json: str = ASSET_JSON):
        with open(asset_json) as f:
            self._assets = json.load(f)

        self._max_criticality = max(
            v["criticality"] for v in self._assets.values()
        ) or 10.0

    def asset_criticality(self, host: str) -> float:
        """Normalised criticality [0, 1] for a given host."""
        raw = self._assets.get(host, {}).get("criticality", 3)
        return raw / self._max_criticality

    def blast_radius(self, host: str, topology: Dict) -> float:
        """
        Fraction of hosts reachable from the compromised host.
        Uses topology dict (loaded from topology.json).
        """
        reachable = len(topology.get(host, {}).get("reachable", []))
        total     = len(topology)
        return reachable / max(1, total)

    def disruption_cost(self, action: str) -> float:
        """
        Estimated operational disruption cost of the recommended action.
        Higher = more disruptive = we should penalise in the score.
        """
        cost_map = {
            "ISOLATE_HOST":    0.8,
            "KILL_PROC":       0.3,
            "BLOCK_IP":        0.2,
            "REVOKE_SESSION":  0.4,
            "RESET_CREDS":     0.5,
            "WATCHLIST":       0.05,
            "NOTIFY_SOC":      0.01,
            "CAPTURE_MEMORY":  0.1,
            "QUARANTINE_EMAIL": 0.15,
            "SCAN_ATTACHMENTS": 0.05,
            "USER_ALERT":      0.02,
        }
        return cost_map.get(action, 0.1)

    def compute(
        self,
        confidence_score:    float,
        host:                str,
        topology:            Dict,
        primary_action:      str = "WATCHLIST",
    ) -> float:
        """
        Compute composite risk score.
        Returns float in [0, 1].
        """
        crit   = self.asset_criticality(host)
        blast  = self.blast_radius(host, topology)
        disrupt = self.disruption_cost(primary_action)

        score = (
            ALPHA * confidence_score
            + BETA  * crit
            + GAMMA * blast
            - DELTA * disrupt
        )
        return max(0.0, min(1.0, round(score, 4)))

    def severity_label(self, risk_score: float) -> str:
        if risk_score > 0.85:   return "CRITICAL"
        elif risk_score > 0.6:  return "HIGH"
        elif risk_score > 0.35: return "MEDIUM"
        else:                   return "LOW"


# ── Global singleton ──────────────────────────────────────────────────────────
risk_scorer = RiskScorer()
