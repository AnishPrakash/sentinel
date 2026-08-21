# backend/layer5_risk/playbook_engine.py
"""
Maps a MITRE ATT&CK technique + risk score to the correct playbook
and selects the appropriate action tier.
"""
import os
import yaml
from typing import List, Dict, Any
from config import PLAYBOOK_DIR


class PlaybookEngine:

    def __init__(self, playbook_dir: str = PLAYBOOK_DIR):
        self._playbooks: Dict[str, dict] = {}
        self._load_all(playbook_dir)

    def _load_all(self, directory: str):
        if not os.path.isdir(directory):
            print(f"[Playbook] Directory not found: {directory}")
            return
        for fname in os.listdir(directory):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                path = os.path.join(directory, fname)
                with open(path) as f:
                    pb = yaml.safe_load(f)
                    tid = pb.get("technique_id")
                    if tid:
                        self._playbooks[tid] = pb
        print(f"[Playbook] Loaded {len(self._playbooks)} playbook(s).")

    def get_actions(
        self,
        technique_ids: List[str],
        risk_score:    float,
    ) -> List[Dict[str, Any]]:
        """
        Returns list of recommended actions for given techniques and risk score.
        Selects tier: critical (>0.85) | high (0.6-0.85) | medium (<0.6).
        """
        all_actions = []

        tier = (
            "critical" if risk_score > 0.85
            else "high" if risk_score > 0.6
            else "medium"
        )

        seen_ids = set()
        for tid in technique_ids:
            pb = self._playbooks.get(tid)
            if not pb:
                continue
            actions = pb.get("actions", {}).get(tier, [])
            for action in actions:
                aid = action.get("id")
                if aid and aid not in seen_ids:
                    all_actions.append(action)
                    seen_ids.add(aid)

        # Default fallback
        if not all_actions:
            all_actions = [{"id": "WATCHLIST", "label": "Add to Watchlist",
                            "description": "Monitor for further activity.", "auto_execute": True}]

        return all_actions


# ── Global singleton ──────────────────────────────────────────────────────────
playbook_engine = PlaybookEngine()
