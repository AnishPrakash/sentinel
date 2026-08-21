# backend/layer4_symbolic/symbolic_validator.py
"""
Master symbolic validation engine.
Orchestrates NetworkReachabilityChecker, PrivilegeConstraintChecker,
and TemporalConsistencyChecker against the LLM's proposed narrative.
"""
from typing import List, Dict, Any, Tuple
from models.schemas import ValidationResult
from layer4_symbolic.network_checker    import NetworkReachabilityChecker
from layer4_symbolic.privilege_checker  import PrivilegeConstraintChecker
from layer4_symbolic.temporal_checker   import TemporalConsistencyChecker


class SymbolicValidator:

    def __init__(self):
        self.network   = NetworkReachabilityChecker()
        self.privilege = PrivilegeConstraintChecker()
        self.temporal  = TemporalConsistencyChecker()

    def validate(self, narrative_json: dict, user: str = "SYSTEM") -> ValidationResult:
        """
        Run all three checkers against a narrative JSON produced by the LLM.

        Expected narrative_json keys (optional — checker skips if absent):
            lateral_steps: [{src_host, dst_host, port, technique}]
            matched_techniques: [{technique_id, ...}]
            event_sequence: [{description, timestamp}]

        Returns a ValidationResult with status VALID | PARTIAL | INVALID and issues.
        """
        all_issues: List[str] = []

        # ── 1. Network reachability ──────────────────────────────────────────
        lateral_steps = narrative_json.get("lateral_steps", [])
        if lateral_steps:
            _, net_issues = self.network.check_narrative_path(lateral_steps)
            all_issues.extend(net_issues)

        # ── 2. Privilege constraints ─────────────────────────────────────────
        techniques = narrative_json.get("matched_techniques", [])
        if techniques:
            _, priv_issues = self.privilege.check_narrative_techniques(techniques, user)
            all_issues.extend(priv_issues)

        # ── 3. Temporal ordering ─────────────────────────────────────────────
        event_seq = narrative_json.get("event_sequence", [])
        if event_seq:
            _, time_issues = self.temporal.check_sequence(event_seq)
            all_issues.extend(time_issues)

        if not all_issues:
            status = "VALID"
        elif len(all_issues) <= 2:
            status = "PARTIAL"
        else:
            status = "INVALID"

        return ValidationResult(
            status  = status,
            issues  = all_issues,
        )

    def get_topology_context(self) -> str:
        return self.network.get_topology_context()


# ── Global singleton ──────────────────────────────────────────────────────────
symbolic_validator = SymbolicValidator()
