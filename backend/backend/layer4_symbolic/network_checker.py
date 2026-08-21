# backend/layer4_symbolic/network_checker.py
"""
Checks whether a proposed lateral movement path is possible
given the simulated network topology.
"""
import json
from typing import List, Tuple
from config import TOPOLOGY_JSON


class NetworkReachabilityChecker:

    def __init__(self, topology_path: str = TOPOLOGY_JSON):
        with open(topology_path) as f:
            self.topology = json.load(f)

    def can_reach(self, src_host: str, dst_host: str, port: int = 0) -> bool:
        """
        Returns True if src_host can reach dst_host on the given port.
        If port=0, checks only host-level reachability.
        """
        entry = self.topology.get(src_host)
        if not entry:
            return False   # Unknown host assumed isolated

        reachable = entry.get("reachable", [])
        if dst_host not in reachable:
            return False

        if port == 0:
            return True

        allowed_ports = entry.get("allowed_ports", [])
        return port in allowed_ports

    def check_narrative_path(
        self, steps: List[dict]
    ) -> Tuple[bool, List[str]]:
        """
        Validate a list of lateral movement steps from the LLM narrative.
        Each step: {"src_host": "...", "dst_host": "...", "port": 445, "technique": "SMB"}

        Returns (all_valid: bool, issues: List[str])
        """
        issues = []
        for step in steps:
            src  = step.get("src_host", "")
            dst  = step.get("dst_host", "")
            port = step.get("port", 0)
            tech = step.get("technique", "unknown")

            if src and dst and src != dst:
                if not self.can_reach(src, dst, port):
                    issues.append(
                        f"Topology violation: {src} cannot reach {dst} "
                        f"on port {port} (technique: {tech})."
                    )

        return len(issues) == 0, issues

    def get_topology_context(self) -> str:
        """Return a concise topology summary for LLM prompt injection."""
        lines = ["Network reachability constraints:"]
        for host, info in self.topology.items():
            reach = ", ".join(info.get("reachable", []))
            ports = ", ".join(str(p) for p in info.get("allowed_ports", []))
            lines.append(f"  {host} → [{reach}] (ports: {ports})")
        return "\n".join(lines)
