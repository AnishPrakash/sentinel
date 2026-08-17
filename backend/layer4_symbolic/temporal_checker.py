# backend/layer4_symbolic/temporal_checker.py
"""
Checks that events in the narrative are temporally consistent —
no effect happens before its cause.
"""
from typing import List, Tuple
from datetime import datetime


class TemporalConsistencyChecker:

    def parse_ts(self, ts: str) -> float:
        """Convert timestamp string to Unix epoch. Returns 0.0 on failure."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%s",   # raw epoch string
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt).timestamp()
            except ValueError:
                pass
        try:
            return float(ts)
        except (ValueError, TypeError):
            return 0.0

    def check_sequence(
        self, events: List[dict]
    ) -> Tuple[bool, List[str]]:
        """
        Validate that events are in chronological order.
        Each event dict: {"description": "...", "timestamp": "..."}

        Returns (valid: bool, issues: List[str])
        """
        issues = []
        prev_ts = 0.0
        prev_desc = "start"

        for ev in events:
            ts   = self.parse_ts(ev.get("timestamp", "0"))
            desc = ev.get("description", "unknown event")
            if ts != 0.0 and ts < prev_ts:
                issues.append(
                    f"Temporal contradiction: '{desc}' (ts={ts}) occurs "
                    f"before '{prev_desc}' (ts={prev_ts})."
                )
            if ts != 0.0:
                prev_ts   = ts
                prev_desc = desc

        return len(issues) == 0, issues
