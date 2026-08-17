# backend/layer5_risk/action_executor.py
"""
Simulated action executor.
In production: calls real firewall API, AD API, EDR API.
For demo: logs the action and returns a success result.
"""
import json
from datetime import datetime
from typing import Dict, Any
from models.schemas import ActionResult


class ActionExecutor:

    def execute(self, alert_id: str, action: str, approved_by: str = "AUTO") -> ActionResult:
        """
        Simulate execution of a remediation action.
        Prints a descriptive log line for demo visibility.
        """
        ts = datetime.utcnow().isoformat()

        action_messages = {
            "KILL_PROC":        f"[EXECUTOR] Sent SIGKILL to suspicious process tree on alert {alert_id}.",
            "BLOCK_IP":         f"[EXECUTOR] Injected BLOCK rule into simulated firewall for IP from alert {alert_id}.",
            "ISOLATE_HOST":     f"[EXECUTOR] Host isolation command sent to EDR agent on alert {alert_id}.",
            "REVOKE_SESSION":   f"[EXECUTOR] Revoked all active session tokens for user on alert {alert_id}.",
            "RESET_CREDS":      f"[EXECUTOR] Password reset initiated for account on alert {alert_id}.",
            "WATCHLIST":        f"[EXECUTOR] Host added to SOC watchlist for alert {alert_id}.",
            "NOTIFY_SOC":       f"[EXECUTOR] SOC analyst notification sent for alert {alert_id}.",
            "CAPTURE_MEMORY":   f"[EXECUTOR] Memory dump capture triggered on host for alert {alert_id}.",
            "QUARANTINE_EMAIL": f"[EXECUTOR] Phishing email quarantined from all mailboxes for alert {alert_id}.",
            "SCAN_ATTACHMENTS": f"[EXECUTOR] Attachments submitted to sandbox for alert {alert_id}.",
            "USER_ALERT":       f"[EXECUTOR] End-user security alert sent for alert {alert_id}.",
        }

        message = action_messages.get(action, f"[EXECUTOR] Unknown action '{action}' logged.")
        print(message)

        return ActionResult(
            alert_id  = alert_id,
            action    = action,
            executed  = True,
            message   = message,
            timestamp = ts,
        )


# ── Global singleton ──────────────────────────────────────────────────────────
action_executor = ActionExecutor()
