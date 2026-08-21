# backend/models/alert_store.py
"""
Thread-safe in-memory alert registry.
No database dependency — works completely offline for demo.
"""
import threading
from typing import Dict, List, Optional
from models.schemas import Alert


class AlertStore:
    def __init__(self):
        self._alerts: Dict[str, Alert] = {}
        self._lock = threading.Lock()

    def add(self, alert: Alert) -> None:
        with self._lock:
            self._alerts[alert.alert_id] = alert

    def get(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(alert_id)

    def get_all(self, sort_by_risk: bool = True) -> List[Alert]:
        alerts = list(self._alerts.values())
        if sort_by_risk:
            alerts.sort(key=lambda a: a.risk_score, reverse=True)
        return alerts

    def update_status(self, alert_id: str, status: str) -> bool:
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id].status = status
                return True
        return False

    def count(self) -> int:
        return len(self._alerts)


# Singleton instance shared across the app
alert_store = AlertStore()
