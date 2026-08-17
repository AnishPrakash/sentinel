# backend/api/routes_alerts.py
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from models.alert_store import alert_store
from models.schemas import Alert

router = APIRouter()


@router.get("", response_model=list[Alert])
async def list_alerts(
    min_risk: float = Query(default=0.0, ge=0.0, le=1.0),
    severity: Optional[str] = Query(default=None),
    status:   Optional[str] = Query(default=None),
):
    """
    Returns all active alerts, sorted by risk score descending.
    Optional filters: min_risk, severity (CRITICAL/HIGH/MEDIUM/LOW), status (OPEN/ACTIONED).
    """
    alerts = alert_store.get_all(sort_by_risk=True)

    if min_risk > 0:
        alerts = [a for a in alerts if a.risk_score >= min_risk]
    if severity:
        alerts = [a for a in alerts if a.severity.value == severity.upper()]
    if status:
        alerts = [a for a in alerts if a.status == status.upper()]

    return alerts


@router.get("/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str):
    alert = alert_store.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return alert


@router.get("/{alert_id}/narrative")
async def get_narrative(alert_id: str):
    alert = alert_store.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return {
        "alert_id":         alert.alert_id,
        "narrative":        alert.narrative,
        "mitre_matches":    [m.model_dump() for m in alert.mitre_matches],
        "predicted_next":   alert.predicted_next,
        "validation":       alert.validation.model_dump() if alert.validation else None,
        "playbook_actions": alert.playbook_actions,
        "risk_score":       alert.risk_score,
        "severity":         alert.severity.value,
    }
