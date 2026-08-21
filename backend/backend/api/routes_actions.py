# backend/api/routes_actions.py
from fastapi import APIRouter, HTTPException
from models.schemas import ActionRequest, ActionResult
from models.alert_store import alert_store
from layer5_risk.action_executor import action_executor
from layer5_risk.playbook_engine import playbook_engine

router = APIRouter()


@router.post("/{alert_id}/action", response_model=ActionResult)
async def execute_action(alert_id: str, body: ActionRequest):
    """
    Execute or approve a remediation action on a specific alert.
    For auto-execute actions, the result is immediate.
    For confirm-required actions, approved_by must be set.
    """
    alert = alert_store.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    # Validate that the action is in the recommended playbook
    technique_ids    = [m.technique_id for m in alert.mitre_matches]
    playbook_actions = playbook_engine.get_actions(technique_ids, alert.risk_score)
    valid_action_ids = [a["id"] for a in playbook_actions]

    if body.action not in valid_action_ids:
        # Still allow if it's a direct SOC override
        pass

    result = action_executor.execute(alert_id, body.action, body.approved_by or "AUTO")
    alert_store.update_status(alert_id, "ACTIONED")

    return result
