import { useEffect, useState, useCallback } from "react";
import { api, createWebSocket } from "../services/api";

type AlertData = {
  alert_id: string;
  severity: string;
  timestamp: string;
  host: string;
  narrative: string;
  playbook_actions: string[];
  status: string;
  mitre_matches: { technique_name: string }[];
};

function Alerts() {
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertData | null>(null);
  const [narrativeLoading, setNarrativeLoading] = useState(false);
  const [actionStatus, setActionStatus] = useState<string | null>(null);

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await api.getAlerts();
      setAlerts(data);
    } catch (err) {
      console.error(err);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const ws = createWebSocket((msg) => {
      if (msg.type === "NEW_ALERTS") {
        fetchAlerts();
      }
    });

    return () => {
      ws.close();
    };
  }, [fetchAlerts]);

  const handleAlertClick = async (alert: AlertData) => {
    setSelectedAlert(alert);
    setActionStatus(null);
    setNarrativeLoading(true);
    try {
      const detail = await api.getAlertNarrative(alert.alert_id);
      setSelectedAlert((prev) => prev && prev.alert_id === detail.alert_id ? detail : prev);
    } catch (e) {
      console.error("Failed to load narrative");
    } finally {
      setNarrativeLoading(false);
    }
  };

  const handleAction = async (action: string) => {
    if (!selectedAlert) return;
    try {
      await api.executeAction(selectedAlert.alert_id, action);
      setActionStatus("EXECUTED: " + action);
      fetchAlerts();
    } catch (e) {
      setActionStatus("FAILED to execute action");
    }
  };

  const criticalCount = alerts.filter(a => a.severity === "CRITICAL").length;
  const highCount = alerts.filter(a => a.severity === "HIGH").length;
  const mediumCount = alerts.filter(a => a.severity === "MEDIUM").length;

  return (
    <section className="panel alerts-panel">
      <div className="alerts-atmosphere"></div>
      <div className="alerts-content">
        <div className="overview-eyebrow">
          <span className="pulse-dot threat-pulse"></span>
          SECURITY EVENT STREAM
        </div>
        <h1>
          DETECT<br /><span>RESPOND</span>
        </h1>
        <p className="alerts-description">
          Sentinel continuously transforms network activity into prioritized security events. Every signal is tracked, classified and prepared for response.
        </p>
        <div className="alerts-meta">
          <div>
            <span>INCIDENT</span>
            <strong>#SNT-LIVE</strong>
          </div>
          <div>
            <span>EVENTS</span>
            <strong>{alerts.length < 10 ? `0${alerts.length}` : alerts.length} ACTIVE</strong>
          </div>
          <div>
            <span>STREAM</span>
            <strong>LIVE</strong>
          </div>
        </div>
      </div>

      <div className="alerts-stream">
        <div className="alerts-stream-header">
          <div>
            <span>LIVE SECURITY EVENTS</span>
            <strong>NETWORK ACTIVITY</strong>
          </div>
          <div className="stream-status">
            <span className="status-dot"></span>
            MONITORING
          </div>
        </div>

        <div className="alerts-list">
          {alerts.map((alert, index) => {
            const timeStr = new Date(alert.timestamp).toLocaleTimeString();
            const typeStr = alert.mitre_matches?.length > 0 ? alert.mitre_matches[0].technique_name : "ANOMALY DETECTED";
            
            return (
              <div
                className={`alert-item ${alert.severity.toLowerCase()} ${index === 0 ? "alert-active" : ""} ${selectedAlert?.alert_id === alert.alert_id ? "alert-selected" : ""}`}
                key={alert.alert_id}
                onClick={() => handleAlertClick(alert)}
              >
                <div className="alert-marker"><span></span></div>
                <div className="alert-time">{timeStr}</div>
                <div className="alert-event">
                  <strong>{typeStr.toUpperCase()}</strong>
                  <span>UNKNOWN <b> → </b> {alert.host}</span>
                </div>
                <div className="alert-type">{alert.status}</div>
                <div className="alert-severity">{alert.severity}</div>
              </div>
            );
          })}
        </div>
      </div>

      {selectedAlert && (
        <div className="alert-details" style={{ overflowY: 'auto' }}>
          <div className="alert-details-header">
            <span>EVENT DETAILS</span>
            <button onClick={() => setSelectedAlert(null)}>×</button>
          </div>

          <div className="alert-details-title">
            {selectedAlert.mitre_matches?.length > 0 ? selectedAlert.mitre_matches[0].technique_name : "Anomaly Detected"}
          </div>
          <div className="alert-investigation-status">
            <span className="status-dot"></span>
            {selectedAlert.status === "OPEN" ? "INVESTIGATION ACTIVE" : "ACTIONED"}
          </div>

          <div className="alert-detail-row">
            <span>SEVERITY</span>
            <strong className="danger">{selectedAlert.severity}</strong>
          </div>
          <div className="alert-detail-row">
            <span>TARGET</span>
            <strong>{selectedAlert.host}</strong>
          </div>

          <div style={{ marginTop: '20px', padding: '15px', backgroundColor: 'rgba(0,0,0,0.3)', borderLeft: '2px solid #ef4444' }}>
            <h4 style={{ margin: '0 0 10px 0', fontSize: '10px', letterSpacing: '0.1em', color: '#888' }}>LLM ATTACK NARRATIVE</h4>
            <p style={{ margin: 0, fontSize: '13px', lineHeight: '1.5', color: '#ccc' }}>
              {narrativeLoading ? "Loading narrative from LLM..." : selectedAlert.narrative || "No narrative generated."}
            </p>
          </div>

          {selectedAlert.playbook_actions && selectedAlert.playbook_actions.length > 0 && (
            <div style={{ marginTop: '20px' }}>
              <h4 style={{ margin: '0 0 10px 0', fontSize: '10px', letterSpacing: '0.1em', color: '#888' }}>RECOMMENDED ACTIONS</h4>
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                {selectedAlert.playbook_actions.map(action => (
                  <button 
                    key={action}
                    onClick={() => handleAction(action)}
                    style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '8px 12px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                  >
                    {action}
                  </button>
                ))}
              </div>
              {actionStatus && <div style={{ marginTop: '10px', color: '#4ade80', fontSize: '12px' }}>{actionStatus}</div>}
            </div>
          )}
        </div>
      )}

      <div className="alert-summary">
        <div className="alert-summary-eyebrow">INCIDENT STATUS</div>
        <div className="alert-summary-number">{alerts.length < 10 ? `0${alerts.length}` : alerts.length}</div>
        <span className="alert-summary-label">ACTIVE EVENTS</span>
        <div className="alert-summary-divider"></div>
        <div className="alert-summary-row">
          <span>CRITICAL</span>
          <strong className="critical">{criticalCount < 10 ? `0${criticalCount}` : criticalCount}</strong>
        </div>
        <div className="alert-summary-row">
          <span>HIGH</span>
          <strong>{highCount < 10 ? `0${highCount}` : highCount}</strong>
        </div>
        <div className="alert-summary-row">
          <span>MEDIUM</span>
          <strong>{mediumCount < 10 ? `0${mediumCount}` : mediumCount}</strong>
        </div>
      </div>

      <div className="alerts-footer">
        <span>LAST EVENT</span>
        <strong>{alerts.length > 0 ? new Date(alerts[0].timestamp).toLocaleTimeString() : "N/A"}</strong>
        <span>·</span>
        <span>SIGNAL INTEGRITY</span>
        <strong className="integrity">99.2%</strong>
      </div>
    </section>
  );
}

export default Alerts;
