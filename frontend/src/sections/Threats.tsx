import { useEffect, useState } from "react";
import ThreatNetwork from "../components/ThreatNetwork";
import { api, createWebSocket } from "../services/api";

type AlertData = {
  alert_id: string;
  severity: string;
  anomaly_score: number;
  mitre_matches: { technique_name: string }[];
  status: string;
};

function Threats() {
  const [topAlert, setTopAlert] = useState<AlertData | null>(null);

  const fetchTopAlert = async () => {
    try {
      const data = await api.getAlerts();
      if (data && data.length > 0) {
        setTopAlert(data[0]); // top risk score alert
      } else {
        setTopAlert(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchTopAlert();
    const ws = createWebSocket((msg) => {
      if (msg.type === "NEW_ALERTS") {
        fetchTopAlert();
      }
    });

    return () => {
      ws.close();
    };
  }, []);

  return (
    <section className="panel threats-panel">
      <div className="threats-content">
        <div className="overview-eyebrow">
          <span className="pulse-dot threat-pulse"></span>
          ACTIVE THREAT DETECTION
        </div>
        <h1>
          THREAT<br /><span>DETECTED</span>
        </h1>
        <p className="threats-description">
          SENTINEL has identified anomalous activity moving through the network. The threat is being actively tracked and analyzed in real time.
        </p>
        
        {topAlert ? (
          <div className="threat-card">
            <div className="threat-stat">
              <span>THREAT LEVEL</span>
              <strong className={topAlert.severity.toLowerCase()}>{topAlert.severity}</strong>
            </div>
            <div className="threat-stat">
              <span>CONFIDENCE</span>
              <strong>{(topAlert.anomaly_score * 100).toFixed(1)}%</strong>
            </div>
            <div className="threat-stat">
              <span>STATUS</span>
              <strong>{topAlert.status === "OPEN" ? "TRACKING" : "ACTIONED"}</strong>
            </div>
          </div>
        ) : (
          <div className="threat-card">
            <div className="threat-stat">
              <span>THREAT LEVEL</span>
              <strong>SECURE</strong>
            </div>
            <div className="threat-stat">
              <span>CONFIDENCE</span>
              <strong>100%</strong>
            </div>
            <div className="threat-stat">
              <span>STATUS</span>
              <strong>MONITORING</strong>
            </div>
          </div>
        )}

        <div className="threat-meta">
          <div>
            <span>INCIDENT</span>
            <strong>{topAlert ? `#SNT-${topAlert.alert_id.substring(0,6)}` : "NONE"}</strong>
          </div>
          <div>
            <span>VECTOR</span>
            <strong>{topAlert?.mitre_matches?.length > 0 ? topAlert.mitre_matches[0].technique_name.toUpperCase() : "NETWORK INTRUSION"}</strong>
          </div>
        </div>
      </div>

      <div className="threats-visual">
        <ThreatNetwork threatMode={!!topAlert} />
        <div className="threat-visual-label">
          <span>LIVE ATTACK PATH</span>
          <strong>{topAlert ? "THREAT SIGNAL ACTIVE" : "MONITORING"}</strong>
        </div>
      </div>
    </section>
  );
}

export default Threats;
