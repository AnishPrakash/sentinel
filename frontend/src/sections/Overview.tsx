import ThreatNetwork from "../components/ThreatNetwork";

function Overview() {
  return (
    <section className="panel overview-panel">

      <div className="overview-content">

        <div className="overview-eyebrow">
          <span className="pulse-dot"></span>
          AI-POWERED CYBER DEFENSE
        </div>

        <h1>
          SEE THE
          <br />
          <span>THREAT</span>
          <br />
          STOP THE
          <br />
          <span>ATTACK</span>
        </h1>

        <p className="overview-description">
          SENTINEL transforms raw security events into
          intelligent, explainable and actionable cyber
          intelligence.
        </p>

        <div className="overview-actions">

          <button className="primary-button">
            EXPLORE SENTINEL
            <span>→</span>
          </button>

          <button className="secondary-button">
            WATCH DEMO
            <span>↗</span>
          </button>

        </div>

      </div>


      <div className="threat-visual">

        <ThreatNetwork threatMode={false} />

        <div className="visual-label">
            <span>LIVE THREAT ENVIRONMENT</span>
            <strong>NETWORK STATUS: ACTIVE</strong>
        </div>

    </div>


      <div className="overview-status">

        <div>
          <span>GRAPH ENGINE</span>
          <strong>ONLINE</strong>
        </div>

        <div>
          <span>AI DETECTOR</span>
          <strong>ONLINE</strong>
        </div>

        <div>
          <span>VALIDATOR</span>
          <strong>ONLINE</strong>
        </div>

      </div>

    </section>
  );
}

export default Overview;