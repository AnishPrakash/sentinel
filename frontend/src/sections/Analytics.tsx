import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const threatActivity = [
  { time: "08:00", value: 2 },
  { time: "09:00", value: 4 },
  { time: "10:00", value: 3 },
  { time: "11:00", value: 7 },
  { time: "12:00", value: 5 },
  { time: "13:00", value: 9 },
  { time: "14:00", value: 6 },
];

function Analytics() {
  return (
    <section className="panel analytics-panel">

      {/* ATMOSPHERE */}

      <div className="analytics-atmosphere"></div>


      {/* LEFT SIDE */}

      <div className="analytics-content">

        <div className="overview-eyebrow">
          <span className="pulse-dot"></span>
          SECURITY INTELLIGENCE
        </div>

        <h1>
          UNDERSTAND
          <br />
          <span>ADAPT</span>
        </h1>

        <p className="analytics-description">
          SENTINEL transforms security events into
          measurable intelligence, revealing patterns,
          response performance and network behavior.
        </p>


        <div className="analytics-meta">

          <div>
            <span>ANALYSIS ENGINE</span>
            <strong>ONLINE</strong>
          </div>

          <div>
            <span>DATA WINDOW</span>
            <strong>24 HOURS</strong>
          </div>

          <div>
            <span>CONFIDENCE</span>
            <strong>98.7%</strong>
          </div>

        </div>

        <div className="threat-profile">

  <div className="threat-profile-header">
    <span>THREAT PROFILE</span>
    <strong>ACTIVITY BY CATEGORY</strong>
  </div>

  <div className="threat-profile-bars">

    <div className="profile-row">
      <span>NETWORK INTRUSION</span>

      <div className="profile-track">
        <div
          className="profile-fill"
          style={{ width: "78%" }}
        ></div>
      </div>

      <strong>78</strong>
    </div>


    <div className="profile-row">
      <span>AUTHENTICATION</span>

      <div className="profile-track">
        <div
          className="profile-fill"
          style={{ width: "61%" }}
        ></div>
      </div>

      <strong>61</strong>
    </div>


    <div className="profile-row">
      <span>LATERAL MOVEMENT</span>

      <div className="profile-track">
        <div
          className="profile-fill"
          style={{ width: "46%" }}
        ></div>
      </div>

      <strong>46</strong>
    </div>


    <div className="profile-row">
      <span>OUTBOUND TRAFFIC</span>

      <div className="profile-track">
        <div
          className="profile-fill"
          style={{ width: "29%" }}
        ></div>
      </div>

      <strong>29</strong>
    </div>

  </div>

</div>
 
      </div>


      {/* LIVE STATUS */}

      <div className="analytics-status">

        <span className="status-dot"></span>

        ANALYSIS ACTIVE

      </div>


      {/* DATA VISUAL */}

      <div className="analytics-visual">

        <div className="analytics-visual-header">

          <div>
            <span>THREAT ACTIVITY</span>
            <strong>NETWORK EVENTS / 24H</strong>
          </div>

          <div className="analytics-live">
            <span></span>
            LIVE
          </div>

        </div>


        <div className="analytics-chart">

          <ResponsiveContainer
            width="100%"
            height="100%"
          >
            <LineChart
              data={threatActivity}
              margin={{
                top: 20,
                right: 10,
                left: -20,
                bottom: 5,
              }}
            >

              <CartesianGrid
                stroke="rgba(255,255,255,0.045)"
                vertical={false}
              />

              <XAxis
                dataKey="time"
                axisLine={false}
                tickLine={false}
                tick={{
                  fill: "rgba(255,255,255,0.28)",
                  fontSize: 8,
                }}
              />

              <YAxis
                axisLine={false}
                tickLine={false}
                tick={{
                  fill: "rgba(255,255,255,0.25)",
                  fontSize: 8,
                }}
              />

              <Tooltip
                cursor={{
                  stroke:
                    "rgba(99,102,241,0.25)",
                }}
                contentStyle={{
                  background: "#080810",
                  border:
                    "1px solid rgba(99,102,241,0.2)",
                  borderRadius: 0,
                  color: "#ffffff",
                  fontSize: 9,
                }}
                labelStyle={{
                  color:
                    "rgba(255,255,255,0.45)",
                }}
              />

              <Line
                type="monotone"
                dataKey="value"
                stroke="#6366f1"
                strokeWidth={2}
                dot={false}
                activeDot={{
                  r: 4,
                  fill: "#22d3ee",
                  stroke: "#22d3ee",
                }}
              />

            </LineChart>
          </ResponsiveContainer>

        </div>


        <div className="analytics-chart-footer">

          <div>
            <span>PEAK ACTIVITY</span>
            <strong>13:00</strong>
          </div>

          <div>
            <span>MAX EVENTS</span>
            <strong>09</strong>
          </div>

          <div>
            <span>TREND</span>
            <strong className="trend-up">
              +18.4%
            </strong>
          </div>

        </div>

      </div>


      {/* METRICS */}

      <div className="analytics-metrics">

        <div className="analytics-metric">

          <span>DETECTION RATE</span>

          <strong>98.7%</strong>

          <small>
            +2.4% / THIS HOUR
          </small>

        </div>


        <div className="analytics-metric">

          <span>THREATS BLOCKED</span>

          <strong>127</strong>

          <small>
            LAST 24 HOURS
          </small>

        </div>


        <div className="analytics-metric">

          <span>AVG RESPONSE</span>

          <strong>1.8s</strong>

          <small>
            -0.6s / IMPROVEMENT
          </small>

        </div>


        <div className="analytics-metric">

          <span>NETWORK HEALTH</span>

          <strong>94%</strong>

          <small>
            SYSTEM STABLE
          </small>

        </div>

      </div>


      {/* FOOTER */}

      <div className="analytics-footer">

        <span>MODEL STATUS</span>

        <strong>STABLE</strong>

        <span>·</span>

        <span>LAST ANALYSIS</span>

        <strong>10:42:18</strong>

      </div>

    </section>
  );
}

export default Analytics;