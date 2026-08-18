import { useEffect, useRef, useState, useCallback } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type cytoscape from "cytoscape";
import { api, createWebSocket } from "../services/api";

type NodeInfo = {
  label: string;
  type: string;
  status: string;
  anomaly_score: number;
};

const stylesheet = [

  // =================================
  // BASE NODE
  // =================================

  {
    selector: "node",
    style: {
      label: "data(label)",

      color: "rgba(255,255,255,0.72)",

      "font-family": "Inter, sans-serif",

      "font-size": 9,

      "font-weight": 500,

      "letter-spacing": "0.08em",

      "text-valign": "bottom",

      "text-margin-y": 12,

      width: 30,
      height: 30,

      "background-color": "#6366f1",

      "border-width": 1,

      "border-color": "rgba(129,140,248,0.7)",

      "overlay-opacity": 0,

      "transition-property":
        "background-color, border-color, border-width, opacity",

      "transition-duration": 250,
    },
  },


  // =================================
  // SERVER
  // =================================

  {
    selector: 'node[type = "SERVER"]',
    style: {
      shape: "round-rectangle",

      width: 42,
      height: 42,

      "background-color": "#7c3aed",

      "border-color": "#8b5cf6",

      "border-width": 1.5,

      "text-margin-y": 13,
    },
  },


  // =================================
  // ENDPOINT
  // =================================

  {
    selector: 'node[type = "ENDPOINT"]',
    style: {
      shape: "ellipse",

      width: 34,
      height: 34,

      "background-color": "#6366f1",

      "border-color": "#818cf8",
    },
  },


  // =================================
  // NETWORK
  // =================================

  {
    selector: 'node[type = "NETWORK"]',
    style: {
      shape: "diamond",

      width: 42,
      height: 42,

      "background-color": "#2563eb",

      "border-color": "#60a5fa",

      "border-width": 1.5,
    },
  },


  // =================================
  // DATABASE
  // =================================

  {
    selector: 'node[type = "DATABASE"]',
    style: {
      shape: "barrel",

      width: 38,
      height: 38,

      "background-color": "#6d28d9",

      "border-color": "#8b5cf6",
    },
  },


  // =================================
  // COMPROMISED
  // =================================

  {
    selector: 'node[status = "COMPROMISED"]',
    style: {
      "background-color": "#ef4444",

      "border-color": "#f87171",

      "border-width": 2,

      "color": "#ffffff",

      "font-weight": 600,

      "text-margin-y": 14,
    },
  },


  // =================================
  // THREAT
  // =================================

  {
    selector: 'node[type = "THREAT"]',
    style: {
      shape: "triangle",

      width: 42,
      height: 42,

      "background-color": "#ef4444",

      "border-color": "#fca5a5",

      "border-width": 2,

      "color": "#ffb4b4",

      "font-weight": 600,

      "text-margin-y": 14,
    },
  },


  // =================================
  // NORMAL EDGES
  // =================================

  {
    selector: 'edge[kind = "normal"]',
    style: {
      width: 1,

      "line-color": "#4f46e5",

      "target-arrow-color": "#4f46e5",

      "target-arrow-shape": "triangle",

      "arrow-scale": 0.8,

      "curve-style": "bezier",

      opacity: 0.5,
    },
  },


  // =================================
  // ATTACK EDGES
  // =================================

  {
    selector: 'edge[kind = "attack"]',
    style: {
      width: 2,

      "line-color": "#ef4444",

      "target-arrow-color": "#ef4444",

      "target-arrow-shape": "triangle",

      "arrow-scale": 0.9,

      "curve-style": "bezier",

      opacity: 0.95,

      "line-style": "solid",
    },
  },


  // =================================
  // SELECTED
  // =================================

  {
    selector: ":selected",
    style: {
      "border-width": 3,

      "border-color": "#22d3ee",

      "background-opacity": 1,
    },
  },
];



function Graph() {
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [elements, setElements] = useState<cytoscape.ElementDefinition[]>([]);
  const [selectedNode, setSelectedNode] = useState<NodeInfo | null>(null);
  const [stats, setStats] = useState({ nodes: 0, edges: 0, compromised: 0 });

  const fetchGraph = useCallback(async () => {
    try {
      const data = await api.getGraphSnapshot();
      const newElements: cytoscape.ElementDefinition[] = [];
      let compromisedCount = 0;

      data.nodes.forEach((n: any) => {
        const isCompromised = n.anomaly_score > 0.65;
        if (isCompromised) compromisedCount++;
        newElements.push({
          data: {
            id: n.id,
            label: n.label,
            type: n.node_type.toUpperCase(),
            status: isCompromised ? "COMPROMISED" : "SECURE",
            anomaly_score: n.anomaly_score
          }
        });
      });

      data.edges.forEach((e: any, i: number) => {
        newElements.push({
          data: {
            id: `edge-${e.source}-${e.target}-${i}`,
            source: e.source,
            target: e.target,
            kind: "normal"
          }
        });
      });

      setElements(newElements);
      setStats({ nodes: data.nodes.length, edges: data.edges.length, compromised: compromisedCount });
    } catch (err) {
      console.error(err);
    }
  }, []);

  useEffect(() => {
    fetchGraph();
    const ws = createWebSocket((msg) => {
      if (msg.type === "UPDATE_GRAPH") {
        fetchGraph();
      }
    });

    return () => {
      ws.close();
    };
  }, [fetchGraph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    
    cy.layout({ name: 'cose', animate: true }).run();
    
    const handleNodeTap = (event: cytoscape.EventObject) => {
      const node = event.target;
      setSelectedNode({
        label: node.data("label"),
        type: node.data("type"),
        status: node.data("status"),
        anomaly_score: node.data("anomaly_score"),
      });
      
      cy.elements().removeClass("dimmed");
      cy.elements().removeClass("focused");
      node.addClass("focused");
      node.connectedEdges().addClass("focused");
      node.connectedNodes().addClass("focused");
      cy.elements().not(node).not(node.connectedEdges()).not(node.connectedNodes()).addClass("dimmed");
    };

    const handleBackgroundTap = (event: cytoscape.EventObject) => {
      if (event.target === cy) {
        setSelectedNode(null);
        cy.elements().removeClass("dimmed");
        cy.elements().removeClass("focused");
      }
    };

    cy.on("tap", "node", handleNodeTap);
    cy.on("tap", handleBackgroundTap);

    return () => {
      cy.removeListener("tap", "node");
      cy.removeListener("tap");
    };
  }, [elements]);

  return (
    <section className="panel graph-panel">
      <div className="graph-content">
        <div className="overview-eyebrow">
          <span className="pulse-dot"></span>
          NETWORK INTELLIGENCE
        </div>
        <h1>
          TRACE<br />THE<br /><span>ATTACK.</span>
        </h1>
        <p className="graph-description">
          SENTINEL maps relationships between devices, infrastructure and active threats to reveal how attacks move through the network.
        </p>
        <div className="graph-meta">
          <div>
            <span>GRAPH ENGINE</span>
            <strong>ONLINE</strong>
          </div>
          <div>
            <span>ACTIVE NODES</span>
            <strong>{stats.nodes < 10 ? `0${stats.nodes}` : stats.nodes}</strong>
          </div>
          <div>
            <span>CONNECTIONS</span>
            <strong>{stats.edges < 10 ? `0${stats.edges}` : stats.edges}</strong>
          </div>
        </div>
      </div>

      <div className="graph-environment">
        <div className="graph-environment-header">
          <div>
            <span>NETWORK TOPOLOGY</span>
            <strong>LIVE RELATIONSHIP MAP</strong>
          </div>
          <div className="graph-live">
            <span></span>LIVE
          </div>
        </div>

        <div className="graph-canvas">
          <CytoscapeComponent
            elements={elements}
            stylesheet={stylesheet}
            layout={{ name: "cose" }}
            cy={(cy) => { cyRef.current = cy; }}
            style={{ width: "100%", height: "100%" }}
          />
        </div>
        
        {selectedNode && (
          <div className="graph-node-details">
            <div className="graph-node-details-header">
              <span>NODE DETAILS</span>
              <button onClick={() => setSelectedNode(null)}>×</button>
            </div>
            <div className="graph-node-name">{selectedNode.label}</div>
            <div className="graph-detail-row">
              <span>TYPE</span>
              <strong>{selectedNode.type}</strong>
            </div>
            <div className="graph-detail-row">
              <span>STATUS</span>
              <strong className={selectedNode.status !== "SECURE" ? "danger" : ""}>
                {selectedNode.status}
              </strong>
            </div>
            <div className="graph-detail-row">
              <span>ANOMALY</span>
              <strong className={selectedNode.anomaly_score > 0.65 ? "danger" : ""}>
                {selectedNode.anomaly_score.toFixed(3)}
              </strong>
            </div>
          </div>
        )}

        <div className="graph-environment-footer">
          <div>
            <span>SECURE</span>
            <strong>{stats.nodes - stats.compromised}</strong>
          </div>
          <div>
            <span>COMPROMISED</span>
            <strong>{stats.compromised}</strong>
          </div>
        </div>
      </div>
    </section>
  );
}

export default Graph;
