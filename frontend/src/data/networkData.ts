export const networkNodes = [
  {
    id: "server",
    label: "SERVER-01",
    type: "SERVER",
    status: "SECURE",
  },
  {
    id: "pc01",
    label: "WORKSTATION-04",
    type: "ENDPOINT",
    status: "SECURE",
  },
  {
    id: "pc02",
    label: "WORKSTATION-07",
    type: "ENDPOINT",
    status: "COMPROMISED",
  },
  {
    id: "router",
    label: "GATEWAY-01",
    type: "NETWORK",
    status: "SECURE",
  },
  {
    id: "database",
    label: "DATABASE-01",
    type: "DATABASE",
    status: "SECURE",
  },
  {
    id: "attacker",
    label: "UNKNOWN",
    type: "THREAT",
    status: "MALICIOUS",
  },
];

export const networkEdges = [
  {
    id: "edge-server-router",
    source: "server",
    target: "router",
    kind: "normal",
  },
  {
    id: "edge-pc01-router",
    source: "pc01",
    target: "router",
    kind: "normal",
  },
  {
    id: "edge-router-db",
    source: "router",
    target: "database",
    kind: "normal",
  },
  {
    id: "edge-attacker-pc02",
    source: "attacker",
    target: "pc02",
    kind: "attack",
  },
  {
    id: "edge-pc02-router",
    source: "pc02",
    target: "router",
    kind: "attack",
  },
];