const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export const api = {
  getGraphSnapshot: async () => {
    const res = await fetch(`${API_BASE}/graph/snapshot`);
    if (!res.ok) throw new Error('Failed to fetch graph snapshot');
    return res.json();
  },
  getAlerts: async () => {
    const res = await fetch(`${API_BASE}/alerts`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },
  getAlertNarrative: async (id: string) => {
    const res = await fetch(`${API_BASE}/alerts/${id}/narrative`);
    if (!res.ok) throw new Error('Failed to fetch narrative');
    return res.json();
  },
  executeAction: async (id: string, action: string) => {
    const res = await fetch(`${API_BASE}/alerts/${id}/action`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ action }),
    });
    if (!res.ok) throw new Error('Failed to execute action');
    return res.json();
  }
};

export const createWebSocket = (onMessage: (msg: any) => void) => {
  const wsUrl = API_BASE.replace(/^http/, 'ws') + '/ws';
  const ws = new WebSocket(wsUrl);
  
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error("Failed to parse websocket message", e);
    }
  };
  
  return ws;
};
