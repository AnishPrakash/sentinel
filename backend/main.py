# backend/main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from api.routes_ingest  import router as ingest_router
from api.routes_graph   import router as graph_router
from api.routes_alerts  import router as alerts_router
from api.routes_actions import router as actions_router
from api.websocket_manager import manager

app = FastAPI(
    title="SENTINEL — AI Cyber Threat Intelligence",
    description="PS28 | VITISH 2026 | Structural Event Narrative & Threat Intelligence Neuron",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router,  prefix="/ingest",  tags=["Ingestion"])
app.include_router(graph_router,   prefix="/graph",   tags=["Graph"])
app.include_router(alerts_router,  prefix="/alerts",  tags=["Alerts"])
app.include_router(actions_router, prefix="/alerts",  tags=["Actions"])


@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "operational",
        "service": "SENTINEL",
        "version": "1.0.0",
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle client messages if necessary, or just wait
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
