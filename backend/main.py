"""
FastAPI Server for Honeywell Cyber Operations Console.
Provides REST APIs, WebSocket real-time event stream, analyst state management,
and mounts pre-built React frontend static assets.
"""

import asyncio
import os
import sys
from typing import Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Ensure parent directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.store import store
from scripts.trigger_attack import trigger_live_attack_burst

app = FastAPI(
    title="Honeywell Cyber Operations Console API",
    description="Backend API & WebSocket Server for AI-Powered Behavioral Anomaly Detection",
    version="2.0.0"
)

# Enable CORS for local Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Data models
class ActionRequest(BaseModel):
    action: str  # ACKNOWLEDGE, MARK_FALSE_POSITIVE, ESCALATE, ADD_NOTE
    note: Optional[str] = None

class ThresholdRequest(BaseModel):
    threshold: float

# Background WebSocket Event Streaming Task
@app.on_event("startup")
async def startup_event_stream():
    asyncio.create_task(stream_events_loop())

async def stream_events_loop():
    """Simulates live event streaming over WebSockets to connected frontend clients."""
    idx = 0
    while True:
        await asyncio.sleep(2.0)  # Emit every 2 seconds
        if store.analyzed_events:
            event = store.analyzed_events[idx % len(store.analyzed_events)]
            await manager.broadcast({
                "type": "NEW_EVENT",
                "data": event
            })
            idx += 1

# REST Endpoints
@app.get("/api/overview")
def get_overview():
    return store.get_overview_metrics()

@app.get("/api/events")
def get_events(limit: int = 100, domain: Optional[str] = None):
    events = store.analyzed_events
    if domain in ["IT", "OT"]:
        events = [e for e in events if e.get("asset_domain") == domain]
    return events[-limit:]

@app.websocket("/api/events/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/alerts")
def get_alerts(
    status: Optional[str] = None,
    domain: Optional[str] = None,
    min_risk: float = 0.0,
    taxonomy: Optional[str] = None
):
    alerts = [e for e in store.analyzed_events if e["is_alert"]]
    
    if status:
        alerts = [a for a in alerts if a.get("status") == status]
    if domain:
        alerts = [a for a in alerts if a.get("asset_domain") == domain]
    if min_risk > 0:
        alerts = [a for a in alerts if a.get("risk_score", 0) >= min_risk]
    if taxonomy:
        alerts = [a for a in alerts if a.get("predicted_taxonomy") == taxonomy]
        
    alerts.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return alerts

@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    for ev in store.analyzed_events:
        if ev["id"] == alert_id:
            return ev
    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

@app.post("/api/alerts/{alert_id}/action")
def perform_analyst_action(alert_id: str, req: ActionRequest):
    updated = store.perform_action(alert_id, req.action, req.note)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return updated

@app.get("/api/entities")
def list_entities():
    df = store.raw_df
    users = sorted(df["user_id"].unique().tolist())
    result = []
    for u in users:
        u_events = [e for e in store.analyzed_events if e["user_id"] == u]
        role = u_events[0]["role"] if u_events else "Unknown"
        domain = u_events[0]["domain"] if u_events else "IT"
        alert_cnt = sum(1 for e in u_events if e["is_alert"])
        result.append({
            "user_id": u,
            "role": role,
            "domain": domain,
            "event_count": len(u_events),
            "alert_count": alert_cnt
        })
    return result

@app.get("/api/entities/{entity_id}")
def get_entity_investigation(entity_id: str):
    u_events = [e for e in store.analyzed_events if e["user_id"] == entity_id]
    if not u_events:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found")
        
    user_role = u_events[0]["role"]
    user_domain = u_events[0]["domain"]
    
    # Calculate hour distribution
    hours = [int(e["timestamp"].split(" ")[1].split(":")[0]) for e in u_events]
    mb_transfers = [float(e["mb_transferred"]) for e in u_events]
    
    alerts = [e for e in u_events if e["is_alert"]]
    
    return {
        "entity_id": entity_id,
        "role": user_role,
        "domain": user_domain,
        "total_events": len(u_events),
        "alert_count": len(alerts),
        "events": u_events,
        "alerts": alerts,
        "hours": hours,
        "mb_transfers": mb_transfers
    }

@app.get("/api/metrics")
def get_metrics():
    return store.get_evaluation_metrics()

@app.post("/api/simulate/trigger-attack")
async def trigger_attack():
    data_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_access_logs.csv"))
    trigger_live_attack_burst(data_file)
    store.load_and_process_data()
    
    # Notify WebSocket listeners
    await manager.broadcast({
        "type": "ATTACK_BURST_TRIGGERED",
        "message": "Injected High-Severity IT-OT Crossover & Impossible Travel Attacks!"
    })
    return {"status": "SUCCESS", "message": "Live attack burst injected!"}

@app.post("/api/settings/threshold")
def update_threshold(req: ThresholdRequest):
    store.update_threshold(req.threshold)
    return {"status": "SUCCESS", "current_threshold": store.current_threshold}

# Static file serving for React production build (frontend/dist)
dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(dist_dir):
    app.mount("/assets", StaticFiles(directory=os.path.join(dist_dir, "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        file_path = os.path.join(dist_dir, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(dist_dir, "index.html"))
