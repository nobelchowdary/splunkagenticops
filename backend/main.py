"""SentinelFlow Backend — FastAPI Application."""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import json
import asyncio
from typing import Dict

from config import get_settings
from agents.orchestrator import run_investigation
from models import InvestigationRequest, InvestigationState


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, investigation_id: str):
        await websocket.accept()
        self.active_connections[investigation_id] = websocket

    def disconnect(self, investigation_id: str):
        self.active_connections.pop(investigation_id, None)

    async def send_update(self, investigation_id: str, data: dict):
        ws = self.active_connections.get(investigation_id)
        if ws:
            await ws.send_json(data)


manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    settings = get_settings()
    print(f"SentinelFlow Backend starting on port {settings.backend_port}")
    print(f"Splunk MCP Server: {settings.splunk_mcp_url}")
    yield
    # Shutdown
    print("SentinelFlow Backend shutting down")


app = FastAPI(
    title="SentinelFlow",
    description="Autonomous AI Security Operations Agent",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": "ok", "service": "SentinelFlow Backend"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/api/investigations")
async def create_investigation(request: InvestigationRequest):
    """Start a new autonomous investigation."""
    investigation = InvestigationState.from_request(request)

    # Run investigation in background
    asyncio.create_task(
        _run_investigation_with_updates(investigation)
    )

    return {
        "investigation_id": investigation.id,
        "status": "started",
        "message": "Investigation started. Connect to WebSocket for real-time updates.",
    }


@app.get("/api/investigations/{investigation_id}")
async def get_investigation(investigation_id: str):
    """Get the current state of an investigation."""
    # TODO: Retrieve from database
    return {"investigation_id": investigation_id, "status": "in_progress"}


@app.get("/api/investigations")
async def list_investigations():
    """List all investigations."""
    # TODO: Retrieve from database
    return {"investigations": []}


@app.post("/api/chat")
async def chat(payload: dict):
    """Interactive investigation chat — ask questions in natural language."""
    question = payload.get("question", "")
    investigation_id = payload.get("investigation_id")

    # TODO: Route to investigation agent for interactive queries
    return {
        "response": f"Processing question: {question}",
        "investigation_id": investigation_id,
    }


@app.websocket("/ws/{investigation_id}")
async def websocket_endpoint(websocket: WebSocket, investigation_id: str):
    """WebSocket endpoint for real-time investigation updates."""
    await manager.connect(websocket, investigation_id)
    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await websocket.receive_text()
            # Handle client commands if needed
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(investigation_id)


async def _run_investigation_with_updates(investigation: InvestigationState):
    """Run the investigation and stream updates via WebSocket."""

    async def send_update(update: dict):
        await manager.send_update(investigation.id, update)

    try:
        await send_update({
            "type": "status",
            "status": "starting",
            "message": "Investigation initiated",
        })

        # Run the multi-agent investigation
        result = await run_investigation(investigation, callback=send_update)

        # Serialize result (handle datetime objects)
        serializable_result = json.loads(
            json.dumps(result, default=str)
        )

        await send_update({
            "type": "status",
            "status": "completed",
            "message": "Investigation complete",
            "result": serializable_result,
        })

    except Exception as e:
        await send_update({
            "type": "error",
            "message": str(e),
        })


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(app, host="0.0.0.0", port=settings.backend_port)
