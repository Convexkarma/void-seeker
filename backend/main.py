"""AutoRecon FastAPI Backend — Local scan orchestration with WebSocket streaming."""

import asyncio
import json
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from db import init_db, get_scan, get_scan_history, delete_scan, load_config, save_config
from scanner import run_scan, cancel_scan, check_all_tools
from terminal import handle_terminal_ws
from report import generate_html, generate_pdf, generate_json, generate_markdown


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(title="AutoRecon", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic Models ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str
    modules: list[str]
    profile: str = "standard"
    wordlist: str = "common"
    threads: int = 50
    authorized: bool = False

class ReportRequest(BaseModel):
    scan_id: str
    format: str = "html"  # html, pdf, json, markdown


# ── WebSocket connections for live scan output ───────────────────

scan_ws_clients: dict[str, list[WebSocket]] = {}


# ── REST Endpoints ───────────────────────────────────────────────

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(status_code=400, detail="Authorization confirmation required")

    scan_id = str(uuid.uuid4())[:8]

    async def send_line(data: dict):
        clients = scan_ws_clients.get(scan_id, [])
        for ws in clients:
            try:
                await ws.send_json(data)
            except Exception:
                pass

    # Launch scan in background
    asyncio.create_task(run_scan(
        scan_id=scan_id,
        domain=req.domain,
        modules=req.modules,
        profile=req.profile,
        wordlist=req.wordlist,
        threads=req.threads,
        send_line=send_line,
    ))

    return {"scan_id": scan_id, "status": "running"}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"id": scan_id, "status": scan["status"], "progress": scan["progress"], "active_module": scan.get("active_module", "")}


@app.get("/api/scan/{scan_id}/results")
async def scan_results(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scan/history")
async def history():
    return await get_scan_history()


@app.delete("/api/scan/{scan_id}")
async def remove_scan(scan_id: str):
    await delete_scan(scan_id)
    return {"deleted": True}


@app.post("/api/scan/{scan_id}/cancel")
async def cancel(scan_id: str):
    await cancel_scan(scan_id)
    return {"cancelled": True}


@app.post("/api/tools/check")
async def tools_check():
    return check_all_tools()


@app.get("/api/settings")
async def get_settings():
    return load_config()


@app.post("/api/settings")
async def save_settings(config: dict):
    save_config(config)
    return {"saved": True}


@app.post("/api/report/generate")
async def gen_report(req: ReportRequest):
    scan = await get_scan(req.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if req.format == "html":
        return Response(content=generate_html(scan), media_type="text/html")
    elif req.format == "pdf":
        pdf_bytes = generate_pdf(scan)
        return Response(content=pdf_bytes, media_type="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename=autorecon_{scan['domain']}.pdf"})
    elif req.format == "json":
        return Response(content=generate_json(scan), media_type="application/json")
    elif req.format == "markdown":
        return Response(content=generate_markdown(scan), media_type="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=autorecon_{scan['domain']}.md"})
    else:
        raise HTTPException(status_code=400, detail="Invalid format")


# ── WebSocket: Live scan output ──────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(ws: WebSocket, scan_id: str):
    await ws.accept()
    scan_ws_clients.setdefault(scan_id, []).append(ws)
    try:
        while True:
            await ws.receive_text()  # Keep alive
    except WebSocketDisconnect:
        scan_ws_clients.get(scan_id, []).remove(ws)


# ── WebSocket: Interactive terminal (PTY) ────────────────────────

@app.websocket("/ws/terminal/{terminal_id}")
async def ws_terminal(ws: WebSocket, terminal_id: str):
    await handle_terminal_ws(ws, terminal_id)
