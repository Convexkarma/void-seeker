"""
AutoRecon - main.py
FastAPI Backend — All endpoints for scan management, tools, settings, reports
Run: uvicorn main:app --host 127.0.0.1 --port 8000 --reload
"""

import asyncio
import json
import os
import uuid
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from db import init_db, get_scan, list_scans, save_scan, update_scan, delete_scan_db
from scanner import ScanOrchestrator, active_scans
from terminal import TerminalManager
from report import generate_report

# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(title="AutoRecon API", version="1.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AUTORECON_DIR = Path.home() / ".autorecon"
AUTORECON_DIR.mkdir(exist_ok=True)
CONFIG_FILE = AUTORECON_DIR / "config.json"
SCANS_DIR = AUTORECON_DIR / "scans"
SCANS_DIR.mkdir(exist_ok=True)

terminal_manager = TerminalManager()


@app.on_event("startup")
async def startup():
    await init_db()
    print("\n\033[32m[+] AutoRecon backend started on http://127.0.0.1:8000\033[0m")
    print("\033[36m[*] API docs: http://127.0.0.1:8000/api/docs\033[0m\n")


# ── Pydantic Models ───────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str
    modules: List[str]
    threads: int = 10
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    stealth: bool = False
    proxy: Optional[str] = None
    scope: Optional[List[str]] = None
    out_of_scope: Optional[List[str]] = None
    rate_limit: Optional[int] = None


class SettingsModel(BaseModel):
    shodan_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    securitytrails_key: Optional[str] = None
    ipinfo_key: Optional[str] = None
    github_token: Optional[str] = None
    default_wordlist: Optional[str] = "/usr/share/wordlists/dirb/common.txt"
    default_threads: Optional[int] = 10
    proxy: Optional[str] = None
    discord_webhook: Optional[str] = None
    slack_webhook: Optional[str] = None


class ReportRequest(BaseModel):
    scan_id: str
    format: str = "html"  # html | pdf | json | md


class CompareRequest(BaseModel):
    scan_id_a: str
    scan_id_b: str


# ── Scan Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    """Start a new automated recon scan."""
    if not req.domain or "." not in req.domain:
        raise HTTPException(400, "Invalid domain")

    scan_id = str(uuid.uuid4())
    scan_data = {
        "id": scan_id,
        "domain": req.domain,
        "modules": req.modules,
        "threads": req.threads,
        "wordlist": req.wordlist,
        "stealth": req.stealth,
        "proxy": req.proxy,
        "status": "running",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "results": {},
        "progress": 0,
        "current_module": "",
        "duration": 0,
    }

    await save_scan(scan_data)

    orchestrator = ScanOrchestrator(
        scan_id=scan_id,
        domain=req.domain,
        modules=req.modules,
        threads=req.threads,
        wordlist=req.wordlist,
        stealth=req.stealth,
        proxy=req.proxy,
        rate_limit=req.rate_limit,
    )
    active_scans[scan_id] = orchestrator
    asyncio.create_task(orchestrator.run())

    return {"scan_id": scan_id, "status": "started", "domain": req.domain}


@app.get("/api/scan/history")
async def scan_history():
    """List all past scans."""
    return await list_scans()


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    """Poll current scan status and progress."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "status": scan["status"],
        "progress": scan.get("progress", 0),
        "current_module": scan.get("current_module", ""),
        "duration": scan.get("duration", 0),
    }


@app.get("/api/scan/{scan_id}/results")
async def scan_results(scan_id: str):
    """Get full scan results."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from history."""
    await delete_scan_db(scan_id)
    # Also remove output files
    scan_dir = SCANS_DIR / scan_id
    if scan_dir.exists():
        shutil.rmtree(scan_dir, ignore_errors=True)
    return {"deleted": scan_id}


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    if scan_id in active_scans:
        await active_scans[scan_id].cancel()
        return {"cancelled": scan_id}
    raise HTTPException(404, "Scan not running")


@app.post("/api/scan/compare")
async def compare_scans(req: CompareRequest):
    """Diff two scans — return new/removed findings."""
    a = await get_scan(req.scan_id_a)
    b = await get_scan(req.scan_id_b)
    if not a or not b:
        raise HTTPException(404, "One or both scans not found")

    def get_subs(scan):
        s = set()
        for m in ("subfinder", "amass"):
            for sub in scan.get("results", {}).get(m, {}).get("subdomains", []):
                s.add(sub)
        return s

    def get_ports(scan):
        return {f"{p['port']}/{p['protocol']}" for p in scan.get("results", {}).get("nmap", {}).get("ports", [])}

    def get_vulns(scan):
        return {v.get("template", "") + v.get("url", "") for v in scan.get("results", {}).get("nuclei", {}).get("findings", [])}

    subs_a, subs_b = get_subs(a), get_subs(b)
    ports_a, ports_b = get_ports(a), get_ports(b)
    vulns_a, vulns_b = get_vulns(a), get_vulns(b)

    return {
        "scan_a": {"id": req.scan_id_a, "domain": a["domain"], "date": a["created_at"]},
        "scan_b": {"id": req.scan_id_b, "domain": b["domain"], "date": b["created_at"]},
        "diff": {
            "subdomains": {
                "new": list(subs_b - subs_a),
                "removed": list(subs_a - subs_b),
                "total_a": len(subs_a),
                "total_b": len(subs_b),
            },
            "ports": {
                "new": list(ports_b - ports_a),
                "removed": list(ports_a - ports_b),
            },
            "vulns": {
                "new": list(vulns_b - vulns_a),
                "removed": list(vulns_a - vulns_b),
            },
        }
    }


# ── WebSocket: Live Scan Stream ───────────────────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """Stream live scan output to browser via WebSocket."""
    await websocket.accept()
    try:
        if scan_id not in active_scans:
            # Send current state for completed scans
            scan = await get_scan(scan_id)
            if scan:
                await websocket.send_text(json.dumps({
                    "type": "scan_complete",
                    "status": scan["status"],
                    "scan_id": scan_id,
                }))
            return

        queue = asyncio.Queue()
        active_scans[scan_id].add_subscriber(queue)

        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=60)
                    if msg is None:
                        break
                    await websocket.send_text(json.dumps(msg))
                except asyncio.TimeoutError:
                    # Keepalive ping
                    await websocket.send_text(json.dumps({"type": "ping"}))
        finally:
            if scan_id in active_scans:
                active_scans[scan_id].remove_subscriber(queue)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[!] WebSocket error for scan {scan_id}: {e}")


# ── WebSocket: PTY Terminal ───────────────────────────────────────────────────

@app.websocket("/ws/terminal/{session_id}")
async def terminal_websocket(websocket: WebSocket, session_id: str):
    """Bidirectional PTY shell — full interactive terminal in browser."""
    await websocket.accept()
    await terminal_manager.handle(websocket, session_id)


# ── Tools ─────────────────────────────────────────────────────────────────────

TOOLS_LIST = [
    "subfinder", "amass", "httpx", "nmap", "gobuster", "nuclei",
    "whatweb", "gowitness", "wafw00f", "dnsx", "theHarvester",
    "testssl.sh", "whois", "dig", "curl", "python3", "go", "git",
]


@app.post("/api/tools/check")
async def check_tools():
    """Check which tools are installed on the system."""
    results = {}

    async def check_one(tool: str):
        path = shutil.which(tool)
        version = None
        if path:
            try:
                proc = await asyncio.create_subprocess_exec(
                    tool, "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                out, err = await asyncio.wait_for(proc.communicate(), timeout=4)
                raw = (out or err).decode("utf-8", errors="replace")
                version = raw.strip().split("\n")[0][:100]
            except Exception:
                version = "installed"
        return tool, {"installed": bool(path), "path": path or "", "version": version or ""}

    tasks = [check_one(t) for t in TOOLS_LIST]
    tool_results = await asyncio.gather(*tasks)
    return dict(tool_results)


@app.post("/api/tools/install")
async def install_tool(data: dict):
    """Trigger install of a specific tool via setup.sh snippet."""
    tool = data.get("tool", "")
    install_cmds = {
        "nmap": "sudo apt-get install -y nmap",
        "gobuster": "sudo apt-get install -y gobuster",
        "whatweb": "sudo apt-get install -y whatweb",
        "whois": "sudo apt-get install -y whois",
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "amass": "go install github.com/projectdiscovery/amass/v4/...@latest",
        "gowitness": "go install github.com/sensepost/gowitness@latest",
        "theHarvester": "pip3 install theHarvester --break-system-packages",
        "wafw00f": "pip3 install wafw00f --break-system-packages",
    }
    cmd = install_cmds.get(tool)
    if not cmd:
        raise HTTPException(400, f"No install recipe for tool: {tool}")
    return {"tool": tool, "command": cmd, "message": f"Run in terminal: {cmd}"}


# ── Screenshots ───────────────────────────────────────────────────────────────

@app.get("/api/screenshot")
async def get_screenshot(path: str):
    """Serve screenshot files."""
    p = Path(path)
    if not p.exists() or not str(p).startswith(str(AUTORECON_DIR)):
        raise HTTPException(404, "Screenshot not found")
    return FileResponse(p)


# ── Settings ──────────────────────────────────────────────────────────────────

@app.get("/api/settings")
async def get_settings():
    """Get saved API keys and config."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


@app.post("/api/settings")
async def save_settings(settings: SettingsModel):
    """Save API keys and config to ~/.autorecon/config.json."""
    CONFIG_FILE.write_text(json.dumps(settings.model_dump(), indent=2))
    return {"saved": True}


# ── Reports ───────────────────────────────────────────────────────────────────

@app.post("/api/report/generate")
async def gen_report(req: ReportRequest):
    """Generate HTML, PDF, JSON, or Markdown report for a scan."""
    scan = await get_scan(req.scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if req.format not in ("html", "pdf", "json", "md"):
        raise HTTPException(400, f"Invalid format: {req.format}")

    output_path = await generate_report(scan, req.format)
    return FileResponse(
        output_path,
        filename=Path(output_path).name,
        media_type="application/octet-stream",
    )


# ── Health Check ──────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "active_scans": len(active_scans),
        "autorecon_dir": str(AUTORECON_DIR),
    }
