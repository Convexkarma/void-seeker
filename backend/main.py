"""
AutoRecon - main.py
FastAPI backend — scan management, tools, settings, reports, terminals.
Run: uvicorn main:app --host 127.0.0.1 --port 8000 --reload
"""

import asyncio
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from db import delete_scan_db, get_scan, init_db, list_scans, save_scan, update_scan
from report import generate_report
from scanner import ScanOrchestrator, active_scans
from terminal import TerminalManager

# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(title="AutoRecon API", version="2.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.on_event("startup")
async def startup():
    await init_db()
    print("\n\033[32m[+] AutoRecon v2.0 backend started on http://127.0.0.1:8000\033[0m")
    print("\033[36m[*] API docs: http://127.0.0.1:8000/api/docs\033[0m\n")


# ── Models ────────────────────────────────────────────────────────────────────

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
    format: str = "html"


class CompareRequest(BaseModel):
    scan_id_a: str
    scan_id_b: str


# ── Scan Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
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
        "created_at": _now(),
        "updated_at": _now(),
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
    return await list_scans()


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
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
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    await delete_scan_db(scan_id)
    scan_dir = SCANS_DIR / scan_id
    if scan_dir.exists():
        shutil.rmtree(scan_dir, ignore_errors=True)
    return {"deleted": scan_id}


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    if scan_id in active_scans:
        await active_scans[scan_id].cancel()
        return {"cancelled": scan_id}
    raise HTTPException(404, "Scan not running")


@app.post("/api/scan/compare")
async def compare_scans(req: CompareRequest):
    a = await get_scan(req.scan_id_a)
    b = await get_scan(req.scan_id_b)
    if not a or not b:
        raise HTTPException(404, "One or both scans not found")

    def _subs(scan):
        s = set()
        for m in ("subfinder", "amass"):
            for sub in scan.get("results", {}).get(m, {}).get("subdomains", []):
                s.add(sub)
        return s

    def _ports(scan):
        return {f"{p['port']}/{p['protocol']}" for p in scan.get("results", {}).get("nmap", {}).get("ports", [])}

    def _vulns(scan):
        return {v.get("template", "") + v.get("url", "") for v in scan.get("results", {}).get("nuclei", {}).get("findings", [])}

    sa, sb = _subs(a), _subs(b)
    pa, pb = _ports(a), _ports(b)
    va, vb = _vulns(a), _vulns(b)

    return {
        "scan_a": {"id": req.scan_id_a, "domain": a["domain"], "date": a["created_at"]},
        "scan_b": {"id": req.scan_id_b, "domain": b["domain"], "date": b["created_at"]},
        "diff": {
            "subdomains": {"new": list(sb - sa), "removed": list(sa - sb), "total_a": len(sa), "total_b": len(sb)},
            "ports": {"new": list(pb - pa), "removed": list(pa - pb)},
            "vulns": {"new": list(vb - va), "removed": list(va - vb)},
        },
    }


# ── WebSocket: Live Scan Stream ──────────────────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    try:
        if scan_id not in active_scans:
            scan = await get_scan(scan_id)
            if scan:
                await websocket.send_text(json.dumps({
                    "type": "scan_complete", "status": scan["status"], "scan_id": scan_id,
                }))
            return

        queue: asyncio.Queue = asyncio.Queue()
        active_scans[scan_id].add_subscriber(queue)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=60)
                    if msg is None:
                        break
                    await websocket.send_text(json.dumps(msg))
                except asyncio.TimeoutError:
                    await websocket.send_text(json.dumps({"type": "ping"}))
        finally:
            if scan_id in active_scans:
                active_scans[scan_id].remove_subscriber(queue)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        print(f"[!] WebSocket error for scan {scan_id}: {exc}")


# ── WebSocket: PTY Terminal ──────────────────────────────────────────────────

@app.websocket("/ws/terminal/{session_id}")
async def terminal_websocket(websocket: WebSocket, session_id: str):
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
    async def _check(tool: str):
        path = shutil.which(tool)
        version = None
        if path:
            try:
                proc = await asyncio.create_subprocess_exec(
                    tool, "--version",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                out, err = await asyncio.wait_for(proc.communicate(), timeout=4)
                version = (out or err).decode("utf-8", errors="replace").strip().split("\n")[0][:100]
            except Exception:
                version = "installed"
        return tool, {"installed": bool(path), "path": path or "", "version": version or ""}

    results = await asyncio.gather(*[_check(t) for t in TOOLS_LIST])
    return dict(results)


@app.post("/api/tools/install")
async def install_tool(data: dict):
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
        raise HTTPException(400, f"No install recipe for: {tool}")
    return {"tool": tool, "command": cmd, "message": f"Run in terminal: {cmd}"}


# ── Screenshots ───────────────────────────────────────────────────────────────

@app.get("/api/screenshot")
async def get_screenshot(path: str):
    p = Path(path)
    if not p.exists() or not str(p).startswith(str(AUTORECON_DIR)):
        raise HTTPException(404, "Screenshot not found")
    return FileResponse(p)


# ── Settings ──────────────────────────────────────────────────────────────────

@app.get("/api/settings")
async def get_settings():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


@app.post("/api/settings")
async def save_settings(settings: SettingsModel):
    CONFIG_FILE.write_text(json.dumps(settings.model_dump(), indent=2))
    return {"saved": True}


# ── Reports ───────────────────────────────────────────────────────────────────

@app.post("/api/report/generate")
async def gen_report(req: ReportRequest):
    scan = await get_scan(req.scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if req.format not in ("html", "pdf", "json", "md"):
        raise HTTPException(400, f"Invalid format: {req.format}")
    output_path = await generate_report(scan, req.format)
    return FileResponse(output_path, filename=Path(output_path).name, media_type="application/octet-stream")


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "active_scans": len(active_scans),
        "autorecon_dir": str(AUTORECON_DIR),
    }
