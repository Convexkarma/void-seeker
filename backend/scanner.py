"""
AutoRecon - scanner.py
Scan orchestrator — runs real system tools as OS subprocesses,
streams output live via WebSocket queues.
"""

import asyncio
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from db import update_scan
from parser import parse_output

# ── Global registry of active scans ──────────────────────────────────────────
active_scans: Dict[str, "ScanOrchestrator"] = {}

AUTORECON_DIR = Path.home() / ".autorecon"
SCANS_DIR = AUTORECON_DIR / "scans"

# ── Tool command templates ────────────────────────────────────────────────────
# Placeholders: {domain}, {out}, {wordlist}, {threads}

COMMANDS: Dict[str, str] = {
    "subfinder":    "subfinder -d {domain} -silent -all -t {threads} -o {out}/subdomains_sf.txt",
    "amass":        "amass enum -passive -d {domain} -o {out}/subdomains_am.txt -timeout 10",
    "httpx":        "httpx -l {out}/subdomains_all.txt -silent -status-code -title -tech-detect -content-length -threads {threads} -o {out}/live_hosts.txt",
    "nmap":         "nmap -sV -sC -T4 --open --min-parallelism {threads} -p 21,22,23,25,53,80,110,143,443,445,465,587,993,995,1433,1521,2375,2376,3000,3306,3389,4848,5432,5900,5985,6379,8080,8443,8888,9200,9300,11211,27017,50070 {domain} -oX {out}/nmap.xml -oN {out}/nmap.txt",
    "gobuster":     "gobuster dir -u http://{domain} -w {wordlist} -t {threads} -o {out}/dirs.txt -b 404,403,400 --no-error -q",
    "nuclei":       "nuclei -u http://{domain} -severity low,medium,high,critical -c {threads} -o {out}/nuclei.txt -silent -no-color",
    "whatweb":      "whatweb -a 3 http://{domain} --log-json={out}/whatweb.json --quiet",
    "gowitness":    "gowitness file -f {out}/subdomains_all.txt -P {out}/screenshots/ --threads {threads} --quiet",
    "wafw00f":      "wafw00f http://{domain} -o {out}/waf.txt -a",
    "dnsx":         "dnsx -d {domain} -a -aaaa -mx -ns -txt -cname -ptr -soa -t {threads} -o {out}/dns.txt -silent",
    "theHarvester": "theHarvester -d {domain} -b all -f {out}/harvester",
    "testssl":      "testssl.sh --jsonfile {out}/ssl.json --quiet https://{domain}",
    "whois":        "whois {domain}",
    "dig":          "dig any {domain} +noall +answer +multiline",
    "curl_headers": "curl -sI --max-time 15 --user-agent 'Mozilla/5.0' http://{domain}",
}

# Execution order — discovery first, then enrichment, then active scanning
MODULE_ORDER = [
    "subfinder", "amass", "dnsx", "dig", "whois", "httpx", "nmap",
    "whatweb", "wafw00f", "curl_headers", "gobuster", "nuclei",
    "theHarvester", "gowitness", "testssl",
]

INSTALL_HINTS: Dict[str, str] = {
    "subfinder":    "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass":        "go install github.com/projectdiscovery/amass/v4/...@latest",
    "httpx":        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei":       "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "dnsx":         "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "gowitness":    "go install github.com/sensepost/gowitness@latest",
    "nmap":         "sudo apt install nmap",
    "gobuster":     "sudo apt install gobuster",
    "whatweb":      "sudo apt install whatweb",
    "wafw00f":      "pip3 install wafw00f",
    "theHarvester": "pip3 install theHarvester",
    "testssl.sh":   "sudo apt install testssl.sh",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanOrchestrator:
    """Orchestrates a full recon scan — one module at a time, streaming output."""

    def __init__(
        self,
        scan_id: str,
        domain: str,
        modules: List[str],
        threads: int = 10,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        stealth: bool = False,
        proxy: Optional[str] = None,
        rate_limit: Optional[int] = None,
    ):
        self.scan_id = scan_id
        self.domain = domain
        self.modules = set(modules)
        self.threads = threads
        self.wordlist = wordlist
        self.stealth = stealth
        self.proxy = proxy
        self.rate_limit = rate_limit
        self.cancelled = False

        self._subscribers: List[asyncio.Queue] = []
        self._current_proc: Optional[asyncio.subprocess.Process] = None
        self.out_dir = SCANS_DIR / scan_id
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "screenshots").mkdir(exist_ok=True)
        self.results: Dict[str, Any] = {}
        self.start_time = time.time()
        self._subdomain_files: List[Path] = []

    # ── Pub/Sub ───────────────────────────────────────────────────────────────

    def add_subscriber(self, q: asyncio.Queue) -> None:
        self._subscribers.append(q)

    def remove_subscriber(self, q: asyncio.Queue) -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def broadcast(self, msg: dict) -> None:
        dead: List[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                await q.put(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            self.remove_subscriber(q)

    # ── Cancel ────────────────────────────────────────────────────────────────

    async def cancel(self) -> None:
        self.cancelled = True
        proc = self._current_proc
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.sleep(1)
                if proc.returncode is None:
                    proc.kill()
            except ProcessLookupError:
                pass
        await self.broadcast({"type": "cancelled", "scan_id": self.scan_id})

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        ordered = [m for m in MODULE_ORDER if m in self.modules]
        total = len(ordered)

        await self.broadcast({
            "type": "started", "scan_id": self.scan_id,
            "domain": self.domain, "modules": ordered,
            "total_modules": total, "timestamp": _now(),
        })

        for idx, module in enumerate(ordered):
            if self.cancelled:
                break

            progress = int((idx / max(total, 1)) * 100)
            await update_scan(self.scan_id, {
                "status": "running", "progress": progress,
                "current_module": module, "updated_at": _now(),
            })
            await self.broadcast({
                "type": "module_start", "module": module,
                "index": idx + 1, "total": total, "progress": progress,
            })

            if self.stealth and idx > 0:
                await asyncio.sleep(3)

            await self._run_module(module)

        # Finalise
        status = "cancelled" if self.cancelled else "completed"
        duration = int(time.time() - self.start_time)

        await update_scan(self.scan_id, {
            "status": status, "progress": 100, "current_module": "",
            "results": self.results, "duration": duration,
            "completed_at": _now(), "updated_at": _now(),
        })
        await self.broadcast({
            "type": "scan_complete", "scan_id": self.scan_id,
            "status": status, "duration": duration,
            "summary": self._build_summary(),
        })
        await self._notify_webhooks(status)

        # Signal subscribers to close
        for q in self._subscribers:
            try:
                await q.put(None)
            except Exception:
                pass

        active_scans.pop(self.scan_id, None)

    # ── Single module ─────────────────────────────────────────────────────────

    async def _run_module(self, module: str) -> None:
        # Pre-step: merge subdomains before httpx
        if module == "httpx":
            await self._merge_subdomains()

        cmd = self._build_command(module)
        if not cmd:
            await self.broadcast({"type": "module_skip", "module": module, "reason": "No command template"})
            return

        tool_bin = cmd.split()[0]
        if not shutil.which(tool_bin):
            await self.broadcast({
                "type": "module_skip", "module": module,
                "reason": f"Tool not installed: {tool_bin}",
                "install_hint": INSTALL_HINTS.get(tool_bin, f"See docs for {tool_bin}"),
            })
            return

        await self.broadcast({"type": "command", "module": module, "command": cmd})

        output_lines: List[str] = []
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=self._build_env(),
                cwd=str(self.out_dir),
            )
            self._current_proc = proc

            async for raw_line in proc.stdout:
                if self.cancelled:
                    proc.terminate()
                    break
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                output_lines.append(line)
                await self.broadcast({"type": "output", "module": module, "line": line})
                if self.stealth:
                    await asyncio.sleep(0.05)

            await proc.wait()
            self._current_proc = None

            # Track subdomain files
            if module == "subfinder":
                f = self.out_dir / "subdomains_sf.txt"
                if f.exists() and f.stat().st_size > 0:
                    self._subdomain_files.append(f)
            elif module == "amass":
                f = self.out_dir / "subdomains_am.txt"
                if f.exists() and f.stat().st_size > 0:
                    self._subdomain_files.append(f)

            # Parse
            parsed = await parse_output(module, output_lines, self.out_dir)
            self.results[module] = parsed

            await update_scan(self.scan_id, {"results": self.results, "updated_at": _now()})
            await self.broadcast({
                "type": "module_complete", "module": module,
                "parsed": parsed, "exit_code": proc.returncode,
                "lines": len(output_lines),
            })

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self.broadcast({"type": "module_error", "module": module, "error": str(exc)})

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_command(self, module: str) -> Optional[str]:
        template = COMMANDS.get(module)
        if not template:
            return None
        cmd = template.format(
            domain=self.domain, out=str(self.out_dir),
            wordlist=self.wordlist, threads=self.threads,
        )
        if self.proxy and module in ("gobuster", "nuclei", "httpx", "whatweb", "curl_headers"):
            proxy_flags = {"gobuster": f" --proxy {self.proxy}", "httpx": f" -proxy {self.proxy}", "curl_headers": f" --proxy {self.proxy}"}
            cmd += proxy_flags.get(module, "")
        if self.rate_limit:
            rate_flags = {"gobuster": f" --delay {int(1000 / self.rate_limit)}ms", "nuclei": f" -rate-limit {self.rate_limit}", "httpx": f" -rate-limit {self.rate_limit}"}
            cmd += rate_flags.get(module, "")
        return cmd

    def _build_env(self) -> dict:
        env = os.environ.copy()
        go_bin = str(Path.home() / "go" / "bin")
        if go_bin not in env.get("PATH", ""):
            env["PATH"] = f"{go_bin}:{env.get('PATH', '')}"
        if self.proxy:
            for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
                env[k] = self.proxy
        config = self._load_config()
        for env_key, cfg_key in [("SHODAN_API_KEY", "shodan_key"), ("GITHUB_TOKEN", "github_token")]:
            if config.get(cfg_key):
                env[env_key] = config[cfg_key]
        return env

    def _load_config(self) -> dict:
        cfg = AUTORECON_DIR / "config.json"
        if cfg.exists():
            try:
                return json.loads(cfg.read_text())
            except Exception:
                pass
        return {}

    async def _merge_subdomains(self) -> None:
        seen: set = set()
        for sf in self._subdomain_files:
            if sf.exists():
                for line in sf.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("["):
                        seen.add(line)
        seen.add(self.domain)
        if seen:
            (self.out_dir / "subdomains_all.txt").write_text("\n".join(sorted(seen)) + "\n")
            await self.broadcast({
                "type": "info", "module": "httpx",
                "message": f"Merged {len(seen)} unique subdomains for live-host detection",
            })

    def _build_summary(self) -> dict:
        subs: set = set()
        for m in ("subfinder", "amass"):
            for s in self.results.get(m, {}).get("subdomains", []):
                subs.add(s)
        ports = self.results.get("nmap", {}).get("ports", [])
        vulns = self.results.get("nuclei", {}).get("findings", [])
        dirs = self.results.get("gobuster", {}).get("directories", [])
        return {
            "subdomains": len(subs),
            "live_hosts": self.results.get("httpx", {}).get("count", 0),
            "open_ports": len(ports),
            "high_risk_ports": [p["port"] for p in ports if p.get("risk") == "high"],
            "vulnerabilities": len(vulns),
            "critical": sum(1 for v in vulns if v.get("severity") == "critical"),
            "high": sum(1 for v in vulns if v.get("severity") == "high"),
            "medium": sum(1 for v in vulns if v.get("severity") == "medium"),
            "low": sum(1 for v in vulns if v.get("severity") == "low"),
            "directories": len(dirs),
            "sensitive_dirs": [d["path"] for d in dirs if d.get("sensitive")],
            "emails": self.results.get("theHarvester", {}).get("count", 0),
            "technologies": [t["name"] for t in self.results.get("whatweb", {}).get("technologies", [])[:10]],
            "waf": self.results.get("wafw00f", {}).get("waf"),
            "duration_seconds": int(time.time() - self.start_time),
        }

    async def _notify_webhooks(self, status: str) -> None:
        config = self._load_config()
        discord = config.get("discord_webhook")
        slack = config.get("slack_webhook")
        if not discord and not slack:
            return

        summary = self._build_summary()
        msg = (
            f"🔍 **AutoRecon scan {status}** for `{self.domain}`\n"
            f"• Subdomains: {summary['subdomains']}\n"
            f"• Open ports: {summary['open_ports']}\n"
            f"• Vulnerabilities: {summary['vulnerabilities']} "
            f"({summary['critical']} critical, {summary['high']} high)\n"
            f"• Duration: {summary['duration_seconds']}s\n"
            f"• Scan ID: `{self.scan_id}`"
        )

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                if discord:
                    await session.post(discord, json={"content": msg}, timeout=aiohttp.ClientTimeout(total=5))
                if slack:
                    await session.post(slack, json={"text": msg}, timeout=aiohttp.ClientTimeout(total=5))
        except Exception as exc:
            print(f"[!] Webhook notification failed: {exc}")
