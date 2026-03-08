"""
AutoRecon - scanner.py
Scan Orchestrator — runs real system tools, streams output live via WebSocket queues.
Each tool runs as a real OS subprocess. Output is streamed line-by-line to all
connected WebSocket subscribers in real time.
"""

import asyncio
import json
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from db import update_scan
from parser import parse_output

# ── Global registry of active scans ──────────────────────────────────────────
active_scans: dict = {}

# ── Paths ─────────────────────────────────────────────────────────────────────
AUTORECON_DIR = Path.home() / ".autorecon"
SCANS_DIR = AUTORECON_DIR / "scans"

# ── Tool command templates ────────────────────────────────────────────────────
# {domain}   → target domain
# {out}      → scan output directory
# {wordlist} → wordlist path
# {threads}  → thread count

COMMANDS = {
    "subfinder": (
        "subfinder -d {domain} -silent -all -t {threads} -o {out}/subdomains_sf.txt"
    ),
    "amass": (
        "amass enum -passive -d {domain} -o {out}/subdomains_am.txt -timeout 10"
    ),
    "httpx": (
        "httpx -l {out}/subdomains_all.txt -silent -status-code -title "
        "-tech-detect -content-length -threads {threads} -o {out}/live_hosts.txt"
    ),
    "nmap": (
        "nmap -sV -sC -T4 --open --min-parallelism {threads} "
        "-p 21,22,23,25,53,80,110,143,443,445,465,587,993,995,"
        "1433,1521,2375,2376,3000,3306,3389,4848,5432,5900,5985,"
        "6379,8080,8443,8888,9200,9300,11211,27017,50070 "
        "{domain} -oX {out}/nmap.xml -oN {out}/nmap.txt"
    ),
    "gobuster": (
        "gobuster dir -u http://{domain} -w {wordlist} -t {threads} "
        "-o {out}/dirs.txt -b 404,403,400 --no-error -q"
    ),
    "nuclei": (
        "nuclei -u http://{domain} -severity low,medium,high,critical "
        "-c {threads} -o {out}/nuclei.txt -silent -no-color"
    ),
    "whatweb": (
        "whatweb -a 3 http://{domain} --log-json={out}/whatweb.json --quiet"
    ),
    "gowitness": (
        "gowitness file -f {out}/subdomains_all.txt -P {out}/screenshots/ "
        "--threads {threads} --quiet"
    ),
    "wafw00f": (
        "wafw00f http://{domain} -o {out}/waf.txt -a"
    ),
    "dnsx": (
        "dnsx -d {domain} -a -aaaa -mx -ns -txt -cname -ptr -soa "
        "-t {threads} -o {out}/dns.txt -silent"
    ),
    "theHarvester": (
        "theHarvester -d {domain} -b all -f {out}/harvester"
    ),
    "testssl": (
        "testssl.sh --jsonfile {out}/ssl.json --quiet https://{domain}"
    ),
    "whois": (
        "whois {domain}"
    ),
    "dig": (
        "dig any {domain} +noall +answer +multiline"
    ),
    "curl_headers": (
        "curl -sI --max-time 15 --user-agent 'Mozilla/5.0' "
        "http://{domain}"
    ),
}

# Execution order — matters! Discovery must happen before live-host checks
MODULE_ORDER = [
    "subfinder",      # Passive subdomain enum
    "amass",          # Deep subdomain enum (runs after subfinder so we can merge)
    "dnsx",           # DNS records
    "dig",            # Any DNS records
    "whois",          # WHOIS data
    "httpx",          # Live host detection (needs subdomain list)
    "nmap",           # Port scan
    "whatweb",        # Tech fingerprinting
    "wafw00f",        # WAF detection
    "curl_headers",   # HTTP headers
    "gobuster",       # Dir brute force
    "nuclei",         # Vuln scanning
    "theHarvester",   # OSINT emails/intel
    "gowitness",      # Screenshots
    "testssl",        # TLS analysis
]

# High-risk ports to flag in results
HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 445, 3389, 5900, 6379, 27017, 1433, 5432, 3306, 2375, 2376, 4848, 9200}


class ScanOrchestrator:
    """
    Orchestrates a full recon scan against a target domain.
    Each module runs as a real OS subprocess. Output is streamed line-by-line
    to all connected WebSocket subscriber queues in real time.
    """

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

        # Output directory for this scan
        self.out_dir = SCANS_DIR / scan_id
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "screenshots").mkdir(exist_ok=True)

        self.results: dict = {}
        self.start_time = time.time()
        self._subdomain_files: List[Path] = []

    # ── Subscriber management ─────────────────────────────────────────────────

    def add_subscriber(self, q: asyncio.Queue):
        self._subscribers.append(q)

    def remove_subscriber(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def broadcast(self, msg: dict):
        """Send a message to all connected WebSocket subscribers."""
        dead = []
        for q in self._subscribers:
            try:
                await q.put(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            self.remove_subscriber(q)

    # ── Cancel ────────────────────────────────────────────────────────────────

    async def cancel(self):
        """Cancel the running scan and kill the active subprocess."""
        self.cancelled = True
        if self._current_proc and self._current_proc.returncode is None:
            try:
                self._current_proc.terminate()
                await asyncio.sleep(1)
                if self._current_proc.returncode is None:
                    self._current_proc.kill()
            except ProcessLookupError:
                pass
        await self.broadcast({"type": "cancelled", "scan_id": self.scan_id})

    # ── Main run loop ─────────────────────────────────────────────────────────

    async def run(self):
        """Main scan loop — runs each module in order."""
        # Only run modules that were requested AND appear in our order list
        ordered_modules = [m for m in MODULE_ORDER if m in self.modules]
        total = len(ordered_modules)

        await self.broadcast({
            "type": "started",
            "scan_id": self.scan_id,
            "domain": self.domain,
            "modules": ordered_modules,
            "total_modules": total,
            "timestamp": datetime.utcnow().isoformat(),
        })

        for idx, module in enumerate(ordered_modules):
            if self.cancelled:
                break

            progress = int((idx / total) * 100)
            await update_scan(self.scan_id, {
                "status": "running",
                "progress": progress,
                "current_module": module,
                "updated_at": datetime.utcnow().isoformat(),
            })
            await self.broadcast({
                "type": "module_start",
                "module": module,
                "index": idx + 1,
                "total": total,
                "progress": progress,
            })

            # Stealth mode: slow down
            if self.stealth and idx > 0:
                await asyncio.sleep(3)

            await self._run_module(module)

        # ── Finalise ──────────────────────────────────────────────────────────
        status = "cancelled" if self.cancelled else "completed"
        duration = int(time.time() - self.start_time)

        await update_scan(self.scan_id, {
            "status": status,
            "progress": 100,
            "current_module": "",
            "results": self.results,
            "duration": duration,
            "completed_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        })

        await self.broadcast({
            "type": "scan_complete",
            "scan_id": self.scan_id,
            "status": status,
            "duration": duration,
            "summary": self._build_summary(),
        })

        # Notify webhooks
        await self._notify_webhooks(status)

        # Signal all subscribers to close
        for q in self._subscribers:
            await q.put(None)

        # Remove from active scans
        active_scans.pop(self.scan_id, None)

    # ── Run a single module ───────────────────────────────────────────────────

    async def _run_module(self, module: str):
        """Execute a single scan module."""

        # Special pre-processing: merge subdomain files before httpx
        if module == "httpx":
            await self._merge_subdomains()

        # Build the command string
        cmd = self._build_command(module)
        if not cmd:
            await self.broadcast({
                "type": "module_skip",
                "module": module,
                "reason": "No command template found",
            })
            return

        # Check if the tool binary exists
        tool_binary = cmd.split()[0]
        if not shutil.which(tool_binary):
            await self.broadcast({
                "type": "module_skip",
                "module": module,
                "reason": f"Tool not installed: {tool_binary}",
                "install_hint": self._install_hint(tool_binary),
            })
            return

        # Broadcast the exact command being run
        await self.broadcast({
            "type": "command",
            "module": module,
            "command": cmd,
        })

        output_lines: List[str] = []

        try:
            env = self._build_env()

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
                cwd=str(self.out_dir),
            )
            self._current_proc = proc

            # Stream stdout line by line
            async for raw_line in proc.stdout:
                if self.cancelled:
                    proc.terminate()
                    break

                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue

                output_lines.append(line)
                await self.broadcast({
                    "type": "output",
                    "module": module,
                    "line": line,
                })

                # Stealth mode: micro-delay per line
                if self.stealth:
                    await asyncio.sleep(0.05)

            await proc.wait()
            self._current_proc = None

            # Track subdomain output files for merging
            if module == "subfinder":
                f = self.out_dir / "subdomains_sf.txt"
                if f.exists() and f.stat().st_size > 0:
                    self._subdomain_files.append(f)

            elif module == "amass":
                f = self.out_dir / "subdomains_am.txt"
                if f.exists() and f.stat().st_size > 0:
                    self._subdomain_files.append(f)

            # Parse tool output into structured data
            parsed = await parse_output(module, output_lines, self.out_dir)
            self.results[module] = parsed

            # Persist to DB after every module completes
            await update_scan(self.scan_id, {
                "results": self.results,
                "updated_at": datetime.utcnow().isoformat(),
            })

            await self.broadcast({
                "type": "module_complete",
                "module": module,
                "parsed": parsed,
                "exit_code": proc.returncode,
                "lines": len(output_lines),
            })

        except asyncio.CancelledError:
            raise
        except Exception as e:
            await self.broadcast({
                "type": "module_error",
                "module": module,
                "error": str(e),
            })

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_command(self, module: str) -> Optional[str]:
        template = COMMANDS.get(module)
        if not template:
            return None

        cmd = template.format(
            domain=self.domain,
            out=str(self.out_dir),
            wordlist=self.wordlist,
            threads=self.threads,
        )

        # Apply proxy if set
        if self.proxy and module in ("gobuster", "nuclei", "httpx", "whatweb", "curl_headers"):
            if module == "gobuster":
                cmd += f" --proxy {self.proxy}"
            elif module == "httpx":
                cmd += f" -proxy {self.proxy}"
            elif module == "curl_headers":
                cmd += f" --proxy {self.proxy}"

        # Apply rate limiting
        if self.rate_limit:
            if module == "gobuster":
                cmd += f" --delay {int(1000 / self.rate_limit)}ms"
            elif module == "nuclei":
                cmd += f" -rate-limit {self.rate_limit}"
            elif module == "httpx":
                cmd += f" -rate-limit {self.rate_limit}"

        return cmd

    def _build_env(self) -> dict:
        env = os.environ.copy()
        # Ensure Go binaries are on PATH
        go_bin = Path.home() / "go" / "bin"
        if str(go_bin) not in env.get("PATH", ""):
            env["PATH"] = f"{go_bin}:{env.get('PATH', '')}"
        # Apply proxy
        if self.proxy:
            env["http_proxy"] = self.proxy
            env["https_proxy"] = self.proxy
            env["HTTP_PROXY"] = self.proxy
            env["HTTPS_PROXY"] = self.proxy
        # Inject API keys from config
        config = self._load_config()
        if config.get("shodan_key"):
            env["SHODAN_API_KEY"] = config["shodan_key"]
        if config.get("github_token"):
            env["GITHUB_TOKEN"] = config["github_token"]
        return env

    def _load_config(self) -> dict:
        config_file = AUTORECON_DIR / "config.json"
        if config_file.exists():
            try:
                return json.loads(config_file.read_text())
            except Exception:
                pass
        return {}

    async def _merge_subdomains(self):
        """Merge all discovered subdomain files into a single deduplicated list."""
        all_subs_file = self.out_dir / "subdomains_all.txt"
        seen: set = set()

        for sf in self._subdomain_files:
            if sf.exists():
                for line in sf.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("["):
                        seen.add(line)

        # Also add the main domain itself
        seen.add(self.domain)

        if seen:
            all_subs_file.write_text("\n".join(sorted(seen)) + "\n")
            await self.broadcast({
                "type": "info",
                "module": "httpx",
                "message": f"Merged {len(seen)} unique subdomains for live-host detection",
            })

    def _build_summary(self) -> dict:
        """Build a quick summary dict of key findings."""
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

    async def _notify_webhooks(self, status: str):
        """Fire Discord/Slack webhooks when scan completes."""
        config = self._load_config()
        if not config.get("discord_webhook") and not config.get("slack_webhook"):
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
                if config.get("discord_webhook"):
                    await session.post(
                        config["discord_webhook"],
                        json={"content": msg},
                        timeout=aiohttp.ClientTimeout(total=5),
                    )
                if config.get("slack_webhook"):
                    await session.post(
                        config["slack_webhook"],
                        json={"text": msg},
                        timeout=aiohttp.ClientTimeout(total=5),
                    )
        except Exception as e:
            print(f"[!] Webhook notification failed: {e}")

    @staticmethod
    def _install_hint(tool: str) -> str:
        hints = {
            "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "amass": "go install github.com/projectdiscovery/amass/v4/...@latest",
            "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "gowitness": "go install github.com/sensepost/gowitness@latest",
            "nmap": "sudo apt install nmap",
            "gobuster": "sudo apt install gobuster",
            "whatweb": "sudo apt install whatweb",
            "wafw00f": "pip3 install wafw00f",
            "theHarvester": "pip3 install theHarvester",
            "testssl.sh": "sudo apt install testssl.sh",
        }
        return hints.get(tool, f"See tool documentation for {tool}")
