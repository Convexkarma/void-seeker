"""Scan orchestration — spawns real OS processes for each recon tool."""

import asyncio
import json
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from db import create_scan, update_scan, add_log, load_config

COMMANDS = {
    "subfinder":    "subfinder -d {domain} -silent -o {out}/subdomains_sf.txt",
    "amass":        "amass enum -passive -d {domain} -o {out}/subdomains_am.txt",
    "httpx":        "httpx -l {out}/subdomains_all.txt -silent -status-code -title -tech-detect -o {out}/live_hosts.txt",
    "nmap":         "nmap -sV -sC -T4 --open -p- {domain} -oX {out}/nmap.xml",
    "gobuster":     "gobuster dir -u https://{domain} -w {wordlist} -t {threads} -o {out}/dirs.txt --no-error -b 404 -k",
    "nuclei":       "nuclei -u http://{domain} -severity low,medium,high,critical -o {out}/nuclei.txt",
    "whatweb":      "whatweb -a 3 http://{domain} --log-json {out}/whatweb.json",
    "gowitness":    "gowitness file -f {out}/live_hosts.txt -P {out}/screenshots/",
    "wafw00f":      "wafw00f http://{domain} -o {out}/waf.txt",
    "dnsx":         "dnsx -d {domain} -a -mx -ns -txt -cname -o {out}/dns.txt",
    "theharvester": "theHarvester -d {domain} -b all -f {out}/harvester",
    "testssl":      "testssl.sh --jsonfile {out}/ssl.json http://{domain}",
}

MODULE_TO_TOOLS = {
    "subdomain":  ["subfinder", "amass"],
    "portscan":   ["nmap"],
    "techfp":     ["whatweb"],
    "dirbrute":   ["gobuster"],
    "vulnscan":   ["nuclei"],
    "screenshot": ["gowitness"],
    "waf":        ["wafw00f"],
    "dns":        ["dnsx"],
    "email":      ["theharvester"],
    "ssl":        ["testssl"],
}

# Track running scans for cancellation
active_scans: dict[str, bool] = {}


def check_tool_installed(tool_name: str) -> Optional[str]:
    """Check if a tool binary is available on PATH."""
    return shutil.which(tool_name)


def check_all_tools() -> dict:
    """Return install status for every known tool."""
    results = {}
    for tool in COMMANDS:
        path = check_tool_installed(tool)
        results[tool] = {"installed": path is not None, "path": path or ""}
    return results


async def run_tool(
    tool: str,
    domain: str,
    out_dir: str,
    wordlist: str,
    threads: int,
    scan_id: str,
    send_line: Callable,
):
    """Run a single tool as a subprocess, streaming stdout/stderr."""
    binary = check_tool_installed(tool)
    if not binary:
        msg = f"[{tool}] ⚠ Not installed — skipping"
        await send_line({"module": tool, "color": "terminal-amber", "text": msg})
        await add_log(scan_id, tool, "warn", f"{tool} not found, skipping")
        return

    cmd_template = COMMANDS.get(tool, "")
    cmd = cmd_template.format(domain=domain, out=out_dir, wordlist=wordlist, threads=threads)

    await send_line({"module": tool, "color": "terminal-blue", "text": f"[{tool}] $ {cmd}"})
    await add_log(scan_id, tool, "info", f"Running: {cmd}")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=out_dir,
        )

        async for line_bytes in proc.stdout:
            if active_scans.get(scan_id) is False:
                proc.terminate()
                await send_line({"module": tool, "color": "terminal-red", "text": f"[{tool}] Cancelled by user"})
                return
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            if line:
                await send_line({"module": tool, "color": "terminal-green", "text": f"[{tool}] {line}"})

        await proc.wait()

        if proc.returncode == 0:
            await send_line({"module": tool, "color": "terminal-green", "text": f"[{tool}] ✓ Complete"})
            await add_log(scan_id, tool, "success", "Completed successfully")
        else:
            await send_line({"module": tool, "color": "terminal-red", "text": f"[{tool}] ✗ Exit code {proc.returncode}"})
            await add_log(scan_id, tool, "error", f"Exited with code {proc.returncode}")

    except Exception as e:
        await send_line({"module": tool, "color": "terminal-red", "text": f"[{tool}] Error: {str(e)}"})
        await add_log(scan_id, tool, "error", str(e))


async def run_scan(
    scan_id: str,
    domain: str,
    modules: list[str],
    profile: str,
    wordlist: str,
    threads: int,
    send_line: Callable,
):
    """Orchestrate a full scan — run enabled modules sequentially."""
    config = load_config()
    out_dir = str(Path.home() / ".autorecon" / "output" / scan_id)
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "screenshots"), exist_ok=True)

    active_scans[scan_id] = True

    await create_scan(scan_id, domain, profile, wordlist, threads, modules)
    await send_line({"module": "System", "color": "terminal-cyan", "text": f"AutoRecon v2.0 — Initializing scan engine..."})
    await send_line({"module": "System", "color": "terminal-cyan", "text": f"Target: {domain} | Profile: {profile} | Threads: {threads}"})
    await send_line({"module": "System", "color": "terminal-cyan", "text": f"Output: {out_dir}"})

    # Resolve wordlist path
    wl = wordlist
    if wordlist == "common":
        wl = "/usr/share/wordlists/dirb/common.txt"
    elif wordlist == "medium":
        wl = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    elif wordlist == "big":
        wl = "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"
    elif config.get("default_wordlist"):
        wl = config["default_wordlist"]

    total_tools = sum(len(MODULE_TO_TOOLS.get(m, [])) for m in modules)
    completed = 0

    for module_id in modules:
        if active_scans.get(scan_id) is False:
            break

        tools = MODULE_TO_TOOLS.get(module_id, [])
        await update_scan(scan_id, active_module=module_id)

        for tool in tools:
            if active_scans.get(scan_id) is False:
                break

            await run_tool(tool, domain, out_dir, wl, threads, scan_id, send_line)
            completed += 1
            progress = int((completed / total_tools) * 100) if total_tools else 100
            await update_scan(scan_id, progress=progress)

    # Merge subdomain files if they exist
    sf_file = os.path.join(out_dir, "subdomains_sf.txt")
    am_file = os.path.join(out_dir, "subdomains_am.txt")
    all_file = os.path.join(out_dir, "subdomains_all.txt")
    subs = set()
    for f in [sf_file, am_file]:
        if os.path.exists(f):
            subs.update(open(f).read().strip().splitlines())
    with open(all_file, "w") as fh:
        fh.write("\n".join(sorted(subs)))

    # Parse results
    from parser import parse_all_results
    results = parse_all_results(out_dir, domain)

    final_status = "cancelled" if active_scans.get(scan_id) is False else "completed"
    await update_scan(
        scan_id,
        status=final_status,
        completed_at=datetime.utcnow().isoformat(),
        progress=100,
        active_module="",
        results=results,
    )

    sub_count = len(results.get("subdomains", []))
    port_count = len(results.get("ports", []))
    vuln_count = len(results.get("vulnerabilities", []))
    await send_line({
        "module": "System",
        "color": "terminal-cyan",
        "text": f"[✓] Scan {final_status} — {sub_count} subdomains, {port_count} ports, {vuln_count} vulnerabilities"
    })

    active_scans.pop(scan_id, None)

    # Send notifications
    await _notify(config, domain, results, final_status)


async def cancel_scan(scan_id: str):
    active_scans[scan_id] = False


async def _notify(config: dict, domain: str, results: dict, status: str):
    """Send Discord/Slack webhook notifications if configured."""
    import aiohttp

    notif = config.get("notifications", {})
    vuln_count = len(results.get("vulnerabilities", []))
    crit = sum(1 for v in results.get("vulnerabilities", []) if v.get("severity") == "critical")
    msg = f"🔍 AutoRecon scan of **{domain}** {status}. Found {vuln_count} vulns ({crit} critical)."

    for webhook_url in [notif.get("discord_webhook"), notif.get("slack_webhook")]:
        if webhook_url:
            try:
                async with aiohttp.ClientSession() as session:
                    payload = {"content": msg} if "discord" in webhook_url else {"text": msg}
                    await session.post(webhook_url, json=payload)
            except Exception:
                pass
