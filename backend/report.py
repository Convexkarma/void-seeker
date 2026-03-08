"""
AutoRecon - report.py
Report generator — HTML, PDF, JSON, Markdown.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPORTS_DIR = Path.home() / ".autorecon" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SEVERITY_COLORS = {
    "critical": ("#ff2d55", "#ff2d5520"),
    "high":     ("#ff9500", "#ff950020"),
    "medium":   ("#ffcc00", "#ffcc0020"),
    "low":      ("#34c759", "#34c75920"),
    "info":     ("#636366", "#63636620"),
}
RISK_COLORS = {"high": "#ff2d55", "medium": "#ff9500", "low": "#34c759"}


# ── Entry Point ───────────────────────────────────────────────────────────────

async def generate_report(scan: Dict[str, Any], fmt: str) -> str:
    domain = scan.get("domain", "unknown").replace("/", "_").replace(".", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"autorecon_{domain}_{ts}"

    if fmt == "json":
        out = REPORTS_DIR / f"{base}.json"
        out.write_text(json.dumps(scan, indent=2, default=str))
        return str(out)

    if fmt == "md":
        out = REPORTS_DIR / f"{base}.md"
        out.write_text(_generate_markdown(scan))
        return str(out)

    if fmt in ("html", "pdf"):
        html_path = REPORTS_DIR / f"{base}.html"
        html_path.write_text(_generate_html(scan), encoding="utf-8")
        if fmt == "pdf":
            pdf_path = REPORTS_DIR / f"{base}.pdf"
            return await _html_to_pdf(str(html_path), str(pdf_path))
        return str(html_path)

    raise ValueError(f"Unsupported format: {fmt}")


async def _html_to_pdf(html_path: str, pdf_path: str) -> str:
    try:
        import weasyprint
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
        return pdf_path
    except ImportError:
        pass
    except Exception as exc:
        print(f"[!] weasyprint failed: {exc}")

    try:
        proc = await asyncio.create_subprocess_exec(
            "wkhtmltopdf", "--quiet", html_path, pdf_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=60)
        if Path(pdf_path).exists():
            return pdf_path
    except (FileNotFoundError, asyncio.TimeoutError) as exc:
        print(f"[!] wkhtmltopdf failed: {exc}")

    print("[!] PDF conversion unavailable — returning HTML")
    return html_path


# ── Data Extraction ───────────────────────────────────────────────────────────

def _extract(scan: Dict[str, Any]) -> Dict[str, Any]:
    r = scan.get("results") or {}

    subs: set = set()
    for m in ("subfinder", "amass"):
        for s in (r.get(m) or {}).get("subdomains", []):
            subs.add(s)

    ports       = (r.get("nmap") or {}).get("ports", [])
    vulns       = (r.get("nuclei") or {}).get("findings", [])
    dirs        = (r.get("gobuster") or {}).get("directories", [])
    tech        = (r.get("whatweb") or {}).get("technologies", [])
    dns_records = (r.get("dnsx") or {}).get("records", [])
    whois_data  = (r.get("whois") or {}).get("whois", {})
    whois_raw   = (r.get("whois") or {}).get("raw", "")
    headers     = (r.get("curl_headers") or {}).get("headers", {})
    sec_headers = (r.get("curl_headers") or {}).get("missing_security_headers", [])
    emails      = (r.get("theHarvester") or {}).get("emails", [])
    waf         = (r.get("wafw00f") or {}).get("waf")
    live_hosts  = (r.get("httpx") or {}).get("live_hosts", [])
    screenshots = (r.get("gowitness") or {}).get("screenshots", [])
    ssl_findings = (r.get("testssl") or {}).get("findings", [])

    critical = sum(1 for v in vulns if v.get("severity") == "critical")
    high     = sum(1 for v in vulns if v.get("severity") == "high")
    medium   = sum(1 for v in vulns if v.get("severity") == "medium")
    low      = sum(1 for v in vulns if v.get("severity") == "low")

    score = min(100, int(
        len(subs) * 0.5 + len(ports) * 2 +
        critical * 20 + high * 10 + medium * 5 + low * 2 + len(dirs) * 0.3
    ))

    return {
        "subdomains": sorted(subs), "ports": ports, "vulns": vulns, "dirs": dirs,
        "tech": tech, "dns_records": dns_records, "whois": whois_data,
        "whois_raw": whois_raw, "headers": headers,
        "missing_security_headers": sec_headers, "emails": emails,
        "waf": waf, "live_hosts": live_hosts, "screenshots": screenshots,
        "ssl_findings": ssl_findings,
        "critical": critical, "high": high, "medium": medium, "low": low,
        "score": score,
    }


# ── Markdown ──────────────────────────────────────────────────────────────────

def _generate_markdown(scan: Dict[str, Any]) -> str:
    d = _extract(scan)
    domain = scan.get("domain", "unknown")
    date = scan.get("created_at", "")
    duration = scan.get("duration", 0)
    modules = ", ".join(scan.get("modules", []))

    lines = [
        f"# AutoRecon Report: `{domain}`",
        f"> Generated: {date} | Duration: {duration}s | Status: {scan.get('status', 'unknown')}",
        f"> Modules: {modules}", "", "---", "",
        "## Executive Summary", "",
        "| Metric | Count |", "|--------|-------|",
        f"| Subdomains | {len(d['subdomains'])} |",
        f"| Live hosts | {len(d['live_hosts'])} |",
        f"| Open ports | {len(d['ports'])} |",
        f"| Critical vulns | {d['critical']} |",
        f"| High vulns | {d['high']} |",
        f"| Medium vulns | {d['medium']} |",
        f"| Low vulns | {d['low']} |",
        f"| Directories | {len(d['dirs'])} |",
        f"| Emails | {len(d['emails'])} |",
        f"| Attack Surface Score | {d['score']}/100 |", "",
    ]

    if d["waf"]:
        lines += [f"> **WAF Detected:** {d['waf']}", ""]

    if d["vulns"]:
        lines += ["## Vulnerabilities", ""]
        for v in d["vulns"]:
            lines += [f"### [{v.get('severity','info').upper()}] {v.get('template','Finding')}"]
            if v.get("url"):
                lines.append(f"- **URL:** `{v['url']}`")
            lines += [f"- **Raw:** `{v.get('raw','')[:200]}`", ""]

    high_risk = [p for p in d["ports"] if p.get("risk") == "high"]
    if high_risk:
        lines += ["## High Risk Ports", "", "| Port | Proto | Service | Note |", "|------|-------|---------|------|"]
        for p in high_risk:
            lines.append(f"| {p['port']} | {p['protocol']} | {p['service']} | {p.get('danger_description','')} |")
        lines.append("")

    if d["ports"]:
        lines += ["## All Open Ports", "", "| Port | Proto | Service | Version | Risk |", "|------|-------|---------|---------|------|"]
        for p in d["ports"]:
            lines.append(f"| {p['port']} | {p['protocol']} | {p['service']} | {p.get('product','')} {p.get('version','')} | {p.get('risk','').upper()} |")
        lines.append("")

    if d["subdomains"]:
        lines += [f"## Subdomains ({len(d['subdomains'])})", ""]
        for s in d["subdomains"][:100]:
            lines.append(f"- `{s}`")
        if len(d["subdomains"]) > 100:
            lines.append(f"- _... and {len(d['subdomains']) - 100} more_")
        lines.append("")

    sensitive = [x for x in d["dirs"] if x.get("sensitive")]
    if sensitive:
        lines += ["## Sensitive Directories", ""]
        for di in sensitive:
            lines.append(f"- `{di['path']}` (HTTP {di['status']})")
        lines.append("")

    if d["tech"]:
        lines += ["## Technology Stack", ""]
        for t in d["tech"]:
            ver = f" ({t['version']})" if t.get("version") else ""
            lines.append(f"- **{t['name']}**{ver}")
        lines.append("")

    if d["missing_security_headers"]:
        lines += ["## Missing Security Headers", ""]
        for h in d["missing_security_headers"]:
            lines.append(f"- `{h}`")
        lines.append("")

    if d["emails"]:
        lines += [f"## Email Addresses ({len(d['emails'])})", ""]
        for e in d["emails"][:30]:
            lines.append(f"- `{e}`")
        lines.append("")

    if d["whois"]:
        lines += ["## WHOIS", ""]
        for k, v in d["whois"].items():
            val = ", ".join(v) if isinstance(v, list) else str(v)
            lines.append(f"- **{k}:** {val}")
        lines.append("")

    lines += ["---", "", "_Report generated by AutoRecon. For authorized testing only._"]
    return "\n".join(l for l in lines if l is not None)


# ── HTML ──────────────────────────────────────────────────────────────────────

def _esc(s: Any) -> str:
    if not isinstance(s, str):
        s = str(s) if s is not None else ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _generate_html(scan: Dict[str, Any]) -> str:
    d = _extract(scan)
    domain = scan.get("domain", "unknown")
    date = scan.get("created_at", "")[:19].replace("T", " ")
    duration = scan.get("duration", 0)
    status = scan.get("status", "unknown")

    score_color = "#ff2d55" if d["score"] > 70 else "#ff9500" if d["score"] > 40 else "#34c759"
    score_label = "HIGH RISK" if d["score"] > 70 else "MODERATE" if d["score"] > 40 else "LIMITED"

    # Vulns rows
    vuln_rows = ""
    for v in d["vulns"]:
        sev = v.get("severity", "info")
        fg, bg = SEVERITY_COLORS.get(sev, ("#636366", "#63636620"))
        vuln_rows += f'<tr><td><span class="badge" style="color:{fg};background:{bg};border:1px solid {fg}">{sev.upper()}</span></td><td class="mono">{_esc(v.get("template",""))}</td><td class="mono url">{_esc(v.get("url",""))}</td></tr>'
    if not vuln_rows:
        vuln_rows = '<tr><td colspan="3" class="empty">No vulnerabilities found</td></tr>'

    # Port rows
    port_rows = ""
    for p in d["ports"]:
        c = RISK_COLORS.get(p.get("risk", "low"), "#34c759")
        port_rows += f'<tr><td style="color:{c};font-weight:700">{p["port"]}</td><td class="muted">{p["protocol"]}</td><td>{_esc(p.get("service",""))}</td><td class="muted">{_esc(p.get("product",""))} {_esc(p.get("version",""))}</td><td><span class="badge" style="color:{c};background:{c}20;border:1px solid {c}">{p.get("risk","?").upper()}</span></td><td class="muted small">{_esc(p.get("danger_description",""))}</td></tr>'
    if not port_rows:
        port_rows = '<tr><td colspan="6" class="empty">No open ports found</td></tr>'

    # Subdomains
    sub_html = "".join(f'<div class="sub-item"><code>{_esc(s)}</code></div>' for s in d["subdomains"][:200])
    if len(d["subdomains"]) > 200:
        sub_html += f'<div class="muted small">... and {len(d["subdomains"])-200} more</div>'

    # Dirs
    dir_rows = ""
    for di in d["dirs"]:
        sensitive = di.get("sensitive", False)
        sc = "#34c759" if di["status"] < 300 else "#ffcc00" if di["status"] < 400 else "#636366"
        rs = 'style="background:#ff2d5508"' if sensitive else ""
        flag = '<span style="color:#ff2d55">⚠ Sensitive</span>' if sensitive else ""
        dir_rows += f'<tr {rs}><td class="mono">{_esc(di["path"])}</td><td style="color:{sc}">{di["status"]}</td><td>{flag}</td></tr>'
    if not dir_rows:
        dir_rows = '<tr><td colspan="3" class="empty">No directories found</td></tr>'

    # Tech
    tech_html = "".join(f'<span class="tech-badge">{_esc(t["name"])}{f" <span class=muted>{_esc(str(t["version"]))}</span>" if t.get("version") else ""}</span>' for t in d["tech"])
    if not tech_html:
        tech_html = '<span class="muted">No technologies detected</span>'

    # DNS
    dns_rows = "".join(f'<tr><td class="mono cyan">{_esc(r.get("domain",r.get("name","")))}</td><td class="green">{_esc(r.get("type","?"))}</td><td class="mono">{_esc(r.get("value",""))}</td></tr>' for r in d["dns_records"][:50])
    if not dns_rows:
        dns_rows = '<tr><td colspan="3" class="empty">No DNS records</td></tr>'

    # WHOIS
    whois_html = "".join(f'<div class="kv"><span class="kv-key cyan">{_esc(k)}</span><span class="kv-val">{_esc(", ".join(v) if isinstance(v, list) else str(v))}</span></div>' for k, v in d["whois"].items())
    if not whois_html:
        whois_html = '<div class="muted">No WHOIS data</div>'

    # Emails
    emails_html = "".join(f'<div class="sub-item"><code>{_esc(e)}</code></div>' for e in d["emails"][:30])
    if not emails_html:
        emails_html = '<div class="muted">No emails discovered</div>'

    # Missing headers
    miss_html = "".join(f'<div class="miss-header">✗ <code>{_esc(h)}</code></div>' for h in d["missing_security_headers"])
    if not miss_html:
        miss_html = '<div class="green">✓ All major security headers present</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AutoRecon — {_esc(domain)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');
:root {{ --bg:#06060a; --card:#0d0d1a; --border:#1e1e2e; --green:#00ff88; --cyan:#00c8ff; --red:#ff2d55; --orange:#ff9500; --yellow:#ffcc00; --muted:#636366; --text:#e0e0e0; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:'JetBrains Mono',monospace; font-size:13px; line-height:1.6; padding:2rem; }}
h1 {{ color:var(--green); font-size:1.8rem; margin-bottom:.25rem; text-shadow:0 0 20px rgba(0,255,136,.4); }}
h2 {{ color:var(--cyan); font-size:1rem; border-bottom:1px solid var(--border); padding-bottom:.5rem; margin:2.5rem 0 1rem; text-transform:uppercase; letter-spacing:.1em; }}
.meta {{ color:var(--muted); font-size:.8rem; margin-bottom:2rem; }}
.meta span {{ color:var(--text); }}
.stats {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:2rem; }}
.stat {{ background:var(--card); border:1px solid var(--border); padding:1rem 1.5rem; min-width:110px; }}
.stat-num {{ font-size:2rem; font-weight:700; color:var(--green); }}
.stat-label {{ color:var(--muted); font-size:.75rem; text-transform:uppercase; }}
.score-box {{ background:var(--card); border:1px solid var(--border); padding:1.5rem; display:flex; align-items:center; gap:2rem; }}
.score-num {{ font-size:3.5rem; font-weight:700; color:{score_color}; }}
.score-bar {{ flex:1; height:8px; background:var(--border); border-radius:4px; overflow:hidden; }}
.score-fill {{ height:100%; background:linear-gradient(90deg,var(--green),{score_color}); width:{d['score']}%; }}
.score-label {{ color:{score_color}; font-size:.9rem; margin-top:.25rem; }}
table {{ width:100%; border-collapse:collapse; margin-bottom:1rem; }}
th {{ background:var(--card); color:var(--cyan); padding:.6rem .75rem; text-align:left; border:1px solid var(--border); font-weight:500; text-transform:uppercase; font-size:.75rem; letter-spacing:.05em; }}
td {{ padding:.6rem .75rem; border:1px solid var(--border); }}
tr:hover td {{ background:#0d0d1a; }}
.badge {{ padding:.2rem .6rem; border-radius:3px; font-size:.7rem; font-weight:700; letter-spacing:.05em; white-space:nowrap; }}
.mono {{ font-family:'JetBrains Mono',monospace; }}
.url {{ max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#00c8ff; }}
.muted {{ color:var(--muted); }}
.small {{ font-size:.75rem; }}
.green {{ color:var(--green); }}
.cyan {{ color:var(--cyan); }}
.empty {{ color:var(--muted); text-align:center; padding:1.5rem; }}
.sub-item {{ padding:.2rem 0; color:var(--green); font-family:monospace; }}
.subs-grid {{ column-count:3; column-gap:1rem; }}
.tech-badge {{ display:inline-block; background:var(--card); border:1px solid var(--border); padding:.3rem .75rem; margin:.2rem; border-radius:20px; }}
.kv {{ display:flex; gap:1rem; padding:.3rem 0; border-bottom:1px solid var(--border); }}
.kv-key {{ color:var(--cyan); min-width:160px; }}
.miss-header {{ color:var(--red); padding:.2rem 0; }}
.waf-badge {{ display:inline-block; padding:.4rem 1rem; background:#ff950020; border:1px solid var(--orange); color:var(--orange); margin-bottom:1rem; }}
.footer {{ margin-top:3rem; padding-top:1rem; border-top:1px solid var(--border); color:var(--muted); font-size:.75rem; }}
@media print {{ body {{ background:#fff; color:#000; }} h1,h2 {{ color:#000; }} }}
</style>
</head>
<body>
<h1>🔍 AutoRecon Report</h1>
<div class="meta">Target: <span>{_esc(domain)}</span> | Date: <span>{date} UTC</span> | Duration: <span>{duration}s</span> | Status: <span>{status.upper()}</span></div>

<h2>Attack Surface</h2>
<div class="score-box">
  <div><div class="score-num">{d['score']}</div><div style="color:{score_color};font-size:.8rem">{score_label}</div></div>
  <div style="flex:1"><div class="score-bar"><div class="score-fill"></div></div><div class="score-label">{d['score']}/100 attack surface score</div></div>
</div>

<h2>Summary</h2>
<div class="stats">
  <div class="stat"><div class="stat-num">{len(d['subdomains'])}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat"><div class="stat-num">{len(d['live_hosts'])}</div><div class="stat-label">Live Hosts</div></div>
  <div class="stat"><div class="stat-num">{len(d['ports'])}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat"><div class="stat-num" style="color:var(--red)">{d['critical']}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-num" style="color:var(--orange)">{d['high']}</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-num" style="color:var(--yellow)">{d['medium']}</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-num">{len(d['dirs'])}</div><div class="stat-label">Directories</div></div>
  <div class="stat"><div class="stat-num">{len(d['emails'])}</div><div class="stat-label">Emails</div></div>
</div>
{f'<div class="waf-badge">⚡ WAF Detected: {_esc(str(d["waf"]))}</div>' if d['waf'] else ''}

<h2>Vulnerabilities</h2>
<table><thead><tr><th>Severity</th><th>Template</th><th>URL</th></tr></thead><tbody>{vuln_rows}</tbody></table>

<h2>Open Ports ({len(d['ports'])})</h2>
<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Product/Version</th><th>Risk</th><th>Note</th></tr></thead><tbody>{port_rows}</tbody></table>

<h2>Subdomains ({len(d['subdomains'])})</h2>
<div class="subs-grid">{sub_html or '<div class="muted">None found</div>'}</div>

<h2>Directories ({len(d['dirs'])})</h2>
<table><thead><tr><th>Path</th><th>Status</th><th>Flag</th></tr></thead><tbody>{dir_rows}</tbody></table>

<h2>Technology Stack</h2>
<div style="margin-bottom:1rem">{tech_html}</div>

<h2>DNS Records</h2>
<table><thead><tr><th>Domain</th><th>Type</th><th>Value</th></tr></thead><tbody>{dns_rows}</tbody></table>

<h2>WHOIS</h2>
{whois_html}

<h2>Security Headers</h2>
{miss_html}

<h2>Harvested Emails</h2>
{emails_html}

<div class="footer">⚠ This report is for authorized penetration testing only. Generated by AutoRecon v2.0.0.</div>
</body>
</html>"""
