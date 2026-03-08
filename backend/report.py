"""
AutoRecon - report.py
Report Generator — produces HTML, PDF, JSON, and Markdown reports.
HTML report is self-contained (dark themed). PDF uses weasyprint or wkhtmltopdf.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

REPORTS_DIR = Path.home() / ".autorecon" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Severity display config
SEVERITY_COLORS = {
    "critical": ("#ff2d55", "#ff2d5520"),
    "high":     ("#ff9500", "#ff950020"),
    "medium":   ("#ffcc00", "#ffcc0020"),
    "low":      ("#34c759", "#34c75920"),
    "info":     ("#636366", "#63636620"),
}
RISK_COLORS = {
    "high":   "#ff2d55",
    "medium": "#ff9500",
    "low":    "#34c759",
}


# ── Entry Point ───────────────────────────────────────────────────────────────

async def generate_report(scan: Dict[str, Any], fmt: str) -> str:
    """Generate a report in the requested format and return the file path."""
    domain = scan.get("domain", "unknown").replace("/", "_").replace(".", "_")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
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
        html_content = _generate_html(scan)
        html_path.write_text(html_content, encoding="utf-8")

        if fmt == "pdf":
            pdf_path = REPORTS_DIR / f"{base}.pdf"
            converted = await _html_to_pdf(str(html_path), str(pdf_path))
            return converted  # May return html_path on conversion failure

        return str(html_path)

    raise ValueError(f"Unsupported format: {fmt}")


async def _html_to_pdf(html_path: str, pdf_path: str) -> str:
    """Convert HTML to PDF using weasyprint or wkhtmltopdf."""
    import asyncio

    # Try weasyprint first
    try:
        import weasyprint
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
        return pdf_path
    except ImportError:
        pass
    except Exception as e:
        print(f"[!] weasyprint failed: {e}")

    # Try wkhtmltopdf
    try:
        proc = await asyncio.create_subprocess_exec(
            "wkhtmltopdf", "--quiet", html_path, pdf_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=60)
        if Path(pdf_path).exists():
            return pdf_path
    except (FileNotFoundError, asyncio.TimeoutError) as e:
        print(f"[!] wkhtmltopdf failed: {e}")

    # Fallback: return HTML
    print("[!] PDF conversion unavailable — returning HTML report")
    return html_path


# ── Helper: extract data ──────────────────────────────────────────────────────

def _extract(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Pull commonly-needed fields out of the results dict."""
    results = scan.get("results", {})

    subs: set = set()
    for m in ("subfinder", "amass"):
        for s in results.get(m, {}).get("subdomains", []):
            subs.add(s)

    ports       = results.get("nmap", {}).get("ports", [])
    vulns       = results.get("nuclei", {}).get("findings", [])
    dirs        = results.get("gobuster", {}).get("directories", [])
    tech        = results.get("whatweb", {}).get("technologies", [])
    dns_records = results.get("dnsx", {}).get("records", [])
    whois_data  = results.get("whois", {}).get("whois", {})
    whois_raw   = results.get("whois", {}).get("raw", "")
    headers     = results.get("curl_headers", {}).get("headers", {})
    sec_headers = results.get("curl_headers", {}).get("missing_security_headers", [])
    emails      = results.get("theHarvester", {}).get("emails", [])
    waf         = results.get("wafw00f", {}).get("waf")
    live_hosts  = results.get("httpx", {}).get("live_hosts", [])
    screenshots = results.get("gowitness", {}).get("screenshots", [])
    ssl_findings = results.get("testssl", {}).get("findings", [])

    critical = sum(1 for v in vulns if v.get("severity") == "critical")
    high     = sum(1 for v in vulns if v.get("severity") == "high")
    medium   = sum(1 for v in vulns if v.get("severity") == "medium")
    low      = sum(1 for v in vulns if v.get("severity") == "low")

    # Attack surface score
    score = min(100, int(
        len(subs) * 0.5 +
        len(ports) * 2 +
        critical * 20 + high * 10 + medium * 5 + low * 2 +
        len(dirs) * 0.3
    ))

    return {
        "subdomains": sorted(subs),
        "ports": ports,
        "vulns": vulns,
        "dirs": dirs,
        "tech": tech,
        "dns_records": dns_records,
        "whois": whois_data,
        "whois_raw": whois_raw,
        "headers": headers,
        "missing_security_headers": sec_headers,
        "emails": emails,
        "waf": waf,
        "live_hosts": live_hosts,
        "screenshots": screenshots,
        "ssl_findings": ssl_findings,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "score": score,
    }


# ── Markdown Report ───────────────────────────────────────────────────────────

def _generate_markdown(scan: Dict[str, Any]) -> str:
    d = _extract(scan)
    domain = scan.get("domain", "unknown")
    date = scan.get("created_at", datetime.utcnow().isoformat())
    duration = scan.get("duration", 0)
    modules = ", ".join(scan.get("modules", []))

    lines = [
        f"# AutoRecon Report: `{domain}`",
        f"> Generated: {date}  |  Duration: {duration}s  |  Status: {scan.get('status', 'unknown')}",
        f"> Modules: {modules}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Subdomains discovered | {len(d['subdomains'])} |",
        f"| Live hosts | {len(d['live_hosts'])} |",
        f"| Open ports | {len(d['ports'])} |",
        f"| Critical vulnerabilities | {d['critical']} |",
        f"| High vulnerabilities | {d['high']} |",
        f"| Medium vulnerabilities | {d['medium']} |",
        f"| Low vulnerabilities | {d['low']} |",
        f"| Directories found | {len(d['dirs'])} |",
        f"| Emails harvested | {len(d['emails'])} |",
        f"| Attack Surface Score | {d['score']}/100 |",
        "",
    ]

    if d["waf"]:
        lines += [f"> **WAF Detected:** {d['waf']}", ""]

    # Vulnerabilities
    if d["vulns"]:
        lines += ["## Vulnerabilities", ""]
        for v in d["vulns"]:
            sev = v.get("severity", "info").upper()
            tmpl = v.get("template", "Finding")
            url = v.get("url", "")
            lines += [
                f"### [{sev}] {tmpl}",
                f"- **URL:** `{url}`" if url else "",
                f"- **Raw:** `{v.get('raw', '')[:200]}`",
                "",
            ]

    # High-risk ports
    high_risk_ports = [p for p in d["ports"] if p.get("risk") == "high"]
    if high_risk_ports:
        lines += ["## High Risk Open Ports", ""]
        lines += ["| Port | Protocol | Service | Product | Risk Note |",
                  "|------|----------|---------|---------|-----------|"]
        for p in high_risk_ports:
            lines.append(
                f"| {p['port']} | {p['protocol']} | {p['service']} | "
                f"{p.get('product','')} | {p.get('danger_description','')} |"
            )
        lines.append("")

    # All ports
    if d["ports"]:
        lines += ["## All Open Ports", ""]
        lines += ["| Port | Protocol | Service | Version | Risk |",
                  "|------|----------|---------|---------|------|"]
        for p in d["ports"]:
            lines.append(
                f"| {p['port']} | {p['protocol']} | {p['service']} | "
                f"{p.get('product','')} {p.get('version','')} | {p.get('risk','').upper()} |"
            )
        lines.append("")

    # Subdomains
    if d["subdomains"]:
        lines += [f"## Subdomains ({len(d['subdomains'])})", ""]
        for s in d["subdomains"][:100]:
            lines.append(f"- `{s}`")
        if len(d["subdomains"]) > 100:
            lines.append(f"- _... and {len(d['subdomains']) - 100} more_")
        lines.append("")

    # Sensitive directories
    sensitive = [x for x in d["dirs"] if x.get("sensitive")]
    if sensitive:
        lines += ["## Sensitive Directories", ""]
        for di in sensitive:
            lines.append(f"- `{di['path']}` (HTTP {di['status']})")
        lines.append("")

    # Tech stack
    if d["tech"]:
        lines += ["## Technology Stack", ""]
        for t in d["tech"]:
            ver = f" ({t['version']})" if t.get("version") else ""
            lines.append(f"- **{t['name']}**{ver}")
        lines.append("")

    # Missing security headers
    if d["missing_security_headers"]:
        lines += ["## Missing Security Headers", ""]
        for h in d["missing_security_headers"]:
            lines.append(f"- `{h}`")
        lines.append("")

    # Emails
    if d["emails"]:
        lines += [f"## Email Addresses ({len(d['emails'])})", ""]
        for e in d["emails"][:30]:
            lines.append(f"- `{e}`")
        lines.append("")

    # WHOIS
    if d["whois"]:
        lines += ["## WHOIS", ""]
        for k, v in d["whois"].items():
            if isinstance(v, list):
                lines.append(f"- **{k}:** {', '.join(v)}")
            else:
                lines.append(f"- **{k}:** {v}")
        lines.append("")

    lines += [
        "---",
        "",
        "_Report generated by AutoRecon. For authorized penetration testing only._",
    ]

    return "\n".join(l for l in lines if l is not None)


# ── HTML Report ───────────────────────────────────────────────────────────────

def _generate_html(scan: Dict[str, Any]) -> str:
    d = _extract(scan)
    domain = scan.get("domain", "unknown")
    date = scan.get("created_at", datetime.utcnow().isoformat())[:19].replace("T", " ")
    duration = scan.get("duration", 0)
    status = scan.get("status", "unknown")

    score_color = "#ff2d55" if d["score"] > 70 else "#ff9500" if d["score"] > 40 else "#34c759"
    score_label = "HIGH RISK" if d["score"] > 70 else "MODERATE" if d["score"] > 40 else "LIMITED"

    # ── Vulns table rows ──────────────────────────────────────────────────────
    vuln_rows = ""
    for v in d["vulns"]:
        sev = v.get("severity", "info")
        fg, bg = SEVERITY_COLORS.get(sev, ("#636366", "#63636620"))
        vuln_rows += f"""
        <tr>
          <td><span class="badge" style="color:{fg};background:{bg};border:1px solid {fg}">{sev.upper()}</span></td>
          <td class="mono">{_esc(v.get('template',''))}</td>
          <td class="mono url">{_esc(v.get('url',''))}</td>
        </tr>"""

    if not vuln_rows:
        vuln_rows = '<tr><td colspan="3" class="empty">No vulnerabilities found</td></tr>'

    # ── Port rows ─────────────────────────────────────────────────────────────
    port_rows = ""
    for p in d["ports"]:
        c = RISK_COLORS.get(p.get("risk", "low"), "#34c759")
        danger = p.get("danger_description", "")
        port_rows += f"""
        <tr>
          <td style="color:{c};font-weight:700">{p['port']}</td>
          <td class="muted">{p['protocol']}</td>
          <td>{_esc(p.get('service',''))}</td>
          <td class="muted">{_esc(p.get('product',''))} {_esc(p.get('version',''))}</td>
          <td><span class="badge" style="color:{c};background:{c}20;border:1px solid {c}">{p.get('risk','?').upper()}</span></td>
          <td class="muted small">{_esc(danger)}</td>
        </tr>"""

    if not port_rows:
        port_rows = '<tr><td colspan="6" class="empty">No open ports found</td></tr>'

    # ── Subdomain list ────────────────────────────────────────────────────────
    sub_html = ""
    for s in d["subdomains"][:200]:
        sub_html += f'<div class="sub-item"><code>{_esc(s)}</code></div>\n'
    if len(d["subdomains"]) > 200:
        sub_html += f'<div class="muted small">... and {len(d["subdomains"])-200} more</div>'

    # ── Directory rows ────────────────────────────────────────────────────────
    dir_rows = ""
    for di in d["dirs"]:
        sensitive = di.get("sensitive", False)
        status_c = "#34c759" if di["status"] < 300 else "#ffcc00" if di["status"] < 400 else "#636366"
        row_style = 'style="background:#ff2d5508"' if sensitive else ""
        dir_rows += f"""
        <tr {row_style}>
          <td class="mono">{_esc(di['path'])}</td>
          <td style="color:{status_c}">{di['status']}</td>
          <td>{('<span style="color:#ff2d55">⚠ Sensitive</span>' if sensitive else '')}</td>
        </tr>"""

    if not dir_rows:
        dir_rows = '<tr><td colspan="3" class="empty">No directories found</td></tr>'

    # ── Tech badges ───────────────────────────────────────────────────────────
    tech_html = ""
    for t in d["tech"]:
        ver = f' <span class="muted">{_esc(str(t["version"]))}</span>' if t.get("version") else ""
        tech_html += f'<span class="tech-badge">{_esc(t["name"])}{ver}</span>'
    if not tech_html:
        tech_html = '<span class="muted">No technologies detected</span>'

    # ── DNS rows ──────────────────────────────────────────────────────────────
    dns_rows = ""
    for r in d["dns_records"][:50]:
        dns_rows += f"""
        <tr>
          <td class="mono cyan">{_esc(r.get('domain',r.get('name','')))}</td>
          <td class="green">{_esc(r.get('type','?'))}</td>
          <td class="mono">{_esc(r.get('value',''))}</td>
        </tr>"""
    if not dns_rows:
        dns_rows = '<tr><td colspan="3" class="empty">No DNS records</td></tr>'

    # ── WHOIS block ───────────────────────────────────────────────────────────
    whois_html = ""
    for k, v in d["whois"].items():
        val = ", ".join(v) if isinstance(v, list) else str(v)
        whois_html += f'<div class="kv"><span class="kv-key cyan">{_esc(k)}</span><span class="kv-val">{_esc(val)}</span></div>'
    if not whois_html:
        whois_html = '<div class="muted">No WHOIS data</div>'

    # ── Emails ────────────────────────────────────────────────────────────────
    emails_html = ""
    for e in d["emails"][:30]:
        emails_html += f'<div class="sub-item"><code>{_esc(e)}</code></div>'
    if not emails_html:
        emails_html = '<div class="muted">No emails discovered</div>'

    # ── Missing security headers ──────────────────────────────────────────────
    miss_headers_html = ""
    for h in d["missing_security_headers"]:
        miss_headers_html += f'<div class="miss-header">✗ <code>{_esc(h)}</code></div>'
    if not miss_headers_html:
        miss_headers_html = '<div class="green">✓ All major security headers present</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AutoRecon — {_esc(domain)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');
  :root {{
    --bg:       #06060a;
    --card:     #0d0d1a;
    --border:   #1e1e2e;
    --green:    #00ff88;
    --cyan:     #00c8ff;
    --red:      #ff2d55;
    --orange:   #ff9500;
    --yellow:   #ffcc00;
    --muted:    #636366;
    --text:     #e0e0e0;
  }}
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
  .url  {{ max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#00c8ff; }}
  .muted {{ color:var(--muted); }}
  .small {{ font-size:.75rem; }}
  .green {{ color:var(--green); }}
  .cyan  {{ color:var(--cyan);  }}
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
<div class="meta">
  Target: <span>{_esc(domain)}</span> &nbsp;|&nbsp;
  Date: <span>{date} UTC</span> &nbsp;|&nbsp;
  Duration: <span>{duration}s</span> &nbsp;|&nbsp;
  Status: <span>{status.upper()}</span>
</div>

<h2>Attack Surface</h2>
<div class="score-box">
  <div>
    <div class="score-num">{d['score']}</div>
    <div style="color:{score_color};font-size:.8rem">{score_label}</div>
  </div>
  <div style="flex:1">
    <div class="score-bar"><div class="score-fill"></div></div>
    <div class="score-label">{d['score']}/100 attack surface score</div>
  </div>
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
<table>
  <thead><tr><th>Severity</th><th>Template</th><th>URL</th></tr></thead>
  <tbody>{vuln_rows}</tbody>
</table>

<h2>Open Ports ({len(d['ports'])})</h2>
<table>
  <thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Product/Version</th><th>Risk</th><th>Note</th></tr></thead>
  <tbody>{port_rows}</tbody>
</table>

<h2>Subdomains ({len(d['subdomains'])})</h2>
<div class="subs-grid">{sub_html or '<div class="muted">None found</div>'}</div>

<h2>Directories ({len(d['dirs'])})</h2>
<table>
  <thead><tr><th>Path</th><th>Status</th><th>Flag</th></tr></thead>
  <tbody>{dir_rows}</tbody>
</table>

<h2>Technology Stack</h2>
<div style="margin-bottom:1rem">{tech_html}</div>

<h2>DNS Records</h2>
<table>
  <thead><tr><th>Domain</th><th>Type</th><th>Value</th></tr></thead>
  <tbody>{dns_rows}</tbody>
</table>

<h2>WHOIS</h2>
{whois_html}

<h2>Security Headers</h2>
{miss_headers_html}

<h2>Harvested Emails</h2>
{emails_html}

<div class="footer">
  ⚠ This report is for authorized penetration testing only. Generated by AutoRecon v1.0.0.
</div>

</body>
</html>"""


def _esc(s: str) -> str:
    """HTML-escape a string."""
    if not isinstance(s, str):
        s = str(s) if s is not None else ""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))
