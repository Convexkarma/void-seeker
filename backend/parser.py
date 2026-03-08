"""
AutoRecon - parser.py
Tool output parsers — converts raw stdout / file output into structured JSON.
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List


# ── Dispatcher ────────────────────────────────────────────────────────────────

async def parse_output(module: str, lines: List[str], out_dir: Path) -> Dict[str, Any]:
    handlers = {
        "subfinder":    _parse_subfinder,
        "amass":        _parse_amass,
        "httpx":        _parse_httpx,
        "nmap":         _parse_nmap,
        "gobuster":     _parse_gobuster,
        "nuclei":       _parse_nuclei,
        "whatweb":      _parse_whatweb,
        "wafw00f":      _parse_wafw00f,
        "dnsx":         _parse_dnsx,
        "dig":          _parse_dig,
        "whois":        _parse_whois,
        "curl_headers": _parse_curl_headers,
        "theHarvester": _parse_harvester,
        "testssl":      _parse_testssl,
        "gowitness":    _parse_gowitness,
    }
    handler = handlers.get(module)
    if not handler:
        return {"raw": lines[:500], "count": 0}
    try:
        return handler(lines, out_dir)
    except Exception as exc:
        return {"raw": lines[:500], "error": str(exc), "count": 0}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dedup(items: list) -> list:
    return list(dict.fromkeys(items))


def _read_lines(path: Path) -> List[str]:
    if path.exists():
        return [l.strip() for l in path.read_text().splitlines() if l.strip()]
    return []


def _is_subdomain(s: str) -> bool:
    return bool(s) and "." in s and " " not in s and len(s) < 255


# ── Subfinder ─────────────────────────────────────────────────────────────────

def _parse_subfinder(lines: List[str], out_dir: Path) -> dict:
    subs = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("\\"):
            continue
        if _is_subdomain(line):
            subs.append(line.lower())

    for line in _read_lines(out_dir / "subdomains_sf.txt"):
        l = line.lower()
        if _is_subdomain(l) and l not in subs:
            subs.append(l)

    subs = sorted(_dedup(subs))
    return {"subdomains": subs, "count": len(subs), "source": "subfinder"}


# ── Amass ─────────────────────────────────────────────────────────────────────

def _parse_amass(lines: List[str], out_dir: Path) -> dict:
    subs = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("["):
            continue
        candidate = line.split(" --> ")[0].strip() if " --> " in line else (line.split()[0] if " " in line else line)
        candidate = candidate.lower().strip()
        if _is_subdomain(candidate):
            subs.append(candidate)

    for line in _read_lines(out_dir / "subdomains_am.txt"):
        l = line.lower()
        if _is_subdomain(l) and l not in subs:
            subs.append(l)

    subs = sorted(_dedup(subs))
    return {"subdomains": subs, "count": len(subs), "source": "amass"}


# ── HTTPX ─────────────────────────────────────────────────────────────────────

def _parse_httpx(lines: List[str], out_dir: Path) -> dict:
    hosts = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("["):
            continue
        entry: Dict[str, Any] = {"url": "", "status": None, "title": None, "tech": [], "content_length": None}
        parts = line.split()
        if parts:
            entry["url"] = parts[0]

        brackets = re.findall(r"\[([^\]]+)\]", line)
        for b in brackets:
            b = b.strip()
            if b.isdigit():
                entry["status"] = int(b)
            elif "," in b:
                entry["tech"] = [t.strip() for t in b.split(",") if t.strip()]
            elif entry["title"] is None and len(b) < 100:
                entry["title"] = b

        if entry["url"]:
            hosts.append(entry)

    if not hosts:
        for line in _read_lines(out_dir / "live_hosts.txt"):
            hosts.append({"url": line, "status": None, "title": None, "tech": []})

    return {"live_hosts": hosts, "count": len(hosts), "urls": [h["url"] for h in hosts]}


# ── Nmap ──────────────────────────────────────────────────────────────────────

_HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 445, 512, 513, 514, 1433, 1521, 2375, 2376,
                    3306, 3389, 4848, 5432, 5900, 5985, 6379, 9200, 9300, 11211, 27017, 50070}
_MEDIUM_RISK_PORTS = {80, 8080, 8443, 8888, 110, 143, 161, 993, 995, 3000, 4000, 5000}

_DANGER_NOTES = {
    21: "FTP — Cleartext auth, anonymous login",
    22: "SSH — Brute force, weak ciphers",
    23: "Telnet — Cleartext protocol",
    25: "SMTP — Open relay, user enumeration",
    53: "DNS — Zone transfer, amplification",
    445: "SMB — EternalBlue, Pass-the-Hash",
    1433: "MSSQL — SA brute force, xp_cmdshell",
    1521: "Oracle — TNS listener attacks",
    2375: "Docker API — Unauthenticated socket",
    3306: "MySQL — Brute force, file read",
    3389: "RDP — BlueKeep, brute force",
    5432: "PostgreSQL — Brute force, COPY PROGRAM",
    5900: "VNC — No-auth mode",
    6379: "Redis — Unauthenticated RCE",
    9200: "Elasticsearch — Unauthenticated data access",
    27017: "MongoDB — Unauthenticated access",
}


def _port_risk(port: int) -> str:
    if port in _HIGH_RISK_PORTS:
        return "high"
    if port in _MEDIUM_RISK_PORTS:
        return "medium"
    return "low"


def _parse_nmap(lines: List[str], out_dir: Path) -> dict:
    ports: List[dict] = []
    hosts: List[dict] = []

    xml_file = out_dir / "nmap.xml"
    if xml_file.exists():
        try:
            root = ET.parse(xml_file).getroot()
            for host in root.findall("host"):
                addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
                ip = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"
                hn_el = host.find(".//hostname")
                hostname = hn_el.get("name", "") if hn_el is not None else ""
                hosts.append({"ip": ip, "hostname": hostname})

                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    pnum = int(port_el.get("portid", 0))
                    svc = port_el.find("service")
                    scripts = {s.get("id", ""): s.get("output", "")[:200] for s in port_el.findall("script")}
                    ports.append({
                        "port": pnum,
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": "open",
                        "service": svc.get("name", "") if svc is not None else "",
                        "product": svc.get("product", "") if svc is not None else "",
                        "version": svc.get("version", "") if svc is not None else "",
                        "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                        "tunnel": svc.get("tunnel", "") if svc is not None else "",
                        "ip": ip, "hostname": hostname,
                        "risk": _port_risk(pnum),
                        "danger_description": _DANGER_NOTES.get(pnum, ""),
                        "scripts": scripts,
                    })
        except ET.ParseError as exc:
            print(f"[!] Nmap XML parse error: {exc}")

    # Text fallback
    if not ports:
        current_ip = ""
        for line in lines:
            ip_m = re.match(r"Nmap scan report for (?:.*\()?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if ip_m:
                current_ip = ip_m.group(1)
            port_m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if port_m:
                pnum = int(port_m.group(1))
                ports.append({
                    "port": pnum, "protocol": port_m.group(2), "state": "open",
                    "service": port_m.group(3), "product": port_m.group(4).strip(),
                    "version": "", "ip": current_ip,
                    "risk": _port_risk(pnum),
                    "danger_description": _DANGER_NOTES.get(pnum, ""),
                    "scripts": {},
                })

    ports.sort(key=lambda p: p["port"])
    return {
        "ports": ports, "count": len(ports), "hosts": hosts,
        "high_risk": [p for p in ports if p["risk"] == "high"],
        "open_port_numbers": [p["port"] for p in ports],
    }


# ── Gobuster ──────────────────────────────────────────────────────────────────

_SENSITIVE_PATHS = {
    ".git", ".env", ".htaccess", ".htpasswd", ".svn", ".DS_Store",
    "admin", "administrator", "wp-admin", "phpmyadmin", "phpinfo",
    "backup", "backups", "db", "database", "dump",
    "config", "configuration", "settings",
    "api", "swagger", "openapi", "graphql",
    "console", "debug", "actuator", "metrics", "health", "info",
    "upload", "uploads", "files", "tmp", "temp",
    "test", "testing", "dev", "staging",
    "robots.txt", "sitemap.xml", ".well-known",
}


def _parse_gobuster(lines: List[str], out_dir: Path) -> dict:
    directories: List[dict] = []
    for line in lines:
        if line.startswith("[") or "Progress:" in line or not line.strip():
            continue
        m = re.search(r"(/.+?)\s+\(Status:\s*(\d+)\)", line)
        if m:
            path, status = m.group(1).split()[0], int(m.group(2))
        else:
            m2 = re.match(r"(/\S+)\s+(\d{3})\s+", line.strip())
            if not m2:
                continue
            path, status = m2.group(1), int(m2.group(2))

        path_lower = path.lower()
        is_sensitive = any(s in path_lower for s in _SENSITIVE_PATHS)
        size_m = re.search(r"\[Size:\s*(\d+)\]", line)
        directories.append({
            "path": path, "status": status,
            "size": int(size_m.group(1)) if size_m else None,
            "sensitive": is_sensitive,
            "interesting": is_sensitive or status in (200, 201, 204, 301, 302, 307),
        })

    directories.sort(key=lambda d: (not d["sensitive"], d["status"]))
    return {
        "directories": directories, "count": len(directories),
        "sensitive": [d for d in directories if d["sensitive"]],
        "sensitive_count": sum(1 for d in directories if d["sensitive"]),
    }


# ── Nuclei ────────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _parse_nuclei(lines: List[str], out_dir: Path) -> dict:
    findings: List[dict] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("[INF]") or line.startswith("[WRN]"):
            continue

        severity = "info"
        for sev in ("critical", "high", "medium", "low", "info"):
            if f"[{sev}]" in line.lower():
                severity = sev
                break

        tmpl_m = re.search(r"\[([a-z0-9_\-:]+)\]", line)
        template_id = tmpl_m.group(1) if tmpl_m else ""
        clean = re.sub(r"\[\d{4}-\d{2}-\d{2}[^\]]*\]", "", line).strip()
        url_m = re.search(r"https?://\S+", clean)
        url = url_m.group(0).rstrip("])") if url_m else ""

        matcher = ""
        for item in re.findall(r"\[([^\]]+)\]", clean):
            if item not in (template_id, severity) and "://" not in item:
                matcher = item
                break

        findings.append({
            "template": template_id, "severity": severity,
            "url": url, "matcher": matcher,
            "raw": line[:300], "type": "vulnerability",
        })

    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 5))
    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in ("critical", "high", "medium", "low", "info")}
    return {"findings": findings, "count": len(findings), **counts}


# ── WhatWeb ───────────────────────────────────────────────────────────────────

def _parse_whatweb(lines: List[str], out_dir: Path) -> dict:
    technologies: List[dict] = []

    json_file = out_dir / "whatweb.json"
    if json_file.exists():
        try:
            for json_line in json_file.read_text().strip().splitlines():
                if not json_line.strip():
                    continue
                try:
                    entry = json.loads(json_line)
                    for name, data in entry.get("plugins", {}).items():
                        ver = None
                        if isinstance(data, dict):
                            versions = data.get("version", [])
                            ver = versions[0] if versions else None
                        technologies.append({"name": name, "version": ver, "info": None, "raw": data})
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    if not technologies:
        for line in lines:
            for name, info in re.findall(r"([\w\s\-\.]+)\[([^\]]*)\]", line):
                name = name.strip()
                if name and name not in ("http", "https") and len(name) < 50:
                    technologies.append({"name": name, "version": info or None, "info": None})

    seen: set = set()
    unique = []
    for t in technologies:
        if t["name"] not in seen:
            seen.add(t["name"])
            unique.append(t)

    return {"technologies": unique, "count": len(unique), "names": [t["name"] for t in unique]}


# ── WAFw00f ───────────────────────────────────────────────────────────────────

def _parse_wafw00f(lines: List[str], out_dir: Path) -> dict:
    waf_detected = None
    protected = False

    for line in lines:
        ll = line.lower()
        if "is behind" in ll:
            protected = True
            m = re.search(r"is behind (.+?)(?:\s+WAF)?$", line, re.IGNORECASE)
            if m:
                waf_detected = m.group(1).strip()
        elif "no waf" in ll or "not behind" in ll:
            protected = False
            waf_detected = None
        elif "generic" in ll and ("detect" in ll or "block" in ll):
            protected = True
            waf_detected = "Generic WAF"

    if not waf_detected:
        waf_file = out_dir / "waf.txt"
        if waf_file.exists():
            content = waf_file.read_text()
            if "is behind" in content.lower():
                protected = True
                m = re.search(r"is behind (.+?)(?:\s+WAF)?", content, re.IGNORECASE)
                if m:
                    waf_detected = m.group(1).strip()

    return {"protected": protected, "waf": waf_detected, "raw": "\n".join(lines[:50])}


# ── DNSX ──────────────────────────────────────────────────────────────────────

_DNS_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "ANY"}


def _parse_dnsx(lines: List[str], out_dir: Path) -> dict:
    records: List[dict] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("["):
            continue

        brackets = re.findall(r"\[([^\]]+)\]", line)
        if brackets:
            domain_part = line.split("[")[0].strip()
            rtype = None
            values = []
            for b in brackets:
                b = b.strip()
                if b in _DNS_TYPES:
                    rtype = b
                elif b:
                    values.append(b)
            for val in values:
                records.append({"domain": domain_part, "type": rtype or "?", "value": val})
        else:
            parts = line.split()
            if len(parts) >= 3:
                records.append({"domain": parts[0], "type": parts[1] if parts[1] in _DNS_TYPES else "?", "value": " ".join(parts[2:])})
            elif len(parts) == 2:
                records.append({"domain": parts[0], "type": "?", "value": parts[1]})

    return {"records": records, "count": len(records), "types": list({r["type"] for r in records})}


# ── Dig ───────────────────────────────────────────────────────────────────────

def _parse_dig(lines: List[str], out_dir: Path) -> dict:
    records = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5:
            records.append({"name": parts[0], "ttl": parts[1], "class": parts[2], "type": parts[3], "value": " ".join(parts[4:])})
    return {"records": records, "count": len(records)}


# ── WHOIS ─────────────────────────────────────────────────────────────────────

_WHOIS_FIELDS = {
    "registrar":        ["Registrar:", "registrar:"],
    "registrant":       ["Registrant Name:", "Registrant Organization:"],
    "registrant_email": ["Registrant Email:"],
    "created":          ["Creation Date:", "Created:", "created:"],
    "updated":          ["Updated Date:", "Last Modified:", "updated:"],
    "expires":          ["Registry Expiry Date:", "Expiry Date:", "Expiration Date:"],
    "status":           ["Domain Status:", "status:"],
    "nameservers":      ["Name Server:", "nserver:"],
    "dnssec":           ["DNSSEC:"],
}


def _parse_whois(lines: List[str], out_dir: Path) -> dict:
    data: dict = {}
    raw_text = "\n".join(lines)

    for field, keywords in _WHOIS_FIELDS.items():
        for kw in keywords:
            for line in lines:
                if line.strip().lower().startswith(kw.lower()):
                    value = line.split(":", 1)[-1].strip()
                    if not value:
                        continue
                    if field == "nameservers":
                        data.setdefault("nameservers", [])
                        if value.lower() not in [ns.lower() for ns in data["nameservers"]]:
                            data["nameservers"].append(value)
                    elif field == "status":
                        data.setdefault("status", [])
                        clean = value.split(" ")[0]
                        if clean not in data["status"]:
                            data["status"].append(clean)
                    elif field not in data:
                        data[field] = value

    return {
        "whois": data,
        "spf": "v=spf1" in raw_text,
        "dmarc": "_dmarc" in raw_text.lower() or "v=DMARC1" in raw_text,
        "dkim": "v=DKIM1" in raw_text,
        "raw": raw_text[:3000],
    }


# ── Curl Headers ──────────────────────────────────────────────────────────────

_SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy",
    "Permissions-Policy", "Access-Control-Allow-Origin",
]


def _parse_curl_headers(lines: List[str], out_dir: Path) -> dict:
    headers: dict = {}
    status_code = None
    status_line = None

    for line in lines:
        if line.startswith("HTTP/"):
            status_line = line.strip()
            parts = line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key and not key.startswith(" "):
                headers[key] = value

    lower_keys = {k.lower() for k in headers}
    security = {h: {"present": h.lower() in lower_keys, "value": headers.get(h, "")} for h in _SECURITY_HEADERS}
    missing = [h for h, v in security.items() if not v["present"]]

    return {
        "status": status_code, "status_line": status_line, "headers": headers,
        "security_headers": security, "missing_security_headers": missing,
        "server": headers.get("Server", headers.get("server", "")),
        "powered_by": headers.get("X-Powered-By", ""),
    }


# ── theHarvester ──────────────────────────────────────────────────────────────

def _parse_harvester(lines: List[str], out_dir: Path) -> dict:
    emails: List[str] = []
    hosts_list: List[str] = []
    ips: List[str] = []
    email_re = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}")
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    in_hosts = False

    for line in lines:
        ls = line.strip()
        ll = ls.lower()
        if "emails found" in ll or "email addresses" in ll:
            in_hosts = False
            continue
        if "hosts found" in ll or "subdomains" in ll:
            in_hosts = True
            continue
        if ls.startswith("---") or ls.startswith("==="):
            in_hosts = False
            continue

        for e in email_re.findall(ls):
            if e not in emails:
                emails.append(e)
        for ip in ip_re.findall(ls):
            if ip not in ips and not ip.startswith("0."):
                ips.append(ip)
        if in_hosts and ls and "." in ls:
            candidate = ls.split()[0] if " " in ls else ls
            if _is_subdomain(candidate) and "@" not in candidate and candidate not in hosts_list:
                hosts_list.append(candidate)

    json_file = out_dir / "harvester.json"
    if json_file.exists():
        try:
            data = json.loads(json_file.read_text())
            for e in data.get("emails", []):
                if e not in emails:
                    emails.append(e)
            for h in data.get("hosts", []):
                if h not in hosts_list:
                    hosts_list.append(h)
        except Exception:
            pass

    return {
        "emails": _dedup(emails), "hosts": _dedup(hosts_list), "ips": _dedup(ips),
        "count": len(emails), "email_count": len(emails), "host_count": len(hosts_list),
    }


# ── TestSSL ───────────────────────────────────────────────────────────────────

def _parse_testssl(lines: List[str], out_dir: Path) -> dict:
    findings: List[dict] = []
    protocols: dict = {}
    cert_info: dict = {}

    ssl_file = out_dir / "ssl.json"
    if ssl_file.exists():
        try:
            data = json.loads(ssl_file.read_text())
            if isinstance(data, dict):
                for key, entry in data.items():
                    if not isinstance(entry, dict):
                        continue
                    sev = entry.get("severity", "INFO").lower()
                    finding = entry.get("finding", "")
                    if sev in ("critical", "high", "medium", "low", "warn"):
                        findings.append({"id": key, "severity": "high" if sev == "warn" else sev, "finding": finding[:200]})
                    if key.startswith("SSLv") or key.startswith("TLSv"):
                        protocols[key] = finding
                    if "cert" in key.lower():
                        cert_info[key] = finding
                return {"findings": findings, "protocols": protocols, "cert": cert_info, "count": len(findings)}
        except Exception:
            pass

    for line in lines:
        ls = line.strip()
        if "VULNERABLE" in line or "NOT ok" in line.upper():
            findings.append({"id": "", "severity": "high" if "CRITICAL" in line.upper() else "medium", "finding": ls[:200]})
        elif ls.startswith("SSLv") or ls.startswith("TLSv"):
            parts = ls.split()
            if len(parts) >= 2:
                protocols[parts[0]] = " ".join(parts[1:])

    return {"findings": findings, "protocols": protocols, "cert": cert_info, "count": len(findings), "raw": [l for l in lines if l.strip()][:100]}


# ── GoWitness ─────────────────────────────────────────────────────────────────

def _parse_gowitness(lines: List[str], out_dir: Path) -> dict:
    screenshots: List[dict] = []
    ss_dir = out_dir / "screenshots"
    if ss_dir.exists():
        for f in sorted(ss_dir.glob("*.png")):
            screenshots.append({
                "path": str(f), "filename": f.name,
                "url": f.name.replace("_", "://", 1).replace("_", "/"),
                "size": f.stat().st_size,
            })

    for line in lines:
        if "screenshot" in line.lower() and "saved" in line.lower():
            m = re.search(r"saved (.+\.png)", line)
            if m:
                p = Path(m.group(1))
                if p.exists() and str(p) not in [s["path"] for s in screenshots]:
                    screenshots.append({"path": str(p), "filename": p.name, "url": "", "size": p.stat().st_size})

    return {"screenshots": screenshots, "count": len(screenshots), "paths": [s["path"] for s in screenshots]}
