"""
AutoRecon - parser.py
Tool Output Parsers — converts raw stdout/file output into structured JSON.
Each parser handles a specific tool and returns a clean dict ready for the UI.
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Dispatcher ────────────────────────────────────────────────────────────────

async def parse_output(module: str, lines: List[str], out_dir: Path) -> Dict[str, Any]:
    """Route to the correct parser for a module."""
    HANDLERS = {
        "subfinder":    parse_subfinder,
        "amass":        parse_amass,
        "httpx":        parse_httpx,
        "nmap":         parse_nmap,
        "gobuster":     parse_gobuster,
        "nuclei":       parse_nuclei,
        "whatweb":      parse_whatweb,
        "wafw00f":      parse_wafw00f,
        "dnsx":         parse_dnsx,
        "dig":          parse_dig,
        "whois":        parse_whois,
        "curl_headers": parse_curl_headers,
        "theHarvester": parse_harvester,
        "testssl":      parse_testssl,
        "gowitness":    parse_gowitness,
    }
    handler = HANDLERS.get(module)
    if handler:
        try:
            return handler(lines, out_dir)
        except Exception as e:
            return {"raw": lines[:500], "error": str(e), "count": 0}
    return {"raw": lines[:500], "count": 0}


# ── Subfinder ─────────────────────────────────────────────────────────────────

def parse_subfinder(lines: List[str], out_dir: Path) -> dict:
    """Parse subfinder output — one subdomain per line."""
    subs = []
    for line in lines:
        line = line.strip()
        # Skip status/info lines
        if not line or line.startswith("[") or line.startswith("\\"):
            continue
        # Valid subdomain: contains a dot, no spaces
        if "." in line and " " not in line:
            subs.append(line.lower())

    # Also read output file if it exists (more reliable)
    out_file = out_dir / "subdomains_sf.txt"
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            line = line.strip().lower()
            if line and "." in line and line not in subs:
                subs.append(line)

    subs = sorted(list(dict.fromkeys(subs)))  # deduplicate, preserve order
    return {
        "subdomains": subs,
        "count": len(subs),
        "source": "subfinder",
    }


# ── Amass ─────────────────────────────────────────────────────────────────────

def parse_amass(lines: List[str], out_dir: Path) -> dict:
    """Parse amass output — handles both raw text and structured output."""
    subs = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("["):
            continue
        # Amass adds ' --> ' for relationship lines
        if " --> " in line:
            parts = line.split(" --> ")
            candidate = parts[0].strip()
        else:
            candidate = line.split()[0] if " " in line else line

        candidate = candidate.lower().strip()
        if "." in candidate and " " not in candidate and len(candidate) < 255:
            subs.append(candidate)

    # Read output file
    out_file = out_dir / "subdomains_am.txt"
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            line = line.strip().lower()
            if line and "." in line and line not in subs:
                subs.append(line)

    subs = sorted(list(dict.fromkeys(subs)))
    return {
        "subdomains": subs,
        "count": len(subs),
        "source": "amass",
    }


# ── HTTPX ─────────────────────────────────────────────────────────────────────

def parse_httpx(lines: List[str], out_dir: Path) -> dict:
    """
    Parse httpx output.
    Example line: https://sub.example.com [200] [Page Title] [nginx,PHP]
    """
    hosts = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("["):
            continue

        entry = {
            "url": "",
            "status": None,
            "title": None,
            "tech": [],
            "content_length": None,
        }

        # Extract URL (first token)
        parts = line.split()
        if parts:
            entry["url"] = parts[0]

        # Extract bracketed fields: [200] [Title] [tech1,tech2]
        brackets = re.findall(r"\[([^\]]+)\]", line)
        for b in brackets:
            b = b.strip()
            if b.isdigit():
                entry["status"] = int(b)
            elif b.endswith("KB") or b.endswith("B") or re.match(r"^\d+$", b):
                try:
                    entry["content_length"] = int(re.sub(r"[^\d]", "", b))
                except Exception:
                    pass
            elif "," in b or (len(b) < 60 and not re.search(r"https?://", b)):
                if entry["title"] is None and not any(c in b for c in ["/", "\\", "."]):
                    entry["title"] = b
                elif "," in b:
                    entry["tech"] = [t.strip() for t in b.split(",") if t.strip()]
            else:
                if entry["title"] is None:
                    entry["title"] = b[:100]

        if entry["url"]:
            hosts.append(entry)

    # Also read output file
    out_file = out_dir / "live_hosts.txt"
    if out_file.exists() and not hosts:
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if line:
                hosts.append({"url": line, "status": None, "title": None, "tech": []})

    return {
        "live_hosts": hosts,
        "count": len(hosts),
        "urls": [h["url"] for h in hosts],
    }


# ── Nmap ──────────────────────────────────────────────────────────────────────

# Known dangerous ports and their typical vulnerability
DANGEROUS_PORTS = {
    21:    ("FTP", "Cleartext auth, anonymous login, directory traversal"),
    22:    ("SSH", "Brute force, weak ciphers"),
    23:    ("Telnet", "Cleartext protocol — replace with SSH"),
    25:    ("SMTP", "Open relay, user enumeration"),
    53:    ("DNS", "Zone transfer, amplification DDoS"),
    80:    ("HTTP", "Unencrypted traffic"),
    110:   ("POP3", "Cleartext email credentials"),
    143:   ("IMAP", "Cleartext email credentials"),
    161:   ("SNMP", "Default community strings"),
    445:   ("SMB", "EternalBlue (MS17-010), Pass-the-Hash"),
    512:   ("rexec", "Remote execution without auth"),
    513:   ("rlogin", "Cleartext remote login"),
    514:   ("rsh", "Unauthenticated remote shell"),
    1433:  ("MSSQL", "SA brute force, xp_cmdshell"),
    1521:  ("Oracle DB", "TNS listener attacks"),
    2375:  ("Docker API", "Unauthenticated Docker socket"),
    2376:  ("Docker TLS", "Weak TLS Docker API"),
    3306:  ("MySQL", "Brute force, file read via SELECT INTO"),
    3389:  ("RDP", "BlueKeep, DejaBlue, brute force"),
    4848:  ("GlassFish", "Default admin credentials"),
    5432:  ("PostgreSQL", "Brute force, COPY TO/FROM PROGRAM"),
    5900:  ("VNC", "No-auth mode, weak passwords"),
    5985:  ("WinRM", "Lateral movement"),
    6379:  ("Redis", "Unauthenticated access, RCE via config"),
    8080:  ("HTTP-Alt", "Admin panels, default credentials"),
    9200:  ("Elasticsearch", "Unauthenticated data access"),
    9300:  ("Elasticsearch", "Cluster communication"),
    11211: ("Memcached", "Unauthenticated, amplification"),
    27017: ("MongoDB", "Unauthenticated access"),
    50070: ("HDFS NameNode", "Hadoop cluster access"),
}


def classify_port_risk(port: int) -> str:
    high_risk = {21, 22, 23, 25, 53, 445, 512, 513, 514, 1433, 1521, 2375, 2376,
                 3306, 3389, 4848, 5432, 5900, 5985, 6379, 9200, 9300, 11211, 27017, 50070}
    medium_risk = {80, 8080, 8443, 8888, 110, 143, 161, 993, 995, 3000, 4000, 5000}
    if port in high_risk:
        return "high"
    if port in medium_risk:
        return "medium"
    return "low"


def parse_nmap(lines: List[str], out_dir: Path) -> dict:
    """
    Parse nmap output. Prefers XML file for accuracy, falls back to text parsing.
    """
    ports = []
    hosts = []

    xml_file = out_dir / "nmap.xml"
    if xml_file.exists():
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall("host"):
                addr_el = host.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    addr_el = host.find("address")
                ip = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

                hostname_el = host.find(".//hostname")
                hostname = hostname_el.get("name", "") if hostname_el is not None else ""

                hosts.append({"ip": ip, "hostname": hostname})

                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    port_num = int(port_el.get("portid", 0))
                    proto = port_el.get("protocol", "tcp")
                    svc_el = port_el.find("service")

                    service = svc_el.get("name", "") if svc_el is not None else ""
                    product = svc_el.get("product", "") if svc_el is not None else ""
                    version = svc_el.get("version", "") if svc_el is not None else ""
                    extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""
                    tunnel = svc_el.get("tunnel", "") if svc_el is not None else ""

                    # Script output (e.g. banner, http-title)
                    scripts = {}
                    for script_el in port_el.findall("script"):
                        scripts[script_el.get("id", "")] = script_el.get("output", "")[:200]

                    risk = classify_port_risk(port_num)
                    danger_info = DANGEROUS_PORTS.get(port_num)

                    ports.append({
                        "port": port_num,
                        "protocol": proto,
                        "state": "open",
                        "service": service,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "tunnel": tunnel,
                        "ip": ip,
                        "hostname": hostname,
                        "risk": risk,
                        "danger_description": danger_info[1] if danger_info else "",
                        "scripts": scripts,
                    })

        except ET.ParseError as e:
            print(f"[!] Nmap XML parse error: {e}")

    # Text fallback
    if not ports:
        current_ip = ""
        for line in lines:
            ip_match = re.match(r"Nmap scan report for (?:.*\()?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if ip_match:
                current_ip = ip_match.group(1)

            port_match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if port_match:
                port_num = int(port_match.group(1))
                danger_info = DANGEROUS_PORTS.get(port_num)
                ports.append({
                    "port": port_num,
                    "protocol": port_match.group(2),
                    "state": "open",
                    "service": port_match.group(3),
                    "product": port_match.group(4).strip(),
                    "version": "",
                    "ip": current_ip,
                    "risk": classify_port_risk(port_num),
                    "danger_description": danger_info[1] if danger_info else "",
                    "scripts": {},
                })

    ports.sort(key=lambda p: p["port"])

    return {
        "ports": ports,
        "count": len(ports),
        "hosts": hosts,
        "high_risk": [p for p in ports if p["risk"] == "high"],
        "open_port_numbers": [p["port"] for p in ports],
    }


# ── Gobuster ──────────────────────────────────────────────────────────────────

SENSITIVE_PATHS = {
    ".git", ".env", ".htaccess", ".htpasswd", ".svn", ".DS_Store",
    "admin", "administrator", "wp-admin", "phpmyadmin", "phpinfo",
    "backup", "backups", "db", "database", "dump",
    "config", "configuration", "settings",
    "api", "swagger", "openapi", "graphql",
    "console", "debug", "actuator", "metrics", "health", "info",
    "upload", "uploads", "files", "tmp", "temp",
    "test", "testing", "dev", "staging",
    "robots.txt", "sitemap.xml",
    ".well-known",
}


def parse_gobuster(lines: List[str], out_dir: Path) -> dict:
    """Parse gobuster directory output."""
    directories = []

    for line in lines:
        # Skip progress/status lines
        if line.startswith("[") or "Progress:" in line or not line.strip():
            continue

        # Format: /path (Status: 200) [Size: 1234]
        m = re.search(r"(/.+?)\s+\(Status:\s*(\d+)\)", line)
        if not m:
            # Alternative format: /path  STATUS  SIZE
            m2 = re.match(r"(/\S+)\s+(\d{3})\s+", line.strip())
            if m2:
                path = m2.group(1)
                status = int(m2.group(2))
            else:
                continue
        else:
            path = m.group(1).split()[0]  # Remove trailing content
            status = int(m.group(2))

        # Check if path is sensitive
        path_lower = path.lower()
        is_sensitive = any(
            sensitive in path_lower
            for sensitive in SENSITIVE_PATHS
        )

        # Extract size if present
        size_match = re.search(r"\[Size:\s*(\d+)\]", line)
        size = int(size_match.group(1)) if size_match else None

        directories.append({
            "path": path,
            "status": status,
            "size": size,
            "sensitive": is_sensitive,
            "interesting": is_sensitive or status in (200, 201, 204, 301, 302, 307),
        })

    # Sort: sensitive first, then by status
    directories.sort(key=lambda d: (not d["sensitive"], d["status"]))

    return {
        "directories": directories,
        "count": len(directories),
        "sensitive": [d for d in directories if d["sensitive"]],
        "sensitive_count": sum(1 for d in directories if d["sensitive"]),
    }


# ── Nuclei ────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def parse_nuclei(lines: List[str], out_dir: Path) -> dict:
    """
    Parse nuclei output.
    Format: [template-id] [type] [severity] URL [matcher-name]
    Or:     [timestamp] [template-id:matcher] [severity] URL
    """
    findings = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("[INF]") or line.startswith("[WRN]"):
            continue

        # Detect severity
        severity = "info"
        for sev in ("critical", "high", "medium", "low", "info"):
            if f"[{sev}]" in line.lower():
                severity = sev
                break

        # Extract template ID
        template_match = re.search(r"\[([a-z0-9_\-:]+)\]", line)
        template_id = template_match.group(1) if template_match else ""

        # Remove timestamp pattern [2024-01-01 ...]
        clean = re.sub(r"\[\d{4}-\d{2}-\d{2}[^\]]*\]", "", line).strip()

        # Extract URL
        url_match = re.search(r"https?://\S+", clean)
        url = url_match.group(0).rstrip("]").rstrip(")") if url_match else ""

        # Extract matcher name if present
        matcher = ""
        bracket_items = re.findall(r"\[([^\]]+)\]", clean)
        for item in bracket_items:
            if item not in (template_id, severity) and "://" not in item:
                matcher = item
                break

        findings.append({
            "template": template_id,
            "severity": severity,
            "url": url,
            "matcher": matcher,
            "raw": line[:300],
            "type": "vulnerability",
        })

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in ("critical", "high", "medium", "low", "info")}

    return {
        "findings": findings,
        "count": len(findings),
        **counts,
    }


# ── WhatWeb ───────────────────────────────────────────────────────────────────

def parse_whatweb(lines: List[str], out_dir: Path) -> dict:
    """Parse whatweb JSON output file, fall back to text parsing."""
    technologies = []

    json_file = out_dir / "whatweb.json"
    if json_file.exists():
        try:
            raw = json_file.read_text().strip()
            # WhatWeb outputs one JSON object per line
            for json_line in raw.splitlines():
                json_line = json_line.strip()
                if not json_line:
                    continue
                try:
                    entry = json.loads(json_line)
                    plugins = entry.get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        version = None
                        string = None
                        if isinstance(plugin_data, dict):
                            versions = plugin_data.get("version", [])
                            version = versions[0] if versions else None
                            strings = plugin_data.get("string", [])
                            string = strings[0] if strings else None
                        technologies.append({
                            "name": plugin_name,
                            "version": version,
                            "info": string,
                            "raw": plugin_data,
                        })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    # Text fallback
    if not technologies:
        for line in lines:
            # WhatWeb text format: URL [200 OK] Technology[version], Technology2
            tech_matches = re.findall(r"([\w\s\-\.]+)\[([^\]]*)\]", line)
            for name, info in tech_matches:
                name = name.strip()
                if name and name not in ("http", "https") and len(name) < 50:
                    technologies.append({"name": name, "version": info if info else None, "info": None})

    # Deduplicate by name
    seen = set()
    unique_tech = []
    for t in technologies:
        if t["name"] not in seen:
            seen.add(t["name"])
            unique_tech.append(t)

    return {
        "technologies": unique_tech,
        "count": len(unique_tech),
        "names": [t["name"] for t in unique_tech],
    }


# ── WAFw00f ───────────────────────────────────────────────────────────────────

def parse_wafw00f(lines: List[str], out_dir: Path) -> dict:
    """Parse wafw00f output to detect WAF presence."""
    waf_detected = None
    waf_vendor = None
    protected = False

    for line in lines:
        line_lower = line.lower()

        if "is behind" in line_lower:
            protected = True
            # Extract WAF name: "target.com is behind XYZ WAF"
            m = re.search(r"is behind (.+?)(?:\s+WAF)?$", line, re.IGNORECASE)
            if m:
                waf_detected = m.group(1).strip()

        elif "no waf" in line_lower or "not behind" in line_lower:
            protected = False
            waf_detected = None

        elif "generic" in line_lower and ("detect" in line_lower or "block" in line_lower):
            protected = True
            waf_detected = "Generic WAF"

    # Also read output file
    waf_file = out_dir / "waf.txt"
    if waf_file.exists() and not waf_detected:
        content = waf_file.read_text()
        if "is behind" in content.lower():
            protected = True
            m = re.search(r"is behind (.+?)(?:\s+WAF)?", content, re.IGNORECASE)
            if m:
                waf_detected = m.group(1).strip()

    return {
        "protected": protected,
        "waf": waf_detected,
        "raw": "\n".join(lines[:50]),
    }


# ── DNSX ──────────────────────────────────────────────────────────────────────

def parse_dnsx(lines: List[str], out_dir: Path) -> dict:
    """Parse dnsx DNS record output."""
    records = []
    record_types = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "ANY"}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("["):
            continue

        # Format: domain [A] [1.2.3.4]  or  domain A 1.2.3.4
        brackets = re.findall(r"\[([^\]]+)\]", line)
        if brackets:
            domain_part = line.split("[")[0].strip()
            record_type = None
            values = []
            for b in brackets:
                b = b.strip()
                if b in record_types:
                    record_type = b
                elif b:
                    values.append(b)
            for val in values:
                records.append({
                    "domain": domain_part,
                    "type": record_type or "?",
                    "value": val,
                })
        else:
            # Plain whitespace-separated format
            parts = line.split()
            if len(parts) >= 3:
                records.append({
                    "domain": parts[0],
                    "type": parts[1] if parts[1] in record_types else "?",
                    "value": " ".join(parts[2:]),
                })
            elif len(parts) == 2:
                records.append({"domain": parts[0], "type": "?", "value": parts[1]})

    return {
        "records": records,
        "count": len(records),
        "types": list({r["type"] for r in records}),
    }


# ── Dig ───────────────────────────────────────────────────────────────────────

def parse_dig(lines: List[str], out_dir: Path) -> dict:
    """Parse dig ANY output."""
    records = []
    for line in lines:
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5:
            records.append({
                "name": parts[0],
                "ttl": parts[1],
                "class": parts[2],
                "type": parts[3],
                "value": " ".join(parts[4:]),
            })
    return {"records": records, "count": len(records)}


# ── WHOIS ─────────────────────────────────────────────────────────────────────

WHOIS_FIELDS = {
    "registrar":         ["Registrar:", "registrar:"],
    "registrant":        ["Registrant Name:", "Registrant Organization:"],
    "registrant_email":  ["Registrant Email:"],
    "created":           ["Creation Date:", "Created:", "created:"],
    "updated":           ["Updated Date:", "Last Modified:", "updated:"],
    "expires":           ["Registry Expiry Date:", "Expiry Date:", "Expiration Date:"],
    "status":            ["Domain Status:", "status:"],
    "nameservers":       ["Name Server:", "nserver:"],
    "dnssec":            ["DNSSEC:"],
}


def parse_whois(lines: List[str], out_dir: Path) -> dict:
    """Parse WHOIS output into structured fields."""
    data: dict = {}
    raw_text = "\n".join(lines)

    for field, keywords in WHOIS_FIELDS.items():
        for keyword in keywords:
            for line in lines:
                if line.strip().lower().startswith(keyword.lower()):
                    value = line.split(":", 1)[-1].strip()
                    if not value:
                        continue
                    if field == "nameservers":
                        data.setdefault("nameservers", [])
                        if value.lower() not in [ns.lower() for ns in data["nameservers"]]:
                            data["nameservers"].append(value)
                    elif field == "status":
                        data.setdefault("status", [])
                        # Strip URL part from status
                        status_clean = value.split(" ")[0]
                        if status_clean not in data["status"]:
                            data["status"].append(status_clean)
                    elif field not in data:
                        data[field] = value

    # Check for SPF, DMARC, DKIM in raw text
    spf = "v=spf1" in raw_text
    dmarc = "_dmarc" in raw_text.lower() or "v=DMARC1" in raw_text
    dkim = "v=DKIM1" in raw_text

    return {
        "whois": data,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "raw": raw_text[:3000],
    }


# ── Curl Headers ──────────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
]


def parse_curl_headers(lines: List[str], out_dir: Path) -> dict:
    """Parse HTTP response headers from curl -I output."""
    headers: dict = {}
    status_code = None
    status_line = None

    for line in lines:
        # HTTP status line
        if line.startswith("HTTP/"):
            status_line = line.strip()
            parts = line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            continue

        # Header line: Key: Value
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key and not key.startswith(" "):
                headers[key] = value

    # Check which security headers are present/missing
    security_analysis = {}
    for h in SECURITY_HEADERS:
        security_analysis[h] = {
            "present": h in headers or h.lower() in {k.lower() for k in headers},
            "value": headers.get(h, ""),
        }

    missing_security = [h for h, v in security_analysis.items() if not v["present"]]

    return {
        "status": status_code,
        "status_line": status_line,
        "headers": headers,
        "security_headers": security_analysis,
        "missing_security_headers": missing_security,
        "server": headers.get("Server", headers.get("server", "")),
        "powered_by": headers.get("X-Powered-By", ""),
    }


# ── theHarvester ──────────────────────────────────────────────────────────────

def parse_harvester(lines: List[str], out_dir: Path) -> dict:
    """Parse theHarvester output for emails, hosts, IPs."""
    emails: List[str] = []
    hosts: List[str] = []
    ips: List[str] = []

    email_re = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}")
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    in_emails = False
    in_hosts = False

    for line in lines:
        line_stripped = line.strip()
        line_lower = line_stripped.lower()

        if "emails found" in line_lower or "email addresses" in line_lower:
            in_emails = True
            in_hosts = False
            continue
        if "hosts found" in line_lower or "subdomains" in line_lower:
            in_hosts = True
            in_emails = False
            continue
        if line_stripped.startswith("---") or line_stripped.startswith("==="):
            in_emails = False
            continue

        # Always extract emails from any line
        found_emails = email_re.findall(line_stripped)
        for e in found_emails:
            if e not in emails:
                emails.append(e)

        # Extract IPs
        found_ips = ip_re.findall(line_stripped)
        for ip in found_ips:
            if ip not in ips and not ip.startswith("0."):
                ips.append(ip)

        # Extract hostnames when in hosts section
        if in_hosts and line_stripped and "." in line_stripped:
            candidate = line_stripped.split()[0] if " " in line_stripped else line_stripped
            if "." in candidate and "@" not in candidate and len(candidate) < 255:
                if candidate not in hosts:
                    hosts.append(candidate)

    # Try reading JSON output if available
    json_file = out_dir / "harvester.json"
    if json_file.exists():
        try:
            data = json.loads(json_file.read_text())
            for e in data.get("emails", []):
                if e not in emails:
                    emails.append(e)
            for h in data.get("hosts", []):
                if h not in hosts:
                    hosts.append(h)
        except Exception:
            pass

    return {
        "emails": list(dict.fromkeys(emails)),
        "hosts": list(dict.fromkeys(hosts)),
        "ips": list(dict.fromkeys(ips)),
        "count": len(emails),
        "email_count": len(emails),
        "host_count": len(hosts),
    }


# ── TestSSL ───────────────────────────────────────────────────────────────────

def parse_testssl(lines: List[str], out_dir: Path) -> dict:
    """Parse testssl.sh output for SSL/TLS vulnerabilities."""
    findings = []
    protocols = {}
    cipher_info = {}
    cert_info = {}

    ssl_file = out_dir / "ssl.json"
    if ssl_file.exists():
        try:
            data = json.loads(ssl_file.read_text())
            if isinstance(data, dict):
                for key, entry in data.items():
                    if isinstance(entry, dict):
                        severity = entry.get("severity", "INFO").lower()
                        finding = entry.get("finding", "")
                        if severity in ("critical", "high", "medium", "low", "warn"):
                            findings.append({
                                "id": key,
                                "severity": "high" if severity == "warn" else severity,
                                "finding": finding[:200],
                            })
                        if key.startswith("SSLv") or key.startswith("TLSv"):
                            protocols[key] = finding
                        if "cert" in key.lower():
                            cert_info[key] = finding
            return {
                "findings": findings,
                "protocols": protocols,
                "cert": cert_info,
                "count": len(findings),
            }
        except Exception:
            pass

    # Text fallback
    for line in lines:
        line_stripped = line.strip()
        if "VULNERABLE" in line or "NOT ok" in line.upper():
            findings.append({
                "id": "",
                "severity": "high" if "CRITICAL" in line.upper() else "medium",
                "finding": line_stripped[:200],
            })
        elif line_stripped.startswith("SSLv") or line_stripped.startswith("TLSv"):
            parts = line_stripped.split()
            if len(parts) >= 2:
                protocols[parts[0]] = " ".join(parts[1:])

    return {
        "findings": findings,
        "protocols": protocols,
        "cert": cert_info,
        "count": len(findings),
        "raw": [l for l in lines if l.strip()][:100],
    }


# ── GoWitness ─────────────────────────────────────────────────────────────────

def parse_gowitness(lines: List[str], out_dir: Path) -> dict:
    """Parse gowitness output — find captured screenshot files."""
    screenshots = []

    ss_dir = out_dir / "screenshots"
    if ss_dir.exists():
        for f in sorted(ss_dir.glob("*.png")):
            screenshots.append({
                "path": str(f),
                "filename": f.name,
                "url": f.name.replace("_", "://", 1).replace("_", "/").replace("http://", "http://").replace("https://", "https://"),
                "size": f.stat().st_size,
            })

    # Also read any gowitness database
    for line in lines:
        if "screenshot" in line.lower() and "saved" in line.lower():
            m = re.search(r"saved (.+\.png)", line)
            if m:
                p = Path(m.group(1))
                if p.exists() and str(p) not in [s["path"] for s in screenshots]:
                    screenshots.append({"path": str(p), "filename": p.name, "url": "", "size": p.stat().st_size})

    return {
        "screenshots": screenshots,
        "count": len(screenshots),
        "paths": [s["path"] for s in screenshots],
    }
