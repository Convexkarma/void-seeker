"""Parse raw tool output files into structured JSON findings."""

import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Any


def parse_all_results(out_dir: str, domain: str) -> dict:
    """Parse all tool output files in the scan output directory."""
    return {
        "subdomains": _parse_subdomains(out_dir),
        "ports": _parse_nmap(out_dir),
        "vulnerabilities": _parse_nuclei(out_dir),
        "directories": _parse_gobuster(out_dir),
        "technologies": _parse_whatweb(out_dir),
        "screenshots": _parse_screenshots(out_dir),
        "dns": _parse_dns(out_dir, domain),
        "secrets": _parse_secrets(out_dir),
        "logs": [],  # Logs are stored separately in DB
    }


def _parse_subdomains(out_dir: str) -> list[dict]:
    """Parse merged subdomains list + httpx live hosts."""
    results = []
    live_data = {}

    # Parse httpx output for status/title/tech
    live_file = os.path.join(out_dir, "live_hosts.txt")
    if os.path.exists(live_file):
        for line in open(live_file).read().strip().splitlines():
            # httpx format: url [status] [title] [tech]
            parts = line.split()
            if parts:
                url = parts[0]
                host = url.replace("https://", "").replace("http://", "").rstrip("/")
                live_data[host] = {
                    "statusCode": int(parts[1].strip("[]")) if len(parts) > 1 else 0,
                    "title": parts[2].strip("[]") if len(parts) > 2 else "",
                    "techStack": parts[3].strip("[]").split(",") if len(parts) > 3 else [],
                }

    all_file = os.path.join(out_dir, "subdomains_all.txt")
    if os.path.exists(all_file):
        for sub in open(all_file).read().strip().splitlines():
            sub = sub.strip()
            if not sub:
                continue
            info = live_data.get(sub, {})
            results.append({
                "subdomain": sub,
                "ip": "",
                "statusCode": info.get("statusCode", 0),
                "title": info.get("title", ""),
                "techStack": info.get("techStack", []),
            })

    return results


def _parse_nmap(out_dir: str) -> list[dict]:
    """Parse nmap XML output into port objects."""
    results = []
    xml_file = os.path.join(out_dir, "nmap.xml")
    if not os.path.exists(xml_file):
        return results

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall(".//host"):
            for port_el in host.findall(".//port"):
                port_id = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp").upper()
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                service = service_el.get("name", "") if service_el is not None else ""
                version = f"{service_el.get('product', '')} {service_el.get('version', '')}".strip() if service_el is not None else ""

                dangerous = {21, 23, 445, 3389, 6379, 27017, 9200, 5432, 3306}
                risk = "high" if port_id in dangerous else ("medium" if port_id < 1024 else "low")

                results.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service,
                    "version": version,
                    "risk": risk,
                })
    except Exception:
        pass

    return results


def _parse_nuclei(out_dir: str) -> list[dict]:
    """Parse nuclei text output into vulnerability findings."""
    results = []
    nuclei_file = os.path.join(out_dir, "nuclei.txt")
    if not os.path.exists(nuclei_file):
        return results

    for i, line in enumerate(open(nuclei_file).read().strip().splitlines()):
        # nuclei format: [template-id] [protocol] [severity] url info
        match = re.match(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)', line)
        if match:
            template_id, protocol, severity, url, info = match.groups()
            cve_match = re.search(r'(CVE-\d{4}-\d+)', template_id)
            results.append({
                "id": f"v{i+1}",
                "severity": severity.lower(),
                "cveId": cve_match.group(1) if cve_match else None,
                "url": url,
                "title": template_id.replace("-", " ").title(),
                "description": info or f"Detected by template: {template_id}",
                "remediation": "Review and patch the affected component.",
                "falsePositive": False,
            })

    return results


def _parse_gobuster(out_dir: str) -> list[dict]:
    """Parse gobuster directory output."""
    results = []
    dirs_file = os.path.join(out_dir, "dirs.txt")
    if not os.path.exists(dirs_file):
        return results

    interesting_patterns = {"admin", ".git", ".env", "backup", "config", "api", "swagger", "phpinfo", "server-status", "wp-admin"}

    for line in open(dirs_file).read().strip().splitlines():
        # gobuster format: /path (Status: 200) [Size: 1234]
        match = re.match(r'(/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]', line)
        if match:
            path, status, size = match.groups()
            is_interesting = any(p in path.lower() for p in interesting_patterns)
            results.append({
                "path": path,
                "statusCode": int(status),
                "size": int(size),
                "interesting": is_interesting,
            })

    return results


def _parse_whatweb(out_dir: str) -> list[dict]:
    """Parse WhatWeb JSON output into technology list."""
    results = []
    json_file = os.path.join(out_dir, "whatweb.json")
    if not os.path.exists(json_file):
        return results

    try:
        data = json.loads(open(json_file).read())
        seen = set()
        for entry in data if isinstance(data, list) else [data]:
            plugins = entry.get("plugins", {})
            for name, info in plugins.items():
                if name in seen or name in ("IP", "Country", "HTTPServer"):
                    continue
                seen.add(name)
                version_list = info.get("version", [])
                version = version_list[0] if version_list else None
                results.append({
                    "name": name,
                    "category": _categorize_tech(name),
                    "version": version,
                    "outdated": False,
                })
    except Exception:
        pass

    return results


def _parse_screenshots(out_dir: str) -> list[dict]:
    """List gowitness screenshots."""
    results = []
    ss_dir = os.path.join(out_dir, "screenshots")
    if os.path.exists(ss_dir):
        for f in os.listdir(ss_dir):
            if f.endswith((".png", ".jpg", ".jpeg")):
                results.append({
                    "url": f.replace(".png", "").replace("-", "://", 1).replace("-", "/"),
                    "imageUrl": os.path.join(ss_dir, f),
                    "title": f,
                })
    return results


def _parse_dns(out_dir: str, domain: str) -> dict:
    """Parse dnsx output into DNS records structure."""
    result = {
        "a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": [],
        "whois": {"registrar": "", "createdDate": "", "expiryDate": "", "nameServers": []},
        "spf": False, "dmarc": False, "dkim": False,
    }

    dns_file = os.path.join(out_dir, "dns.txt")
    if os.path.exists(dns_file):
        for line in open(dns_file).read().strip().splitlines():
            line = line.strip()
            if " [A] " in line:
                result["a"].append(line.split("[A]")[-1].strip())
            elif " [AAAA] " in line:
                result["aaaa"].append(line.split("[AAAA]")[-1].strip())
            elif " [MX] " in line:
                mx = line.split("[MX]")[-1].strip()
                result["mx"].append({"host": mx, "priority": 10})
            elif " [NS] " in line:
                result["ns"].append(line.split("[NS]")[-1].strip())
            elif " [TXT] " in line:
                txt = line.split("[TXT]")[-1].strip()
                result["txt"].append(txt)
                if "spf" in txt.lower():
                    result["spf"] = True
                if "dmarc" in txt.lower():
                    result["dmarc"] = True
            elif " [CNAME] " in line:
                result["cname"].append(line.split("[CNAME]")[-1].strip())

    return result


def _parse_secrets(out_dir: str) -> list[dict]:
    """Parse harvested secrets and emails."""
    results = []

    # Parse theHarvester output
    harvester_file = os.path.join(out_dir, "harvester.json")
    if os.path.exists(harvester_file):
        try:
            data = json.loads(open(harvester_file).read())
            for email in data.get("emails", []):
                results.append({"type": "email", "source": "theHarvester", "value": email, "severity": "low"})
        except Exception:
            pass

    return results


def _categorize_tech(name: str) -> str:
    categories = {
        "nginx": "Web Server", "apache": "Web Server", "iis": "Web Server",
        "react": "Framework", "angular": "Framework", "vue": "Framework", "django": "Framework", "rails": "Framework",
        "php": "Language", "python": "Language", "ruby": "Language",
        "mysql": "Database", "postgres": "Database", "mongodb": "Database", "redis": "Cache",
        "cloudflare": "CDN", "cloudfront": "CDN",
        "jquery": "Library", "bootstrap": "Library",
    }
    for key, cat in categories.items():
        if key in name.lower():
            return cat
    return "Other"
