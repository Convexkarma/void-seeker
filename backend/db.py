"""
AutoRecon - db.py
Async SQLite persistence layer for scan data.
Database: ~/.autorecon/scans.db
"""

import json
import aiosqlite
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path.home() / ".autorecon" / "scans.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    domain       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running',
    created_at   TEXT NOT NULL,
    updated_at   TEXT,
    completed_at TEXT,
    data         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_domain  ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> aiosqlite.Connection:
    """Return an aiosqlite connection (use as `async with _connect() as db:`)."""
    return aiosqlite.connect(DB_PATH)


# ── Init ──────────────────────────────────────────────────────────────────────

async def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with _connect() as db:
        await db.executescript(SCHEMA_SQL)
        await db.commit()
    print(f"[*] Database ready: {DB_PATH}")


# ── CRUD ──────────────────────────────────────────────────────────────────────

async def save_scan(scan_data: Dict[str, Any]) -> bool:
    try:
        async with await _connect() as db:
            await db.execute(
                """INSERT OR REPLACE INTO scans
                   (id, domain, status, created_at, updated_at, data)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_data["id"],
                    scan_data["domain"],
                    scan_data.get("status", "running"),
                    scan_data.get("created_at", _now()),
                    _now(),
                    json.dumps(scan_data, default=str),
                ),
            )
            await db.commit()
        return True
    except Exception as exc:
        print(f"[!] DB save_scan error: {exc}")
        return False


async def update_scan(scan_id: str, updates: Dict[str, Any]) -> bool:
    try:
        async with await _connect() as db:
            cursor = await db.execute("SELECT data FROM scans WHERE id = ?", (scan_id,))
            row = await cursor.fetchone()
            if not row:
                return False

            existing: dict = json.loads(row[0])
            existing.update(updates)

            await db.execute(
                "UPDATE scans SET data = ?, status = ?, updated_at = ? WHERE id = ?",
                (json.dumps(existing, default=str), existing.get("status", "running"), _now(), scan_id),
            )
            await db.commit()
        return True
    except Exception as exc:
        print(f"[!] DB update_scan error: {exc}")
        return False


async def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    try:
        async with await _connect() as db:
            cursor = await db.execute("SELECT data FROM scans WHERE id = ?", (scan_id,))
            row = await cursor.fetchone()
            return json.loads(row[0]) if row else None
    except Exception as exc:
        print(f"[!] DB get_scan error: {exc}")
        return None


async def list_scans(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        async with await _connect() as db:
            cursor = await db.execute(
                "SELECT data FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
            return [_scan_summary(json.loads(r[0])) for r in rows]
    except Exception as exc:
        print(f"[!] DB list_scans error: {exc}")
        return []


async def delete_scan_db(scan_id: str) -> bool:
    try:
        async with await _connect() as db:
            await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            await db.commit()
        return True
    except Exception as exc:
        print(f"[!] DB delete_scan error: {exc}")
        return False


async def get_scans_for_domain(domain: str) -> List[Dict[str, Any]]:
    try:
        async with await _connect() as db:
            cursor = await db.execute(
                "SELECT data FROM scans WHERE domain = ? ORDER BY created_at DESC", (domain,)
            )
            rows = await cursor.fetchall()
            return [json.loads(r[0]) for r in rows]
    except Exception as exc:
        print(f"[!] DB get_scans_for_domain error: {exc}")
        return []


async def search_scans(query: str) -> List[Dict[str, Any]]:
    try:
        async with await _connect() as db:
            cursor = await db.execute(
                "SELECT data FROM scans WHERE domain LIKE ? ORDER BY created_at DESC LIMIT 50",
                (f"%{query}%",),
            )
            rows = await cursor.fetchall()
            return [_scan_summary(json.loads(r[0])) for r in rows]
    except Exception as exc:
        print(f"[!] DB search_scans error: {exc}")
        return []


async def get_stats() -> Dict[str, Any]:
    try:
        async with await _connect() as db:
            total = (await (await db.execute("SELECT COUNT(*) FROM scans")).fetchone())[0]
            status_rows = await (await db.execute("SELECT status, COUNT(*) FROM scans GROUP BY status")).fetchall()
            unique = (await (await db.execute("SELECT COUNT(DISTINCT domain) FROM scans")).fetchone())[0]
        return {"total_scans": total, "by_status": dict(status_rows), "unique_domains": unique}
    except Exception as exc:
        print(f"[!] DB get_stats error: {exc}")
        return {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts."""
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


def _scan_summary(scan: Dict[str, Any]) -> Dict[str, Any]:
    results = scan.get("results") or {}

    subs: set = set()
    for m in ("subfinder", "amass"):
        for s in _safe_get(results, m, "subdomains", default=[]):
            subs.add(s)

    nuclei = _safe_get(results, "nuclei", default={})

    return {
        "id": scan.get("id"),
        "domain": scan.get("domain"),
        "status": scan.get("status"),
        "created_at": scan.get("created_at"),
        "completed_at": scan.get("completed_at"),
        "duration": scan.get("duration", 0),
        "progress": scan.get("progress", 0),
        "modules": scan.get("modules", []),
        "summary": {
            "subdomains": len(subs),
            "open_ports": len(_safe_get(results, "nmap", "ports", default=[])),
            "live_hosts": _safe_get(results, "httpx", "count", default=0),
            "vulnerabilities": nuclei.get("count", 0) if isinstance(nuclei, dict) else 0,
            "critical": nuclei.get("critical", 0) if isinstance(nuclei, dict) else 0,
            "high": nuclei.get("high", 0) if isinstance(nuclei, dict) else 0,
            "medium": nuclei.get("medium", 0) if isinstance(nuclei, dict) else 0,
            "low": nuclei.get("low", 0) if isinstance(nuclei, dict) else 0,
            "directories": _safe_get(results, "gobuster", "count", default=0),
        },
    }
