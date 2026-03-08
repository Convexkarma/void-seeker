"""
AutoRecon - db.py
SQLite Database Layer — async persistence for all scan data using aiosqlite.
Database stored at ~/.autorecon/scans.db
"""

import json
import aiosqlite
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

DB_PATH = Path.home() / ".autorecon" / "scans.db"


# ── Schema ────────────────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    created_at  TEXT NOT NULL,
    updated_at  TEXT,
    completed_at TEXT,
    data        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_domain  ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
"""


# ── Init ──────────────────────────────────────────────────────────────────────

async def init_db():
    """Initialize the SQLite database and create tables if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLE_SQL)
        await db.commit()
    print(f"[*] Database ready: {DB_PATH}")


# ── CRUD ──────────────────────────────────────────────────────────────────────

async def save_scan(scan_data: Dict[str, Any]) -> bool:
    """
    Insert or replace a scan record.
    scan_data must contain: id, domain, status, created_at
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO scans
                    (id, domain, status, created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_data["id"],
                    scan_data["domain"],
                    scan_data.get("status", "running"),
                    scan_data.get("created_at", datetime.utcnow().isoformat()),
                    datetime.utcnow().isoformat(),
                    json.dumps(scan_data, default=str),
                )
            )
            await db.commit()
        return True
    except Exception as e:
        print(f"[!] DB save_scan error: {e}")
        return False


async def update_scan(scan_id: str, updates: Dict[str, Any]) -> bool:
    """
    Apply partial updates to a scan record.
    Merges `updates` into the existing JSON data blob.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "SELECT data FROM scans WHERE id = ?", (scan_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return False

            existing = json.loads(row[0])
            existing.update(updates)

            await db.execute(
                """
                UPDATE scans
                SET data = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(existing, default=str),
                    existing.get("status", "running"),
                    datetime.utcnow().isoformat(),
                    scan_id,
                )
            )
            await db.commit()
        return True
    except Exception as e:
        print(f"[!] DB update_scan error: {e}")
        return False


async def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single scan by ID. Returns None if not found."""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "SELECT data FROM scans WHERE id = ?", (scan_id,)
            )
            row = await cursor.fetchone()
            if row:
                return json.loads(row[0])
    except Exception as e:
        print(f"[!] DB get_scan error: {e}")
    return None


async def list_scans(limit: int = 100) -> List[Dict[str, Any]]:
    """
    List all scans ordered by creation date (newest first).
    Returns lightweight summaries (without large results blobs).
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                SELECT data FROM scans
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = await cursor.fetchall()
            scans = []
            for row in rows:
                scan = json.loads(row[0])
                # Return a summary for the history list (not full results)
                scans.append(_scan_summary(scan))
            return scans
    except Exception as e:
        print(f"[!] DB list_scans error: {e}")
        return []


async def delete_scan_db(scan_id: str) -> bool:
    """Delete a scan record by ID."""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            await db.commit()
        return True
    except Exception as e:
        print(f"[!] DB delete_scan error: {e}")
        return False


async def get_scans_for_domain(domain: str) -> List[Dict[str, Any]]:
    """Get all scans for a specific domain."""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                SELECT data FROM scans
                WHERE domain = ?
                ORDER BY created_at DESC
                """,
                (domain,)
            )
            rows = await cursor.fetchall()
            return [json.loads(row[0]) for row in rows]
    except Exception as e:
        print(f"[!] DB get_scans_for_domain error: {e}")
        return []


async def search_scans(query: str) -> List[Dict[str, Any]]:
    """Full-text search over domain names."""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                SELECT data FROM scans
                WHERE domain LIKE ?
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (f"%{query}%",)
            )
            rows = await cursor.fetchall()
            return [_scan_summary(json.loads(row[0])) for row in rows]
    except Exception as e:
        print(f"[!] DB search_scans error: {e}")
        return []


async def get_stats() -> Dict[str, Any]:
    """Get aggregate stats across all scans."""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            # Total scans
            cursor = await db.execute("SELECT COUNT(*) FROM scans")
            total = (await cursor.fetchone())[0]

            # By status
            cursor = await db.execute(
                "SELECT status, COUNT(*) FROM scans GROUP BY status"
            )
            by_status = {row[0]: row[1] for row in await cursor.fetchall()}

            # Unique domains
            cursor = await db.execute("SELECT COUNT(DISTINCT domain) FROM scans")
            unique_domains = (await cursor.fetchone())[0]

        return {
            "total_scans": total,
            "by_status": by_status,
            "unique_domains": unique_domains,
        }
    except Exception as e:
        print(f"[!] DB get_stats error: {e}")
        return {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan_summary(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a lightweight summary from a full scan dict (for history listing)."""
    results = scan.get("results", {})

    # Aggregate subdomains
    subs: set = set()
    for m in ("subfinder", "amass"):
        for s in results.get(m, {}).get("subdomains", []):
            subs.add(s)

    nuclei = results.get("nuclei", {})

    return {
        "id": scan.get("id"),
        "domain": scan.get("domain"),
        "status": scan.get("status"),
        "created_at": scan.get("created_at"),
        "completed_at": scan.get("completed_at"),
        "duration": scan.get("duration", 0),
        "progress": scan.get("progress", 0),
        "modules": scan.get("modules", []),
        # Summary counts — for display in history sidebar
        "summary": {
            "subdomains": len(subs),
            "open_ports": len(results.get("nmap", {}).get("ports", [])),
            "live_hosts": results.get("httpx", {}).get("count", 0),
            "vulnerabilities": nuclei.get("count", 0),
            "critical": nuclei.get("critical", 0),
            "high": nuclei.get("high", 0),
            "medium": nuclei.get("medium", 0),
            "low": nuclei.get("low", 0),
            "directories": results.get("gobuster", {}).get("count", 0),
        },
    }
