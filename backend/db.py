"""SQLite database models and helpers for AutoRecon scan persistence."""

import aiosqlite
import json
import os
from pathlib import Path
from datetime import datetime

DB_DIR = Path.home() / ".autorecon"
DB_PATH = DB_DIR / "scans.db"
CONFIG_PATH = DB_DIR / "config.json"

async def init_db():
    """Initialize database and create tables if they don't exist."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(DB_PATH)) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                profile TEXT,
                wordlist TEXT,
                threads INTEGER DEFAULT 50,
                modules TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                progress INTEGER DEFAULT 0,
                active_module TEXT,
                results TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                module TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        await db.commit()


async def create_scan(scan_id: str, domain: str, profile: str, wordlist: str, threads: int, modules: list):
    async with aiosqlite.connect(str(DB_PATH)) as db:
        await db.execute(
            "INSERT INTO scans (id, domain, status, profile, wordlist, threads, modules, started_at) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, domain, "running", profile, wordlist, threads, json.dumps(modules), datetime.utcnow().isoformat())
        )
        await db.commit()


async def update_scan(scan_id: str, **kwargs):
    async with aiosqlite.connect(str(DB_PATH)) as db:
        sets = []
        vals = []
        for k, v in kwargs.items():
            sets.append(f"{k} = ?")
            vals.append(json.dumps(v) if isinstance(v, (dict, list)) else v)
        vals.append(scan_id)
        await db.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)
        await db.commit()


async def get_scan(scan_id: str):
    async with aiosqlite.connect(str(DB_PATH)) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row:
            data = dict(row)
            if data.get("results"):
                data["results"] = json.loads(data["results"])
            if data.get("modules"):
                data["modules"] = json.loads(data["modules"])
            return data
        return None


async def get_scan_history():
    async with aiosqlite.connect(str(DB_PATH)) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT id, domain, status, profile, started_at, completed_at, progress FROM scans ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def delete_scan(scan_id: str):
    async with aiosqlite.connect(str(DB_PATH)) as db:
        await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()


async def add_log(scan_id: str, module: str, level: str, message: str):
    async with aiosqlite.connect(str(DB_PATH)) as db:
        await db.execute(
            "INSERT INTO scan_logs (scan_id, timestamp, module, level, message) VALUES (?,?,?,?,?)",
            (scan_id, datetime.utcnow().isoformat(), module, level, message)
        )
        await db.commit()


async def get_logs(scan_id: str):
    async with aiosqlite.connect(str(DB_PATH)) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id", (scan_id,))
        return [dict(r) for r in await cursor.fetchall()]


def load_config():
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    return {
        "api_keys": {"shodan": "", "virustotal": "", "censys_id": "", "censys_secret": "", "securitytrails": "", "ipinfo": "", "github": ""},
        "default_wordlist": "/usr/share/wordlists/dirb/common.txt",
        "default_threads": 50,
        "proxy": "",
        "notifications": {"discord_webhook": "", "slack_webhook": ""},
        "scope": {"in_scope": [], "out_of_scope": []},
    }


def save_config(config: dict):
    DB_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
