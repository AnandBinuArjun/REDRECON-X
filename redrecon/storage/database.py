import os
import sqlite3
from pathlib import Path
from redrecon.core.logger import get_logger

logger = get_logger()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_sec REAL DEFAULT 0,
    metrics_json TEXT,
    raw_data_json TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    root_domain TEXT NOT NULL,
    confidence TEXT NOT NULL,
    is_live INTEGER DEFAULT 0,
    asset_json TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    target TEXT NOT NULL,
    source TEXT NOT NULL,
    template_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    reference TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL, -- ADMIN, ANALYST, VIEWER
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    username TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    status TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_progress (
    scan_id TEXT PRIMARY KEY,
    current_stage TEXT NOT NULL,
    progress_percent INTEGER NOT NULL,
    message TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);
"""


class Database:
    """Manages SQLite database connection and table schema creation."""

    def __init__(self, db_path: str = "reports/redrecon.db"):
        self.db_path = db_path
        self._ensure_db_dir()
        self.init_db()

    def _ensure_db_dir(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
