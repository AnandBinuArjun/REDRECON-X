import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from redrecon.core.logger import get_logger
from redrecon.models.asset import Asset
from redrecon.models.finding import Finding
from redrecon.models.scan import ScanMetrics, ScanMode, ScanResult, ScanStatus
from redrecon.storage.database import Database

logger = get_logger()


class ScanRepository:
    """Repository handling CRUD operations for Scans, Assets, and Findings."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def save_scan(self, scan: ScanResult) -> None:
        """Persist a completed or in-progress scan."""
        with self.db.get_connection() as conn:
            # 1. Upsert scan record
            conn.execute(
                """
                INSERT INTO scans (scan_id, target, mode, status, started_at, completed_at, duration_sec, metrics_json, raw_data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    status=excluded.status,
                    completed_at=excluded.completed_at,
                    duration_sec=excluded.duration_sec,
                    metrics_json=excluded.metrics_json,
                    raw_data_json=excluded.raw_data_json
                """,
                (
                    scan.scan_id,
                    scan.target,
                    scan.mode.value,
                    scan.status.value,
                    scan.started_at.isoformat(),
                    scan.completed_at.isoformat() if scan.completed_at else None,
                    scan.metrics.scan_duration_sec,
                    scan.metrics.model_dump_json(),
                    json.dumps(scan.raw_data),
                ),
            )

            # 2. Insert assets
            for asset in scan.assets:
                conn.execute(
                    """
                    INSERT INTO assets (scan_id, hostname, root_domain, confidence, is_live, asset_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan.scan_id,
                        asset.hostname,
                        asset.root_domain,
                        asset.confidence.value,
                        1 if asset.is_live else 0,
                        asset.model_dump_json(),
                    ),
                )

            # 3. Insert findings
            for finding in scan.findings:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (id, scan_id, target, source, template_id, name, severity, description, evidence, reference, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.id,
                        scan.scan_id,
                        finding.target,
                        finding.source,
                        finding.template_id,
                        finding.name,
                        finding.severity.value,
                        finding.description,
                        finding.evidence,
                        finding.reference,
                        finding.created_at.isoformat(),
                    ),
                )

            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve full scan details by ID."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if not row:
                return None

            # Retrieve assets
            asset_rows = conn.execute("SELECT asset_json FROM assets WHERE scan_id = ?", (scan_id,)).fetchall()
            assets = [Asset(**json.loads(r["asset_json"])) for r in asset_rows]

            # Retrieve findings
            finding_rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
            findings = [
                Finding(
                    id=r["id"],
                    target=r["target"],
                    source=r["source"],
                    template_id=r["template_id"],
                    name=r["name"],
                    severity=r["severity"],
                    description=r["description"] or "",
                    evidence=r["evidence"],
                    reference=r["reference"],
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
                for r in finding_rows
            ]

            metrics_data = json.loads(row["metrics_json"]) if row["metrics_json"] else {}
            raw_data = json.loads(row["raw_data_json"]) if row["raw_data_json"] else {}

            return ScanResult(
                scan_id=row["scan_id"],
                target=row["target"],
                mode=ScanMode(row["mode"]),
                status=ScanStatus(row["status"]),
                started_at=datetime.fromisoformat(row["started_at"]),
                completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                assets=assets,
                findings=findings,
                metrics=ScanMetrics(**metrics_data),
                raw_data=raw_data,
            )

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List summary of scans."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT scan_id, target, mode, status, started_at, completed_at, duration_sec, metrics_json FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

            scans = []
            for r in rows:
                metrics = json.loads(r["metrics_json"]) if r["metrics_json"] else {}
                scans.append({
                    "scan_id": r["scan_id"],
                    "target": r["target"],
                    "mode": r["mode"],
                    "status": r["status"],
                    "started_at": r["started_at"],
                    "completed_at": r["completed_at"],
                    "duration_sec": r["duration_sec"],
                    "metrics": metrics,
                })
            return scans

    def get_previous_scan_for_target(self, target: str, exclude_scan_id: Optional[str] = None) -> Optional[ScanResult]:
        """Retrieve the most recent prior scan for a target."""
        with self.db.get_connection() as conn:
            query = "SELECT scan_id FROM scans WHERE target = ?"
            params = [target]
            if exclude_scan_id:
                query += " AND scan_id != ?"
                params.append(exclude_scan_id)
            query += " AND status = 'completed' ORDER BY started_at DESC LIMIT 1"

            row = conn.execute(query, tuple(params)).fetchone()
            if not row:
                return None
            return self.get_scan(row["scan_id"])

    def list_assets(
        self,
        target: Optional[str] = None,
        scan_id: Optional[str] = None,
        confidence: Optional[str] = None,
        min_priority: Optional[int] = None,
        limit: int = 100,
    ) -> List[Asset]:
        """Retrieve assets matching filters."""
        with self.db.get_connection() as conn:
            query = "SELECT asset_json FROM assets WHERE 1=1"
            params: List[Any] = []
            if scan_id:
                query += " AND scan_id = ?"
                params.append(scan_id)
            if target:
                query += " AND root_domain = ?"
                params.append(target)
            if confidence:
                query += " AND confidence = ?"
                params.append(confidence.upper())

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, tuple(params)).fetchall()
            assets = [Asset(**json.loads(r["asset_json"])) for r in rows]

            if min_priority is not None:
                assets = [a for a in assets if a.priority_score >= min_priority]

            return assets

    def get_asset(self, asset_id: int) -> Optional[Asset]:
        """Retrieve single asset by database ID."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT asset_json FROM assets WHERE id = ?", (asset_id,)).fetchone()
            if not row:
                return None
            return Asset(**json.loads(row["asset_json"]))

    def list_findings(
        self,
        target: Optional[str] = None,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Finding]:
        """Retrieve findings matching filters."""
        with self.db.get_connection() as conn:
            query = "SELECT * FROM findings WHERE 1=1"
            params: List[Any] = []
            if scan_id:
                query += " AND scan_id = ?"
                params.append(scan_id)
            if target:
                query += " AND target LIKE ?"
                params.append(f"%{target}%")
            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, tuple(params)).fetchall()
            return [
                Finding(
                    id=r["id"],
                    target=r["target"],
                    source=r["source"],
                    template_id=r["template_id"],
                    name=r["name"],
                    severity=r["severity"],
                    description=r["description"] or "",
                    evidence=r["evidence"],
                    reference=r["reference"],
                    created_at=datetime.fromisoformat(r["created_at"]),
                )
                for r in rows
            ]

    def delete_scan(self, scan_id: str) -> bool:
        """Delete scan and all associated assets, findings, and progress records."""
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM assets WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scan_progress WHERE scan_id = ?", (scan_id,))
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    # -------------------------------------------------------------
    # Scan Progress Tracking
    # -------------------------------------------------------------
    def update_scan_progress(
        self,
        scan_id: str,
        current_stage: str,
        progress_percent: int,
        message: Optional[str] = None,
    ) -> None:
        """Update live execution stage and percentage for active scan."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scan_progress (scan_id, current_stage, progress_percent, message, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    current_stage=excluded.current_stage,
                    progress_percent=excluded.progress_percent,
                    message=excluded.message,
                    updated_at=excluded.updated_at
                """,
                (scan_id, current_stage, progress_percent, message or "", datetime.now().isoformat()),
            )
            conn.commit()

    def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve current scan stage and percentage."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM scan_progress WHERE scan_id = ?", (scan_id,)).fetchone()
            if not row:
                return None
            return {
                "scan_id": row["scan_id"],
                "current_stage": row["current_stage"],
                "progress_percent": row["progress_percent"],
                "message": row["message"],
                "updated_at": row["updated_at"],
            }

    # -------------------------------------------------------------
    # User Management & RBAC Authentication
    # -------------------------------------------------------------
    @staticmethod
    def _hash_pw(password: str, salt: Optional[str] = None) -> tuple[str, str]:
        import hashlib, secrets
        salt = salt or secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
        return pw_hash, salt

    def create_user(self, username: str, password: str, role: str = "ANALYST") -> Dict[str, Any]:
        """Create new user with specified RBAC role (ADMIN, ANALYST, VIEWER)."""
        import uuid
        role = role.upper()
        if role not in ("ADMIN", "ANALYST", "VIEWER"):
            raise ValueError(f"Invalid role: {role}. Must be ADMIN, ANALYST, or VIEWER.")
        
        pw_hash, salt = self._hash_pw(password)
        user_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash=excluded.password_hash,
                    salt=excluded.salt,
                    role=excluded.role
                """,
                (user_id, username.lower().strip(), pw_hash, salt, role, created_at),
            )
            conn.commit()
        return {"id": user_id, "username": username, "role": role, "created_at": created_at}

    def verify_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify username & password and return user object if valid."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username.lower().strip(),)).fetchone()
            if not row:
                return None
            expected_hash, _ = self._hash_pw(password, salt=row["salt"])
            if expected_hash == row["password_hash"]:
                return {
                    "id": row["id"],
                    "username": row["username"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                }
            return None

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve user details without password hash."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT id, username, role, created_at FROM users WHERE username = ?", (username.lower().strip(),)).fetchone()
            if not row:
                return None
            return dict(row)

    def list_users(self) -> List[Dict[str, Any]]:
        """List all registered system users."""
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at ASC").fetchall()
            return [dict(r) for r in rows]

    def delete_user(self, username: str) -> bool:
        """Delete user by username."""
        with self.db.get_connection() as conn:
            cursor = conn.execute("DELETE FROM users WHERE username = ?", (username.lower().strip(),))
            conn.commit()
            return cursor.rowcount > 0

    def init_default_admin(self) -> None:
        """Initialize default admin if user table is empty."""
        with self.db.get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
            if count == 0:
                import os
                default_pw = os.getenv("REDRECON_ADMIN_PASSWORD", "RedReconAdmin!2026")
                self.create_user(username="admin", password=default_pw, role="ADMIN")
                self.log_audit(
                    username="system",
                    action="INIT_DEFAULT_ADMIN",
                    resource="users/admin",
                    status="SUCCESS",
                    details="Initialized default administrative account",
                )

    # -------------------------------------------------------------
    # Audit Logging
    # -------------------------------------------------------------
    def log_audit(
        self,
        username: str,
        action: str,
        resource: Optional[str] = None,
        status: str = "SUCCESS",
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Record administrative or operational audit log event."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (username, action, resource, status, details, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (username, action, resource or "", status, details or "", ip_address or "127.0.0.1", datetime.now().isoformat()),
            )
            conn.commit()

    def list_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent security and operational audit logs."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
