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
