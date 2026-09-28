from typing import Any, Dict, Optional
from redrecon.modules.base import BaseModule
from redrecon.reporting.html import HTMLReporter
from redrecon.reporting.json import JSONReporter
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository


class ReportGenerator(BaseModule):
    """
    Module [12]: Report Generator.
    Loads scan results from repository and generates machine-readable JSON and interactive HTML reports.
    """

    @property
    def name(self) -> str:
        return "Report Generator"

    @property
    def description(self) -> str:
        return "Compiles scan telemetry into structured JSON outputs and an interactive HTML report"

    async def scan(self, target: str) -> Dict[str, Any]:
        db = Database(db_path=self.config.db_path)
        repo = ScanRepository(db)

        # Look up most recent scan for this target
        all_scans = repo.list_scans()
        matching = [s for s in all_scans if s.get("target") == target]
        if not matching:
            return {
                "target": target,
                "status": "error",
                "message": f"No scan records found in database for target {target}",
            }

        latest_id = matching[0]["scan_id"]
        scan_result = repo.get_scan(latest_id)
        if not scan_result:
            return {
                "target": target,
                "status": "error",
                "message": f"Could not load scan {latest_id}",
            }

        json_dir = JSONReporter.export(scan_result, base_dir=self.config.output_dir)
        html_file = HTMLReporter.generate(scan_result, base_dir=self.config.output_dir)

        return {
            "target": target,
            "scan_id": latest_id,
            "status": "success",
            "json_dir": json_dir,
            "html_report": html_file,
        }
