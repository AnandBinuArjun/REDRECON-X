import os
from typing import Any, Dict, List, Optional
import httpx
from redrecon.core.logger import get_logger
from redrecon.models.finding import Finding
from redrecon.models.scan import ScanResult

logger = get_logger()


class NotificationDispatcher:
    """
    Dispatches attack-surface alerts and scan completion events to configured webhooks
    (Slack, Discord, Microsoft Teams, generic SOC endpoint).
    """

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("REDRECON_WEBHOOK_URL")

    async def send_event(self, event_type: str, title: str, details: Dict[str, Any]) -> bool:
        if not self.webhook_url:
            logger.debug("No webhook URL configured; skipping notification.")
            return False

        payload = {
            "source": "REDRECON-X",
            "event_type": event_type,
            "title": title,
            "details": details,
        }

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(self.webhook_url, json=payload)
                if res.status_code in (200, 204):
                    logger.info(f"Webhook notification sent successfully for: {title}")
                    return True
                else:
                    logger.warning(f"Webhook response error {res.status_code}: {res.text}")
                    return False
        except Exception as e:
            logger.warning(f"Failed to deliver webhook notification: {e}")
            return False

    async def notify_scan_completed(self, scan_result: ScanResult) -> bool:
        """Alerts when a full or passive reconnaissance scan finishes."""
        m = scan_result.metrics
        return await self.send_event(
            event_type="SCAN_COMPLETED",
            title=f"Reconnaissance Completed: {scan_result.target}",
            details={
                "scan_id": scan_result.scan_id,
                "target": scan_result.target,
                "mode": scan_result.mode.value,
                "duration_seconds": scan_result.duration_sec,
                "discovered_hosts": m.discovered_hosts,
                "unique_ips": m.unique_ips,
                "open_ports": m.total_open_ports,
                "candidate_findings": m.nuclei_findings,
            },
        )

    async def notify_drift_detected(self, target: str, drift_summary: Dict[str, Any]) -> bool:
        """Alerts when the attack surface difference engine detects new assets or open ports."""
        return await self.send_event(
            event_type="ATTACK_SURFACE_DRIFT",
            title=f"Attack Surface Drift Detected: {target}",
            details=drift_summary,
        )

    async def notify_critical_finding(self, target: str, finding: Finding) -> bool:
        """Immediate alert for high or critical candidate security exposures."""
        return await self.send_event(
            event_type="SECURITY_FINDING_ALERT",
            title=f"[{finding.severity.value}] Candidate Finding on {target}",
            details={
                "name": finding.name,
                "severity": finding.severity.value,
                "target": finding.target,
                "template_id": finding.template_id,
                "evidence": finding.evidence,
            },
        )
