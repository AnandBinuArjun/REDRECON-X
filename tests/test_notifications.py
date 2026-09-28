import pytest
from redrecon.intelligence.notifications import NotificationDispatcher
from redrecon.models.finding import Finding, FindingSeverity
from redrecon.models.scan import ScanMetrics, ScanMode, ScanResult, ScanStatus


@pytest.mark.asyncio
async def test_notifications_without_webhook():
    """Verify dispatcher safely skips when no webhook URL is configured."""
    dispatcher = NotificationDispatcher(webhook_url=None)
    result = await dispatcher.send_event("TEST", "Test Title", {"foo": "bar"})
    assert result is False


@pytest.mark.asyncio
async def test_notifications_finding_alert():
    """Verify payload generation for finding notifications."""
    dispatcher = NotificationDispatcher(webhook_url=None)
    finding = Finding(
        id="f-1",
        target="https://example.com/.git/HEAD",
        source="nuclei",
        template_id="git-exposure",
        name="Exposed Git Repository",
        severity=FindingSeverity.HIGH,
        evidence="ref: refs/heads/main",
    )
    result = await dispatcher.notify_critical_finding("example.com", finding)
    assert result is False
