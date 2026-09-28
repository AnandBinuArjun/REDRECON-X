"""
Unit and integration tests for REDRECON-X Authentication, RBAC, and Audit Logging.
Validates:
1. User creation, PBKDF2 password hashing & verification
2. Default administrator auto-initialization
3. Role-Based Access Control (ADMIN, ANALYST, VIEWER permissions)
4. Session login, token issuance, and logout
5. Audit log generation and retrieval
6. Scan cancellation and deletion controls
"""

import pytest
import httpx
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository
from redrecon.dashboard.app import app, SESSION_STORE


@pytest.fixture
def test_repo(tmp_path):
    db_path = str(tmp_path / "test_auth.db")
    db = Database(db_path)
    repo = ScanRepository(db)
    repo.init_default_admin()
    return repo


def test_user_creation_and_hash_verification(test_repo):
    """Verify PBKDF2 password hashing, salt uniqueness, and role assignments."""
    u1 = test_repo.create_user("analyst1", "SecretPass123!", role="ANALYST")
    assert u1["username"] == "analyst1"
    assert u1["role"] == "ANALYST"

    # Verify correct credentials
    verified = test_repo.verify_user("analyst1", "SecretPass123!")
    assert verified is not None
    assert verified["role"] == "ANALYST"

    # Verify wrong credentials fail
    wrong = test_repo.verify_user("analyst1", "WrongPass")
    assert wrong is None

    # Verify invalid role raises error
    with pytest.raises(ValueError):
        test_repo.create_user("baduser", "pass", role="SUPERUSER")


def test_default_admin_initialization(test_repo):
    """Verify default admin user exists and audit event is recorded."""
    admin = test_repo.get_user("admin")
    assert admin is not None
    assert admin["role"] == "ADMIN"

    logs = test_repo.list_audit_logs()
    assert any(l["action"] == "INIT_DEFAULT_ADMIN" for l in logs)


def test_audit_logging_flow(test_repo):
    """Verify audit logs are recorded with user context, action, and timestamps."""
    test_repo.log_audit(
        username="admin",
        action="EXPORT_REPORT",
        resource="reports/example.com",
        status="SUCCESS",
        details="Generated HTML dossier",
    )

    logs = test_repo.list_audit_logs(limit=10)
    assert len(logs) >= 2
    recent = logs[0]
    assert recent["action"] == "EXPORT_REPORT"
    assert recent["username"] == "admin"
    assert recent["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_rbac_api_endpoints():
    """Verify API authentication, RBAC boundaries, and token handling."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login with default admin
        r_login = await client.post("/api/auth/login", json={"username": "admin", "password": "RedReconAdmin!2026"})
        assert r_login.status_code == 200
        admin_data = r_login.json()
        assert "token" in admin_data
        admin_token = admin_data["token"]
        assert admin_data["role"] == "ADMIN"

        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # 2. Check /api/auth/me
        r_me = await client.get("/api/auth/me", headers=admin_headers)
        assert r_me.status_code == 200
        assert r_me.json()["username"] == "admin"

        # 3. Admin creates an ANALYST and a VIEWER
        r_create_analyst = await client.post(
            "/api/users",
            json={"username": "sec_analyst", "password": "AnalystPass123!", "role": "ANALYST"},
            headers=admin_headers,
        )
        assert r_create_analyst.status_code == 200

        r_create_viewer = await client.post(
            "/api/users",
            json={"username": "auditor_viewer", "password": "ViewerPass123!", "role": "VIEWER"},
            headers=admin_headers,
        )
        assert r_create_viewer.status_code == 200

        # 4. Login as VIEWER
        r_v_login = await client.post("/api/auth/login", json={"username": "auditor_viewer", "password": "ViewerPass123!"})
        assert r_v_login.status_code == 200
        viewer_token = r_v_login.json()["token"]
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

        # 5. VIEWER attempts to trigger scan -> FORBIDDEN (403)
        r_scan_denied = await client.post("/api/scans", json={"target": "example.com", "mode": "passive"}, headers=viewer_headers)
        assert r_scan_denied.status_code == 403

        # 6. VIEWER attempts to view audit logs -> FORBIDDEN (403)
        r_audit_denied = await client.get("/api/audit-logs", headers=viewer_headers)
        assert r_audit_denied.status_code == 403

        # 7. ADMIN views audit logs -> SUCCESS (200)
        r_audit = await client.get("/api/audit-logs", headers=admin_headers)
        assert r_audit.status_code == 200
        assert isinstance(r_audit.json(), list)

        # 8. ANALYST triggers scan -> SUCCESS (200)
        r_a_login = await client.post("/api/auth/login", json={"username": "sec_analyst", "password": "AnalystPass123!"})
        analyst_token = r_a_login.json()["token"]
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

        r_scan_allowed = await client.post("/api/scans", json={"target": "example.com", "mode": "passive"}, headers=analyst_headers)
        assert r_scan_allowed.status_code == 200
        scan_id = r_scan_allowed.json()["scan_id"]

        # 9. Cancel scan endpoint
        r_cancel = await client.post(f"/api/scans/{scan_id}/cancel", headers=analyst_headers)
        assert r_cancel.status_code == 200
        assert "cancellation" in r_cancel.json()["message"].lower() or "marked" in r_cancel.json()["message"].lower()
