import asyncio
import httpx
import pytest
from redrecon.dashboard.app import app

@pytest.mark.asyncio
async def test_dashboard_endpoints():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Dashboard UI
        r_index = await client.get("/")
        assert r_index.status_code == 200
        assert "REDRECON" in r_index.text

        # 2. Scans API
        r_scans = await client.get("/api/scans")
        assert r_scans.status_code == 200
        scans = r_scans.json()
        assert isinstance(scans, list)

        # 3. Modules API
        r_mods = await client.get("/api/modules")
        assert r_mods.status_code == 200
        mods = r_mods.json()
        assert len(mods) == 12

        # 4. Assets API
        r_assets = await client.get("/api/assets")
        assert r_assets.status_code == 200
        assert isinstance(r_assets.json(), list)

        # 5. Attack Surface Graph API
        if scans:
            latest_id = scans[0]["scan_id"]
            r_graph = await client.get(f"/api/scans/{latest_id}/graph")
            assert r_graph.status_code == 200
            g = r_graph.json()
            assert "total_nodes" in g

            # 6. Report info API
            r_rep = await client.get(f"/api/reports/{latest_id}")
            assert r_rep.status_code == 200

        # 7. Serve generated report file
        r_file = await client.get("/reports/abarjun.online/report.html")
        assert r_file.status_code == 200
        assert "text/html" in r_file.headers.get("content-type", "")
        assert "REDRECON-X" in r_file.text
