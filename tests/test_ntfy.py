"""Notification delivery and phone approval preserve Hilait's grant boundary."""

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from hilait.server import create_app


@pytest.mark.asyncio
async def test_ntfy_settings_delivery_and_protected_decision(tmp_path, monkeypatch, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    admin = {"Authorization": "Bearer " + activate_otp(runtime)}
    sent = []
    request_sent = asyncio.Event()

    async def capture(config, payload):
        sent.append((config, payload))
        if len(sent) == 2:
            request_sent.set()

    monkeypatch.setattr(runtime.ntfy, "_post", capture)
    runtime.store.save_profiles([{"id": "machine-1", "name": "Alfred", "host": "localhost", "port": 22,
                                  "username": "hidden-user", "allowed_agent_ids": None}])
    agent, _ = runtime.store.create_agent("Reviewer agent")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/api/notifications/ntfy")).status_code == 401
        invalid = await client.put("/api/notifications/ntfy", headers=admin, json={"enabled": True,
            "server_url": "http://ntfy.example", "topic": "hilait", "hilait_url": "https://hilait.example"})
        assert invalid.status_code == 400
        saved = await client.put("/api/notifications/ntfy", headers=admin, json={"enabled": True,
            "server_url": "https://ntfy.example", "topic": "hilait-private", "hilait_url": "https://hilait.example",
            "token": "ntfy-secret-token"})
        assert saved.status_code == 200, saved.text
        assert saved.json()["has_token"] is True
        assert "ntfy-secret-token" not in saved.text
        assert "ntfy-secret-token" not in (tmp_path / "ntfy.json").read_text()
        assert (await client.post("/api/notifications/ntfy/test", headers=admin)).json() == {"sent": True}
        purpose = "Inspect the selected machine, verify service health, and report findings without modifying its files or settings."
        grant = await runtime.agents.request(agent, "machine-1", purpose, "Remote")
        await asyncio.wait_for(request_sent.wait(), 2)
        assert len(sent) == 2
        payload = sent[1][1]
        assert payload["topic"] == "hilait-private"
        assert "Reviewer agent" in payload["title"]
        assert "Files: Remote" in payload["message"]
        assert "hidden-user" not in str(payload)
        assert payload["actions"][0]["url"] == f"https://hilait.example/approve/{grant.id}?choice=approve"
        assert payload["actions"][1]["url"] == f"https://hilait.example/approve/{grant.id}?choice=reject"
        assert (await client.get(f"/approve/{grant.id}")).status_code == 200
        assert (await client.get(f"/api/grants/{grant.id}")).status_code == 401
        detail = await client.get(f"/api/grants/{grant.id}", headers=admin)
        assert detail.json()["purpose"] == purpose
        assert detail.json()["fileAccess"] == "Remote"
        denied = await client.post(f"/api/grants/{grant.id}/reject", headers=admin, json={})
        assert denied.json()["state"] == "Denied"
        assert (await client.post(f"/api/grants/{grant.id}/reject", headers=admin, json={})).status_code == 400


@pytest.mark.asyncio
async def test_expired_request_cannot_be_approved_or_denied(tmp_path, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    admin = {"Authorization": "Bearer " + activate_otp(runtime)}
    runtime.store.save_profiles([{"id": "machine-1", "name": "Machine", "host": "localhost", "port": 22,
                                  "username": "user", "allowed_agent_ids": None}])
    agent, _ = runtime.store.create_agent("Agent")
    grant = await runtime.agents.request(agent, "machine-1", "Inspect this machine and report what is available without changing unrelated data or system settings.")
    grant.requested_utc = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get(f"/api/grants/{grant.id}", headers=admin)).json()["state"] == "Expired"
        assert (await client.post(f"/api/grants/{grant.id}/approve", headers=admin, json={})).status_code == 400
        assert (await client.post(f"/api/grants/{grant.id}/reject", headers=admin, json={})).status_code == 400
