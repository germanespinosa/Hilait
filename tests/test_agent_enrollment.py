import httpx
import pytest
import asyncio
import json
from types import SimpleNamespace
from urllib.parse import urlsplit
from fastapi.testclient import TestClient

from hilait import mcp_server
from hilait.server import create_app


@pytest.mark.asyncio
async def test_agent_enrollment_requires_otp_and_private_claim(tmp_path, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://hilait.example") as client:
        discovery = (await client.get("/.well-known/hilait")).json()
        assert discovery["mcp"]["args"] == ["mcp", "--server", "https://hilait.example"]
        request = {"name": "Review agent", "reason": "I need to inspect the approved machines and report on their state."}
        assert (await client.post("/api/agent-enrollment", json=request)).status_code == 403
        admin_session = activate_otp(runtime)
        admin = {"Authorization": "Bearer " + admin_session}
        runtime.store.save_profiles([
            {"id": "one", "name": "One", "host": "one.example", "username": "root", "port": 22, "allowed_agent_ids": None},
            {"id": "two", "name": "Two", "host": "two.example", "username": "root", "port": 22, "allowed_agent_ids": None},
        ])
        created = await client.post("/api/agent-enrollment", json=request)
        assert created.status_code == 200
        item = created.json()
        assert item["state"] == "Pending" and len(item["claim"]) > 30
        assert "claim" not in (await client.get("/api/state", headers=admin)).text
        status_url = f"/api/agent-enrollment/{item['id']}/status"
        assert (await client.post(status_url, json={"claim": "wrong"})).status_code == 404
        assert (await client.post(status_url, json={"claim": item["claim"]})).json()["state"] == "Pending"
        assert (await client.post(f"/api/agent-enrollment/{item['id']}/approve",
                                  headers={"Authorization": "Bearer " + runtime.store.admin_token},
                                  json={"connection_ids": ["one"]})).status_code == 403
        approved = await client.post(f"/api/agent-enrollment/{item['id']}/approve", headers=admin,
                                     json={"connection_ids": ["one"]})
        assert approved.status_code == 200, approved.text
        assert "token" not in approved.json()
        claimed = (await client.post(status_url, json={"claim": item["claim"]})).json()
        assert claimed["state"] == "Approved" and len(claimed["token"]) == 64
        restarted = create_app(tmp_path)
        assert restarted.state.runtime.enrollment.status(item["id"], item["claim"])["token"] == claimed["token"]
        headers = {"Authorization": "Bearer " + claimed["token"]}
        visible = (await client.post("/agent/connections", headers=headers, json={})).json()
        assert [entry["id"] for entry in visible] == ["one"]
        assert "host" not in visible[0] and "username" not in visible[0]
        assert (await client.post(f"/api/agent-enrollment/{item['id']}/approve", headers=admin,
                                  json={"connection_ids": []})).status_code == 400


@pytest.mark.asyncio
async def test_agent_enrollment_denial_and_expiry(tmp_path, activate_otp, monkeypatch):
    app = create_app(tmp_path)
    admin = {"Authorization": "Bearer " + activate_otp(app.state.runtime)}
    clock = [1000.0]
    monkeypatch.setattr("hilait.enrollment.time.monotonic", lambda: clock[0])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://hilait.example") as client:
        body = {"name": "Agent", "reason": "I need a token so I can request approved machine connections."}
        first = (await client.post("/api/agent-enrollment", json=body)).json()
        denied = await client.post(f"/api/agent-enrollment/{first['id']}/reject", headers=admin)
        assert denied.json()["state"] == "Denied"
        assert (await client.post(f"/api/agent-enrollment/{first['id']}/status",
                                  json={"claim": first["claim"]})).json() == {"id": first["id"], "state": "Denied"}
        second = (await client.post("/api/agent-enrollment", json=body)).json()
        clock[0] += 601
        assert (await client.post(f"/api/agent-enrollment/{second['id']}/status",
                                  json={"claim": second["claim"]})).json()["state"] == "Expired"
        assert (await client.post(f"/api/agent-enrollment/{second['id']}/approve", headers=admin,
                                  json={"connection_ids": []})).status_code == 400


def test_mcp_bootstrap_stores_token_without_exposing_it_to_agent(tmp_path, activate_otp, monkeypatch):
    app = create_app(tmp_path / "server")
    session = activate_otp(app.state.runtime)
    app.state.runtime.store.save_profiles([{"id": "machine", "name": "Machine", "host": "host.example",
                                           "username": "root", "port": 22, "allowed_agent_ids": None}])
    monkeypatch.setattr(mcp_server, "user_data_path", lambda *args: tmp_path / "client")
    with TestClient(app) as client:
        class LocalClient:
            def __init__(self, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def post(self, url, **kwargs):
                return client.post(urlsplit(url).path, **kwargs)

        monkeypatch.setattr(mcp_server, "httpx", SimpleNamespace(Client=LocalClient))
        bridge = mcp_server.build_mcp("https://hilait.example")

        def call(tool_name, **kwargs):
            result = asyncio.run(bridge.call_tool(tool_name, kwargs))
            assert not result.is_error, result
            if tool_name == "connections":
                return [json.loads(block.text) for block in result.content]
            return json.loads(result.content[0].text)

        requested = call("request_agent_token", name="MCP agent",
                         reason="I need a named identity to request approved access to one machine.")
        assert requested["state"] == "Pending" and "claim" not in requested
        assert call("agent_token_status")["state"] == "Pending"
        approved = client.post(f"/api/agent-enrollment/{requested['id']}/approve",
                               headers={"Authorization": "Bearer " + session},
                               json={"connection_ids": ["machine"]})
        assert approved.status_code == 200
        claimed = call("agent_token_status")
        assert claimed["ready"] is True and "token" not in claimed
        assert [entry["id"] for entry in call("connections")] == ["machine"]
        credential_files = list((tmp_path / "client" / "agent-clients").glob("*.json"))
        assert len(credential_files) == 1
        saved = json.loads(credential_files[0].read_text())
        assert "token" in saved and "pending" not in saved
