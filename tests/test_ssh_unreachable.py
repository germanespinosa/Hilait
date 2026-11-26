"""An unreachable machine must produce a clear 502, not a bare 500, and never reveal its host."""
import socket

import httpx
import pytest

from hilait.server import create_app
from hilait.sessions import SSHConnectionError


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_unreachable_machine_reports_502_without_host(tmp_path, activate_otp):
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    profile = {"id": "m1", "name": "alfredAI", "host": "127.0.0.1", "port": closed_port(), "username": "nobody",
               "secret": runtime.store.encrypt("x"), "platform": "unix", "allowed_agent_ids": None}
    runtime.store.save_profiles([profile])
    with pytest.raises(SSHConnectionError) as failure:
        await runtime.sessions.open(profile)
    assert "alfredAI" in str(failure.value) and "127.0.0.1" not in str(failure.value)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/sessions", json={"profile": "m1"}, headers=headers)
    assert response.status_code == 502
    assert "alfredAI" in response.json()["error"] and "127.0.0.1" not in response.json()["error"]
