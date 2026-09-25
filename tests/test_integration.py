import asyncio
import base64
import os
import sys
from pathlib import Path

import httpx
import pytest

from hilait.server import create_app
from hilait.sessions import HostKeyApprovalNeeded
from hilait.server import run_agent_tool


@pytest.fixture
async def fixture_server(tmp_path):
    process = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).parent / "ssh_fixture.py"),
                                                    str(tmp_path / "remote"), stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
    port = int((await asyncio.wait_for(process.stdout.readline(), 15)).decode())
    try:
        yield port
    finally:
        process.terminate()
        await asyncio.wait_for(process.wait(), 10)


@pytest.mark.asyncio
async def test_ssh_host_trust_terminal_sftp_and_agent_scope(tmp_path, fixture_server):
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    profile = {"id":"machine-1", "name":"Loopback", "host":"127.0.0.1", "port":fixture_server,
               "username":"harbor-test", "secret":runtime.store.encrypt("loopback-fixture-only"),
               "platform":"unix", "shell":"default", "allowed_agent_ids":None}
    runtime.store.save_profiles([profile])
    with pytest.raises(HostKeyApprovalNeeded) as warning:
        await runtime.sessions.open(profile)
    assert warning.value.fingerprint.startswith("SHA256:")
    endpoint = warning.value.host
    runtime.store.write("known-hosts.json", {endpoint:warning.value.fingerprint})
    first = await runtime.sessions.open(profile)
    second = await runtime.sessions.open(profile)
    try:
        await asyncio.sleep(.25)
        before = first.base_cursor + len(first.output)
        await runtime.sessions.write(first.id, b"hello\r")
        for _ in range(20):
            if "echo: hello" in first.read(before)["text"]:
                break
            await asyncio.sleep(.1)
        assert "echo: hello" in first.read(before)["text"]
        assert "echo: hello" not in second.read()["text"]
        result = await runtime.files.operate(first.id, "write", "/test.txt", base64=base64.b64encode(b"hello files").decode())
        assert result["written"] == 11
        assert base64.b64decode((await runtime.files.operate(first.id,"read","/test.txt"))["base64"]) == b"hello files"
        await runtime.files.copy(first.id,"remote","/test.txt","/copy.txt", destination_id=second.id)
        assert (tmp_path/"remote"/"copy.txt").read_bytes() == b"hello files"
        agent, token = runtime.store.create_agent("Fixture agent")
        assert runtime.agents.visible_connections(agent)[0]["name"] == "Loopback"
        assert "host" not in runtime.agents.visible_connections(agent)[0]
        purpose = "Inspect the loopback fixture, read its test file, compare the result, and report the outcome without changing unrelated data."
        pending = await runtime.agents.request(agent, profile["id"], purpose, "None")
        with pytest.raises(PermissionError):
            runtime.agents.owned(agent, pending.id, active=True)
        await runtime.agents.approve(pending.id)
        runtime.store.save_profiles([{**profile, "sudo_secret": runtime.store.encrypt("fixture-sudo-secret"), "sudo_policy": "never"}])
        sudo = await run_agent_tool(runtime, agent, "request_sudo", {"access": pending.id, "command": "true", "reason": "Check managed sudo without changing state."})
        assert sudo["exitCode"] == 0
        assert "managed sudo succeeded" in sudo["output"]
        assert pending.state == "Approved"
        with pytest.raises(PermissionError, match="file"):
            runtime.agents.owned(agent, pending.id, active=True, files=True)
        runtime.agents.change(pending,"Paused","Test pause")
        with pytest.raises(PermissionError):
            runtime.agents.owned(agent,pending.id,active=True)
        runtime.agents.change(pending,"Approved","Test resume")
        await runtime.agents.release(agent,pending.id,close_connection=True)
        assert pending.session_id not in runtime.sessions.sessions
        assert token not in (tmp_path/"data"/"activity.audit").read_text()
    finally:
        for session_id in list(runtime.sessions.sessions):
            await runtime.sessions.close(session_id)


@pytest.mark.asyncio
async def test_api_token_and_machine_authorization(tmp_path):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/api/state")).status_code == 401
        headers = {"Authorization":"Bearer "+runtime.store.admin_token}
        created = await client.post("/api/profiles", headers=headers, json={"name":"One","host":"localhost","username":"ada"})
        assert created.status_code == 200, created.text
        profile = created.json()
        assert "secret" not in profile
        agent = (await client.post("/api/agents", headers=headers, json={"name":"Agent"})).json()
        token = agent["config"]["mcpServers"]["hilait"]["env"]["HILAIT_AGENT_TOKEN"]
        agent_headers = {"Authorization":"Bearer "+token}
        listed = await client.post("/agent/connections", headers=agent_headers, json={})
        assert listed.json()[0]["name"] == "One"
        assert "host" not in listed.json()[0]
        purpose = "Check the saved machine's state and report what is available, without changing files, services, settings, or other resources."
        request = await client.post("/agent/request_access", headers=agent_headers, json={"connection":profile["id"],"purpose":purpose,"fileAccess":"Remote"})
        assert request.status_code == 200, request.text
        access = request.json()["access"]
        denied = await client.post("/agent/files", headers=agent_headers, json={"access":access,"action":"list","path":"/"})
        assert denied.status_code == 403
        saved = await client.post("/api/authorizations", headers=headers, json={"agent_id":agent["agent"]["id"],"profile_id":profile["id"],"hours":1,"file_access":"Remote"})
        assert saved.status_code == 200, saved.text
        listed = await client.post("/api/profiles/order", headers=headers, json={"ids":[profile["id"]]})
        assert listed.status_code == 200
        changed = await client.post("/api/profiles", headers=headers, json={**profile, "allowed_agent_ids": []})
        assert changed.status_code == 200, changed.text
        assert (await client.post("/agent/connections", headers=agent_headers, json={})).json() == []
        assert runtime.agents.active_authorization(agent["agent"]["id"], profile["id"]) is None
        refused = await client.post("/agent/request_access", headers=agent_headers,
                                    json={"connection":profile["id"],"purpose":purpose,"fileAccess":"None"})
        assert refused.status_code == 403
