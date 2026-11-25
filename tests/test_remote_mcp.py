import asyncio
import json
import socket
import sys
import threading
from pathlib import Path

import httpx
import httpx2
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from hilait.server import create_app

PURPOSE = ("Run read-only diagnostics on the loopback fixture through the hosted MCP endpoint to confirm "
           "that terminal and file tools work without the local bridge.")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
async def hosted(tmp_path, activate_otp):
    process = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).parent / "ssh_fixture.py"),
                                                    str(tmp_path / "remote"), stdout=asyncio.subprocess.PIPE)
    ssh_port = int((await asyncio.wait_for(process.stdout.readline(), 15)).decode())
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    activate_otp(runtime)
    profile = {"id": "m1", "name": "Loopback", "host": "127.0.0.1", "port": ssh_port, "username": "harbor-test",
               "secret": runtime.store.encrypt("loopback-fixture-only"), "platform": "unix",
               "allowed_agent_ids": None}
    runtime.store.save_profiles([profile])
    http_port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=http_port, log_level="warning"))
    loop: dict = {}

    def serve():
        loop["loop"] = asyncio.new_event_loop()
        loop["loop"].run_until_complete(server.serve())

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)

    def in_server(coro):
        return asyncio.run_coroutine_threadsafe(coro, loop["loop"]).result(30)

    async def trust():
        try:
            await runtime.sessions.open(profile)
        except Exception as warning:
            runtime.store.write("known-hosts.json", {warning.host: warning.fingerprint})
    in_server(trust())
    try:
        yield runtime, f"http://127.0.0.1:{http_port}/mcp", in_server
    finally:
        async def close_all():
            for session_id in list(runtime.sessions.sessions):
                await runtime.sessions.close(session_id)
        in_server(close_all())
        server.should_exit = True
        thread.join(10)
        process.terminate()
        await process.wait()


def _result(response):
    assert not response.is_error, response.content
    data = response.structured_content
    if data is None:
        return json.loads(response.content[0].text)
    return data.get("result", data) if set(data) == {"result"} else data


async def test_hosted_mcp_requires_agent_token(hosted):
    _, url, _ = hosted
    async with httpx.AsyncClient() as client:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        missing = await client.post(url, json=body)
        assert missing.status_code == 401 and missing.headers["www-authenticate"].startswith("Bearer")
        wrong = await client.post(url, json=body, headers={"Authorization": "Bearer " + "0" * 64})
        assert wrong.status_code == 401
        assert wrong.headers["x-frame-options"] == "DENY"  # security middleware still applies


async def test_hosted_mcp_full_agent_flow(hosted):
    runtime, url, in_server = hosted
    agent, token = runtime.store.create_agent("Claude Code (hosted)")
    async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token}, timeout=60) as http:
        async with streamable_http_client(url, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {tool.name for tool in (await session.list_tools()).tools}
                assert {"connections", "request_access", "terminal_write", "files", "release_access"} <= names
                assert "request_agent_token" not in names
                assert _result(await session.call_tool("connections", {}))[0]["id"] == "m1"
                grant = _result(await session.call_tool("request_access", {"connection": "m1", "purpose": PURPOSE}))
                assert grant["state"] == "Pending"
                in_server(runtime.agents.approve(grant["access"]))
                status = _result(await session.call_tool("access_status", {"access": grant["access"]}))
                assert status["state"] == "Approved"
                written = _result(await session.call_tool("terminal_write", {"access": grant["access"], "text": "status\n"}))
                assert "cursor" in written["output"]
                refused = await session.call_tool("files", {"access": grant["access"], "action": "list", "path": "/"})
                assert refused.is_error and "file access was not requested" in refused.content[0].text
                denied = await session.call_tool("access_status", {"access": "not-a-grant"})
                assert denied.is_error and "Unknown access" in denied.content[0].text
                _result(await session.call_tool("release_access", {"access": grant["access"], "closeConnection": True}))
    kinds = {record["kind"] for record in runtime.audit.records()}
    assert {"access_requested", "terminal_input_sent"} <= kinds
