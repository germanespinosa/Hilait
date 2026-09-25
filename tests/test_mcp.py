"""Exercise the installed MCP protocol boundary, not just Python imports."""

import asyncio
import os
import sys

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


@pytest.mark.asyncio
async def test_stdio_tools_initialize():
    env = {**os.environ, "HILAIT_AGENT_TOKEN": "protocol-fixture-token"}
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from hilait.mcp_server import run; run()"],
        env=env,
    )
    async with asyncio.timeout(15):
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                names = {tool.name for tool in (await client.list_tools()).tools}
                assert {"connections", "request_access", "release_access", "terminal_write",
                        "terminal_read", "terminal_screen", "files", "copy", "request_sudo"} <= names
