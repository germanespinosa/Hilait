"""Hilait's own MCP endpoint (Streamable HTTP at /mcp).

Agents can connect straight to the web server instead of installing the local
`hilait mcp` bridge, for example:

    claude mcp add --transport http hilait https://hilait.example.com/mcp \\
        --header "Authorization: Bearer <agent token>"

Every HTTP request must carry a registered agent token; the tools then run
in-process for that agent through the same code path as /agent/{tool}.
The endpoint is stateless: no MCP session outlives the request.
"""

from __future__ import annotations

import contextvars
import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Awaitable, Callable

from mcp.server.mcpserver import MCPServer
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import Receive, Scope, Send

from .agents import AGENT_WARNING
from .mcp_server import register_agent_tools

_current_agent: contextvars.ContextVar[dict | None] = contextvars.ContextVar("hilait_remote_agent", default=None)

INSTRUCTIONS = AGENT_WARNING + (
    " This is Hilait's hosted MCP endpoint: your agent token is sent with every request, "
    "so there is no request_agent_token tool here. Ask the administrator to create agent access "
    "in Settings → Agent Access if your token stops working."
)


class RemoteMCP:
    """ASGI app: authenticate the agent token, then hand the request to the MCP transport."""

    def __init__(self, identify: Callable[[str], dict],
                 run_tool: Callable[[dict, str, dict], Awaitable[Any]]) -> None:
        self.identify = identify
        mcp = MCPServer("Hilait", instructions=INSTRUCTIONS)

        async def call(tool: str, payload: dict) -> Any:
            agent = _current_agent.get()
            if agent is None:  # pragma: no cover - the ASGI wrapper always sets it
                raise PermissionError("Registered agent token required.")
            return await run_tool(agent, tool, payload)

        register_agent_tools(mcp, call)
        self.mcp = mcp
        # DNS-rebinding protection is unnecessary here: every request must carry
        # a secret bearer token, which a rebinding page cannot know.
        self.manager = StreamableHTTPSessionManager(
            app=mcp._lowlevel_server, stateless=True, json_response=True,
            security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False))

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        async with self.manager.run():
            yield

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = dict(scope.get("headers") or [])
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        if not authorization.startswith("Bearer ") or len(authorization) < 12:
            await _deny(send, 401, "Registered agent token required: send 'Authorization: Bearer <agent token>'.")
            return
        try:
            agent = self.identify(authorization[7:].strip())
        except KeyError:
            await _deny(send, 401, "Agent token is invalid or revoked.")
            return
        token = _current_agent.set(agent)
        try:
            await self.manager.handle_request(scope, receive, send)
        finally:
            _current_agent.reset(token)


async def _deny(send: Send, status: int, message: str) -> None:
    body = json.dumps({"error": message}).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
        (b"www-authenticate", b'Bearer realm="Hilait"'), (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": body})
