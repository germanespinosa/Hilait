"""Personal stdio MCP bridge. The web server retains every SSH credential."""

from __future__ import annotations

import os

import httpx
from mcp.server.mcpserver import MCPServer


def build_mcp() -> MCPServer:
    token = os.environ.get("HILAIT_AGENT_TOKEN", "")
    if not token:
        raise RuntimeError("HILAIT_AGENT_TOKEN is required. Copy an agent configuration from Hilait settings.")
    base = os.environ.get("HILAIT_SERVER_URL", "http://127.0.0.1:8765").rstrip("/")
    mcp = MCPServer("Hilait")

    def call(tool: str, payload: dict):
        with httpx.Client(timeout=650) as client:
            response = client.post(f"{base}/agent/{tool}", json=payload,
                                   headers={"Authorization": "Bearer " + token})
            if response.is_error:
                try:
                    message = response.json().get("error") or response.text
                except ValueError:
                    message = response.text
                raise ValueError(message)
            return response.json()

    @mcp.tool(description="List only the saved machines this registered agent may request. Names and IDs only; no usernames, hosts, or secrets. Each request still needs human approval.")
    def connections() -> list[dict]:
        return call("connections", {})

    @mcp.tool(description="Request a fresh SSH session for a detailed stated purpose (80–8000 characters). Include desired fileAccess now: None, Remote, or LocalTransfers. Approval is per machine. When done, call release_access with closeConnection=true.")
    def request_access(connection: str, purpose: str, fileAccess: str = "None") -> dict:
        return call("request_access", locals())

    @mcp.tool(description="Check Pending, Approved, Paused, Denied, Revoked, Expired, or Closed state. Only Approved permits operations.")
    def access_status(access: str) -> dict:
        return call("access_status", locals())

    @mcp.tool(description="Release this agent's access after completing the purpose. Set closeConnection=true to close the dedicated SSH session.")
    def release_access(access: str, closeConnection: bool = True) -> dict:
        return call("release_access", locals())

    @mcp.tool(description="Write exactly one of text or base64 bytes to the same visible interactive PTY the user sees. No newline is appended. Read output from the returned cursor.")
    def terminal_write(access: str, text: str | None = None, base64: str | None = None) -> dict:
        return call("terminal_write", locals())

    @mcp.tool(description="Read raw PTY output from a cursor. Returns exact base64, UTF-8 preview, next cursor, and a replay-gap flag.")
    def terminal_read(access: str, cursor: int = 0) -> dict:
        return call("terminal_read", locals())

    @mcp.tool(description="Read the browser-rendered terminal screen when open; otherwise get a bounded plain-text fallback.")
    def terminal_screen(access: str) -> dict:
        return call("terminal_screen", locals())

    @mcp.tool(description="Perform an approved remote SFTP operation. Actions: list, stat, read, write, mkdir, rename, delete, chmod, symlink. Read/write chunks are at most 256 KiB. Files are never overwritten by default.")
    def files(access: str, action: str, path: str, destination: str | None = None,
              base64: str | None = None, offset: int = 0, count: int = 65536,
              overwrite: bool = False, recursive: bool = False, mode: str | None = None) -> dict:
        return call("files", locals())

    @mcp.tool(description="Copy a file or folder without overwriting or following symlinks. Direction is remote, upload, or download. Remote-to-remote requires approved file access on both grants. Local transfers stay inside the human-approved server folder.")
    def copy(access: str, direction: str, path: str, destination: str,
             destinationAccess: str | None = None) -> dict:
        return call("copy", locals())

    @mcp.tool(description="Ask the human to approve a Unix sudo command. Never supply or ask for a password via MCP. The command runs on a separate SSH exec channel and does not inherit the visible shell's cwd.")
    def request_sudo(access: str, command: str, reason: str) -> dict:
        return call("request_sudo", locals())

    return mcp


def run() -> None:
    build_mcp().run(transport="stdio")
