"""Personal stdio MCP bridge. The web server retains every SSH credential."""

from __future__ import annotations

import os
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from mcp.server.mcpserver import MCPServer
from platformdirs import user_data_path

from .storage import atomic_json


def build_mcp(server_url: str | None = None, ca_cert: str | None = None) -> MCPServer:
    base = (server_url or os.environ.get("HILAIT_SERVER_URL") or "http://127.0.0.1:8765").rstrip("/")
    parsed = urlsplit(base)
    if (parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"})) or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use a full HTTPS Hilait URL (HTTP is allowed only on loopback).")
    verify = ca_cert or os.environ.get("HILAIT_CA_CERT") or True
    credential_file = Path(user_data_path("Hilait", "Hilait")) / "agent-clients" / (hashlib.sha256(base.encode()).hexdigest() + ".json")
    saved = json.loads(credential_file.read_text(encoding="utf-8")) if credential_file.exists() else {}
    token = os.environ.get("HILAIT_AGENT_TOKEN") or saved.get("token", "")
    mcp = MCPServer("Hilait")

    def post(path: str, payload: dict, *, authenticated: bool = False) -> dict:
        nonlocal token
        headers = {"Authorization": "Bearer " + token} if authenticated and token else {}
        if authenticated and not token:
            raise ValueError("No agent token yet. Request one and wait for administrator approval.")
        with httpx.Client(timeout=650, verify=verify) as client:
            response = client.post(base + path, json=payload, headers=headers)
            if response.is_error:
                try:
                    message = response.json().get("error") or response.json().get("detail") or response.text
                except ValueError:
                    message = response.text
                if (authenticated and response.status_code == 403 and
                        message == "Agent token is invalid or revoked." and
                        not os.environ.get("HILAIT_AGENT_TOKEN")):
                    token = ""
                    saved.pop("token", None)
                    atomic_json(credential_file, saved)
                raise ValueError(message)
            return response.json()

    def call(tool: str, payload: dict):
        return post(f"/agent/{tool}", payload, authenticated=True)

    @mcp.tool(description="Ask the OTP-signed-in Hilait administrator to create an agent identity for this server. Use this before other tools when no token has been configured. State who you are and why you need access; no machine access is granted automatically.")
    def request_agent_token(name: str, reason: str) -> dict:
        if token:
            return {"state": "Already enrolled", "ready": True}
        if saved.get("pending"):
            return {"id": saved["pending"]["id"], "state": "Pending", "instruction": "Call agent_token_status to check the decision."}
        result = post("/api/agent-enrollment", {"name": name, "reason": reason})
        saved["pending"] = {"id": result["id"], "claim": result.pop("claim")}
        atomic_json(credential_file, saved)
        return {**result, "instruction": "Wait for the Hilait administrator to approve this request, then call agent_token_status."}

    @mcp.tool(description="Check the pending agent-token request. Once the OTP-signed-in administrator approves it, the token is saved privately on this computer and the other Hilait tools become available.")
    def agent_token_status() -> dict:
        nonlocal token
        pending = saved.get("pending")
        if not pending:
            return {"state": "Ready" if token else "No request", "ready": bool(token)}
        result = post(f"/api/agent-enrollment/{pending['id']}/status", {"claim": pending["claim"]})
        state = result["state"]
        if state == "Approved":
            token = result["token"]
            saved["token"] = token
            saved.pop("pending", None)
            atomic_json(credential_file, saved)
            return {"state": state, "ready": True, "instruction": "Token stored locally. You can now list permitted connections."}
        if state in {"Denied", "Expired"}:
            saved.pop("pending", None)
            atomic_json(credential_file, saved)
        return {"state": state, "ready": False}

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
