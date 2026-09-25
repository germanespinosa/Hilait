"""Independent visible SSH PTYs and SFTP channels for humans and agents."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import paramiko

from .storage import Audit, Store, utc_now


class HostKeyApprovalNeeded(Exception):
    def __init__(self, host: str, fingerprint: str, previous: str | None) -> None:
        super().__init__(f"Verify server key for {host}: {fingerprint}")
        self.host, self.fingerprint, self.previous = host, fingerprint, previous


class _TrustPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, store: Store, host: str, port: int) -> None:
        self.store, self.host, self.port = store, host, port

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        endpoint = f"[{self.host.lower()}]:{self.port}"
        previous = self.store.read("known-hosts.json", {}).get(endpoint)
        if previous != fingerprint:
            raise HostKeyApprovalNeeded(endpoint, fingerprint, previous)


@dataclass
class Session:
    id: str
    profile: dict
    owner: str
    purpose: str
    client: paramiko.SSHClient
    channel: paramiko.Channel
    created_utc: str = field(default_factory=utc_now)
    grant_id: str | None = None
    state: str = "Connected"
    output: bytearray = field(default_factory=bytearray)
    base_cursor: int = 0
    listeners: set[asyncio.Queue] = field(default_factory=set)
    file_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    screen_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    output_lock: threading.Lock = field(default_factory=threading.Lock)

    def context(self) -> dict:
        return {"session": self.id, "grant": self.grant_id, "profile": self.profile["id"],
                "connection": self.profile["name"], "agent": self.owner, "purpose": self.purpose}

    def read(self, cursor: int = 0) -> dict:
        with self.output_lock:
            gap = cursor < self.base_cursor
            start = max(cursor, self.base_cursor) - self.base_cursor
            data = bytes(self.output[start:])
            next_cursor = self.base_cursor + len(self.output)
        return {"cursor": next_cursor, "gap": gap, "base64": base64.b64encode(data).decode(),
                "text": data.decode("utf-8", "replace")}

    def append(self, data: bytes) -> None:
        with self.output_lock:
            self.output.extend(data)
            if len(self.output) > 2 * 1024 * 1024:
                extra = len(self.output) - 2 * 1024 * 1024
                del self.output[:extra]
                self.base_cursor += extra
        for queue in list(self.listeners):
            if queue.qsize() < 100:
                queue.put_nowait(data)


class SessionManager:
    def __init__(self, store: Store, audit: Audit) -> None:
        self.store, self.audit = store, audit
        self.sessions: dict[str, Session] = {}
        self.on_close: Callable[[Session], None] | None = None

    async def open(self, profile: dict, *, secret: str | None = None, owner: str = "You",
                   purpose: str = "Manual session", grant_id: str | None = None) -> Session:
        password = secret if secret is not None else self.store.decrypt(profile.get("secret"))

        def connect() -> tuple[paramiko.SSHClient, paramiko.Channel]:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(_TrustPolicy(self.store, profile["host"], int(profile.get("port", 22))))
            try:
                client.connect(profile["host"], port=int(profile.get("port", 22)), username=profile["username"],
                               password=password or None, passphrase=password or None,
                               key_filename=profile.get("private_key") or None,
                               allow_agent=False, look_for_keys=False, timeout=20, auth_timeout=20, banner_timeout=20)
                channel = client.invoke_shell(term="xterm-256color", width=100, height=30)
                channel.settimeout(1)
                shell = profile.get("shell", "default")
                if shell == "powershell7":
                    channel.send("pwsh.exe -NoLogo\r")
                elif shell == "powershell5":
                    channel.send("powershell.exe -NoLogo\r")
                return client, channel
            except Exception:
                client.close()
                raise

        client, channel = await asyncio.to_thread(connect)
        session = Session(str(uuid.uuid4()), profile.copy(), owner, purpose, client, channel, grant_id=grant_id)
        self.sessions[session.id] = session
        self.audit.write("session_opened", session.context(), {"endpoint": f"{profile['host']}:{profile.get('port', 22)}"})
        asyncio.create_task(self._reader(session))
        return session

    async def _reader(self, session: Session) -> None:
        try:
            while session.state == "Connected":
                try:
                    data = await asyncio.to_thread(session.channel.recv, 65536)
                except TimeoutError:
                    continue
                if not data:
                    break
                session.append(data)
                await asyncio.to_thread(self.audit.write, "terminal_output", session.context(),
                                        {"base64": base64.b64encode(data).decode()})
        except Exception as exc:
            self.audit.write("session_error", session.context(), {"error": str(exc)})
        finally:
            await self.close(session.id, "SSH connection closed")

    def get(self, session_id: str) -> Session:
        session = self.sessions.get(session_id)
        if not session or session.state != "Connected":
            raise KeyError("Active SSH session not found.")
        return session

    async def write(self, session_id: str, data: bytes, *, human: bool = False) -> dict:
        session = self.get(session_id)
        # Human keystrokes may contain a password and are never recorded verbatim.
        await asyncio.to_thread(self.audit.write,
                                "human_terminal_input" if human else "terminal_input_sent", session.context(),
                                {"redacted": True, "length": len(data)} if human else {"base64": base64.b64encode(data).decode()})
        await asyncio.to_thread(session.channel.sendall, data)
        if human:
            # The browser receives shell output on its independent stream. Waiting
            # and encoding the full scrollback here delayed every keystroke.
            return {"sent": len(data)}
        await asyncio.sleep(0.05)
        return session.read()

    async def resize(self, session_id: str, columns: int, rows: int) -> None:
        session = self.get(session_id)
        await asyncio.to_thread(session.channel.resize_pty, max(20, min(500, columns)), max(5, min(300, rows)))

    async def screen(self, session_id: str) -> dict:
        session = self.get(session_id)
        if session.listeners:
            request_id = str(uuid.uuid4())
            waiter = asyncio.get_running_loop().create_future()
            session.screen_waiters[request_id] = waiter
            for queue in list(session.listeners):
                queue.put_nowait({"type": "screen_request", "id": request_id})
            try:
                return await asyncio.wait_for(waiter, timeout=2)
            except asyncio.TimeoutError:
                pass
            finally:
                session.screen_waiters.pop(request_id, None)
        # No browser is rendering this PTY. Report only a bounded text preview.
        raw = session.read(max(session.base_cursor, session.base_cursor + len(session.output) - 32768))["text"]
        text = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", raw)
        return {"columns": None, "rows": None, "lines": text.splitlines()[-80:], "buffer": "unrendered",
                "note": "Open this session in the web terminal for an exact rendered screen snapshot."}

    async def close(self, session_id: str, reason: str = "Closed by user") -> None:
        session = self.sessions.pop(session_id, None)
        if not session:
            return
        session.state = "Closed"
        self.audit.write("session_closed", session.context(), {"reason": reason})
        for queue in list(session.listeners):
            queue.put_nowait({"type": "closed", "reason": reason})
        if self.on_close:
            self.on_close(session)
        await asyncio.to_thread(session.client.close)
