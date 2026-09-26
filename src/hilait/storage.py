"""Small, atomic local stores. Secrets and audit contents are encrypted at rest."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from platformdirs import user_data_path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


CONNECTION_FILES = {"connections.json", "known-hosts.json", "authorizations.json"}


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Store:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or user_data_path("Hilait", "Hilait"))
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.root.chmod(0o700)
        self.lock = threading.RLock()
        key_path = self.root / "master.key"
        if not key_path.exists():
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(Fernet.generate_key())
        self.cipher = Fernet(key_path.read_bytes())
        self.token_path = self.root / "admin.token"
        if not self.token_path.exists():
            fd = os.open(self.token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(secrets.token_urlsafe(40))

    @property
    def admin_token(self) -> str:
        return self.token_path.read_text(encoding="ascii").strip()

    def encrypt(self, text: str) -> str:
        return self.cipher.encrypt(text.encode()).decode("ascii")

    def decrypt(self, value: str | None) -> str:
        return self.cipher.decrypt(value.encode()).decode() if value else ""

    def read(self, name: str, default: Any) -> Any:
        with self.lock:
            path = self.root / name
            if name in CONNECTION_FILES:
                seed = self.read_secure("admin-otp.json", {}).get("seed")
                if not seed or not path.exists():
                    return default
                data = path.read_bytes()
                if data.lstrip().startswith((b"[", b"{")):
                    value = json.loads(data)
                    self.write(name, value)
                    return value
                try:
                    return json.loads(self._connection_cipher(seed).decrypt(data))
                except InvalidToken as exc:
                    raise ValueError("Saved connection data cannot be opened with the current authenticator key.") from exc
            return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default

    def write(self, name: str, value: Any) -> None:
        with self.lock:
            if name in CONNECTION_FILES:
                seed = self.read_secure("admin-otp.json", {}).get("seed")
                if not seed:
                    raise PermissionError("Set up an authenticator before saving connections.")
                data = self._connection_cipher(seed).encrypt(json.dumps(value, ensure_ascii=False).encode())
                self._write_connection_bytes(name, data)
                return
            atomic_json(self.root / name, value)

    def read_secure(self, name: str, default: Any) -> Any:
        with self.lock:
            path = self.root / name
            return json.loads(self.cipher.decrypt(path.read_bytes())) if path.exists() else default

    def write_secure(self, name: str, value: Any) -> None:
        with self.lock:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(self.cipher.encrypt(json.dumps(value, ensure_ascii=False).encode()))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                if os.name != "nt":
                    path.chmod(0o600)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    def profiles(self) -> list[dict]:
        return self.read("connections.json", [])

    def save_profiles(self, profiles: list[dict]) -> None:
        self.write("connections.json", profiles)

    @staticmethod
    def _connection_cipher(seed: str) -> Fernet:
        raw = base64.b32decode(seed.upper() + "=" * (-len(seed) % 8))
        key = hashlib.sha256(b"Hilait connection records v1\0" + raw).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def _write_connection_bytes(self, name: str, data: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=name + ".", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.root / name)
            if os.name != "nt":
                (self.root / name).chmod(0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def replace_connection_key(self, new_seed: str, *, first_setup: bool) -> None:
        """Migrate legacy connections on first setup; discard them on key replacement."""
        with self.lock:
            defaults = {"connections.json": [], "known-hosts.json": {}, "authorizations.json": []}
            cipher = self._connection_cipher(new_seed)
            for name, default in defaults.items():
                path = self.root / name
                existing = path.read_bytes() if path.exists() else b""
                legacy = json.loads(existing) if first_setup and existing.lstrip().startswith((b"[", b"{")) else default
                self._write_connection_bytes(name, cipher.encrypt(json.dumps(legacy, ensure_ascii=False).encode()))

    def discard_connections(self) -> None:
        with self.lock:
            for name in CONNECTION_FILES:
                (self.root / name).unlink(missing_ok=True)

    def public_profile(self, profile: dict, *, agent: bool = False) -> dict:
        if agent:
            return {
                "id": profile["id"], "name": profile["name"],
                "platform": profile.get("platform", "unix"),
                "shell": profile.get("shell", "default"),
                "capabilities": ["terminal", "files"] + ([] if profile.get("platform") == "windows" else ["sudo", "chmod", "symlink"]),
            }
        return {**{k: v for k, v in profile.items() if k not in {"secret", "sudo_secret"}},
                "has_saved_secret": bool(profile.get("secret")),
                "has_saved_sudo_secret": bool(profile.get("sudo_secret"))}

    def profile(self, profile_id: str) -> dict:
        return next((p for p in self.profiles() if p["id"] == profile_id), None) or _missing("Connection")

    def agents(self) -> list[dict]:
        return self.read("agents.json", [])

    def agent_for_token(self, token: str) -> dict:
        digest = hashlib.sha256(token.encode()).hexdigest()
        agent = next((a for a in self.agents() if secrets.compare_digest(a["token_hash"], digest) and a["active"]), None)
        return agent or _missing("Active agent token")

    def create_agent(self, name: str) -> tuple[dict, str]:
        name = name.strip()
        if not 1 <= len(name) <= 120:
            raise ValueError("Agent name must be 1–120 characters.")
        token = secrets.token_hex(32)
        agent = {"id": str(uuid.uuid4()), "name": name, "active": True,
                 "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                 "token": self.encrypt(token), "created_utc": utc_now()}
        with self.lock:
            agents = self.agents()
            agents.append(agent)
            self.write("agents.json", agents)
        return agent, token

    def agent_config(self, agent_id: str) -> dict:
        agent = next((a for a in self.agents() if a["id"] == agent_id and a["active"]), None) or _missing("Agent")
        return {"mcpServers": {"hilait": {"command": "hilait", "args": ["mcp"],
                "env": {"HILAIT_AGENT_TOKEN": self.decrypt(agent["token"])}}}}


def _missing(what: str) -> Any:
    raise KeyError(f"{what} not found.")


class Audit:
    """Encrypted append-only records with a checked hash chain."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.path = store.root / "activity.audit"
        self.lock = threading.RLock()
        records = self.records()
        self.sequence = len(records)
        self.previous = records[-1]["_hash"] if records else ""

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        output: list[dict] = []
        previous = ""
        for line in self.path.read_bytes().splitlines():
            record = json.loads(self.store.cipher.decrypt(base64.b64decode(line)))
            if record["sequence"] != len(output) + 1 or record["previous"] != previous:
                raise ValueError("Audit chain is damaged.")
            previous = hashlib.sha256(line).hexdigest()
            record["_hash"] = previous
            output.append(record)
        return output

    def write(self, kind: str, context: dict, data: Any = None) -> dict:
        with self.lock:
            record = {"sequence": self.sequence + 1, "utc": utc_now(), "kind": kind,
                      "context": context, "data": data, "previous": self.previous}
            line = base64.b64encode(self.store.cipher.encrypt(json.dumps(record, ensure_ascii=False).encode()))
            with self.path.open("ab") as stream:
                stream.write(line + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            self.sequence += 1
            self.previous = hashlib.sha256(line).hexdigest()
            return record

    def session(self, grant_id: str) -> list[dict]:
        return [{k: v for k, v in record.items() if k != "_hash"} for record in self.records()
                if record.get("context", {}).get("grant") == grant_id]

    def delete_session(self, grant_id: str) -> None:
        with self.lock:
            kept = [record for record in self.records() if record.get("context", {}).get("grant") != grant_id]
            temporary = self.path.with_suffix(".replacement")
            previous = ""
            with temporary.open("wb") as stream:
                for sequence, record in enumerate(kept, 1):
                    record = {k: v for k, v in record.items() if k != "_hash"}
                    record["sequence"] = sequence
                    record["previous"] = previous
                    line = base64.b64encode(self.store.cipher.encrypt(json.dumps(record, ensure_ascii=False).encode()))
                    stream.write(line + b"\n")
                    previous = hashlib.sha256(line).hexdigest()
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.sequence = len(kept)
            self.previous = previous
            self.write("session_log_deleted", {}, {"note": "A user deleted one ended session log."})
