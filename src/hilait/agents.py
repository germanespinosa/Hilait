"""Agent identity, request approval, timed machine access, and control leases."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .files import FileService
from .sessions import SessionManager
from .storage import Audit, Store, utc_now

SCOPES = {"None": 0, "Remote": 1, "LocalTransfers": 2}
ENDED = {"Denied", "Expired", "Revoked", "Closed"}


@dataclass
class Grant:
    id: str
    agent_id: str
    agent: str
    profile_id: str
    connection: str
    purpose: str
    file_access: str
    requested_utc: str = field(default_factory=utc_now)
    state: str = "Pending"
    session_id: str | None = None
    local_folder: str | None = None
    last_activity: float = field(default_factory=time.monotonic)
    human_controlled: bool = False
    active_ops: int = 0
    sudo_consent: bool = False

    def public(self) -> dict:
        return {"access": self.id, "agentId": self.agent_id, "agent": self.agent,
                "connection": self.connection, "profile": self.profile_id,
                "purpose": self.purpose, "fileAccess": self.file_access,
                "state": self.state, "session": self.session_id, "localFolder": self.local_folder,
                "requestedUtc": self.requested_utc}

    def context(self) -> dict:
        return {"grant": self.id, "agentId": self.agent_id, "agent": self.agent,
                "profile": self.profile_id, "connection": self.connection,
                "purpose": self.purpose, "session": self.session_id,
                "fileAccess": self.file_access}


class AgentRuntime:
    def __init__(self, store: Store, audit: Audit, sessions: SessionManager, files: FileService) -> None:
        self.store, self.audit, self.sessions, self.files = store, audit, sessions, files
        self.grants: dict[str, Grant] = {}
        self.lock = asyncio.Lock()
        self.notifications: set[asyncio.Queue] = set()
        sessions.on_close = self._session_closed

    def _notify(self, event: dict) -> None:
        for queue in list(self.notifications):
            if queue.qsize() < 100:
                queue.put_nowait(event)

    def visible_connections(self, agent: dict) -> list[dict]:
        return [self.store.public_profile(p, agent=True) for p in self.store.profiles()
                if p.get("allowed_agent_ids") is None or agent["id"] in p["allowed_agent_ids"]]

    def permitted_profile(self, agent: dict, profile_id: str) -> dict:
        profile = self.store.profile(profile_id)
        allowed = profile.get("allowed_agent_ids")
        if allowed is not None and agent["id"] not in allowed:
            raise PermissionError("This agent may not request that connection.")
        return profile

    def authorizations(self) -> list[dict]:
        return self.store.read("authorizations.json", [])

    def active_authorization(self, agent_id: str, profile_id: str) -> dict | None:
        agent = next((item for item in self.store.agents() if item["id"] == agent_id and item["active"]), None)
        if not agent:
            return None
        try:
            self.permitted_profile(agent, profile_id)
        except (KeyError, PermissionError):
            return None
        now = datetime.now(timezone.utc)
        for item in self.authorizations():
            if item["agent_id"] == agent_id and item["profile_id"] == profile_id and not item["revoked"] and datetime.fromisoformat(item["expires_utc"]) > now:
                return item
        return None

    def create_authorization(self, agent_id: str, profile_id: str, hours: float, scope: str,
                             local_folder: str | None = None) -> dict:
        if not 0 < hours <= 8760 or scope not in SCOPES:
            raise ValueError("Choose a period up to 365 days and a valid file scope.")
        if scope == "LocalTransfers" and not local_folder:
            raise ValueError("Local transfers require a chosen folder.")
        if self.active_authorization(agent_id, profile_id):
            raise ValueError("An active authorization already exists. Extend or revoke it.")
        agent = next((a for a in self.store.agents() if a["id"] == agent_id and a["active"]), None)
        if not agent:
            raise KeyError("Active agent not found.")
        profile = self.permitted_profile(agent, profile_id)
        item = {"id": str(uuid.uuid4()), "agent_id": agent_id, "profile_id": profile_id,
                "connection": profile["name"], "expires_utc": (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(),
                "file_access": scope, "local_folder": local_folder, "revoked": False}
        items = self.authorizations()
        items.append(item)
        self.audit.write("automatic_approval_enabled", {"agentId": agent_id, "profile": profile_id}, item)
        self.store.write("authorizations.json", items)
        self._notify({"type": "authorizations"})
        return item

    def extend_authorization(self, authorization_id: str, hours: float) -> dict:
        if not 0 < hours <= 8760:
            raise ValueError("Choose a period up to 365 days.")
        items = self.authorizations()
        item = next((a for a in items if a["id"] == authorization_id and not a["revoked"]), None)
        if not item:
            raise KeyError("Active or expired authorization not found.")
        start = max(datetime.now(timezone.utc), datetime.fromisoformat(item["expires_utc"]))
        item["expires_utc"] = (start + timedelta(hours=hours)).isoformat()
        self.audit.write("automatic_approval_extended", {"agentId": item["agent_id"], "profile": item["profile_id"]}, item)
        self.store.write("authorizations.json", items)
        self._notify({"type": "authorizations"})
        return item

    def revoke_authorization(self, authorization_id: str) -> None:
        items = self.authorizations()
        item = next((a for a in items if a["id"] == authorization_id), None)
        if not item:
            raise KeyError("Authorization not found.")
        item["revoked"] = True
        self.audit.write("automatic_approval_ended", {"agentId": item["agent_id"], "profile": item["profile_id"]}, {"authorization": authorization_id})
        self.store.write("authorizations.json", items)
        for grant in list(self.grants.values()):
            if grant.agent_id == item["agent_id"] and grant.profile_id == item["profile_id"] and grant.state not in ENDED:
                self.change(grant, "Revoked", "Agent/machine authorization revoked")
        self._notify({"type": "authorizations"})

    async def request(self, agent: dict, profile_id: str, purpose: str, scope: str = "None") -> Grant:
        profile = self.permitted_profile(agent, profile_id)
        purpose = purpose.strip()
        if not 80 <= len(purpose) <= 8000 or scope not in SCOPES:
            raise ValueError("State a detailed purpose (80–8000 characters) and valid file access.")
        if sum(g.state == "Pending" for g in self.grants.values()) >= 20 or sum(g.state == "Pending" and g.agent_id == agent["id"] for g in self.grants.values()) >= 3:
            raise ValueError("Too many pending requests.")
        grant = Grant(str(uuid.uuid4()), agent["id"], agent["name"], profile_id, profile["name"], purpose, scope)
        self.audit.write("access_requested", grant.context(), {"purpose": purpose, "fileAccess": scope})
        self.grants[grant.id] = grant
        self._notify({"type": "request", "grant": grant.public()})
        authorization = self.active_authorization(agent["id"], profile_id)
        if authorization and SCOPES[scope] <= SCOPES[authorization["file_access"]]:
            try:
                await self.approve(grant.id, local_folder=authorization.get("local_folder"))
            except Exception as exc:
                self.audit.write("automatic_approval_failed", grant.context(), {"error": str(exc)})
        return grant

    def owned(self, agent: dict, grant_id: str, *, active: bool = False, files: bool = False,
              local: bool = False) -> Grant:
        grant = self.grants.get(grant_id)
        if not grant or grant.agent_id != agent["id"] or not agent["active"]:
            raise PermissionError("Unknown access for this registered agent.")
        if grant.state == "Pending" and datetime.now(timezone.utc) - datetime.fromisoformat(grant.requested_utc) > timedelta(minutes=10):
            self.change(grant, "Expired", "Approval request expired")
        if active and grant.state != "Approved":
            raise PermissionError(f"Access is {grant.state}; wait for or obtain human approval.")
        if files and SCOPES[grant.file_access] < SCOPES["Remote"]:
            raise PermissionError("Remote file access was not requested and approved.")
        if local and grant.file_access != "LocalTransfers":
            raise PermissionError("Local transfers were not requested and approved.")
        if active:
            grant.last_activity = time.monotonic()
        return grant

    async def approve(self, grant_id: str, *, local_folder: str | None = None,
                      duration_hours: float | None = None, secret: str | None = None) -> Grant:
        grant = self.grants.get(grant_id)
        if not grant or grant.state != "Pending":
            raise ValueError("Pending request not found.")
        if duration_hours is not None and not 0 < duration_hours <= 8760:
            raise ValueError("Choose an authorization period up to 365 days.")
        if grant.file_access == "LocalTransfers" and not local_folder:
            raise ValueError("Choose a local transfer folder for this request.")
        profile = self.store.profile(grant.profile_id)
        session = await self.sessions.open(profile, secret=secret, owner=grant.agent,
                                           purpose=grant.purpose, grant_id=grant.id)
        grant.session_id, grant.local_folder = session.id, local_folder
        self.change(grant, "Approved", "Connection request approved by user")
        if duration_hours:
            existing = self.active_authorization(grant.agent_id, grant.profile_id)
            if existing:
                items = self.authorizations()
                for item in items:
                    if item["id"] == existing["id"]:
                        item["expires_utc"] = (datetime.now(timezone.utc) + timedelta(hours=duration_hours)).isoformat()
                        item["file_access"] = grant.file_access
                        item["local_folder"] = local_folder
                        self.audit.write("automatic_approval_updated", grant.context(), item)
                        break
                self.store.write("authorizations.json", items)
            else:
                self.create_authorization(grant.agent_id, grant.profile_id, duration_hours,
                                          grant.file_access, local_folder)
        return grant

    def change(self, grant: Grant, state: str, reason: str) -> None:
        if grant.state in ENDED and state != grant.state:
            raise ValueError("Ended access cannot be resumed.")
        grant.state = state
        if state == "Approved":
            grant.last_activity = time.monotonic()
        self.audit.write("access_state_changed", grant.context(), {"state": state, "reason": reason})
        self._notify({"type": "access", "grant": grant.public()})

    def _session_closed(self, session) -> None:
        if session.grant_id and (grant := self.grants.get(session.grant_id)) and grant.state not in ENDED:
            self.change(grant, "Closed", "SSH session closed")
        self._notify({"type": "session_closed", "session": session.id})

    async def release(self, agent: dict, grant_id: str, close_connection: bool = False) -> dict:
        grant = self.owned(agent, grant_id)
        if grant.state not in ENDED:
            self.change(grant, "Revoked", "Agent released access after completing its purpose")
        if close_connection and grant.session_id:
            await self.sessions.close(grant.session_id, "Agent completed its purpose")
        return grant.public()

    async def idle_loop(self) -> None:
        while True:
            await asyncio.sleep(5)
            for grant in list(self.grants.values()):
                if grant.state not in {"Approved", "Paused"} or not grant.session_id or grant.human_controlled or grant.active_ops:
                    continue
                try:
                    minutes = int(self.store.profile(grant.profile_id).get("agent_idle_timeout_minutes", 10))
                except KeyError:
                    minutes = 10
                if minutes > 0 and time.monotonic() - grant.last_activity > 60 * minutes:
                    self.audit.write("agent_idle_timeout", grant.context(), {"minutes": minutes})
                    await self.sessions.close(grant.session_id, "Agent inactivity timeout")
