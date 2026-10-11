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
AGENT_WARNING = ("NO SHENANIGANS. Hilait records agent activity for review. Obfuscated or concealed "
                 "activity will be flagged, and suspicious activity or low review scores can revoke your "
                 "access immediately. Your activity will be reviewed against your approved purpose. "
                 "Use clear, honest commands and stay within that purpose.")
ELEVATED_WARNING = ("ELEVATED ACCESS: You are requesting a privileged SSH account. Every command and file "
                    "operation is recorded for review. Obfuscation, concealed escalation, or work outside "
                    "the stated purpose can immediately revoke this and other access to the machine. "
                    "Use the minimum privilege needed and stop when the approved task is complete. NO SHENANIGANS.")
PRIVILEGES = {"legacy", "normal", "elevated"}


def resolve_privilege(profile: dict, requested: str | None) -> str:
    mode = profile.get("access_mode", "legacy")
    privilege = requested or ("legacy" if mode == "legacy" else "normal")
    if privilege not in PRIVILEGES or (mode == "legacy") != (privilege == "legacy"):
        raise ValueError("Choose an available access tier for this machine.")
    if privilege == "elevated" and (profile.get("platform") == "windows" or not profile.get("elevated_username")):
        raise ValueError("Elevated SSH access is not configured for this machine.")
    return privilege


def credential_revision(profile: dict, privilege: str) -> int:
    return int(profile.get("credential_revisions", {}).get(privilege, 0 if privilege == "legacy" else 1))


def login_profile(profile: dict, privilege: str) -> dict:
    resolved = resolve_privilege(profile, privilege)
    result = {key: value for key, value in profile.items() if not key.startswith("elevated_")}
    result["privilege"] = resolved
    if resolved == "normal":
        result["sudo_secret"] = None
    if resolved == "elevated":
        result.update(username=profile["elevated_username"], private_key=profile.get("elevated_private_key", ""),
                      auth_method=profile.get("elevated_auth_method", "key" if profile.get("elevated_private_key") else "password"),
                      secret=profile.get("elevated_secret"), sudo_secret=profile.get("elevated_sudo_secret"),
                      sudo_policy=profile.get("elevated_sudo_policy", "per_request"))
    return result


@dataclass
class Grant:
    id: str
    agent_id: str
    agent: str
    profile_id: str
    connection: str
    purpose: str
    file_access: str
    privilege: str = "legacy"
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
                "purpose": self.purpose, "fileAccess": self.file_access, "privilege": self.privilege,
                "state": self.state, "session": self.session_id, "localFolder": self.local_folder,
                "requestedUtc": self.requested_utc}

    def context(self) -> dict:
        return {"grant": self.id, "agentId": self.agent_id, "agent": self.agent,
                "profile": self.profile_id, "connection": self.connection,
                "purpose": self.purpose, "session": self.session_id,
                "fileAccess": self.file_access, "privilege": self.privilege}


class AgentRuntime:
    def __init__(self, store: Store, audit: Audit, sessions: SessionManager, files: FileService) -> None:
        self.store, self.audit, self.sessions, self.files = store, audit, sessions, files
        self.grants: dict[str, Grant] = {}
        self.lock = asyncio.Lock()
        self.notifications: set[asyncio.Queue] = set()
        self.on_pending = None
        self.approving: set[str] = set()
        sessions.on_close = self._session_closed

    def _notify(self, event: dict) -> None:
        for queue in list(self.notifications):
            if queue.qsize() < 100:
                queue.put_nowait(event)

    def visible_connections(self, agent: dict) -> list[dict]:
        visible = []
        for profile in self.store.profiles():
            privileges = [tier for tier in ("legacy", "normal", "elevated")
                          if self._tier_allowed(agent, profile, tier)]
            if privileges:
                public = self.store.public_profile(profile, agent=True)
                visible.append({**public, "privileges": privileges,
                                "capabilities": [cap for cap in public["capabilities"]
                                                 if cap != "sudo" or any(tier != "normal" for tier in privileges)]})
        return visible

    @staticmethod
    def _tier_allowed(agent: dict, profile: dict, privilege: str) -> bool:
        try:
            resolve_privilege(profile, privilege)
        except ValueError:
            return False
        allowed = (profile.get("elevated_allowed_agent_ids", []) if privilege == "elevated"
                   else profile.get("allowed_agent_ids"))
        return allowed is None or agent["id"] in allowed

    def permitted_profile(self, agent: dict, profile_id: str, privilege: str | None = None) -> dict:
        profile = self.store.profile(profile_id)
        tier = resolve_privilege(profile, privilege)
        if not self._tier_allowed(agent, profile, tier):
            raise PermissionError("This agent may not request that connection and access tier.")
        return profile

    def authorizations(self) -> list[dict]:
        return self.store.read("authorizations.json", [])

    def active_authorization(self, agent_id: str, profile_id: str, privilege: str | None = None) -> dict | None:
        agent = next((item for item in self.store.agents() if item["id"] == agent_id and item["active"]), None)
        if not agent:
            return None
        try:
            profile = self.permitted_profile(agent, profile_id, privilege)
        except (KeyError, PermissionError, ValueError):
            return None
        tier = resolve_privilege(profile, privilege)
        now = datetime.now(timezone.utc)
        for item in self.authorizations():
            if (item["agent_id"] == agent_id and item["profile_id"] == profile_id and not item["revoked"]
                    and item.get("privilege", "legacy") == tier
                    and item.get("credential_revision", 0) == credential_revision(profile, tier)
                    and (item.get("permanent") or item.get("expires_utc") and datetime.fromisoformat(item["expires_utc"]) > now)):
                return item
        return None

    def create_authorization(self, agent_id: str, profile_id: str, hours: float | None, scope: str,
                             local_folder: str | None = None, *, permanent: bool = False,
                             privilege: str | None = None) -> dict:
        if (not permanent and (hours is None or not 0 < hours <= 8760)) or scope not in SCOPES:
            raise ValueError("Choose a period up to 365 days and a valid file scope.")
        if scope == "LocalTransfers" and not local_folder:
            raise ValueError("Local transfers require a chosen folder.")
        profile = self.store.profile(profile_id)
        tier = resolve_privilege(profile, privilege)
        if self.active_authorization(agent_id, profile_id, tier):
            raise ValueError("An active authorization already exists. Extend or revoke it.")
        agent = next((a for a in self.store.agents() if a["id"] == agent_id and a["active"]), None)
        if not agent:
            raise KeyError("Active agent not found.")
        profile = self.permitted_profile(agent, profile_id, tier)
        item = {"id": str(uuid.uuid4()), "agent_id": agent_id, "profile_id": profile_id,
                "connection": profile["name"], "expires_utc": None if permanent else (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(),
                "permanent": permanent, "privilege": tier,
                "credential_revision": credential_revision(profile, tier),
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
        if item.get("permanent"):
            raise ValueError("Permanent authorization does not expire.")
        start = max(datetime.now(timezone.utc), datetime.fromisoformat(item["expires_utc"]))
        item["expires_utc"] = (start + timedelta(hours=hours)).isoformat()
        self.audit.write("automatic_approval_extended", {"agentId": item["agent_id"], "profile": item["profile_id"]}, item)
        self.store.write("authorizations.json", items)
        self._notify({"type": "authorizations"})
        return item

    def revoke_authorization(self, authorization_id: str, reason: str = "Agent/machine authorization revoked") -> None:
        items = self.authorizations()
        item = next((a for a in items if a["id"] == authorization_id), None)
        if not item:
            raise KeyError("Authorization not found.")
        if item["revoked"]:
            return
        item["revoked"] = True
        self.audit.write("automatic_approval_ended", {"agentId": item["agent_id"], "profile": item["profile_id"]}, {"authorization": authorization_id, "reason": reason})
        self.store.write("authorizations.json", items)
        for grant in list(self.grants.values()):
            if (grant.agent_id == item["agent_id"] and grant.profile_id == item["profile_id"]
                    and grant.privilege == item.get("privilege", "legacy") and grant.state not in ENDED):
                self.change(grant, "Revoked", reason)
        self._notify({"type": "authorizations"})

    async def request(self, agent: dict, profile_id: str, purpose: str, scope: str = "None",
                      privilege: str | None = None) -> Grant:
        profile = self.permitted_profile(agent, profile_id, privilege)
        tier = resolve_privilege(profile, privilege)
        purpose = purpose.strip()
        if not 80 <= len(purpose) <= 8000 or scope not in SCOPES:
            raise ValueError("State a detailed purpose (80–8000 characters) and valid file access.")
        if sum(g.state == "Pending" for g in self.grants.values()) >= 20 or sum(g.state == "Pending" and g.agent_id == agent["id"] for g in self.grants.values()) >= 3:
            raise ValueError("Too many pending requests.")
        grant = Grant(str(uuid.uuid4()), agent["id"], agent["name"], profile_id, profile["name"], purpose, scope, tier)
        self.audit.write("access_requested", grant.context(), {"purpose": purpose, "fileAccess": scope, "privilege": tier})
        self.grants[grant.id] = grant
        self._notify({"type": "request", "grant": grant.public()})
        authorization = self.active_authorization(agent["id"], profile_id, tier)
        if authorization and SCOPES[scope] <= SCOPES[authorization["file_access"]]:
            try:
                await self.approve(grant.id, local_folder=authorization.get("local_folder"))
            except Exception as exc:
                self.audit.write("automatic_approval_failed", grant.context(), {"error": str(exc)})
        if grant.state == "Pending" and self.on_pending:
            asyncio.create_task(self.on_pending(grant))
        return grant

    def pending(self, grant_id: str) -> Grant:
        grant = self.grants.get(grant_id)
        if not grant:
            raise KeyError("Access request not found.")
        if grant.state == "Pending" and datetime.now(timezone.utc) - datetime.fromisoformat(grant.requested_utc) > timedelta(minutes=10):
            self.change(grant, "Expired", "Approval request expired")
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
                      duration_hours: float | None = None, secret: str | None = None,
                      permanent: bool = False) -> Grant:
        grant = self.pending(grant_id)
        if not grant or grant.state != "Pending":
            raise ValueError("Pending request not found.")
        if grant_id in self.approving:
            raise ValueError("This request is already being approved.")
        if permanent and duration_hours is not None:
            raise ValueError("Choose either a duration or permanent authorization.")
        if duration_hours is not None and not 0 < duration_hours <= 8760:
            raise ValueError("Choose an authorization period up to 365 days.")
        if grant.file_access == "LocalTransfers" and not local_folder:
            raise ValueError("Choose a local transfer folder for this request.")
        agent = next((a for a in self.store.agents() if a["id"] == grant.agent_id and a["active"]), None)
        if not agent:
            raise PermissionError("Agent access was revoked.")
        profile = login_profile(self.permitted_profile(agent, grant.profile_id, grant.privilege), grant.privilege)
        self.approving.add(grant_id)
        try:
            session = await self.sessions.open(profile, secret=secret, owner=grant.agent,
                                               purpose=grant.purpose, grant_id=grant.id)
        finally:
            self.approving.discard(grant_id)
        current_agent = next((a for a in self.store.agents() if a["id"] == grant.agent_id and a["active"]), None)
        try:
            if grant.state != "Pending" or current_agent is None:
                raise PermissionError("Access changed while the SSH connection was opening.")
            self.permitted_profile(current_agent, grant.profile_id, grant.privilege)
            if credential_revision(self.store.profile(grant.profile_id), grant.privilege) != credential_revision(profile, grant.privilege):
                raise PermissionError("SSH credentials changed while the connection was opening.")
        except (KeyError, PermissionError, ValueError):
            await self.sessions.close(session.id, "Access changed while SSH was opening")
            raise PermissionError("Access changed while the SSH connection was opening.")
        grant.session_id, grant.local_folder = session.id, local_folder
        self.change(grant, "Approved", "Connection request approved by user")
        if duration_hours or permanent:
            existing = self.active_authorization(grant.agent_id, grant.profile_id, grant.privilege)
            if existing:
                items = self.authorizations()
                for item in items:
                    if item["id"] == existing["id"]:
                        item["expires_utc"] = None if permanent else (datetime.now(timezone.utc) + timedelta(hours=duration_hours)).isoformat()
                        item["permanent"] = permanent
                        item["file_access"] = grant.file_access
                        item["local_folder"] = local_folder
                        self.audit.write("automatic_approval_updated", grant.context(), item)
                        break
                self.store.write("authorizations.json", items)
            else:
                self.create_authorization(grant.agent_id, grant.profile_id, duration_hours,
                                          grant.file_access, local_folder, permanent=permanent,
                                          privilege=grant.privilege)
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
