"""Optional ntfy delivery for human agent-access decisions."""

from __future__ import annotations

import re
from urllib.parse import quote, urlsplit

import httpx

from .storage import Audit, Store


def _url(value: str, label: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            (parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"})):
        raise ValueError(f"{label} must be an HTTPS URL (HTTP is allowed only on loopback).")
    return value


class NtfyNotifier:
    def __init__(self, store: Store, audit: Audit) -> None:
        self.store, self.audit = store, audit

    def settings(self) -> dict:
        return self.store.read_secure("ntfy.json", {})

    def public_settings(self) -> dict:
        saved = self.settings()
        return {"enabled": saved.get("enabled", False), "server_url": saved.get("server_url", ""),
                "topic": saved.get("topic", ""), "hilait_url": saved.get("hilait_url", ""),
                "has_token": bool(saved.get("token"))}

    def save(self, payload: dict) -> dict:
        current = self.settings()
        server_url = str(payload.get("server_url", "")).strip()
        hilait_url = str(payload.get("hilait_url", "")).strip()
        topic = str(payload.get("topic", "")).strip()
        enabled = payload.get("enabled") is True
        if server_url:
            server_url = _url(server_url, "ntfy server URL")
        if hilait_url:
            hilait_url = _url(hilait_url, "Hilait URL")
        if topic and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", topic):
            raise ValueError("Topic must use 1–128 letters, numbers, hyphens, or underscores.")
        if enabled and not (server_url and hilait_url and topic):
            raise ValueError("Set the ntfy server, topic, and phone-accessible Hilait URL before enabling notifications.")
        token = "" if payload.get("clear_token") is True else str(payload.get("token") or current.get("token") or "").strip()
        if len(token) > 1000:
            raise ValueError("ntfy token is too long.")
        self.store.write_secure("ntfy.json", {"enabled": enabled, "server_url": server_url,
                                              "topic": topic, "hilait_url": hilait_url, "token": token})
        self.audit.write("notification_settings_changed", {}, {"enabled": enabled, "server_url": server_url,
                                                                 "topic": topic, "hilait_url": hilait_url})
        return self.public_settings()

    async def _post(self, config: dict, payload: dict) -> None:
        headers = {"Authorization": "Bearer " + config["token"]} if config.get("token") else {}
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            response = await client.post(config["server_url"] + "/", json=payload, headers=headers)
            response.raise_for_status()

    async def test(self) -> None:
        config = self.settings()
        if not all(config.get(key) for key in ("server_url", "topic", "hilait_url")):
            raise ValueError("Save the ntfy server, topic, and Hilait URL first.")
        try:
            await self._post(config, {"topic": config["topic"], "title": "Hilait test notification",
                                      "message": "Notifications are connected. Open Hilait to review agent requests.",
                                      "actions": [{"action": "view", "label": "Open Hilait",
                                                   "url": config["hilait_url"] + "/"}]})
        except httpx.HTTPStatusError as exc:
            raise ValueError(f"ntfy rejected the test notification (HTTP {exc.response.status_code}).") from exc
        except httpx.HTTPError as exc:
            raise ValueError("Could not reach the ntfy server.") from exc

    async def notify_pending(self, grant) -> None:
        config = self.settings()
        if not config.get("enabled"):
            return
        address = config["hilait_url"] + "/approve/" + quote(grant.id, safe="")
        preview = grant.purpose[:180].strip() + ("…" if len(grant.purpose) > 180 else "")
        payload = {"topic": config["topic"], "title": f"Hilait: {grant.agent} requests {grant.connection}",
                   "message": f"{preview}\nFiles: {grant.file_access}", "priority": 4,
                   "actions": [{"action": "view", "label": "Review and approve",
                                "url": address + "?choice=approve"},
                               {"action": "view", "label": "Review and deny",
                                "url": address + "?choice=reject"}]}
        try:
            await self._post(config, payload)
            self.audit.write("notification_sent", grant.context(), {"channel": "ntfy"})
        except (httpx.HTTPError, ValueError) as exc:
            self.audit.write("notification_failed", grant.context(),
                             {"channel": "ntfy", "error": type(exc).__name__})
