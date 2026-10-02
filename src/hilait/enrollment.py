"""Short-lived, human-approved enrollment for remote agent identities."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque

from .storage import Audit, Store, utc_now

REQUEST_SECONDS = 10 * 60
MAX_PENDING = 20
MAX_PER_ADDRESS = 5


class AgentEnrollment:
    def __init__(self, store: Store, audit: Audit) -> None:
        self.store = store
        self.audit = audit
        self.lock = threading.RLock()
        self.requests: dict[str, dict] = store.read_secure("agent-enrollment.json", {})
        self.attempts: dict[str, deque[float]] = defaultdict(deque)

    def _save(self) -> None:
        self.store.write_secure("agent-enrollment.json", self.requests)

    def _expire(self) -> None:
        now = time.monotonic()
        changed = False
        for item in self.requests.values():
            if item["state"] == "Pending" and (now >= item["deadline"] or time.time() >= item["deadline_utc"]):
                item["state"] = "Expired"
                self.audit.write("agent_token_request_expired", {"request": item["id"]})
                changed = True
        for request_id, item in list(self.requests.items()):
            if item["state"] != "Pending" and time.time() >= item["deadline_utc"] + 86400:
                del self.requests[request_id]
                changed = True
        if changed:
            self._save()

    @staticmethod
    def public(item: dict) -> dict:
        return {key: item[key] for key in ("id", "name", "reason", "created_utc", "state")}

    def pending(self) -> list[dict]:
        with self.lock:
            self._expire()
            return [self.public(item) for item in self.requests.values() if item["state"] == "Pending"]

    def create(self, name: str, reason: str, address: str) -> dict:
        name, reason = name.strip(), reason.strip()
        if not 1 <= len(name) <= 120 or not 20 <= len(reason) <= 1000:
            raise ValueError("Provide an agent name and a reason of 20–1000 characters.")
        with self.lock:
            self._expire()
            now = time.monotonic()
            attempts = self.attempts[address]
            while attempts and attempts[0] <= now - REQUEST_SECONDS:
                attempts.popleft()
            if len(attempts) >= MAX_PER_ADDRESS or len(self.pending()) >= MAX_PENDING:
                raise PermissionError("Too many token requests. Try again later.")
            attempts.append(now)
            claim = secrets.token_urlsafe(32)
            item = {"id": str(uuid.uuid4()), "name": name, "reason": reason,
                    "created_utc": utc_now(), "deadline": now + REQUEST_SECONDS,
                    "deadline_utc": time.time() + REQUEST_SECONDS,
                    "claim_hash": hashlib.sha256(claim.encode()).hexdigest(),
                    "state": "Pending", "token": None}
            self.requests[item["id"]] = item
            self._save()
            self.audit.write("agent_token_requested", {"request": item["id"]},
                             {"name": name, "reason": reason})
            return {**self.public(item), "claim": claim, "expires_in_seconds": REQUEST_SECONDS}

    def status(self, request_id: str, claim: str) -> dict:
        with self.lock:
            self._expire()
            item = self.requests.get(request_id)
            digest = hashlib.sha256(claim.encode()).hexdigest()
            if not item or not secrets.compare_digest(item["claim_hash"], digest):
                raise KeyError("Token request")
            result = {"id": item["id"], "state": item["state"]}
            if item["state"] == "Approved":
                result["token"] = item["token"]
            return result

    def decide(self, request_id: str, approved: bool, token: str | None = None) -> dict:
        with self.lock:
            self._expire()
            item = self.requests.get(request_id)
            if not item or item["state"] != "Pending":
                raise ValueError("Pending token request not found.")
            item["state"] = "Approved" if approved else "Denied"
            item["token"] = token if approved else None
            item["deadline_utc"] = time.time()
            self._save()
            self.audit.write("agent_token_request_approved" if approved else "agent_token_request_denied",
                             {"request": request_id}, {"name": item["name"]})
            return self.public(item)
