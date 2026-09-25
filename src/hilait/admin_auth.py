"""Optional TOTP for the human web workspace."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import re
import secrets
import threading
import time
from collections import deque
from urllib.parse import quote, urlencode

import qrcode
from qrcode.image.svg import SvgPathImage

from .storage import Store


STEP_SECONDS = 30
SESSION_SECONDS = 12 * 60 * 60
ATTEMPT_WINDOW_SECONDS = 5 * 60
MAX_FAILED_ATTEMPTS = 5


class RateLimitError(PermissionError):
    pass


def totp(seed: str, timestamp: float, digits: int = 6) -> str:
    key = base64.b32decode(seed.upper() + "=" * (-len(seed) % 8))
    counter = int(timestamp // STEP_SECONDS).to_bytes(8, "big")
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def matching_step(seed: str, code: str, now: float) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int(now // STEP_SECONDS)
    for step in (current, current - 1, current + 1):
        if step >= 0 and secrets.compare_digest(totp(seed, step * STEP_SECONDS), code):
            return step
    return None


def provisioning_uri(seed: str) -> str:
    return "otpauth://totp/" + quote("Hilait:Admin") + "?" + urlencode({
        "secret": seed, "issuer": "Hilait", "algorithm": "SHA1", "digits": 6,
        "period": STEP_SECONDS,
    })


def qr_data_url(seed: str) -> str:
    qr = qrcode.QRCode(border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(provisioning_uri(seed))
    qr.make(fit=True)
    stream = io.BytesIO()
    qr.make_image(image_factory=SvgPathImage).save(stream)
    return "data:image/svg+xml;base64," + base64.b64encode(stream.getvalue()).decode("ascii")


class AdminAuth:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.lock = threading.RLock()
        self.sessions: dict[str, float] = {}
        self.failed: deque[float] = deque()

    def _settings(self) -> dict:
        return self.store.read_secure("admin-otp.json", {})

    def enabled(self) -> bool:
        return bool(self._settings().get("seed"))

    def is_admin_token(self, token: str) -> bool:
        return bool(token) and secrets.compare_digest(token, self.store.admin_token)

    def valid(self, token: str) -> bool:
        if not token:
            return False
        if not self.enabled():
            return self.is_admin_token(token)
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            expires = self.sessions.get(digest, 0)
            if expires <= time.time():
                self.sessions.pop(digest, None)
                return False
            return True

    def status(self) -> dict:
        settings = self._settings()
        result = {"enabled": bool(settings.get("seed")), "pending": bool(settings.get("pending_seed"))}
        if settings.get("pending_seed"):
            result["secret"] = settings["pending_seed"]
            result["qr"] = qr_data_url(settings["pending_seed"])
        return result

    def _check_rate(self) -> None:
        now = time.time()
        while self.failed and self.failed[0] <= now - ATTEMPT_WINDOW_SECONDS:
            self.failed.popleft()
        if len(self.failed) >= MAX_FAILED_ATTEMPTS:
            raise RateLimitError("Too many incorrect codes. Try again in a few minutes.")

    def _check_code(self, seed: str, code: str, last_step: int) -> int:
        self._check_rate()
        step = matching_step(seed, code, time.time())
        if step is None or step <= last_step:
            self.failed.append(time.time())
            raise ValueError("Code is incorrect, expired, or already used.")
        self.failed.clear()
        return step

    def _session(self) -> str:
        token = secrets.token_urlsafe(40)
        self.sessions[hashlib.sha256(token.encode()).hexdigest()] = time.time() + SESSION_SECONDS
        return token

    def verify_login(self, admin_token: str, code: str) -> str:
        if not self.is_admin_token(admin_token):
            raise PermissionError("Invalid admin token.")
        with self.lock:
            settings = self._settings()
            if not settings.get("seed"):
                raise ValueError("OTP is not configured.")
            step = self._check_code(settings["seed"], code, settings.get("last_step", -1))
            settings["last_step"] = step
            self.store.write_secure("admin-otp.json", settings)
            return self._session()

    def begin_setup(self, current_code: str = "") -> dict:
        with self.lock:
            settings = self._settings()
            if settings.get("seed"):
                step = self._check_code(settings["seed"], current_code, settings.get("last_step", -1))
                settings["last_step"] = step
            settings["pending_seed"] = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
            self.store.write_secure("admin-otp.json", settings)
            return self.status()

    def confirm_setup(self, code: str) -> str:
        with self.lock:
            settings = self._settings()
            pending = settings.get("pending_seed")
            if not pending:
                raise ValueError("Generate an OTP seed first.")
            step = self._check_code(pending, code, -1)
            self.store.write_secure("admin-otp.json", {"seed": pending, "last_step": step})
            self.sessions.clear()
            return self._session()

    def cancel_setup(self) -> None:
        with self.lock:
            settings = self._settings()
            settings.pop("pending_seed", None)
            self.store.write_secure("admin-otp.json", settings)

    def disable(self, code: str) -> None:
        with self.lock:
            settings = self._settings()
            if not settings.get("seed"):
                raise ValueError("OTP is not configured.")
            self._check_code(settings["seed"], code, settings.get("last_step", -1))
            self.store.write_secure("admin-otp.json", {})
            self.sessions.clear()
