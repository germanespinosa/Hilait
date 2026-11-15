"""Passkey (WebAuthn) step-up verification for approvals.

When a policy is set, approving agent access asks the administrator to verify
with a passkey that requires user verification, typically a fingerprint. Only
the parts of WebAuthn Hilait needs are implemented here, on top of the
`cryptography` package: attestation is not requested ("none"), and ES256,
RS256, and Ed25519 credentials are accepted.

Each challenge is random, single-use, expires after two minutes, and is bound
to the browser session, the action, and the target it was issued for.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
import struct
import threading
import time
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .storage import Audit, Store, utc_now

CREDENTIALS_FILE = "passkeys.json"
SETTINGS_FILE = "passkey-settings.json"
CHALLENGE_SECONDS = 120
MAX_PASSKEYS = 10
POLICIES = ("off", "elevated", "all")
# Actions that grant or widen access. Rejecting, pausing, and revoking never ask.
ACTIONS = {"grant_approve", "sudo_approve", "authorization_create", "authorization_extend",
           "authorization_file_access", "agent_token_approve"}
ALG_ES256, ALG_EDDSA, ALG_RS256 = -7, -8, -257
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 1_000_000:
        raise ValueError("Invalid passkey data.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid passkey data.") from exc


class _Cbor:
    """Minimal definite-length CBOR decoder for authenticator data."""

    def __init__(self, data: bytes) -> None:
        self.data, self.offset = data, 0

    def _take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise ValueError("Truncated passkey data.")
        chunk = self.data[self.offset:self.offset + count]
        self.offset += count
        return chunk

    def _argument(self, info: int) -> int:
        if info < 24:
            return info
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if info not in sizes:
            raise ValueError("Unsupported passkey encoding.")
        return int.from_bytes(self._take(sizes[info]), "big")

    def item(self, depth: int = 0):
        if depth > 16:
            raise ValueError("Passkey data nests too deeply.")
        initial = self._take(1)[0]
        major, info = initial >> 5, initial & 31
        if major == 7:
            simple = {20: False, 21: True, 22: None}
            if info in simple:
                return simple[info]
            raise ValueError("Unsupported passkey encoding.")
        value = self._argument(info)
        if major == 0:
            return value
        if major == 1:
            return -1 - value
        if major == 2:
            return self._take(value)
        if major == 3:
            return self._take(value).decode("utf-8")
        if major == 4:
            if value > 1024:
                raise ValueError("Passkey data is too large.")
            return [self.item(depth + 1) for _ in range(value)]
        if major == 5:
            if value > 1024:
                raise ValueError("Passkey data is too large.")
            result = {}
            for _ in range(value):
                key = self.item(depth + 1)
                if isinstance(key, (list, dict)):
                    raise ValueError("Unsupported passkey encoding.")
                result[key] = self.item(depth + 1)
            return result
        raise ValueError("Unsupported passkey encoding.")


def cbor_decode(data: bytes, *, partial: bool = False):
    decoder = _Cbor(data)
    value = decoder.item()
    if partial:
        return value, decoder.offset
    if decoder.offset != len(data):
        raise ValueError("Unexpected trailing passkey data.")
    return value


def _public_key(cose: dict):
    kty, alg = cose.get(1), cose.get(3)
    if kty == 2 and alg == ALG_ES256 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise ValueError("Invalid passkey public key.")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y), alg
    if kty == 3 and alg == ALG_RS256:
        n, e = cose.get(-1), cose.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)) or len(n) < 256:
            raise ValueError("Invalid passkey public key.")
        return rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key(), alg
    if kty == 1 and alg == ALG_EDDSA and cose.get(-1) == 6:
        x = cose.get(-2)
        if not isinstance(x, bytes) or len(x) != 32:
            raise ValueError("Invalid passkey public key.")
        return ed25519.Ed25519PublicKey.from_public_bytes(x), alg
    raise ValueError("This passkey type is not supported. Use a fingerprint or device passkey.")


def parse_authenticator_data(data: bytes) -> dict:
    if len(data) < 37:
        raise ValueError("Invalid passkey response.")
    flags = data[32]
    result = {"rp_id_hash": data[:32], "flags": flags, "sign_count": struct.unpack(">I", data[33:37])[0]}
    if flags & FLAG_AT:
        if len(data) < 55:
            raise ValueError("Invalid passkey response.")
        length = struct.unpack(">H", data[53:55])[0]
        credential_id = data[55:55 + length]
        if len(credential_id) != length or not 16 <= length <= 1023:
            raise ValueError("Invalid passkey credential.")
        cose, used = cbor_decode(data[55 + length:], partial=True)
        if not isinstance(cose, dict):
            raise ValueError("Invalid passkey public key.")
        result["credential_id"], result["cose"] = credential_id, cose
    return result


def _verify_signature(public_key, alg: int, signature: bytes, signed: bytes) -> None:
    try:
        if alg == ALG_ES256:
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_RS256:
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(signature, signed)
    except InvalidSignature as exc:
        raise PermissionError("Passkey verification failed.") from exc


def _origin_settings(origin: str) -> tuple[str, str]:
    if not isinstance(origin, str) or len(origin) > 300:
        raise ValueError("Enter the HTTPS address you open Hilait at, such as https://hilait.example.com.")
    parts = urlsplit(origin.strip().rstrip("/"))
    host = (parts.hostname or "").lower()
    if parts.path or parts.query or parts.fragment or parts.username or not host:
        raise ValueError("Enter only the address, such as https://hilait.example.com, without a path.")
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError("Passkeys need a domain name; browsers do not allow them on an IP address.")
    if parts.scheme != "https" and host != "localhost":
        raise ValueError("Passkeys need HTTPS with a trusted certificate.")
    if host != "localhost" and "." not in host:
        raise ValueError("Use the full domain name you open Hilait at.")
    port = f":{parts.port}" if parts.port and parts.port != (443 if parts.scheme == "https" else 80) else ""
    return f"{parts.scheme}://{host}{port}", host


class Passkeys:
    def __init__(self, store: Store, audit: Audit) -> None:
        self.store, self.audit = store, audit
        self.lock = threading.RLock()
        self.challenges: dict[str, dict] = {}

    # Settings and stored credentials.

    def settings(self) -> dict:
        saved = self.store.read_secure(SETTINGS_FILE, {})
        policy = saved.get("policy", "off")
        return {"origin": saved.get("origin", ""), "rp_id": saved.get("rp_id", ""),
                "policy": policy if policy in POLICIES else "off"}

    def credentials(self) -> list[dict]:
        return self.store.read_secure(CREDENTIALS_FILE, [])

    def status(self) -> dict:
        settings = self.settings()
        return {**settings, "configured": bool(settings["origin"]),
                "passkeys": [{"id": item["id"], "name": item["name"], "created_utc": item["created_utc"],
                              "last_used_utc": item.get("last_used_utc")} for item in self.credentials()]}

    def update_settings(self, origin: str | None, policy: str) -> dict:
        if policy not in POLICIES:
            raise ValueError("Choose when to require a passkey.")
        with self.lock:
            current = self.settings()
            if origin is not None and origin != "":
                normalized, rp_id = _origin_settings(origin)
            else:
                normalized, rp_id = current["origin"], current["rp_id"]
            if policy != "off" and not normalized:
                raise ValueError("Set the Hilait address before requiring passkeys.")
            changed_site = bool(current["rp_id"]) and rp_id != current["rp_id"]
            if policy != "off" and (changed_site or not self.credentials()):
                raise ValueError("Add a passkey for this address before requiring it.")
            if changed_site:
                # Passkeys are scoped to one domain; ones for the old domain cannot work.
                self.store.write_secure(CREDENTIALS_FILE, [])
            self.store.write_secure(SETTINGS_FILE, {"origin": normalized, "rp_id": rp_id, "policy": policy})
            self.audit.write("passkey_settings_changed", {}, {"origin": normalized, "policy": policy,
                                                             "passkeys_cleared": changed_site})
            return self.status()

    def delete(self, credential_id: str) -> dict:
        with self.lock:
            items = self.credentials()
            remaining = [item for item in items if item["id"] != credential_id]
            if len(remaining) == len(items):
                raise KeyError("Passkey not found.")
            settings = self.settings()
            if not remaining and settings["policy"] != "off":
                raise ValueError("Turn off the passkey requirement before removing the last passkey.")
            self.store.write_secure(CREDENTIALS_FILE, remaining)
            self.audit.write("passkey_removed", {}, {"id": credential_id})
            return self.status()

    def reset(self) -> None:
        """Recovery: forget every passkey and turn the requirement off (CLI only)."""
        with self.lock:
            settings = self.settings()
            self.store.write_secure(CREDENTIALS_FILE, [])
            self.store.write_secure(SETTINGS_FILE, {**{k: settings[k] for k in ("origin", "rp_id")}, "policy": "off"})
            self.challenges.clear()
            self.audit.write("passkeys_reset", {}, {})

    # Challenges.

    @staticmethod
    def session_key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _challenge(self, session: str, purpose: str, action: str = "", target: str = "", **extra) -> str:
        now = time.time()
        with self.lock:
            for key in [key for key, item in self.challenges.items() if item["expires"] < now]:
                del self.challenges[key]
            if len(self.challenges) > 200:
                raise PermissionError("Too many passkey checks in progress. Try again shortly.")
            challenge = b64url(secrets.token_bytes(32))
            self.challenges[challenge] = {"session": session, "purpose": purpose, "action": action,
                                          "target": target, "expires": now + CHALLENGE_SECONDS, **extra}
            return challenge

    def _consume(self, challenge: str, session: str, purpose: str, action: str = "", target: str = "") -> dict:
        with self.lock:
            item = self.challenges.pop(challenge, None)
        if (not item or item["expires"] < time.time() or item["session"] != session or item["purpose"] != purpose
                or item["action"] != action or item["target"] != target):
            raise PermissionError("Passkey check expired or does not match this action. Try again.")
        return item

    def _client_data(self, encoded: str, kind: str) -> tuple[dict, bytes]:
        raw = unb64url(encoded)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid passkey response.") from exc
        settings = self.settings()
        if not isinstance(data, dict) or data.get("type") != kind:
            raise ValueError("Invalid passkey response.")
        if data.get("origin") != settings["origin"]:
            raise PermissionError(f"Passkeys work only at {settings['origin'] or 'the configured address'}.")
        if data.get("crossOrigin") is True:
            raise PermissionError("Passkey checks cannot come from another site.")
        return data, raw

    # Registration.

    def registration_options(self, session: str, name: str) -> dict:
        settings = self.settings()
        if not settings["origin"]:
            raise ValueError("Set the Hilait address first.")
        name = (name or "").strip()
        if not 1 <= len(name) <= 60:
            raise ValueError("Name the passkey, such as \"Pixel fingerprint\".")
        if len(self.credentials()) >= MAX_PASSKEYS:
            raise ValueError(f"At most {MAX_PASSKEYS} passkeys can be registered.")
        challenge = self._challenge(session, "register", name=name)
        return {"challenge": challenge,
                "rp": {"id": settings["rp_id"], "name": "Hilait"},
                "user": {"id": b64url(hashlib.sha256(b"hilait-admin:" + settings["rp_id"].encode()).digest()[:16]),
                         "name": "hilait-admin", "displayName": "Hilait administrator"},
                "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in (ALG_ES256, ALG_EDDSA, ALG_RS256)],
                "timeout": CHALLENGE_SECONDS * 1000, "attestation": "none",
                "authenticatorSelection": {"residentKey": "preferred", "userVerification": "required"},
                "excludeCredentials": [{"type": "public-key", "id": item["id"]} for item in self.credentials()]}

    def register(self, session: str, credential: dict) -> dict:
        response = (credential or {}).get("response") or {}
        client, _ = self._client_data(response.get("clientDataJSON", ""), "webauthn.create")
        pending = self._consume(str(client.get("challenge", "")), session, "register")
        attestation = cbor_decode(unb64url(response.get("attestationObject", "")))
        if not isinstance(attestation, dict) or not isinstance(attestation.get("authData"), bytes):
            raise ValueError("Invalid passkey response.")
        auth = parse_authenticator_data(attestation["authData"])
        settings = self.settings()
        if auth["rp_id_hash"] != hashlib.sha256(settings["rp_id"].encode()).digest():
            raise PermissionError("This passkey was made for a different site.")
        if not auth["flags"] & FLAG_UP or not auth["flags"] & FLAG_UV:
            raise PermissionError("The passkey must verify you with a fingerprint, face, or device PIN.")
        if "credential_id" not in auth:
            raise ValueError("Invalid passkey response.")
        public_key, alg = _public_key(auth["cose"])
        credential_id = b64url(auth["credential_id"])
        if credential.get("id") not in (None, credential_id):
            raise ValueError("Invalid passkey response.")
        der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.lock:
            items = self.credentials()
            if any(item["id"] == credential_id for item in items):
                raise ValueError("This passkey is already registered.")
            if len(items) >= MAX_PASSKEYS:
                raise ValueError(f"At most {MAX_PASSKEYS} passkeys can be registered.")
            items.append({"id": credential_id, "name": pending["name"], "alg": alg, "public_key": b64url(der),
                          "sign_count": auth["sign_count"], "created_utc": utc_now(), "last_used_utc": None})
            self.store.write_secure(CREDENTIALS_FILE, items)
        self.audit.write("passkey_registered", {}, {"id": credential_id, "name": pending["name"]})
        return self.status()

    # Step-up verification.

    def required(self, action: str, *, elevated: bool) -> bool:
        if action not in ACTIONS:
            raise ValueError("Unknown passkey action.")
        policy = self.settings()["policy"]
        return policy == "all" or (policy == "elevated" and elevated)

    def assertion_options(self, session: str, action: str, target: str, *, elevated: bool) -> dict:
        if not self.required(action, elevated=elevated):
            return {"required": False}
        settings, items = self.settings(), self.credentials()
        if not items:
            raise PermissionError("A passkey is required, but none is registered. Run `hilait passkeys reset` on the server.")
        challenge = self._challenge(session, "assert", action, target or "")
        return {"required": True, "options": {
            "challenge": challenge, "rpId": settings["rp_id"], "timeout": CHALLENGE_SECONDS * 1000,
            "userVerification": "required",
            "allowCredentials": [{"type": "public-key", "id": item["id"]} for item in items]}}

    def verify(self, session: str, action: str, target: str, assertion: dict | None, *, elevated: bool) -> None:
        """Raise unless the policy is satisfied for this action and target."""
        if not self.required(action, elevated=elevated):
            return
        if not isinstance(assertion, dict) or not isinstance(assertion.get("response"), dict):
            raise PermissionError("Verify with your passkey (fingerprint) to approve this.")
        response = assertion["response"]
        client, client_raw = self._client_data(response.get("clientDataJSON", ""), "webauthn.get")
        self._consume(str(client.get("challenge", "")), session, "assert", action, target or "")
        credential_id = assertion.get("id") or assertion.get("rawId")
        with self.lock:
            items = self.credentials()
            stored = next((item for item in items if item["id"] == credential_id), None)
            if not stored:
                raise PermissionError("This passkey is not registered with Hilait.")
            auth_raw = unb64url(response.get("authenticatorData", ""))
            auth = parse_authenticator_data(auth_raw)
            if auth["rp_id_hash"] != hashlib.sha256(self.settings()["rp_id"].encode()).digest():
                raise PermissionError("This passkey was made for a different site.")
            if not auth["flags"] & FLAG_UP or not auth["flags"] & FLAG_UV:
                raise PermissionError("The passkey must verify you with a fingerprint, face, or device PIN.")
            public_key = serialization.load_der_public_key(unb64url(stored["public_key"]))
            _verify_signature(public_key, stored["alg"], unb64url(response.get("signature", "")),
                              auth_raw + hashlib.sha256(client_raw).digest())
            if auth["sign_count"] or stored["sign_count"]:
                if auth["sign_count"] <= stored["sign_count"]:
                    raise PermissionError("Passkey counter went backwards; it may have been cloned.")
            stored["sign_count"], stored["last_used_utc"] = auth["sign_count"], utc_now()
            self.store.write_secure(CREDENTIALS_FILE, items)
        self.audit.write("passkey_verified", {}, {"action": action, "target": target, "passkey": stored["name"]})
