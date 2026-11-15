"""A software WebAuthn authenticator for tests (ES256, Ed25519, or RS256)."""

import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from hilait.passkeys import b64url, unb64url


def cbor(value) -> bytes:
    def head(major, length):
        if length < 24:
            return bytes([major << 5 | length])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if length < 1 << (8 * size):
                return bytes([major << 5 | info]) + length.to_bytes(size, "big")
        raise ValueError(length)
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


class SoftAuthenticator:
    def __init__(self, origin: str, rp_id: str, kind: str = "es256", *, user_verified: bool = True) -> None:
        self.origin, self.rp_id, self.kind, self.user_verified = origin, rp_id, kind, user_verified
        self.credential_id = os.urandom(32)
        self.counter = 0
        if kind == "es256":
            self.key = ec.generate_private_key(ec.SECP256R1())
            numbers = self.key.public_key().public_numbers()
            self.cose = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        elif kind == "ed25519":
            self.key = ed25519.Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives import serialization
            raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.cose = {1: 1, 3: -8, -1: 6, -2: raw}
        else:
            self.key = rsa.generate_private_key(65537, 2048)
            numbers = self.key.public_key().public_numbers()
            self.cose = {1: 3, 3: -257, -1: numbers.n.to_bytes(256, "big"), -2: numbers.e.to_bytes(3, "big")}

    def _client(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def _flags(self, extra: int = 0) -> int:
        return 0x01 | (0x04 if self.user_verified else 0) | extra

    def create(self, options: dict, *, origin: str | None = None, rp_id: str | None = None) -> dict:
        assert options["authenticatorSelection"]["userVerification"] == "required"
        rp_hash = hashlib.sha256((rp_id or options["rp"]["id"]).encode()).digest()
        attested = (b"\x00" * 16 + struct.pack(">H", len(self.credential_id)) + self.credential_id + cbor(self.cose))
        auth = rp_hash + bytes([self._flags(0x40)]) + struct.pack(">I", self.counter) + attested
        attestation = cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64url(self.credential_id), "rawId": b64url(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64url(self._client("webauthn.create", options["challenge"], origin)),
                             "attestationObject": b64url(attestation)}}

    def get(self, options: dict, *, origin: str | None = None, counter: int | None = None,
            tamper: bool = False) -> dict:
        assert options["userVerification"] == "required"
        assert b64url(self.credential_id) in {item["id"] for item in options["allowCredentials"]}
        self.counter = self.counter + 1 if counter is None else counter
        rp_hash = hashlib.sha256(options["rpId"].encode()).digest()
        auth = rp_hash + bytes([self._flags()]) + struct.pack(">I", self.counter)
        client = self._client("webauthn.get", options["challenge"], origin)
        signed = auth + hashlib.sha256(client).digest()
        if self.kind == "es256":
            signature = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        elif self.kind == "ed25519":
            signature = self.key.sign(signed)
        else:
            signature = self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        if tamper:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return {"id": b64url(self.credential_id), "rawId": b64url(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64url(client), "authenticatorData": b64url(auth),
                             "signature": b64url(signature), "userHandle": None}}


__all__ = ["SoftAuthenticator", "cbor", "unb64url"]
