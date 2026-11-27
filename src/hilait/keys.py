"""Parse SSH private keys uploaded through the browser.

Uploaded keys are kept as the original text (encrypted in ``connections.json``) and turned into a
Paramiko key only in memory, when a session opens. Both OpenSSH (``BEGIN OPENSSH PRIVATE KEY``) and
PEM (PKCS#1, SEC1 and PKCS#8) files are accepted, encrypted or not; RSA, ECDSA and Ed25519 only.
"""

from __future__ import annotations

import io

import paramiko
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

MAX_KEY_CHARS = 32 * 1024
_CLASSES = ((rsa.RSAPrivateKey, paramiko.RSAKey), (ec.EllipticCurvePrivateKey, paramiko.ECDSAKey),
            (ed25519.Ed25519PrivateKey, paramiko.Ed25519Key))


class KeyPassphraseNeeded(ValueError):
    """The key is encrypted and no passphrase was supplied."""


def _parse(text: str, passphrase: str | None):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Choose a private key file to upload.")
    if len(text) > MAX_KEY_CHARS:
        raise ValueError("That file is too large to be an SSH private key.")
    if "PuTTY-User-Key-File" in text:
        raise ValueError("PuTTY .ppk keys are not supported. Export the key in OpenSSH format with PuTTYgen first.")
    if "PRIVATE KEY-----" not in text:
        if text.lstrip().startswith(("ssh-", "ecdsa-")) or "PUBLIC KEY" in text:
            raise ValueError("That is a public key. Upload the private key (the file without .pub).")
        raise ValueError("That file is not an SSH private key.")
    data = text.strip().encode() + b"\n"
    loader = (serialization.load_ssh_private_key if b"OPENSSH PRIVATE KEY" in data
              else serialization.load_pem_private_key)
    password = passphrase.encode() if passphrase else None
    try:
        try:
            return loader(data, password=password), bool(password)
        except TypeError as exc:  # passphrase given for an unencrypted key, or missing for an encrypted one
            if password is not None and "not encrypted" in str(exc):
                return loader(data, password=None), False
            raise KeyPassphraseNeeded("This private key is encrypted. Enter its passphrase.") from exc
    except KeyPassphraseNeeded:
        raise
    except UnsupportedAlgorithm as exc:
        raise ValueError("This key type is not supported. Use an RSA, ECDSA or Ed25519 key.") from exc
    except ValueError as exc:
        if password is not None:
            raise ValueError("The passphrase does not unlock this private key.") from exc
        raise ValueError("That file is not a readable SSH private key.") from exc


def _load(text: str, passphrase: str | None) -> tuple[paramiko.PKey, bool]:
    key, encrypted = _parse(text, passphrase)
    cls = next((paramiko_cls for crypto_cls, paramiko_cls in _CLASSES if isinstance(key, crypto_cls)), None)
    if cls is None:
        raise ValueError("This key type is not supported. Use an RSA, ECDSA or Ed25519 key.")
    plain = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                              serialization.NoEncryption()).decode()
    try:
        return cls.from_private_key(io.StringIO(plain)), encrypted
    except paramiko.SSHException as exc:
        raise ValueError("This key type is not supported. Use an RSA, ECDSA or Ed25519 key.") from exc


def load_private_key(text: str, passphrase: str | None = None) -> paramiko.PKey:
    """Return a Paramiko key for an uploaded private key (raises ValueError with a readable message)."""
    return _load(text, passphrase)[0]


def describe_private_key(text: str, passphrase: str | None = None) -> dict:
    """Validate an upload and return non-secret facts shown in the UI (type, SHA-256 fingerprint)."""
    try:
        key, encrypted = _load(text, passphrase)
    except KeyPassphraseNeeded:
        return {"type": None, "fingerprint": None, "encrypted": True}
    return {"type": key.get_name(), "fingerprint": key.fingerprint, "encrypted": encrypted}
