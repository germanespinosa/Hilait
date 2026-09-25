"""Persistent local HTTPS identity for an explicitly enabled LAN listener."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def lan_addresses() -> list[str]:
    """Best-effort local IPv4 addresses to print and put into the certificate."""
    addresses: set[str] = set()
    try:
        for entry in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(entry[4][0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 80))
            addresses.add(probe.getsockname()[0])
    except OSError:
        pass
    return sorted(address for address in addresses
                  if not ipaddress.ip_address(address).is_loopback
                  and not ipaddress.ip_address(address).is_link_local)


def ensure_lan_certificate(root: Path) -> tuple[Path, Path, str, list[str]]:
    """Create a self-signed server certificate once, preserving its fingerprint."""
    certificate = root / "lan.crt"
    private_key = root / "lan.key"
    addresses = lan_addresses()
    if not (certificate.is_file() and private_key.is_file()):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hilait LAN")])
        alternatives = [x509.DNSName("localhost"), x509.DNSName(socket.gethostname()),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        alternatives.extend(x509.IPAddress(ipaddress.ip_address(address)) for address in addresses)
        now = datetime.now(timezone.utc)
        signed = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now - timedelta(minutes=5))
                  .not_valid_after(now + timedelta(days=730))
                  .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
                  .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                  .sign(key, hashes.SHA256()))
        key_bytes = key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        cert_bytes = signed.public_bytes(serialization.Encoding.PEM)
        root.mkdir(parents=True, exist_ok=True)
        for path, contents, mode in ((private_key, key_bytes, 0o600), (certificate, cert_bytes, 0o644)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(contents)
    parsed = x509.load_pem_x509_certificate(certificate.read_bytes())
    fingerprint = hashlib.sha256(parsed.public_bytes(serialization.Encoding.DER)).hexdigest()
    return certificate, private_key, fingerprint, addresses
