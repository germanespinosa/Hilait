"""Security boundaries for the unattended server's on-disk secrets."""

import os
import time

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

from hilait.admin_auth import AdminAuth, totp
from hilait.storage import Audit, Store
from hilait.tls import ensure_lan_certificate


def test_external_master_key_preserves_data_and_is_required(tmp_path, monkeypatch):
    data = tmp_path / "data"
    original = Store(data)
    auth = AdminAuth(original)
    setup = auth.begin_setup()
    auth.confirm_setup(totp(setup["secret"], time.time()))
    original.save_profiles([{"id": "one", "name": "Private host",
                             "secret": original.encrypt("ssh-password") }])
    key = tmp_path / "master.key"
    (data / "master.key").replace(key)
    monkeypatch.setenv("HILAIT_MASTER_KEY_FILE", str(key))
    restored = Store(data)
    assert restored.decrypt(restored.profiles()[0]["secret"]) == "ssh-password"
    assert not (data / "master.key").exists()

    key.write_bytes(Fernet.generate_key())
    with pytest.raises(Exception):
        Store(data).profiles()


def test_admin_token_migrates_to_encrypted_form(tmp_path):
    store = Store(tmp_path / "data")
    token = store.admin_token
    path = store.token_path
    path.write_text(token, encoding="ascii")
    reopened = Store(store.root)
    assert reopened.admin_token == token
    assert token.encode() not in path.read_bytes()


def test_lan_private_key_is_encrypted_without_changing_identity(tmp_path):
    store = Store(tmp_path / "data")
    cert, key, fingerprint, _ = ensure_lan_certificate(store.root)
    assert b"BEGIN PRIVATE KEY" in key.read_bytes()
    migrated = ensure_lan_certificate(store.root, store.tls_password())
    assert migrated[:3] == (cert, key, fingerprint)
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in key.read_bytes()
    serialization.load_pem_private_key(key.read_bytes(), store.tls_password().encode())
    assert ensure_lan_certificate(store.root, store.tls_password())[:3] == migrated[:3]


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_audit_and_secrets_are_owner_only(tmp_path):
    store = Store(tmp_path / "data")
    audit = Audit(store)
    audit.write("test", {}, {})
    for name in ("activity.audit", "master.key", "admin.token"):
        assert (store.root / name).stat().st_mode & 0o077 == 0
    (store.root / "admin.token").chmod(0o644)
    with pytest.raises(PermissionError, match="mode 0600"):
        Store(store.root)


def test_symlinked_key_is_rejected(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    target = tmp_path / "target"
    target.write_bytes(b"not a real key")
    try:
        (data / "master.key").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are unavailable")
    with pytest.raises((PermissionError, FileExistsError)):
        Store(data)
