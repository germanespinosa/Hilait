"""Uploaded SSH private keys: validation, encrypted storage, secrecy and key-based login."""
import asyncio
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from hilait.agents import login_profile
from hilait.keys import KeyPassphraseNeeded, describe_private_key, load_private_key
from hilait.server import create_app


def pem(key, fmt=s.PrivateFormat.OpenSSH, passphrase=None):
    encryption = s.BestAvailableEncryption(passphrase.encode()) if passphrase else s.NoEncryption()
    return key.private_bytes(s.Encoding.PEM, fmt, encryption).decode()


def test_key_formats_and_readable_errors():
    ed, rs, ecd = ed25519.Ed25519PrivateKey.generate(), rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP256R1())
    assert describe_private_key(pem(ed))["type"] == "ssh-ed25519"
    assert describe_private_key(pem(rs, s.PrivateFormat.TraditionalOpenSSL))["type"] == "ssh-rsa"
    assert describe_private_key(pem(ecd, s.PrivateFormat.PKCS8))["type"] == "ecdsa-sha2-nistp256"
    # Windows line endings from a browser upload still parse.
    assert load_private_key(pem(ed).replace("\n", "\r\n")).get_name() == "ssh-ed25519"
    locked = pem(ed, passphrase="correct horse")
    assert describe_private_key(locked) == {"type": None, "fingerprint": None, "encrypted": True}
    unlocked = describe_private_key(locked, "correct horse")
    assert unlocked["encrypted"] is True and unlocked["fingerprint"].startswith("SHA256:")
    with pytest.raises(KeyPassphraseNeeded):
        load_private_key(locked)
    with pytest.raises(ValueError, match="does not unlock"):
        describe_private_key(locked, "wrong")
    with pytest.raises(ValueError, match="does not unlock"):
        describe_private_key(pem(rs, s.PrivateFormat.PKCS8, "pw"), "wrong")
    # A passphrase supplied for an unencrypted key is ignored rather than rejected.
    assert describe_private_key(pem(ed), "unneeded")["encrypted"] is False
    public = ed.public_key().public_bytes(s.Encoding.OpenSSH, s.PublicFormat.OpenSSH).decode()
    for text, message in ((public, "public key"), ("PuTTY-User-Key-File-3: ssh-ed25519", "PuTTY"),
                          ("hello", "not an SSH private key"), ("x" * 40000, "too large"),
                          (pem(dsa.generate_private_key(1024), s.PrivateFormat.PKCS8), "not supported")):
        with pytest.raises(ValueError, match=message):
            describe_private_key(text)


def base_profile(**extra):
    return {"name": "Keyed", "host": "127.0.0.1", "port": 22, "username": "viewer", "platform": "unix",
            "auth_method": "key", **extra}


@pytest.mark.asyncio
async def test_upload_is_encrypted_hidden_and_replaced_with_revision_bump(tmp_path, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    first = pem(ed25519.Ed25519PrivateKey.generate(), passphrase="pp-one")
    second = pem(ed25519.Ed25519PrivateKey.generate())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        missing = await client.post("/api/profiles", headers=headers, json=base_profile(key_source="upload"))
        assert missing.status_code == 400 and "private key file" in missing.json()["error"]
        bad = await client.post("/api/profiles", headers=headers,
                                json=base_profile(key_source="upload", private_key_upload=first, secret="nope"))
        assert bad.status_code == 400 and "does not unlock" in bad.json()["error"]

        saved = await client.post("/api/profiles", headers=headers,
                                  json=base_profile(key_source="upload", private_key_upload=first, secret="pp-one"))
        assert saved.status_code == 200, saved.text
        public = saved.json()
        assert public["has_uploaded_key"] and public["has_saved_secret"] and public["private_key"] == ""
        assert "private_key_data" not in public and "PRIVATE KEY" not in saved.text
        assert public["private_key_info"]["type"] == "ssh-ed25519" and public["private_key_info"]["encrypted"]
        stored = runtime.store.profile(public["id"])
        assert "PRIVATE KEY" not in stored["private_key_data"]
        assert runtime.store.decrypt(stored["private_key_data"]).strip() == first.strip()
        assert "PRIVATE KEY" not in (tmp_path / "connections.json").read_text()
        state = (await client.get("/api/state", headers=headers)).text
        assert "PRIVATE KEY" not in state and stored["private_key_data"] not in state
        assert runtime.store.public_profile(stored, agent=True).keys() == {"id", "name", "platform", "capabilities"}

        # Editing other fields keeps the key and passphrase without a revision change.
        kept = await client.post("/api/profiles", headers=headers, json={**base_profile(name="Renamed"), "id": public["id"]})
        assert kept.status_code == 200, kept.text
        after = runtime.store.profile(public["id"])
        assert after["private_key_data"] == stored["private_key_data"] and after["secret"] == stored["secret"]
        assert after["credential_revisions"] == stored["credential_revisions"]

        # Uploading a different key drops the old passphrase and bumps the credential revision.
        replaced = await client.post("/api/profiles", headers=headers,
                                     json={**base_profile(), "id": public["id"], "private_key_upload": second})
        assert replaced.status_code == 200, replaced.text
        assert replaced.json()["has_saved_secret"] is False and replaced.json()["private_key_info"]["encrypted"] is False
        changed = runtime.store.profile(public["id"])
        assert changed["credential_revisions"]["legacy"] == after["credential_revisions"]["legacy"] + 1

        # Switching to a server-side path removes the uploaded key.
        path = await client.post("/api/profiles", headers=headers,
                                 json={**base_profile(), "id": public["id"], "key_source": "path", "private_key": "/keys/id"})
        assert path.status_code == 200 and not path.json()["has_uploaded_key"]
        assert runtime.store.profile(public["id"])["private_key_data"] is None


@pytest.mark.asyncio
async def test_elevated_tier_upload_maps_into_login_profile(tmp_path, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    normal, elevated = pem(ed25519.Ed25519PrivateKey.generate()), pem(rsa.generate_private_key(65537, 2048))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        result = await client.post("/api/profiles", headers=headers, json=base_profile(
            key_source="upload", private_key_upload=normal, access_mode="tiered", normal_unprivileged_confirmed=True,
            elevated_username="operator", elevated_auth_method="key", elevated_key_source="upload",
            elevated_private_key_upload=elevated))
        assert result.status_code == 200, result.text
        assert result.json()["has_uploaded_elevated_key"] and result.json()["elevated_private_key_info"]["type"] == "ssh-rsa"
    stored = runtime.store.profile(result.json()["id"])
    up = login_profile(stored, "elevated")
    assert up["username"] == "operator" and runtime.store.decrypt(up["private_key_data"]).strip() == elevated.strip()
    down = login_profile(stored, "normal")
    assert runtime.store.decrypt(down["private_key_data"]).strip() == normal.strip()


@pytest.fixture
async def key_server(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    authorized = tmp_path / "authorized_keys"
    authorized.write_text(key.public_key().public_bytes(s.Encoding.OpenSSH, s.PublicFormat.OpenSSH).decode() + "\n")
    process = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).parent / "ssh_fixture.py"),
                                                    str(tmp_path / "remote"), str(authorized),
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    port = int((await asyncio.wait_for(process.stdout.readline(), 15)).decode())
    try:
        yield port, key
    finally:
        process.terminate()
        await asyncio.wait_for(process.wait(), 10)


@pytest.mark.asyncio
async def test_uploaded_key_logs_in_over_ssh(tmp_path, key_server, activate_otp):
    port, key = key_server
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        saved = await client.post("/api/profiles", headers=headers, json={
            **base_profile(port=port, username="harbor-test"), "key_source": "upload",
            "private_key_upload": pem(key, passphrase="unlock-me")})
        assert saved.status_code == 200, saved.text
        profile_id = saved.json()["id"]
        first = await client.post("/api/sessions", headers=headers, json={"profile": profile_id, "secret": "unlock-me"})
        assert first.status_code == 409  # host key must be trusted before any credential is used
        detail = first.json()
        await client.post("/api/hosts/trust", headers=headers, json={"host": detail["host"], "fingerprint": detail["fingerprint"]})
        needs = await client.post("/api/sessions", headers=headers, json={"profile": profile_id, "secret": ""})
        assert needs.status_code == 400 and "passphrase" in needs.json()["error"]
        opened = await client.post("/api/sessions", headers=headers, json={"profile": profile_id, "secret": "unlock-me"})
        assert opened.status_code == 200, opened.text
        await runtime.sessions.close(opened.json()["session"], "test done")
