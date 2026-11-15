import time

import pytest

from hilait.passkeys import Passkeys, cbor_decode
from hilait.storage import Audit, Store
from soft_authenticator import SoftAuthenticator, cbor

ORIGIN, RP_ID = "https://hilait.example.com", "hilait.example.com"


@pytest.fixture
def passkeys(tmp_path):
    store = Store(tmp_path)
    return Passkeys(store, Audit(store))


def register(passkeys, authenticator, session="s1", name="Pixel"):
    options = passkeys.registration_options(session, name)
    return passkeys.register(session, authenticator.create(options))


def check(passkeys, authenticator, action="grant_approve", target="g1", session="s1", elevated=False, **kw):
    options = passkeys.assertion_options(session, action, target, elevated=elevated)
    assert options["required"]
    passkeys.verify(session, action, target, authenticator.get(options["options"], **kw), elevated=elevated)


def test_origin_validation(passkeys):
    for bad in ("http://hilait.example.com", "https://192.168.1.20:8765", "https://[::1]", "https://hilait",
                "https://hilait.example.com/path", "hilait.example.com"):
        with pytest.raises(ValueError):
            passkeys.update_settings(bad, "off")
    assert passkeys.update_settings("https://Hilait.Example.com:443/", "off")["origin"] == ORIGIN
    assert passkeys.update_settings("https://hilait.example.com:8765", "off")["rp_id"] == RP_ID
    assert passkeys.update_settings("http://localhost:8765", "off")["origin"] == "http://localhost:8765"


@pytest.mark.parametrize("kind", ["es256", "ed25519", "rs256"])
def test_register_and_verify_each_algorithm(passkeys, kind):
    passkeys.update_settings(ORIGIN, "off")
    authenticator = SoftAuthenticator(ORIGIN, RP_ID, kind)
    status = register(passkeys, authenticator)
    assert [item["name"] for item in status["passkeys"]] == ["Pixel"]
    with pytest.raises(ValueError, match="already registered"):
        register(passkeys, authenticator)
    passkeys.update_settings(None, "all")
    check(passkeys, authenticator)
    check(passkeys, authenticator, action="agent_token_approve", target="r1")
    assert passkeys.status()["passkeys"][0]["last_used_utc"]


def test_policy_scope(passkeys):
    passkeys.update_settings(ORIGIN, "off")
    with pytest.raises(ValueError, match="Add a passkey"):
        passkeys.update_settings(None, "elevated")
    authenticator = SoftAuthenticator(ORIGIN, RP_ID)
    register(passkeys, authenticator)
    passkeys.update_settings(None, "elevated")
    assert passkeys.assertion_options("s1", "grant_approve", "g1", elevated=False) == {"required": False}
    passkeys.verify("s1", "grant_approve", "g1", None, elevated=False)
    with pytest.raises(PermissionError, match="Verify with your passkey"):
        passkeys.verify("s1", "grant_approve", "g1", None, elevated=True)
    check(passkeys, authenticator, elevated=True)
    with pytest.raises(ValueError, match="Unknown"):
        passkeys.required("grant_reject", elevated=True)
    with pytest.raises(ValueError, match="last passkey"):
        passkeys.delete(passkeys.status()["passkeys"][0]["id"])
    passkeys.update_settings(None, "off")
    passkeys.delete(passkeys.status()["passkeys"][0]["id"])
    assert passkeys.status()["passkeys"] == []


def test_assertions_are_bound_single_use_and_checked(passkeys):
    passkeys.update_settings(ORIGIN, "off")
    authenticator = SoftAuthenticator(ORIGIN, RP_ID)
    register(passkeys, authenticator)
    passkeys.update_settings(None, "all")

    def attempt(*, action="grant_approve", target="g1", session="s1", **kw):
        options = passkeys.assertion_options("s1", "grant_approve", "g1", elevated=False)["options"]
        return lambda: passkeys.verify(session, action, target, authenticator.get(options, **kw), elevated=False)

    for wrong in (dict(target="g2"), dict(action="sudo_approve"), dict(session="other")):
        with pytest.raises(PermissionError, match="does not match"):
            attempt(**wrong)()
    with pytest.raises(PermissionError, match="only at"):
        attempt(origin="https://evil.example.com")()
    with pytest.raises(PermissionError, match="verification failed"):
        attempt(tamper=True)()
    options = passkeys.assertion_options("s1", "grant_approve", "g1", elevated=False)["options"]
    response = authenticator.get(options)
    passkeys.verify("s1", "grant_approve", "g1", response, elevated=False)
    with pytest.raises(PermissionError, match="does not match"):
        passkeys.verify("s1", "grant_approve", "g1", response, elevated=False)  # replay
    with pytest.raises(PermissionError, match="cloned"):
        attempt(counter=1)()
    options = passkeys.assertion_options("s1", "grant_approve", "g1", elevated=False)["options"]
    passkeys.challenges[options["challenge"]]["expires"] = time.time() - 1
    with pytest.raises(PermissionError, match="expired"):
        passkeys.verify("s1", "grant_approve", "g1", authenticator.get(options), elevated=False)
    stranger = SoftAuthenticator(ORIGIN, RP_ID)
    stranger.credential_id = authenticator.credential_id  # same id, different key
    options = passkeys.assertion_options("s1", "grant_approve", "g1", elevated=False)["options"]
    with pytest.raises(PermissionError, match="verification failed"):
        passkeys.verify("s1", "grant_approve", "g1", stranger.get(options, counter=99), elevated=False)


def test_registration_rejections(passkeys):
    passkeys.update_settings(ORIGIN, "off")
    no_uv = SoftAuthenticator(ORIGIN, RP_ID, user_verified=False)
    with pytest.raises(PermissionError, match="fingerprint"):
        register(passkeys, no_uv)
    other_site = SoftAuthenticator(ORIGIN, RP_ID)
    options = passkeys.registration_options("s1", "Phone")
    with pytest.raises(PermissionError, match="different site"):
        passkeys.register("s1", other_site.create(options, rp_id="evil.example.com"))
    options = passkeys.registration_options("s1", "Phone")
    with pytest.raises(PermissionError, match="does not match"):
        passkeys.register("s2", other_site.create(options))
    assert passkeys.status()["passkeys"] == []


def test_changing_domain_clears_passkeys_and_reset(passkeys):
    passkeys.update_settings(ORIGIN, "off")
    register(passkeys, SoftAuthenticator(ORIGIN, RP_ID))
    passkeys.update_settings(None, "all")
    with pytest.raises(ValueError, match="Add a passkey"):
        passkeys.update_settings("https://other.example.com", "all")
    assert passkeys.update_settings("https://other.example.com", "off")["passkeys"] == []
    register(passkeys, SoftAuthenticator("https://other.example.com", "other.example.com"))
    passkeys.update_settings(None, "all")
    passkeys.reset()
    assert passkeys.status()["policy"] == "off" and passkeys.status()["passkeys"] == []
    assert passkeys.status()["origin"] == "https://other.example.com"


def test_cbor_decoder_limits():
    assert cbor_decode(cbor({1: [b"x", -7, "a", True]})) == {1: [b"x", -7, "a", True]}
    for bad in (b"", b"\x5f", b"\x9f", b"\x42a", cbor(1) + b"\x00", b"\xa1\x80\x01"):
        with pytest.raises(ValueError):
            cbor_decode(bad)
    nested = b"\x81" * 40 + b"\x01"
    with pytest.raises(ValueError):
        cbor_decode(nested)


async def test_api_requires_passkey_for_approvals(tmp_path, activate_otp):
    import asyncio
    import sys
    from pathlib import Path

    import httpx

    from hilait.admin_auth import totp
    from hilait.server import create_app

    process = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).parent / "ssh_fixture.py"),
                                                    str(tmp_path / "remote"), stdout=asyncio.subprocess.PIPE)
    port = int((await asyncio.wait_for(process.stdout.readline(), 15)).decode())
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    token = activate_otp(runtime)
    headers = {"Authorization": "Bearer " + token}
    seed = runtime.store.read_secure("admin-otp.json", {})["seed"]

    def code():
        runtime.auth.failed.clear()
        settings = runtime.store.read_secure("admin-otp.json", {})
        settings["last_step"] = -1  # tests reuse the current step
        runtime.store.write_secure("admin-otp.json", settings)
        return totp(seed, time.time())

    profile = {"id": "m1", "name": "Loopback", "host": "127.0.0.1", "port": port, "username": "harbor-test",
               "secret": runtime.store.encrypt("loopback-fixture-only"), "platform": "unix", "shell": "default",
               "allowed_agent_ids": None}
    runtime.store.save_profiles([profile])
    try:
        await runtime.sessions.open(profile)
    except Exception as warning:
        runtime.store.write("known-hosts.json", {warning.host: warning.fingerprint})
    agent, _ = runtime.store.create_agent("Agent")
    purpose = "Inspect the service logs on the loopback fixture to diagnose the failing nightly job, read-only."
    authenticator = SoftAuthenticator(ORIGIN, RP_ID)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            bad = await client.put("/api/passkeys/settings", headers=headers, json={"origin": ORIGIN, "policy": "off", "code": "000000"})
            assert bad.status_code == 400
            saved = await client.put("/api/passkeys/settings", headers=headers,
                                     json={"origin": ORIGIN, "policy": "off", "code": code()})
            assert saved.status_code == 200, saved.text
            options = (await client.post("/api/passkeys/register/options", headers=headers,
                                         json={"name": "Pixel", "code": code()})).json()
            registered = await client.post("/api/passkeys/register", headers=headers,
                                           json={"credential": authenticator.create(options)})
            assert registered.status_code == 200, registered.text
            assert (await client.put("/api/passkeys/settings", headers=headers,
                                     json={"policy": "all", "code": code()})).json()["policy"] == "all"

            grant = await runtime.agents.request(agent, "m1", purpose, "None")
            denied = await client.post(f"/api/grants/{grant.id}/approve", headers=headers, json={})
            assert denied.status_code == 403 and grant.state == "Pending"
            challenge = (await client.post("/api/passkeys/challenge", headers=headers,
                                           json={"action": "grant_approve", "target": grant.id})).json()
            assert challenge["required"] is True
            approved = await client.post(f"/api/grants/{grant.id}/approve", headers=headers,
                                         json={"passkey": authenticator.get(challenge["options"])})
            assert approved.status_code == 200, approved.text
            assert grant.state == "Approved"
            # Narrowing actions never ask.
            assert (await client.post(f"/api/grants/{grant.id}/pause", headers=headers, json={})).status_code == 200
            assert (await client.post(f"/api/grants/{grant.id}/revoke", headers=headers, json={})).status_code == 200
            other = await runtime.agents.request(agent, "m1", purpose, "None")
            assert (await client.post(f"/api/grants/{other.id}/reject", headers=headers, json={})).status_code == 200

            target = f"{agent['id']}/m1/"
            payload = {"agent_id": agent["id"], "profile_id": "m1", "hours": 1, "file_access": "None"}
            assert (await client.post("/api/authorizations", headers=headers, json=payload)).status_code == 403
            challenge = (await client.post("/api/passkeys/challenge", headers=headers,
                                           json={"action": "authorization_create", "target": target})).json()
            created = await client.post("/api/authorizations", headers=headers,
                                        json={**payload, "passkey": authenticator.get(challenge["options"])})
            assert created.status_code == 200, created.text
            narrowed = await client.post(f"/api/authorizations/{created.json()['id']}/file-access", headers=headers,
                                         json={"file_access": "None"})
            assert narrowed.status_code == 200
            widened = await client.post(f"/api/authorizations/{created.json()['id']}/file-access", headers=headers,
                                        json={"file_access": "Remote"})
            assert widened.status_code == 403

            assert (await client.put("/api/passkeys/settings", headers=headers,
                                     json={"policy": "elevated", "code": code()})).status_code == 200
            third = await runtime.agents.request(agent, "m1", purpose, "None")
            plain = await client.post("/api/passkeys/challenge", headers=headers,
                                      json={"action": "grant_approve", "target": third.id})
            assert plain.json() == {"required": False}
    finally:
        for session_id in list(runtime.sessions.sessions):
            await runtime.sessions.close(session_id)
        process.terminate()
        await process.wait()
