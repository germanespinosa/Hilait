import base64
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from hilait.admin_auth import RateLimitError, totp
from hilait.cli import main
from hilait.server import create_app


def test_totp_matches_rfc_6238_sha1_vectors():
    seed = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert totp(seed, 59, digits=8) == "94287082"
    assert totp(seed, 1111111109, digits=8) == "07081804"
    assert totp(seed, 1234567890, digits=8) == "89005924"


@pytest.mark.asyncio
async def test_optional_otp_setup_login_and_disable(tmp_path, monkeypatch):
    clock = [1_700_000_000]
    monkeypatch.setattr("hilait.admin_auth.time.time", lambda: clock[0])
    app = create_app(tmp_path)
    runtime = app.state.runtime
    admin = {"Authorization": "Bearer " + runtime.store.admin_token}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/api/auth/mode")).json() == {"otp_enabled": False}
        assert (await client.get("/api/state", headers=admin)).status_code == 200
        assert (await client.get("/api/otp", headers=admin)).json() == {"enabled": False, "pending": False}
        setup_response = await client.post("/api/otp/setup", headers=admin, json={})
        assert setup_response.headers["cache-control"] == "no-store"
        setup = setup_response.json()
        assert setup["enabled"] is False and setup["pending"] is True
        assert setup["qr"].startswith("data:image/svg+xml;base64,")
        assert b"<svg" in base64.b64decode(setup["qr"].split(",", 1)[1])
        assert setup["secret"] not in (tmp_path / "admin-otp.json").read_text()
        code = totp(setup["secret"], clock[0])
        confirmed = await client.post("/api/otp/confirm", headers=admin, json={"code": code})
        assert confirmed.status_code == 200, confirmed.text
        session = confirmed.json()["session"]
        assert (await client.get("/api/auth/mode")).json() == {"otp_enabled": True}
        verified = {"Authorization": "Bearer " + session}
        assert (await client.get("/api/state", headers=verified)).status_code == 200
        denied = await client.get("/api/state", headers=admin)
        assert denied.status_code == 403 and denied.json()["detail"]["code"] == "otp_required"
        assert (await client.post("/api/auth/verify", json={"code": code})).status_code == 400
        clock[0] += 31
        new_code = totp(setup["secret"], clock[0])
        logged_in = await client.post("/api/auth/verify", json={"code": new_code})
        assert logged_in.status_code == 200
        assert (await client.get("/api/state", headers={"Authorization": "Bearer " + logged_in.json()["session"]})).status_code == 200
        clock[0] += 31
        off_code = totp(setup["secret"], clock[0])
        disabled = await client.post("/api/otp/disable", headers=verified, json={"code": off_code})
        assert disabled.status_code == 200
        assert (await client.get("/api/state", headers=admin)).status_code == 200
        assert (await client.get("/api/state", headers=verified)).status_code == 401


def test_otp_blocks_raw_token_websockets_and_rate_limits(tmp_path, monkeypatch):
    clock = [1_700_000_000]
    monkeypatch.setattr("hilait.admin_auth.time.time", lambda: clock[0])
    app = create_app(tmp_path)
    auth = app.state.runtime.auth
    setup = auth.begin_setup()
    session = auth.confirm_setup(totp(setup["secret"], clock[0]))
    admin_token = app.state.runtime.store.admin_token
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as rejected:
            with client.websocket_connect(f"/ws/events?token={admin_token}", headers={"origin": "http://testserver"}) as ws:
                ws.receive_json()
        assert rejected.value.code == 4401
        with client.websocket_connect(f"/ws/events?token={session}", headers={"origin": "http://testserver"}) as ws:
            assert ws.receive_json()["type"] == "state"
    for _ in range(5):
        with pytest.raises(ValueError):
            auth.verify_login("invalid")
    with pytest.raises(RateLimitError):
        auth.verify_login("invalid")


def test_replacing_seed_keeps_old_factor_until_confirmed(tmp_path, monkeypatch):
    clock = [1_700_000_000]
    monkeypatch.setattr("hilait.admin_auth.time.time", lambda: clock[0])
    app = create_app(tmp_path)
    auth = app.state.runtime.auth
    first = auth.begin_setup()
    old_session = auth.confirm_setup(totp(first["secret"], clock[0]))
    app.state.runtime.store.save_profiles([{"id": "one", "name": "Secret machine", "host": "private.example", "username": "user"}])
    app.state.runtime.store.write("known-hosts.json", {"private.example:22": "fingerprint"})
    assert b"private.example" not in (tmp_path / "connections.json").read_bytes()
    clock[0] += 31
    replacement = auth.begin_setup(totp(first["secret"], clock[0]))
    assert auth.valid(old_session)
    assert auth.status()["enabled"] is True
    assert replacement["secret"] != first["secret"]
    assert app.state.runtime.store.profiles()[0]["name"] == "Secret machine"
    auth.cancel_setup()
    assert auth.status() == {"enabled": True, "pending": False}
    clock[0] += 31
    replacement = auth.begin_setup(totp(first["secret"], clock[0]))
    new_session = auth.confirm_setup(totp(replacement["secret"], clock[0]))
    assert not auth.valid(old_session)
    assert auth.valid(new_session)
    assert auth.enabled()
    assert app.state.runtime.store.profiles() == []
    assert app.state.runtime.store.read("known-hosts.json", {}) == {}


def test_first_otp_setup_migrates_legacy_connections(tmp_path):
    import json
    app = create_app(tmp_path)
    store = app.state.runtime.store
    legacy = [{"id": "old", "name": "Existing machine", "host": "existing.example", "username": "ada"}]
    (tmp_path / "connections.json").write_text(json.dumps(legacy))
    assert store.profiles() == []
    setup = app.state.runtime.auth.begin_setup()
    app.state.runtime.auth.confirm_setup(totp(setup["secret"], time.time()))
    assert store.profiles() == legacy
    assert b"existing.example" not in (tmp_path / "connections.json").read_bytes()


def test_local_cli_recovery_resets_seed(tmp_path, monkeypatch):
    app = create_app(tmp_path)
    auth = app.state.runtime.auth
    setup = auth.begin_setup()
    auth.confirm_setup(totp(setup["secret"], time.time()))
    app.state.runtime.store.save_profiles([{"id": "one", "name": "Private"}])
    assert auth.enabled()
    monkeypatch.setattr("hilait.storage.user_data_path", lambda *args: tmp_path)
    monkeypatch.setattr(sys, "argv", ["hilait", "otp", "reset"])
    main()
    assert not auth.enabled()
    assert not (tmp_path / "connections.json").exists()
