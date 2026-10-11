import httpx
import paramiko
import pytest

from hilait.agents import login_profile
from hilait.server import _sudo, create_app


PURPOSE = ("Inspect the machine and report its state without changing files, services, "
           "settings, permissions, credentials, or any other resources.")


@pytest.mark.asyncio
async def test_authentication_methods_are_separate_and_switching_clears_old_secret(tmp_path, activate_otp, monkeypatch):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        initial = await client.post("/api/profiles", headers=headers, json={
            "name": "Host", "host": "localhost", "username": "viewer", "secret": "normal-password",
            "access_mode": "tiered", "normal_unprivileged_confirmed": True,
            "elevated_username": "operator", "elevated_auth_method": "key",
            "elevated_private_key": "/keys/operator", "elevated_secret": "key-passphrase"})
        assert initial.status_code == 200, initial.text
        public = initial.json()
        assert public["auth_method"] == "password"
        assert public["elevated_auth_method"] == "key"
        saved = runtime.store.profile(public["id"])
        assert login_profile(saved, "elevated")["auth_method"] == "key"
        attempts = []

        def capture_connect(self, *args, **kwargs):
            attempts.append(kwargs)
            raise RuntimeError("captured SSH arguments")

        monkeypatch.setattr(paramiko.SSHClient, "connect", capture_connect)
        for privilege in ("normal", "elevated"):
            with pytest.raises(RuntimeError, match="captured SSH arguments"):
                await runtime.sessions.open(login_profile(saved, privilege))
        assert (attempts[0]["password"], attempts[0]["passphrase"], attempts[0]["key_filename"]) == (
            "normal-password", None, None)
        assert (attempts[1]["password"], attempts[1]["passphrase"], attempts[1]["key_filename"]) == (
            None, "key-passphrase", "/keys/operator")

        switched = await client.post("/api/profiles", headers=headers, json={
            **public, "auth_method": "key", "private_key": "/keys/viewer",
            "elevated_auth_method": "password"})
        assert switched.status_code == 200, switched.text
        new_public = switched.json()
        assert not new_public["has_saved_secret"]
        assert not new_public["has_saved_elevated_secret"]
        changed = runtime.store.profile(public["id"])
        assert changed["secret"] is None and changed["elevated_secret"] is None
        assert changed["elevated_private_key"] == ""
        assert login_profile(changed, "elevated")["auth_method"] == "password"
        invalid = await client.post("/api/profiles", headers=headers, json={
            **new_public, "auth_method": "key", "private_key": ""})
        assert invalid.status_code == 400


@pytest.mark.asyncio
async def test_tiers_keep_credentials_permissions_and_authorizations_separate(tmp_path, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        ordinary = await client.post("/api/profiles", headers=headers, json={
            "name": "Host", "host": "localhost", "username": "viewer", "access_mode": "tiered",
            "elevated_username": "operator", "normal_unprivileged_confirmed": True,
            "secret": "normal-pass", "elevated_secret": "elevated-pass"})
        assert ordinary.status_code == 200, ordinary.text
        profile = ordinary.json()
        assert profile["has_saved_elevated_secret"] is True
        assert "elevated_secret" not in profile
        agent_response = (await client.post("/api/agents", headers=headers, json={"name": "Test agent"})).json()
        agent = agent_response["agent"]
        token = agent_response["config"]["mcpServers"]["hilait"]["env"]["HILAIT_AGENT_TOKEN"]
        agent_headers = {"Authorization": "Bearer " + token}
        connections = (await client.post("/agent/connections", headers=agent_headers, json={})).json()
        assert connections[0]["privileges"] == ["normal"]
        assert "sudo" not in connections[0]["capabilities"]
        denied = await client.post("/agent/request_access", headers=agent_headers, json={
            "connection": profile["id"], "privilege": "elevated", "purpose": PURPOSE})
        assert denied.status_code == 403
        allowed = await client.post(f"/api/agents/{agent['id']}/permissions", headers=headers,
                                    json={"connection_ids": [profile["id"]],
                                          "elevated_connection_ids": [profile["id"]]})
        assert allowed.status_code == 200, allowed.text
        connections = (await client.post("/agent/connections", headers=agent_headers, json={})).json()
        assert connections[0]["privileges"] == ["normal", "elevated"]
        elevated = await client.post("/agent/request_access", headers=agent_headers, json={
            "connection": profile["id"], "privilege": "elevated", "purpose": PURPOSE})
        assert elevated.status_code == 200, elevated.text
        assert "ELEVATED ACCESS" in elevated.json()["warning"]
        assert elevated.json()["privilege"] == "elevated"
        elevated_approval = await client.post(
            f"/api/grants/{elevated.json()['access']}/approve", headers=headers, json={})
        assert elevated_approval.status_code == 400
        normal = await client.post("/agent/request_access", headers=agent_headers, json={
            "connection": profile["id"], "privilege": "normal", "purpose": PURPOSE})
        assert normal.status_code == 200, normal.text
        normal_grant = runtime.agents.grants[normal.json()["access"]]
        with pytest.raises(PermissionError, match="normal access"):
            await _sudo(runtime, normal_grant, "id", "Check my privileges")
        unconfirmed = await client.post("/api/authorizations", headers=headers, json={
            "agent_id": agent["id"], "profile_id": profile["id"], "privilege": "elevated",
            "permanent": True, "file_access": "None"})
        assert unconfirmed.status_code == 400
        confirmed = await client.post("/api/authorizations", headers=headers, json={
            "agent_id": agent["id"], "profile_id": profile["id"], "privilege": "elevated",
            "elevated_confirmed": True, "permanent": True, "file_access": "None"})
        assert confirmed.status_code == 200, confirmed.text
        assert runtime.agents.active_authorization(agent["id"], profile["id"], "normal") is None
        assert runtime.agents.active_authorization(agent["id"], profile["id"], "elevated") is not None
        saved = runtime.store.profile(profile["id"])
        normal_login = login_profile(saved, "normal")
        elevated_login = login_profile(saved, "elevated")
        assert normal_login["username"] == "viewer"
        assert runtime.store.decrypt(normal_login["secret"]) == "normal-pass"
        assert "elevated_secret" not in normal_login
        assert elevated_login["username"] == "operator"
        assert runtime.store.decrypt(elevated_login["secret"]) == "elevated-pass"
        normal_authorization = runtime.agents.create_authorization(
            agent["id"], profile["id"], None, "None", permanent=True, privilege="normal")
        changed = await client.post("/api/profiles", headers=headers, json={
            **profile, "elevated_secret": "new-elevated-pass"})
        assert changed.status_code == 200, changed.text
        assert runtime.agents.active_authorization(agent["id"], profile["id"], "normal")["id"] == normal_authorization["id"]
        assert runtime.agents.active_authorization(agent["id"], profile["id"], "elevated") is None


@pytest.mark.asyncio
async def test_legacy_profile_requires_opt_in_and_unprivileged_confirmation(tmp_path, activate_otp):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        created = await client.post("/api/profiles", headers=headers,
                                    json={"name": "Old", "host": "localhost", "username": "root"})
        assert created.status_code == 200
        assert created.json()["access_mode"] == "legacy"
        profile_id = created.json()["id"]
        invalid = await client.post("/api/profiles", headers=headers, json={
            "id": profile_id, "name": "Old", "host": "localhost", "username": "root",
            "access_mode": "tiered", "elevated_username": "admin"})
        assert invalid.status_code == 400
        same_account = await client.post("/api/profiles", headers=headers, json={
            "id": profile_id, "name": "Old", "host": "localhost", "username": "root",
            "access_mode": "tiered", "elevated_username": "root",
            "normal_unprivileged_confirmed": True})
        assert same_account.status_code == 400


@pytest.mark.asyncio
async def test_elevated_review_revokes_only_its_tier_unless_safety_cross_tier_enabled(
        tmp_path, activate_otp, monkeypatch):
    app = create_app(tmp_path)
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    agent, _ = runtime.store.create_agent("Tier review agent")
    runtime.store.save_profiles([{
        "id": "host", "name": "Host", "host": "localhost", "port": 22,
        "username": "viewer", "elevated_username": "operator", "platform": "unix",
        "access_mode": "tiered", "normal_unprivileged_confirmed": True,
        "allowed_agent_ids": None, "elevated_allowed_agent_ids": [agent["id"]]}])
    normal = await runtime.agents.request(agent, "host", PURPOSE, privilege="normal")
    elevated = await runtime.agents.request(agent, "host", PURPOSE, privilege="elevated")
    for grant in (normal, elevated):
        runtime.agents.change(grant, "Approved", "Fixture")
        grant.session_id = grant.id + "-session"
        runtime.sessions.sessions[grant.session_id] = object()
        runtime.agents.create_authorization(agent["id"], "host", None, "None",
                                            permanent=True, privilege=grant.privilege)
    closed = []

    async def close(session_id, reason):
        closed.append(session_id)
        runtime.sessions.sessions.pop(session_id)

    monkeypatch.setattr(runtime.sessions, "close", close)
    reviewed = [0]

    async def low_review(_grant_id, _progress):
        reviewed[0] += 1
        return {"safety": 2, "purpose_alignment": 8, "correctness": 8,
                "reviewed_utc": f"2026-10-11T00:00:0{reviewed[0]}+00:00"}

    monkeypatch.setattr(runtime.reviewer, "review", low_review)
    runtime.reviewer.save_settings({"elevated_revoke_thresholds": {"safety": 3}})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(f"/api/review/{elevated.id}", headers=headers)
        assert response.status_code == 200, response.text
        assert elevated.state == "Revoked"
        assert normal.state == "Approved"
        assert closed == [elevated.session_id]
        assert runtime.agents.active_authorization(agent["id"], "host", "normal") is not None
        assert runtime.agents.active_authorization(agent["id"], "host", "elevated") is None
        runtime.reviewer.save_settings({"revoke_all_tiers_on_safety": True})
        response = await client.post(f"/api/review/{elevated.id}", headers=headers)
        assert response.status_code == 200, response.text
        assert normal.state == "Revoked"
        assert normal.session_id in closed
