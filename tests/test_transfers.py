import asyncio
import os
import stat
import sys
from pathlib import Path

import httpx
import pytest

from hilait.server import create_app, run_agent_tool


PURPOSE = ("Upload the prepared configuration from the Hilait transfer folder to the loopback fixture, "
           "then download the generated report back for the administrator to review.")


@pytest.fixture
async def fixture_server(tmp_path):
    process = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).parent / "ssh_fixture.py"),
                                                    str(tmp_path / "remote"), stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
    port = int((await asyncio.wait_for(process.stdout.readline(), 15)).decode())
    try:
        yield port
    finally:
        process.terminate()
        await asyncio.wait_for(process.wait(), 10)


def test_default_root_is_outside_data_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("HILAIT_TRANSFER_DIR", raising=False)
    runtime = create_app(tmp_path / "data").state.runtime
    assert runtime.transfers.root() == tmp_path / "data-transfers"
    monkeypatch.setenv("HILAIT_TRANSFER_DIR", str(tmp_path / "from-env"))
    assert runtime.transfers.root() == tmp_path / "from-env"
    monkeypatch.setenv("HILAIT_TRANSFER_DIR", "relative")
    with pytest.raises(ValueError, match="absolute"):
        runtime.transfers.root()


def test_folder_per_agent_machine_and_tier(tmp_path, activate_otp):
    runtime = create_app(tmp_path / "data").state.runtime
    activate_otp(runtime)
    runtime.transfers.update_settings(str(tmp_path / "transfers"))
    agent, _ = runtime.store.create_agent("Build Bot / nightly")
    profile = {"id": "1234567890abcdef", "name": "Prod DB #1"}
    normal = Path(runtime.transfers.folder_for(agent, profile, "normal"))
    elevated = Path(runtime.transfers.folder_for(agent, profile, "elevated"))
    assert normal.parent == elevated.parent
    assert normal != elevated
    assert normal.relative_to(tmp_path / "transfers").parts == (
        f"build-bot-nightly-{agent['id'][:8]}", "prod-db-1-12345678", "normal")
    assert runtime.transfers.folder_for(agent, profile, "normal") == str(normal)
    if os.name != "nt":
        for path in (tmp_path / "transfers", normal.parent.parent, normal.parent, normal):
            assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_transfer_root_validation(tmp_path):
    runtime = create_app(tmp_path / "data").state.runtime
    for bad in ("relative/path", str(tmp_path / "data"), str(tmp_path / "data" / "inside"), str(tmp_path),
                str(runtime.audit.path)):
        with pytest.raises(ValueError):
            runtime.transfers.update_settings(bad)
    if os.name != "nt":
        (tmp_path / "real").mkdir(mode=0o700)
        (tmp_path / "link").symlink_to(tmp_path / "real")
        with pytest.raises(PermissionError, match="symlink"):
            runtime.transfers.update_settings(str(tmp_path / "link"))
    saved = runtime.transfers.update_settings(str(tmp_path / "chosen"))
    assert saved["directory"] == str(tmp_path / "chosen")
    assert saved["exists"] is True
    assert runtime.transfers.update_settings(None)["directory"] == str(runtime.transfers.default_root())


async def test_transfer_area_api(tmp_path, activate_otp):
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    headers = {"Authorization": "Bearer " + activate_otp(runtime)}
    root = tmp_path / "transfers"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/api/transfers/settings")).status_code == 401
        saved = await client.put("/api/transfers/settings", headers=headers, json={"directory": str(root)})
        assert saved.status_code == 200, saved.text
        (root / "agent-a").mkdir(mode=0o700)
        uploaded = await client.post("/api/transfers/file", params={"path": "agent-a/in.txt"},
                                     headers=headers, content=b"staged input")
        assert uploaded.status_code == 200, uploaded.text
        assert (root / "agent-a" / "in.txt").read_bytes() == b"staged input"
        again = await client.post("/api/transfers/file", params={"path": "agent-a/in.txt"},
                                  headers=headers, content=b"overwrite")
        assert again.status_code == 409
        assert (root / "agent-a" / "in.txt").read_bytes() == b"staged input"
        listed = (await client.get("/api/transfers", params={"path": "agent-a"}, headers=headers)).json()
        assert [entry["path"] for entry in listed["entries"]] == ["agent-a/in.txt"]
        top = (await client.get("/api/transfers", headers=headers)).json()
        assert top["path"] == "" and top["entries"][0]["directory"] is True
        downloaded = await client.get("/api/transfers/file", params={"path": "agent-a/in.txt"}, headers=headers)
        assert downloaded.status_code == 200 and downloaded.content == b"staged input"
        escapes = ["../data/master.key", "/etc/passwd", "agent-a/../../data/master.key"]
        if os.name == "nt":
            escapes += ["C:/Windows/win.ini", "C:win.ini", "\\\\server\\share\\x", "agent-a\\..\\..\\x"]
        for escape in escapes:
            response = await client.get("/api/transfers/file", params={"path": escape}, headers=headers)
            assert response.status_code == 400, escape
            response = await client.post("/api/transfers/file", params={"path": escape}, headers=headers, content=b"x")
            assert response.status_code == 400, escape
        assert sorted(item.name for item in root.iterdir()) == ["agent-a"]
        assert (await client.delete("/api/transfers/file", params={"path": ""}, headers=headers)).status_code == 400
        deleted = await client.delete("/api/transfers/file", params={"path": "agent-a/in.txt"}, headers=headers)
        assert deleted.status_code == 200
        assert not (root / "agent-a" / "in.txt").exists()
        if os.name != "nt":
            (tmp_path / "outside.txt").write_text("keep")
            (root / "agent-a" / "link").symlink_to(tmp_path / "outside.txt")
            removed = await client.delete("/api/transfers/file", params={"path": "agent-a/link"}, headers=headers)
            assert removed.status_code == 200
            assert (tmp_path / "outside.txt").read_text() == "keep"
    kinds = {record["kind"] for record in runtime.audit.records()}
    assert {"transfer_settings_changed", "transfer_file_uploaded", "transfer_file_downloaded",
            "transfer_item_deleted"} <= kinds


async def test_local_transfer_approval_uses_managed_folder(tmp_path, fixture_server, activate_otp):
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    activate_otp(runtime)
    runtime.transfers.update_settings(str(tmp_path / "transfers"))
    profile = {"id": "machine-transfer", "name": "Loopback", "host": "127.0.0.1", "port": fixture_server,
               "username": "harbor-test", "secret": runtime.store.encrypt("loopback-fixture-only"),
               "platform": "unix", "allowed_agent_ids": None}
    runtime.store.save_profiles([profile])
    try:
        await runtime.sessions.open(profile)
    except Exception as warning:
        runtime.store.write("known-hosts.json", {warning.host: warning.fingerprint})
    agent, _ = runtime.store.create_agent("Transfer agent")
    try:
        grant = await runtime.agents.request(agent, profile["id"], PURPOSE, "LocalTransfers")
        await runtime.agents.approve(grant.id, duration_hours=1)
        folder = Path(grant.local_folder)
        assert folder.parent.parent.parent == tmp_path / "transfers"
        assert grant.public()["localFolder"] == str(folder)
        assert "local_folder" not in runtime.agents.active_authorization(agent["id"], profile["id"])
        (folder / "config.txt").write_bytes(b"from the server")
        await run_agent_tool(runtime, agent, "copy", {"access": grant.id, "direction": "upload",
                                                      "path": "config.txt", "destination": "/config.txt"})
        assert (tmp_path / "remote" / "config.txt").read_bytes() == b"from the server"
        await run_agent_tool(runtime, agent, "copy", {"access": grant.id, "direction": "download",
                                                      "path": "/config.txt", "destination": "report.txt"})
        assert (folder / "report.txt").read_bytes() == b"from the server"
        with pytest.raises(PermissionError):
            await run_agent_tool(runtime, agent, "copy", {"access": grant.id, "direction": "download",
                                                          "path": "/config.txt", "destination": "../escape.txt"})
        await runtime.agents.release(agent, grant.id, close_connection=True)
        repeat = await runtime.agents.request(agent, profile["id"], PURPOSE, "LocalTransfers")
        assert repeat.state == "Approved"
        assert repeat.local_folder == str(folder)
    finally:
        for session_id in list(runtime.sessions.sessions):
            await runtime.sessions.close(session_id)


def test_read_only_transfer_root_under_systemd_explains_the_fix(tmp_path, monkeypatch):
    import errno
    runtime = create_app(tmp_path / "data").state.runtime
    monkeypatch.setenv("HILAIT_TRANSFER_DIR", str(tmp_path / "locked"))
    monkeypatch.setenv("INVOCATION_ID", "0" * 32)

    def read_only(self, *args, **kwargs):
        raise OSError(errno.EROFS, "Read-only file system")
    monkeypatch.setattr(Path, "mkdir", read_only)
    with pytest.raises(PermissionError, match="updater install"):
        runtime.transfers._ensure_root(tmp_path / "locked")
    monkeypatch.delenv("INVOCATION_ID")
    with pytest.raises(PermissionError, match="Choose a writable folder"):
        runtime.transfers._ensure_root(tmp_path / "locked")
