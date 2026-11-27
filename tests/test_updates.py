"""Settings → Updates: release list, guarded requests, session hand-off, root updater, installer."""
import json
import os
import sys
import time
from pathlib import Path

import httpx
import pytest

import hilait.updates as updates_module
from hilait import __version__
from hilait.admin_auth import totp
from hilait.server import Runtime, create_app
from hilait.updater import Updater, read_request

COMMITS = {"9" * 40: "9.9.9", "8" * 40: "0.1.58", "5" * 40: __version__, "4" * 40: "0.1.40"}
RELEASES = {"releases": [
    {"version": "9.9.9", "date": "2026-12-01", "notes": ["Big fix", ""], "commit": "9" * 40},
    {"version": __version__, "date": "2026-11-26", "notes": ["This one"], "commit": "5" * 40},
    {"version": "0.1.58", "date": "2026-11-26", "notes": ["Previous"], "commit": "8" * 40},
    {"version": "0.1.40", "date": "2026-10-11", "notes": ["Old"], "commit": "4" * 40},
    {"version": "7.7.7", "notes": ["no commit recorded"]},
    {"version": "bad", "notes": ["ignored"]},
]}


def use_github_fixture(runtime):
    real = httpx.AsyncClient
    handler = lambda request: httpx.Response(200, json=RELEASES)
    runtime.updates.client_factory = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)


def next_code(runtime):
    return totp(runtime.auth._settings()["seed"], time.time() + 30)


def install_marker(runtime):
    folder = runtime.store.root / "update"
    folder.mkdir(mode=0o700, exist_ok=True)
    (folder / "updater.json").write_text(json.dumps({"updater_version": 1}))


@pytest.mark.asyncio
async def test_overview_request_and_handoff(tmp_path, activate_otp):
    app = create_app(tmp_path / "data")
    runtime = app.state.runtime
    use_github_fixture(runtime)
    session = activate_otp(runtime)
    headers = {"Authorization": "Bearer " + session}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        health = (await client.get("/health")).json()
        assert health == {"status": "ready", "version": __version__}
        overview = (await client.get("/api/update", headers=headers)).json()
        assert overview["current"] == __version__ and overview["latest"] == "9.9.9"
        assert [r["version"] for r in overview["releases"]][:3] == ["9.9.9", __version__, "0.1.58"]
        assert overview["releases"][0]["newer"] and overview["releases"][1]["current"]
        assert overview["releases"][0]["notes"] == ["Big fix"]
        assert overview["releases"][-1]["version"] == "0.1.40" and overview["releases"][-1]["self_updating"] is False
        assert overview["updater"] is None and overview["confirm"] == "code"
        assert overview["setup_command"].startswith("sudo ") and overview["setup_command"].endswith("updater install")

        refused = await client.post("/api/update", json={"version": "9.9.9", "code": next_code(runtime)}, headers=headers)
        assert refused.status_code == 400 and "not installed" in refused.json()["error"]
        install_marker(runtime)
        wrong = await client.post("/api/update", json={"version": "9.9.9", "code": "000000"}, headers=headers)
        assert wrong.status_code == 400
        unknown = await client.post("/api/update", json={"version": "8.8.8", "code": next_code(runtime)}, headers=headers)
        assert unknown.status_code == 400 and "not a published release" in unknown.json()["error"]
        runtime.auth.store.write_secure("admin-otp.json", {**runtime.auth._settings(), "last_step": -1})
        ok = await client.post("/api/update", json={"version": "9.9.9", "code": next_code(runtime)}, headers=headers)
        assert ok.status_code == 200 and ok.json()["phase"] == "queued"
        request = read_request(runtime.store.root / "update" / "request.json")
        assert request["version"] == "9.9.9"
        status = (await client.get("/api/update/status", headers=headers)).json()
        assert status["phase"] == "queued" and status["current"] == __version__
        busy = await client.post("/api/update", json={"version": "9.9.9", "code": next_code(runtime)}, headers=headers)
        assert busy.status_code == 400 and "already in progress" in busy.json()["error"]
        assert (runtime.store.root / "update-handoff.enc").exists()

    # The restarted process accepts the same browser session, once.
    restarted = Runtime(tmp_path / "data")
    assert restarted.auth.valid(session)
    assert not (restarted.store.root / "update-handoff.enc").exists()
    assert not Runtime(tmp_path / "data").auth.valid(session)


def test_stale_handoff_is_ignored(tmp_path, activate_otp):
    runtime = Runtime(tmp_path / "data")
    session = activate_otp(runtime)
    runtime.updates.save_handoff()
    data = runtime.store.read_secure("update-handoff.enc", {})
    runtime.store.write_secure("update-handoff.enc", {**data, "created": time.time() - 3600})
    assert not Runtime(tmp_path / "data").auth.valid(session)


class FakeSystem:
    def __init__(self, installed="0.1.58", install_ok=True, healthy=True, healthy_after_rollback=True):
        self.installed, self.install_ok, self.healthy = installed, install_ok, healthy
        self.original = installed
        self.healthy_after_rollback, self.commands, self.rolled_back = healthy_after_rollback, [], False

    def run(self, argv, **kwargs):
        self.commands.append(argv)
        class Result:
            returncode, stdout, stderr = 0, "", ""
        result = Result()
        if argv[1:3] == ["-m", "pip"]:
            target = COMMITS[argv[-1].rsplit("/", 1)[1].removesuffix(".zip")]
            if self.install_ok:
                if target == self.original and self.installed != self.original:
                    self.rolled_back = True
                self.installed = target
                result.stdout = f"Successfully installed hilait-{target}"
            else:
                result.returncode, result.stderr = 1, "ERROR: network unreachable"
        elif argv[1] == "-c":
            result.stdout = self.installed + "\n"
        return result

    def fetch(self, url, insecure_local=False):
        if url.endswith("releases.json"):
            return json.dumps(RELEASES).encode()
        ok = self.healthy if not self.rolled_back else self.healthy_after_rollback
        if not ok:
            raise OSError("connection refused")
        return json.dumps({"status": "ready", "version": self.installed}).encode()


def updater_for(tmp_path, system, version="9.9.9"):
    folder = tmp_path / "update"
    folder.mkdir(exist_ok=True)
    (folder / "request.json").write_text(json.dumps({"id": "a" * 32, "version": version}))
    config = {"python": "/opt/hilait-venv/bin/python", "unit": "hilait.service", "repo": "germanespinosa/Hilait",
              "data_dir": str(tmp_path), "health_url": "http://127.0.0.1:8765/health"}
    return Updater(config, run=system.run, fetch=system.fetch, sleep=lambda s: None)


def test_updater_installs_restarts_and_reports(tmp_path):
    system = FakeSystem()
    result = updater_for(tmp_path, system).apply()
    assert result["phase"] == "done" and result["from_version"] == "0.1.58"
    assert ["systemctl", "restart", "hilait.service"] in system.commands
    pip = next(c for c in system.commands if c[1:3] == ["-m", "pip"])
    assert pip[-1] == f"https://github.com/germanespinosa/Hilait/archive/{'9' * 40}.zip"
    assert not (tmp_path / "update" / "request.json").exists()
    assert json.loads((tmp_path / "update" / "status.json").read_text())["phase"] == "done"


def test_updater_install_failure_does_not_restart(tmp_path):
    system = FakeSystem(install_ok=False)
    result = updater_for(tmp_path, system).apply()
    assert result["phase"] == "failed" and "network unreachable" in result["log"]
    assert not any(c[:2] == ["systemctl", "restart"] for c in system.commands)


def test_updater_rolls_back_when_new_version_does_not_start(tmp_path):
    system = FakeSystem(healthy=False, healthy_after_rollback=True)
    result = updater_for(tmp_path, system).apply()
    assert result["phase"] == "failed" and "0.1.58 was restored" in result["message"]
    assert system.installed == "0.1.58"


def test_updater_rejects_bad_and_unpublished_requests(tmp_path):
    system = FakeSystem()
    assert updater_for(tmp_path, system, version="1.2.3; rm -rf /").apply()["phase"] == "failed"
    assert updater_for(tmp_path, system, version="7.7.7").apply()["message"] == "Version 7.7.7 is not a published release."
    assert not any(c[1:3] == ["-m", "pip"] for c in system.commands)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="systemd installer is Linux only")
def test_installer_writes_units_and_marker(tmp_path):
    import pwd
    user = pwd.getpwuid(os.getuid()).pw_name
    (tmp_path / "units").mkdir()
    written = updates_module.install_updater(
        unit="hilait.service", python="/opt/hilait-venv/bin/python", user=user, data_dir=str(tmp_path / "data"),
        health_url="http://127.0.0.1:8765/health", unit_dir=tmp_path / "units", lib_dir=tmp_path / "lib",
        config_path=tmp_path / "etc" / "updater.json", systemctl=False)
    path_unit = (tmp_path / "units" / "hilait-update.path").read_text()
    assert f"PathChanged={tmp_path / 'data' / 'update' / 'request.json'}" in path_unit
    service = (tmp_path / "units" / "hilait-update.service").read_text()
    assert f"{tmp_path / 'lib' / 'updater.py'} --config {tmp_path / 'etc' / 'updater.json'}" in service
    assert json.loads((tmp_path / "etc" / "updater.json").read_text())["repo"] == "germanespinosa/Hilait"
    assert (tmp_path / "lib" / "updater.py").read_text() == Path(updates_module.__file__).with_name("updater.py").read_text()
    assert json.loads((tmp_path / "data" / "update" / "updater.json").read_text())["updater_version"] == 1
    assert len(written) == 4


def test_passkey_step_covers_updates():
    script = (Path(updates_module.__file__).parent / "static" / "passkey.js").read_text()
    assert "path === '/api/update'" in script and "hilait_update" in script


def test_release_notes_are_paged_ten_at_a_time():
    script = (Path(__file__).resolve().parents[1] / "src/hilait/static/app.js").read_text()
    assert "const RELEASE_PAGE=10;" in script
    for marker in ('id="release-pager"', 'id="release-older"', 'id="release-newer"', 'releases.slice(page*RELEASE_PAGE'):
        assert marker in script
