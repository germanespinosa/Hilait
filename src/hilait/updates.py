"""Self-update support: release list, update requests, session hand-off, updater installation.

The service never installs software itself (it runs unprivileged). It only
writes ``<data dir>/update/request.json`` with a version number; the root
``hilait-update`` unit installed by ``hilait updater install`` does the rest
(see ``updater.py``) and reports progress in ``status.json`` next to it.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import httpx

from . import __version__
from .updater import COMMIT_PATTERN, UPDATER_VERSION, VERSION_PATTERN, version_key

REPO = "germanespinosa/Hilait"
RELEASES_URL = f"https://raw.githubusercontent.com/{REPO}/main/releases.json"
CACHE_SECONDS = 600
HANDOFF_FILE = "update-handoff.enc"
HANDOFF_SECONDS = 15 * 60
ACTIVE_PHASES = {"queued", "checking", "installing", "restarting", "rolling_back"}
FIRST_SELF_UPDATING = "0.1.59"


class UpdateManager:
    def __init__(self, store, auth, audit) -> None:
        self.store, self.auth, self.audit = store, auth, audit
        self.dir = Path(store.root) / "update"
        self._cache: tuple[float, list[dict]] | None = None
        self.releases_url = os.environ.get("HILAIT_RELEASES_URL", RELEASES_URL)
        self.client_factory = httpx.AsyncClient

    # -- release list -------------------------------------------------------
    async def releases(self, refresh: bool = False) -> list[dict]:
        if self._cache and not refresh and time.time() - self._cache[0] < CACHE_SECONDS:
            return self._cache[1]
        async with self.client_factory(timeout=15, follow_redirects=True) as client:
            response = await client.get(self.releases_url)
            response.raise_for_status()
            data = response.json()
        releases = []
        for item in data.get("releases", []):
            version = str(item.get("version", ""))
            if not VERSION_PATTERN.fullmatch(version) or not COMMIT_PATTERN.fullmatch(str(item.get("commit", ""))):
                continue  # the updater can only install releases with a recorded commit
            notes = [str(n)[:500] for n in item.get("notes", []) if str(n).strip()][:40]
            releases.append({"version": version, "date": str(item.get("date", ""))[:10], "notes": notes})
        releases.sort(key=lambda r: version_key(r["version"]), reverse=True)
        self._cache = (time.time(), releases)
        return releases

    # -- updater state ------------------------------------------------------
    def updater(self) -> dict | None:
        try:
            return json.loads((self.dir / "updater.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def status(self) -> dict:
        try:
            status = json.loads((self.dir / "status.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            status = {}
        if (self.dir / "request.json").exists() and status.get("phase") not in ACTIVE_PHASES:
            try:
                pending = json.loads((self.dir / "request.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pending = {}
            status = {"phase": "queued", "version": pending.get("version"), "id": pending.get("id"),
                      "message": "Waiting for the updater service to start."}
        return status

    def busy(self) -> bool:
        status = self.status()
        return status.get("phase") in ACTIVE_PHASES and time.time() - float(status.get("updated", time.time())) < 1800

    async def validate(self, version: str) -> None:
        if not VERSION_PATTERN.fullmatch(version):
            raise ValueError("Choose a version from the list.")
        if self.updater() is None:
            raise ValueError("The updater is not installed on this server. Run the setup command shown in Settings → Updates.")
        if self.busy():
            raise ValueError("An update is already in progress.")
        if version not in {r["version"] for r in await self.releases(refresh=True)}:
            raise ValueError(f"Version {version} is not a published release.")
        if version == __version__:
            raise ValueError(f"Hilait {version} is already running.")

    async def request(self, version: str) -> dict:
        await self.validate(version)
        request_id = secrets.token_hex(16)
        self.save_handoff()
        self.dir.mkdir(mode=0o700, exist_ok=True)
        # Written in place (no rename): the path unit fires when the file is closed after writing.
        path = self.dir / "request.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"id": request_id, "version": version, "requested": time.time()}, handle)
        self.audit.write("hilait_update_requested", {}, {"from": __version__, "to": version, "request": request_id})
        return {"id": request_id, "version": version, "phase": "queued"}

    # -- session hand-off across the restart ---------------------------------
    def save_handoff(self) -> None:
        with self.auth.lock:
            sessions = {k: v for k, v in self.auth.sessions.items() if v > time.time()}
        self.store.write_secure(HANDOFF_FILE, {"created": time.time(), "sessions": sessions})

    def load_handoff(self) -> int:
        """Restore admin sessions saved just before an update restart. One use, 15 minutes."""
        path = Path(self.store.root) / HANDOFF_FILE
        if not path.exists():
            return 0
        try:
            data = self.store.read_secure(HANDOFF_FILE, {})
        except Exception:
            data = {}
        path.unlink(missing_ok=True)
        if not isinstance(data, dict) or time.time() - float(data.get("created", 0)) > HANDOFF_SECONDS:
            return 0
        now = time.time()
        restored = {k: float(v) for k, v in dict(data.get("sessions", {})).items()
                    if re.fullmatch(r"[0-9a-f]{64}", str(k)) and float(v) > now}
        with self.auth.lock:
            self.auth.sessions.update(restored)
        return len(restored)


# -- one-time privileged setup (hilait updater install) ------------------------
UNIT_DIR = Path("/etc/systemd/system")
LIB_DIR = Path("/usr/local/lib/hilait-updater")
CONFIG_PATH = Path("/etc/hilait/updater.json")


def _service_property(unit: str, name: str) -> str:
    result = subprocess.run(["systemctl", "show", unit, "-p", name, "--value"], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def detect(unit: str) -> dict:
    """Read user, data directory and port from the running Hilait unit."""
    user = _service_property(unit, "User") or "hilait"
    environment = _service_property(unit, "Environment")
    match = re.search(r"HILAIT_DATA_DIR=(\S+)", environment)
    data_dir = match.group(1) if match else "/var/lib/hilait"
    exec_start = _service_property(unit, "ExecStart")
    port = re.search(r"--port[ =](\d+)", exec_start)
    scheme = "https" if "--lan" in exec_start else "http"
    return {"user": user, "data_dir": data_dir,
            "health_url": f"{scheme}://127.0.0.1:{port.group(1) if port else 8765}/health"}


def install_updater(*, unit: str, python: str, user: str, data_dir: str, health_url: str,
                    unit_dir: Path = UNIT_DIR, lib_dir: Path = LIB_DIR, config_path: Path = CONFIG_PATH,
                    systemctl: bool = True) -> list[str]:
    import pwd  # POSIX only; the updater is a systemd feature
    account = pwd.getpwnam(user)
    lib_dir.mkdir(parents=True, exist_ok=True)
    script = lib_dir / "updater.py"
    shutil.copyfile(Path(__file__).with_name("updater.py"), script)
    script.chmod(0o644)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = {"python": python, "unit": unit, "repo": REPO, "data_dir": data_dir, "health_url": health_url,
              "owner_uid": account.pw_uid, "owner_gid": account.pw_gid}
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    config_path.chmod(0o644)
    update_dir = Path(data_dir) / "update"
    (unit_dir / "hilait-update.path").write_text(
        "[Unit]\nDescription=Watch for Hilait update requests\n\n"
        f"[Path]\nPathChanged={update_dir}/request.json\nUnit=hilait-update.service\n\n"
        "[Install]\nWantedBy=multi-user.target\n", encoding="utf-8")
    (unit_dir / "hilait-update.service").write_text(
        "[Unit]\nDescription=Apply a requested Hilait update\n\n"
        f"[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I {script} --config {config_path}\n"
        "TimeoutStartSec=1800\nPrivateTmp=yes\nNoNewPrivileges=yes\n", encoding="utf-8")
    update_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(update_dir, account.pw_uid, account.pw_gid)
    marker = update_dir / "updater.json"
    marker.write_text(json.dumps({"updater_version": UPDATER_VERSION, "unit": unit, "installed": time.time()}),
                      encoding="utf-8")
    os.chown(marker, account.pw_uid, account.pw_gid)
    marker.chmod(0o600)
    written = [str(script), str(config_path), str(unit_dir / "hilait-update.path"), str(unit_dir / "hilait-update.service")]
    if systemctl:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "hilait-update.path"], check=True)
    return written


def uninstall_updater(data_dir: str, unit_dir: Path = UNIT_DIR, lib_dir: Path = LIB_DIR,
                      config_path: Path = CONFIG_PATH, systemctl: bool = True) -> None:
    if systemctl:
        subprocess.run(["systemctl", "disable", "--now", "hilait-update.path"], check=False)
    for path in (unit_dir / "hilait-update.path", unit_dir / "hilait-update.service", config_path,
                 Path(data_dir) / "update" / "updater.json"):
        path.unlink(missing_ok=True)
    shutil.rmtree(lib_dir, ignore_errors=True)
    if systemctl:
        subprocess.run(["systemctl", "daemon-reload"], check=False)
