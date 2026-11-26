"""Privileged Hilait updater: installs a requested release and restarts the service.

This file is deliberately standalone (standard library only). ``hilait updater
install`` copies it outside the Hilait package, so switching to any version,
including one that predates this file, never removes the updater itself.

The unprivileged service can only ask for a version number by writing
``<data dir>/update/request.json``. Everything else (the repository, the
download URL, the Python environment, the service name) comes from the root-
owned configuration written at install time.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

UPDATER_VERSION = 1
VERSION_PATTERN = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
REQUEST_LIMIT = 4096
DEFAULT_CONFIG = Path("/etc/hilait/updater.json")


def read_request(path: Path) -> dict:
    """Read the service-written request without following links or trusting its size."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > REQUEST_LIMIT:
            raise ValueError("Update request is not a small regular file.")
        data = json.loads(os.read(fd, REQUEST_LIMIT).decode("utf-8"))
    finally:
        os.close(fd)
    version = str(data.get("version", ""))
    request_id = str(data.get("id", ""))
    if not VERSION_PATTERN.fullmatch(version) or not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise ValueError("Update request has an invalid version or id.")
    return {"version": version, "id": request_id}


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


class Updater:
    def __init__(self, config: dict, run=subprocess.run, fetch=None, sleep=time.sleep) -> None:
        self.config = config
        self.update_dir = Path(config["data_dir"]) / "update"
        self.run = run
        self.fetch = fetch or self._fetch
        self.sleep = sleep
        self.status: dict = {}

    # -- helpers -------------------------------------------------------------
    def _fetch(self, url: str, *, insecure_local: bool = False) -> bytes:
        context = None
        if insecure_local:  # the local health check of a --lan self-signed service
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(url, timeout=20, context=context) as response:
            return response.read(2_000_000)

    def write_status(self, **changes) -> None:
        self.status.update(changes, updated=time.time())
        path = self.update_dir / "status.json"
        temporary = path.with_name(f".status.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(self.status, indent=2), encoding="utf-8")
        owner = self.config.get("owner_uid")
        if owner is not None and os.geteuid() == 0:
            os.chown(temporary, owner, self.config.get("owner_gid", owner))
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def installed_version(self) -> str:
        result = self.run([self.config["python"], "-c", "import hilait; print(hilait.__version__)"],
                          capture_output=True, text=True, timeout=60)
        return result.stdout.strip() if result.returncode == 0 else ""

    def releases(self) -> list[dict]:
        url = f"https://raw.githubusercontent.com/{self.config['repo']}/main/releases.json"
        data = json.loads(self.fetch(url).decode("utf-8"))
        return [r for r in data.get("releases", []) if VERSION_PATTERN.fullmatch(str(r.get("version", "")))]

    def install(self, version: str) -> tuple[bool, str]:
        url = f"https://github.com/{self.config['repo']}/archive/refs/tags/v{version}.zip"
        result = self.run([self.config["python"], "-m", "pip", "install", "--disable-pip-version-check",
                           "--no-input", "--upgrade", url], capture_output=True, text=True, timeout=1200)
        log = (result.stdout + result.stderr)[-4000:]
        return result.returncode == 0 and self.installed_version() == version, log

    def restart_and_wait(self, version: str) -> bool:
        self.run(["systemctl", "restart", self.config["unit"]], capture_output=True, text=True, timeout=180)
        health = self.config["health_url"]
        local = health.startswith("https://127.0.0.1") or health.startswith("https://localhost")
        for _ in range(60):
            self.sleep(2)
            try:
                answer = json.loads(self.fetch(health, insecure_local=local).decode("utf-8"))
            except Exception:
                continue
            if answer.get("status") == "ready" and answer.get("version", version) == version:
                return True
        return False

    # -- main flow ----------------------------------------------------------
    def apply(self) -> dict:
        request_path = self.update_dir / "request.json"
        if not request_path.exists():
            return {}
        try:
            request = read_request(request_path)
        except (OSError, ValueError) as exc:
            request_path.unlink(missing_ok=True)
            self.status = {}
            self.write_status(phase="failed", message=f"Ignored an invalid update request: {exc}")
            return self.status
        previous = self.installed_version()
        self.status = {"id": request["id"], "version": request["version"], "from_version": previous,
                       "started": time.time()}
        try:
            self.write_status(phase="checking", message="Checking the release list.")
            if not any(r["version"] == request["version"] for r in self.releases()):
                self.write_status(phase="failed", message=f"Version {request['version']} is not a published release.")
                return self.status
            self.write_status(phase="installing", message=f"Installing Hilait {request['version']}.")
            ok, log = self.install(request["version"])
            if not ok:
                self.write_status(phase="failed", message="Installation failed; nothing was restarted.", log=log)
                return self.status
            self.write_status(phase="restarting", message="Restarting Hilait.", log=log)
            if self.restart_and_wait(request["version"]):
                self.write_status(phase="done", message=f"Hilait {request['version']} is running.")
                return self.status
            if previous and previous != request["version"]:
                self.write_status(phase="rolling_back", message=f"Hilait {request['version']} did not start; restoring {previous}.")
                restored, rollback_log = self.install(previous)
                back = restored and self.restart_and_wait(previous)
                self.write_status(phase="failed", log=rollback_log,
                                  message=(f"Hilait {request['version']} did not start, so {previous} was restored."
                                           if back else f"Hilait {request['version']} did not start and restoring {previous} also failed. "
                                           "Check `journalctl -u hilait`."))
                return self.status
            self.write_status(phase="failed", message="Hilait did not come back after the restart. Check `journalctl -u hilait`.")
            return self.status
        except Exception as exc:  # report every failure where the browser can see it
            self.write_status(phase="failed", message=f"Update failed: {type(exc).__name__}: {exc}")
            return self.status
        finally:
            request_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply a pending Hilait update request (runs as root).")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text(encoding="utf-8"))
    result = Updater(config).apply()
    print(json.dumps(result))
    return 0 if result.get("phase") in (None, "done") else 1


if __name__ == "__main__":
    sys.exit(main())
