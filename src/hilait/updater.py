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

UPDATER_VERSION = 2
VERSION_PATTERN = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REQUEST_LIMIT = 4096
DEFAULT_CONFIG = Path("/etc/hilait/updater.json")
UNIT_DIR = Path("/etc/systemd/system")
DROPIN_NAME = "hilait-transfers.conf"


def transfer_directory(config: dict) -> Path:
    """The service's default transfer folder, from the root-owned config (the unit's HILAIT_TRANSFER_DIR).

    Never read from the service's data directory: the service must not be able to choose a path that
    root then creates, hands to the service account, or opens up with ReadWritePaths=.
    """
    chosen = str(config.get("transfer_dir") or f"{config['data_dir']}-transfers")
    path = Path(chosen)
    if not path.is_absolute() or ".." in path.parts or "\n" in chosen:
        raise ValueError(f"Unusable transfer folder {chosen!r}.")
    return path


def ensure_transfer_access(config: dict, run=subprocess.run, unit_dir: Path | None = None) -> bool:
    """Let the sandboxed service write its transfer folder (ProtectSystem=strict makes the rest read-only).

    Creates the folder for the service account if missing and adds a ReadWritePaths= drop-in.
    Returns True when the drop-in changed, so the service must be restarted to see it.
    """
    path = transfer_directory(config)
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
        if config.get("owner_uid") is not None and os.geteuid() == 0:
            os.chown(path, config["owner_uid"], config.get("owner_gid", config["owner_uid"]))
    dropin = Path(unit_dir or config.get("unit_dir") or UNIT_DIR) / f"{config['unit']}.d" / DROPIN_NAME
    content = ("# Written by the Hilait updater: lets the service write its agent transfer folder.\n"
               f"[Service]\nReadWritePaths={path}\n")
    try:
        if dropin.read_text(encoding="utf-8") == content:
            return False
    except OSError:
        pass
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    dropin.write_text(content, encoding="utf-8")
    dropin.chmod(0o644)
    run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=60)
    return True


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

    def releases(self) -> dict[str, str]:
        """Published versions and the exact commit each one was released from."""
        url = f"https://raw.githubusercontent.com/{self.config['repo']}/main/releases.json"
        data = json.loads(self.fetch(url).decode("utf-8"))
        return {str(r["version"]): str(r["commit"]) for r in data.get("releases", [])
                if VERSION_PATTERN.fullmatch(str(r.get("version", ""))) and COMMIT_PATTERN.fullmatch(str(r.get("commit", "")))}

    def install(self, version: str, commit: str) -> tuple[bool, str]:
        if not COMMIT_PATTERN.fullmatch(commit):
            return False, f"No release commit recorded for {version}."
        url = f"https://github.com/{self.config['repo']}/archive/{commit}.zip"
        result = self.run([self.config["python"], "-m", "pip", "install", "--disable-pip-version-check",
                           "--no-input", "--upgrade", url], capture_output=True, text=True, timeout=1200)
        log = (result.stdout + result.stderr)[-4000:]
        return result.returncode == 0 and self.installed_version() == version, log

    def refresh_self(self) -> None:
        """Replace this updater with a newer copy shipped in the just-installed release (bump UPDATER_VERSION)."""
        result = self.run([self.config["python"], "-c", "import hilait.updater as u; print(u.__file__)"],
                          capture_output=True, text=True, timeout=60)
        shipped = Path(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else None
        target = Path(__file__).resolve()
        if not shipped or not shipped.is_file() or shipped.resolve() == target:
            return
        text = shipped.read_text(encoding="utf-8")
        found = re.search(r"^UPDATER_VERSION = (\d+)$", text, re.M)
        if not found or int(found.group(1)) <= UPDATER_VERSION:  # never downgrade when switching to an older release
            return
        temporary = target.with_name(f".updater.{os.getpid()}.tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.chmod(0o644)
        os.replace(temporary, target)

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
            published = self.releases()
            if request["version"] not in published:
                self.write_status(phase="failed", message=f"Version {request['version']} is not a published release.")
                return self.status
            self.write_status(phase="installing", message=f"Installing Hilait {request['version']}.")
            ok, log = self.install(request["version"], published[request["version"]])
            if not ok:
                self.write_status(phase="failed", message="Installation failed; nothing was restarted.", log=log)
                return self.status
            for step in (lambda: ensure_transfer_access(self.config, self.run), self.refresh_self):
                try:
                    step()
                except Exception as exc:  # never block an update on these housekeeping steps
                    log += f"\n[updater] {type(exc).__name__}: {exc}"
            self.write_status(phase="restarting", message="Restarting Hilait.", log=log)
            if self.restart_and_wait(request["version"]):
                self.write_status(phase="done", message=f"Hilait {request['version']} is running.")
                return self.status
            if previous and previous != request["version"]:
                self.write_status(phase="rolling_back", message=f"Hilait {request['version']} did not start; restoring {previous}.")
                restored, rollback_log = self.install(previous, published.get(previous, ""))
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
