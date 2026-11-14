"""Hilait-managed transfer folders for agent server-side file transfers.

Agents approved for LocalTransfers copy files between a remote machine and a
folder on the Hilait server. Hilait chooses that folder: one per agent,
machine, and access tier, under a single transfer root. The administrator
reaches the files through the browser, so nobody types server paths.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import AsyncIterator

from .files import local_path
from .storage import Audit, Store, _private_directory

SETTINGS_FILE = "transfer-settings.json"
LIST_LIMIT = 1000


def _slug(value: str, fallback: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:40].strip("-")
    return slug or fallback


def _info(path: Path, root: Path) -> dict:
    details = path.lstat()
    return {"name": path.name, "path": path.relative_to(root).as_posix(),
            "directory": stat.S_ISDIR(details.st_mode), "symlink": stat.S_ISLNK(details.st_mode),
            "size": details.st_size if stat.S_ISREG(details.st_mode) else 0,
            "modified": details.st_mtime}


class TransferArea:
    def __init__(self, store: Store, audit: Audit) -> None:
        self.store, self.audit = store, audit

    def default_root(self) -> Path:
        configured = os.environ.get("HILAIT_TRANSFER_DIR")
        if configured:
            if not Path(configured).is_absolute():
                raise ValueError("HILAIT_TRANSFER_DIR must be an absolute path.")
            return Path(configured)
        data = self.store.root
        return data.with_name(data.name + "-transfers")

    def root(self) -> Path:
        saved = self.store.read(SETTINGS_FILE, {}).get("directory")
        return Path(saved) if saved else self.default_root()

    def settings(self) -> dict:
        root = self.root()
        return {"directory": str(root), "default": str(self.default_root()),
                "exists": root.is_dir() and not root.is_symlink()}

    def _validate_root(self, value: str) -> Path:
        if not isinstance(value, str) or not value.strip() or not Path(value.strip()).is_absolute():
            raise ValueError("Use an absolute folder on the Hilait server.")
        candidate = Path(value.strip())
        if candidate.is_symlink():
            raise PermissionError("The transfer folder cannot be a symlink.")
        path = candidate.resolve()
        data = self.store.root.resolve()
        if path == data or path in data.parents or data in path.parents:
            raise ValueError("Choose a transfer folder outside the Hilait data directory.")
        activity = self.audit.path.resolve()
        if path == activity or activity in path.parents or path in activity.parents:
            raise ValueError("Choose a transfer folder separate from the activity records folder.")
        return path

    def _ensure_root(self, path: Path) -> Path:
        try:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise PermissionError(f"Hilait cannot create its transfer folder {path}: {exc.strerror or exc}. "
                                  "Choose a writable folder in Settings → File transfers.") from exc
        _private_directory(path)
        return path

    def update_settings(self, directory: str | None) -> dict:
        if directory in (None, ""):
            path = self._validate_root(str(self.default_root()))
            self._ensure_root(path)
            self.store.write(SETTINGS_FILE, {})
        else:
            path = self._ensure_root(self._validate_root(directory))
            self.store.write(SETTINGS_FILE, {"directory": str(path)})
        self.audit.write("transfer_settings_changed", {}, {"directory": str(path)})
        return self.settings()

    def folder_for(self, agent: dict, profile: dict, privilege: str) -> str:
        """Create (if needed) and return the folder for one agent, machine, and tier."""
        root = self._ensure_root(self._validate_root(str(self.root())))
        path = root
        for part in (f"{_slug(agent['name'], 'agent')}-{agent['id'][:8]}",
                     f"{_slug(profile['name'], 'machine')}-{profile['id'][:8]}",
                     privilege):
            path = path / part
            path.mkdir(exist_ok=True, mode=0o700)
            _private_directory(path)
        return str(path)

    # Administrator access to the transfer area through the browser.

    def _existing_root(self) -> Path:
        root = self.root()
        if not root.is_dir():
            return self._ensure_root(self._validate_root(str(root)))
        _private_directory(root)
        return root.resolve()

    @staticmethod
    def _relative(relative: str) -> str:
        # No roots, drives, UNC paths, or "..". On Windows "\\" and ":" are separator and
        # drive syntax, so they are refused there; on POSIX they are ordinary name characters.
        reserved = "\x00\\:" if os.name == "nt" else "\x00"
        if (not isinstance(relative, str) or any(char in relative for char in reserved)
                or relative.startswith("/") or Path(relative).anchor or ".." in Path(relative).parts):
            raise ValueError("Use a path relative to the transfer folder.")
        return relative

    def _target(self, relative: str, *, exists: bool) -> tuple[Path, Path]:
        relative = self._relative(relative)
        root = self._existing_root()
        try:
            return root, local_path(str(root), relative or ".", exists=exists)
        except FileNotFoundError as exc:
            raise KeyError("Transfer item not found.") from exc

    def _entry(self, relative: str) -> tuple[Path, Path]:
        """Resolve the parent but not the final component, so links are handled as links."""
        if not isinstance(relative, str) or not relative.strip("/"):
            raise ValueError("Choose an item inside the transfer folder.")
        parts = Path(self._relative(relative)).parts
        root, parent = self._target(Path(relative).parent.as_posix(), exists=True)
        if not parent.is_dir():
            raise ValueError("Choose an existing transfer folder.")
        return root, parent / parts[-1]

    def list(self, relative: str = "") -> dict:
        root, folder = self._target(relative, exists=True)
        if not folder.is_dir():
            raise ValueError("Not a folder.")
        entries = sorted(folder.iterdir(), key=lambda item: (not item.is_dir(), item.name.casefold()))
        return {"root": str(root), "path": folder.relative_to(root).as_posix() if folder != root else "",
                "entries": [_info(entry, root) for entry in entries[:LIST_LIMIT]],
                "truncated": len(entries) > LIST_LIMIT}

    def file(self, relative: str) -> Path:
        _, path = self._target(relative, exists=True)
        if not path.is_file():
            raise ValueError("Choose a file to download.")
        self.audit.write("transfer_file_downloaded", {}, {"path": relative})
        return path

    async def upload(self, relative: str, chunks: AsyncIterator[bytes]) -> dict:
        root, path = self._entry(relative)
        if path.exists() or path.is_symlink():
            raise FileExistsError("A file with that name already exists.")
        fd, temporary = tempfile.mkstemp(prefix=".upload-", dir=path.parent)
        size = 0
        try:
            with os.fdopen(fd, "wb") as stream:
                async for chunk in chunks:
                    stream.write(chunk)
                    size += len(chunk)
            os.link(temporary, path)
        finally:
            os.unlink(temporary)
        if os.name != "nt":
            path.chmod(0o600)
        self.audit.write("transfer_file_uploaded", {}, {"path": relative, "size": size})
        return {"path": path.relative_to(root).as_posix(), "size": size}

    def delete(self, relative: str) -> dict:
        root, path = self._entry(relative)
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            raise KeyError("Transfer item not found.")
        self.audit.write("transfer_item_deleted", {}, {"path": relative})
        return {"deleted": relative}

