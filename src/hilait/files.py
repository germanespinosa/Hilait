"""Bounded, audited SFTP operations and collision-safe transfers."""

from __future__ import annotations

import asyncio
import base64
import os
import posixpath
import re
import stat
import uuid
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Callable

from .sessions import Session, SessionManager
from .storage import Audit

MAX_CHUNK = 262144


def remote_path(value: str, windows: bool = False) -> str:
    if "\x00" in value:
        raise ValueError("NUL is not allowed in a path.")
    if windows:
        value = value.replace("\\", "/")
        if re.match(r"^[A-Za-z]:", value):
            value = "/" + value
        if re.match(r"^/[A-Za-z]:", value):
            value = "/" + value[1].upper() + value[2:]
        for component in value.split("/"):
            if component and not re.fullmatch(r"[A-Za-z]:", component):
                if component.rstrip(" .") != component or ":" in component or component.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
                    raise ValueError("Invalid Windows path component.")
    if not value.startswith("/") or ".." in value.split("/"):
        raise ValueError("Use an absolute remote path without parent traversal.")
    return posixpath.normpath(value)


def local_path(root: str, value: str, *, exists: bool = False) -> Path:
    folder = Path(root).expanduser().resolve(strict=True)
    target = Path(value).expanduser()
    if not target.is_absolute():
        target = folder / target
    resolved = target.resolve(strict=exists)
    if resolved != folder and folder not in resolved.parents:
        raise PermissionError("Local transfers must stay inside the approved folder.")
    return resolved


def info(attrs, name: str) -> dict:
    mode = attrs.st_mode or 0
    return {"name": name, "size": attrs.st_size or 0, "mode": oct(stat.S_IMODE(mode)),
            "directory": stat.S_ISDIR(mode), "symlink": stat.S_ISLNK(mode),
            "modified": attrs.st_mtime}


class FileService:
    def __init__(self, sessions: SessionManager, audit: Audit) -> None:
        self.sessions, self.audit = sessions, audit

    async def operate(self, session_id: str, action: str, path: str, *, guard: Callable[[], None] | None = None, **args) -> dict:
        session = self.sessions.get(session_id)
        path = remote_path(path, session.profile.get("platform") == "windows")
        if action in {"chmod", "symlink"} and session.profile.get("platform") == "windows":
            raise ValueError(f"{action} is unavailable on Windows SSH connections.")
        self.audit.write("file_request", session.context(), {"action": action, "path": path,
                          **{k: v for k, v in args.items() if k != "base64"},
                          "base64": args.get("base64") if action == "write" else None})
        async with session.file_lock:
            try:
                if guard:
                    guard()
                result = await asyncio.to_thread(self._operate_sync, session, action, path, args)
                self.audit.write("file_result", session.context(), {"action": action, "path": path, "result": result})
                return result
            except Exception as exc:
                self.audit.write("file_error", session.context(), {"action": action, "path": path, "error": str(exc)})
                raise

    @staticmethod
    def _operate_sync(session: Session, action: str, path: str, args: dict) -> dict:
        sftp = session.client.open_sftp()
        try:
            if action == "list":
                offset = max(0, int(args.get("offset", 0)))
                entries = sorted(sftp.listdir_attr(path), key=lambda entry: entry.filename.casefold())
                return {"entries": [info(item, item.filename) for item in entries[offset:offset + 200]],
                        "nextOffset": offset + 200 if offset + 200 < len(entries) else None}
            if action == "stat":
                return info(sftp.lstat(path), posixpath.basename(path))
            if action == "read":
                count = int(args.get("count", 65536))
                if not 0 <= count <= MAX_CHUNK:
                    raise ValueError("Read count must be at most 256 KiB.")
                with sftp.open(path, "rb") as stream:
                    stream.seek(max(0, int(args.get("offset", 0))))
                    data = stream.read(count)
                return {"base64": base64.b64encode(data).decode(), "count": len(data)}
            if action == "write":
                data = base64.b64decode(args.get("base64", ""), validate=True)
                if len(data) > MAX_CHUNK:
                    raise ValueError("Write chunk must be at most 256 KiB.")
                overwrite = bool(args.get("overwrite", False))
                existing = _exists(sftp, path)
                if overwrite and not existing or not overwrite and existing:
                    raise FileExistsError("Overwrite requires an existing file; new writes require an unused path.")
                with sftp.open(path, "r+b" if overwrite else "wb") as stream:
                    if overwrite:
                        stream.seek(max(0, int(args.get("offset", 0))))
                    stream.write(data)
                return {"written": len(data)}
            if action == "mkdir":
                if _exists(sftp, path):
                    raise FileExistsError(path)
                sftp.mkdir(path)
                return {"created": path}
            if action == "rename":
                target = remote_path(args["destination"], session.profile.get("platform") == "windows")
                if _exists(sftp, target):
                    raise FileExistsError(target)
                sftp.rename(path, target)
                return {"destination": target}
            if action == "delete":
                _delete(sftp, path, bool(args.get("recursive", False)))
                return {"deleted": path}
            if action == "chmod":
                mode = int(str(args["mode"]), 8)
                if not 0 <= mode <= 0o7777:
                    raise ValueError("Invalid POSIX mode.")
                sftp.chmod(path, mode)
                return {"mode": oct(mode)}
            if action == "symlink":
                if _exists(sftp, path):
                    raise FileExistsError(path)
                sftp.symlink(args["destination"], path)
                return {"created": path}
            raise ValueError("Unknown file action.")
        finally:
            sftp.close()

    async def copy(self, source_id: str, direction: str, path: str, destination: str,
                   *, destination_id: str | None = None, local_folder: str | None = None,
                   guard: Callable[[], None] | None = None) -> dict:
        source = self.sessions.get(source_id)
        target = self.sessions.get(destination_id or source_id) if direction == "remote" else None
        if direction in {"upload", "download"} and not local_folder:
            raise PermissionError("A human-approved local transfer folder is required.")
        if direction not in {"remote", "upload", "download"}:
            raise ValueError("Unknown copy direction.")
        locks = {source.id: source.file_lock}
        if target:
            locks[target.id] = target.file_lock
        async with AsyncExitStack() as stack:
            for key in sorted(locks):
                await stack.enter_async_context(locks[key])
            if guard:
                guard()
            result = await asyncio.to_thread(self._copy_sync, source, target, direction, path, destination, local_folder)
        self.audit.write("copy_completed", source.context(), {"direction": direction, "path": path,
                         "destination": destination, "destinationSession": target.id if target else None, **result})
        return result

    @staticmethod
    def _copy_sync(source: Session, target: Session | None, direction: str, path: str,
                   destination: str, local_folder: str | None) -> dict:
        if direction == "upload":
            local = local_path(local_folder, path, exists=True)
            remote = remote_path(destination, source.profile.get("platform") == "windows")
            with source.client.open_sftp() as sftp:
                _upload(sftp, local, remote)
            return {"source": str(local), "destination": remote}
        if direction == "download":
            remote = remote_path(path, source.profile.get("platform") == "windows")
            local = local_path(local_folder, destination)
            with source.client.open_sftp() as sftp:
                _download(sftp, remote, local)
            return {"source": remote, "destination": str(local)}
        remote = remote_path(path, source.profile.get("platform") == "windows")
        dest = remote_path(destination, target.profile.get("platform") == "windows")
        with source.client.open_sftp() as from_sftp, target.client.open_sftp() as to_sftp:
            _copy_remote(from_sftp, remote, to_sftp, dest)
        return {"source": remote, "destination": dest}


def _exists(sftp, path: str) -> bool:
    try:
        sftp.lstat(path)
        return True
    except OSError as exc:
        if getattr(exc, "errno", None) in {2, None} and "No such" in str(exc):
            return False
        if getattr(exc, "errno", None) == 2:
            return False
        raise


def _delete(sftp, path: str, recursive: bool, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("Directory depth exceeds 64.")
    mode = sftp.lstat(path).st_mode or 0
    if stat.S_ISDIR(mode):
        children = sftp.listdir(path)
        if children and not recursive:
            raise ValueError("Directory is not empty; request recursive deletion.")
        for name in children:
            _delete(sftp, posixpath.join(path, name), recursive, depth + 1)
        sftp.rmdir(path)
    else:
        sftp.remove(path)


def _ensure_copyable(sftp, path: str, destination_exists: bool) -> int:
    attrs = sftp.lstat(path)
    mode = attrs.st_mode or 0
    if stat.S_ISLNK(mode):
        raise ValueError("Copying symbolic links is refused.")
    if destination_exists:
        raise FileExistsError("Destination exists; copies never overwrite.")
    return mode


def _copy_remote(source, path: str, target, dest: str, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("Directory depth exceeds 64.")
    mode = _ensure_copyable(source, path, _exists(target, dest))
    if stat.S_ISDIR(mode):
        target.mkdir(dest)
        for name in source.listdir(path):
            _copy_remote(source, posixpath.join(path, name), target, posixpath.join(dest, name), depth + 1)
    else:
        temp = dest + "." + uuid.uuid4().hex + ".part"
        try:
            with source.open(path, "rb") as reader, target.open(temp, "wb") as writer:
                while block := reader.read(MAX_CHUNK):
                    writer.write(block)
            target.rename(temp, dest)
        finally:
            if _exists(target, temp):
                target.remove(temp)


def _upload(sftp, local: Path, remote: str, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("Directory depth exceeds 64.")
    if local.is_symlink() or _exists(sftp, remote):
        raise ValueError("Links and destination collisions are refused.")
    if local.is_dir():
        sftp.mkdir(remote)
        for child in local.iterdir():
            _upload(sftp, child, posixpath.join(remote, child.name), depth + 1)
    else:
        temp = remote + "." + uuid.uuid4().hex + ".part"
        try:
            with local.open("rb") as reader, sftp.open(temp, "wb") as writer:
                while block := reader.read(MAX_CHUNK):
                    writer.write(block)
            sftp.rename(temp, remote)
        finally:
            if _exists(sftp, temp):
                sftp.remove(temp)


def _download(sftp, remote: str, local: Path, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("Directory depth exceeds 64.")
    mode = _ensure_copyable(sftp, remote, local.exists())
    if stat.S_ISDIR(mode):
        local.mkdir()
        for name in sftp.listdir(remote):
            _download(sftp, posixpath.join(remote, name), local / name, depth + 1)
    else:
        temp = local.with_name(local.name + "." + uuid.uuid4().hex + ".part")
        try:
            with sftp.open(remote, "rb") as reader, temp.open("xb") as writer:
                while block := reader.read(MAX_CHUNK):
                    writer.write(block)
            temp.rename(local)
        finally:
            temp.unlink(missing_ok=True)
