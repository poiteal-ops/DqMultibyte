"""Generic filename/timestamp helpers shared by report and fix-script output."""
from __future__ import annotations

import os
import re
import stat
import hashlib
import json
import uuid
from contextlib import contextmanager
from pathlib import Path

TIMESTAMP_FORMAT = "%Y-%m-%d-%H%M%S"

# Every generated artifact lives under one root. The directories are committed
# (via .gitkeep); everything written into them is gitignored.
OUTPUT_ROOT = Path("output")
LOG_DIR = OUTPUT_ROOT / "logs"
REPORTS_DIR = OUTPUT_ROOT / "reports"

# Scan reports and fix scripts can carry real column data (e.g. the mojibake
# preview) or schema/table detail, so output is restricted to the owning
# user rather than left at whatever the process umask allows.
_OWNER_ONLY_DIR_MODE = 0o700
_OWNER_ONLY_FILE_MODE = 0o600


def safe_filename_component(value: str) -> str:
    return (re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "unnamed")[:48]


def secure_mkdir(path: Path) -> None:
    """Create private directories, preserving existing permissions.

    Refuse linked/reparse components. Windows confidentiality still requires
    an operator-owned root with appropriate NTFS/share ACLs.
    """
    with _directory_handle(path):
        pass


def secure_chmod_file(path: Path) -> None:
    """Compatibility helper: validate the handle before changing POSIX mode."""
    if os.name == "posix":
        with _directory_handle(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                _validate_file(fd, require_private=False)
                os.fchmod(fd, _OWNER_ONLY_FILE_MODE)
            finally:
                os.close(fd)


def artifact_suffix(owner: str, name: str) -> str:
    """Exact identity survives lossy filename normalization; UUID separates runs."""
    identity = json.dumps([owner, name], ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(identity).hexdigest()[:16] + "_" + uuid.uuid4().hex


def _validate_file(fd: int, *, require_private: bool = True) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise OSError("Output must be a regular file with exactly one link")
    if os.name == "posix" and (info.st_uid != os.geteuid() or (require_private and info.st_mode & 0o077)):
        raise PermissionError("Output file must be private and owned by the current user")


def _windows_handle(path, *, directory=False, append=False):
    """Open the entry itself, with delete sharing denied, then check its type."""
    import ctypes
    from ctypes import wintypes

    class FileInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
            ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
            ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    get_info = kernel.GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInfo)]
    get_info.restype = wintypes.BOOL
    access = 0x80 if directory else (0x4 | 0x80 if append else 0x40000000 | 0x80)
    # Directories may be shared for creation; files permit readers only. This
    # deliberately fails concurrent daily-log opens instead of sharing writers.
    share = 3 if directory else 1
    disposition = 3 if directory else 4 if append else 1
    flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE_POINT / BACKUP_SEMANTICS
    handle = create(str(path), access, share, None, disposition, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        if error in (80, 183):
            raise FileExistsError("Output path already exists")
        if error in (5, 32):
            raise PermissionError("Output path is inaccessible or already open for writing")
        raise ctypes.WinError(error)
    info = FileInfo()
    if not get_info(handle, ctypes.byref(info)):
        error = ctypes.get_last_error()
        close(handle)
        raise ctypes.WinError(error)
    if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory or (not directory and info.links != 1):
        close(handle)
        raise OSError("Linked or nonregular output entry is not allowed")
    return handle, close


@contextmanager
def _directory_handle(path: Path):
    """Anchor traversal with POSIX dirfds or Windows non-delete-sharing handles."""
    absolute = Path(os.path.abspath(path))
    if os.name == "nt":
        held = []
        current = Path(absolute.anchor)
        try:
            handle, close = _windows_handle(current, directory=True)
            held.append((handle, close))
            for part in absolute.parts[1:]:
                current /= part
                try:
                    current.mkdir()
                except FileExistsError:
                    pass
                handle, close = _windows_handle(current, directory=True)
                held.append((handle, close))
            yield None
        finally:
            for handle, close in reversed(held):
                close(handle)
    else:
        fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in absolute.parts[1:]:
                try:
                    os.mkdir(part, _OWNER_ONLY_DIR_MODE, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                # Sticky system temp roots are allowed, but the final output
                # directory must be owned by this user and not shared writable.
                if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                    raise PermissionError("Output ancestor is writable by other users")
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise PermissionError("Output directory must be owned and not shared writable")
            yield fd
        finally:
            os.close(fd)


def open_private_text(path: Path, *, append: bool = False):
    """Create an artifact exclusively, or safely append to a private daily log.

    No writes or path-based permission changes occur before handle validation.
    The caller owns the returned stream and must close it.
    """
    with _directory_handle(path.parent) as parent:
        if os.name == "nt":
            import msvcrt
            handle, close = _windows_handle(Path(os.path.abspath(path)), append=append)
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | (os.O_APPEND if append else 0))
            except BaseException:
                close(handle)
                raise
        else:
            flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL | (os.O_APPEND if append else 0)
            try:
                fd = os.open(path.name, flags, _OWNER_ONLY_FILE_MODE, dir_fd=parent)
            except FileExistsError:
                if not append:
                    raise
                fd = os.open(path.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            _validate_file(fd)
            return os.fdopen(fd, "a" if append else "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
