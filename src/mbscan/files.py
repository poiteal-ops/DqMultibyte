"""Generic filename/timestamp helpers shared by report and fix-script output."""
from __future__ import annotations

import os
import re
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
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "unnamed"


def secure_mkdir(path: Path) -> None:
    """Create ``path`` (and any missing parents) restricted to the owning
    user.

    POSIX: mode 0700, re-applied on every call so a directory left over from
    before this hardening existed (or loosened by an admin) is corrected
    going forward. Windows: ``os.chmod`` does not touch NTFS ACLs, so this
    is a best-effort no-op there -- protecting scan output on Windows relies
    on filesystem/share permissions instead.
    """
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, _OWNER_ONLY_DIR_MODE)


def secure_chmod_file(path: Path) -> None:
    """Restrict ``path`` to the owning user after it has been written.

    Same POSIX-only scope as :func:`secure_mkdir` -- see its docstring.
    """
    if os.name == "posix":
        os.chmod(path, _OWNER_ONLY_FILE_MODE)
