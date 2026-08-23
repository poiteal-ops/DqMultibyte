"""Generic filename/timestamp helpers shared by report and fix-script output."""
from __future__ import annotations

import re
from pathlib import Path

TIMESTAMP_FORMAT = "%Y-%m-%d-%H%M%S"

# Every generated artifact lives under one root. The directories are committed
# (via .gitkeep); everything written into them is gitignored.
OUTPUT_ROOT = Path("output")
LOG_DIR = OUTPUT_ROOT / "logs"
REPORTS_DIR = OUTPUT_ROOT / "reports"


def safe_filename_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "unnamed"
