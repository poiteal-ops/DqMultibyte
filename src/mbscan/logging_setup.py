"""Continuous daily operational logging under output/logs/.

Only object/column metadata and bare Oracle error codes belong in these
logs -- never credentials or raw Oracle error text, which can embed host,
port, service name, and schema detail. One file per day aggregates every
run, so anything leaked here persists across the whole day's activity.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mbscan.files import LOG_DIR

LOG_FILENAME_FORMAT = "mbscan-%Y-%m-%d.log"
LOG_FORMAT = "%(asctime)s %(levelname)-5s [%(run_id)s] %(component)-24s %(message)s"

_LINE_PARAGRAPH_SEPARATORS = "  "


def _escape_log_controls(value: str) -> str:
    """Keep record content on one physical line and neutralize bidi controls."""
    escaped = []
    for char in value:
        code = ord(char)
        if char == "\r":
            escaped.append(r"\r")
        elif char == "\n":
            escaped.append(r"\n")
        elif char in _LINE_PARAGRAPH_SEPARATORS or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069:
            escaped.append("\\u{0:04x}".format(code))
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            escaped.append("\\x{0:02x}".format(code))
        else:
            escaped.append(char)
    return "".join(escaped)


class _SafeLogFormatter(logging.Formatter):
    """Format records without allowing user-controlled control characters."""

    def format(self, record: logging.LogRecord) -> str:
        return _escape_log_controls(super().format(record))


def _component_name(logger_name: str) -> str:
    """Render a logger name as the short component label for the log line.

    ``mbscan.scan`` becomes ``scan``. Records logged on the ``mbscan``
    parent itself -- the run banner below -- keep the bare name, which
    distinguishes run-level from module-level lines.
    """
    name = logger_name
    prefix = "mbscan."
    if name.startswith(prefix):
        name = name[len(prefix):]
    return name


class _RunContextFilter(logging.Filter):
    """Stamp ``run_id`` and ``component`` onto every record the handler writes.

    Neither is a real ``LogRecord`` attribute, so ``LOG_FORMAT`` would raise
    without this. It is attached to the *handler*, not the logger: filters on
    a logger do not apply to records propagating up from child loggers, but
    handler filters see everything the handler writes -- and every component
    name in this design arrives from a child logger.
    """

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self.run_id = run_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = self.run_id
        record.component = _component_name(record.name)
        return True


def configure_logging(
    owner: str,
    object_name: str,
    log_dir: Optional[Path] = None,
    timestamp: Optional[datetime] = None,
) -> Path:
    """Attach a file handler for today's log and return its path.

    All runs on a given day append to one file. Any handler(s) left over
    from a previous call in this process (e.g. a re-run in the same
    interpreter) are closed and removed first, so exactly one handler stays
    attached and each line is written exactly once.
    """
    logger = logging.getLogger("mbscan")
    for old_handler in list(logger.handlers):
        old_handler.close()
        logger.removeHandler(old_handler)

    if log_dir is None:
        log_dir = LOG_DIR

    moment = timestamp or datetime.now(timezone.utc)
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / moment.strftime(LOG_FILENAME_FORMAT)

    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    formatter = _SafeLogFormatter(LOG_FORMAT)
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    handler.addFilter(_RunContextFilter(uuid.uuid4().hex[:4]))
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.info("Run started")
    return path
