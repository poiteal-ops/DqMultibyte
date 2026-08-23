"""Oracle configuration and connection helpers."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

import oracledb
from dotenv import load_dotenv

class ConfigError(Exception):
    """Raised when required Oracle connection configuration is invalid."""


@dataclass(frozen=True)
class OracleConfig:
    """Oracle connection credentials loaded without logging secret values."""

    username: str
    password: str = field(repr=False)
    dsn: str


def load_config(env: Optional[Mapping[str, str]] = None) -> OracleConfig:
    """Load Oracle connection settings from ``ORACLE_*`` environment variables."""
    load_dotenv(Path("config/.env"))
    source = env if env is not None else os.environ
    required = tuple("ORACLE_" + name for name in ("USERNAME", "PASSWORD", "DSN"))
    missing = [name for name in required if not source.get(name)]
    if missing:
        raise ConfigError("Missing required environment variable(s): " + ", ".join(missing))
    username, password, dsn = required
    return OracleConfig(
        username=source[username],
        password=source[password],
        dsn=source[dsn],
    )


def connect(config: OracleConfig, timeout_seconds: int = 30) -> oracledb.Connection:
    """Open an Oracle thin-mode connection with a bounded call timeout."""
    try:
        connection = oracledb.connect(
            user=config.username,
            password=config.password,
            dsn=config.dsn,
        )
    except oracledb.Error as exc:
        (error,) = exc.args
        if getattr(error, "code", None) == 1017:
            raise ConfigError("Invalid Oracle username or password (ORA-01017).") from exc
        raise
    connection.call_timeout = timeout_seconds * 1000
    return connection
