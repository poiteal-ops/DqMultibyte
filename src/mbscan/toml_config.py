"""TOML configuration loading (``config/config.toml``)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import tomllib

from mbscan.oracle.connection import ConfigError

DEFAULT_CONFIG_PATH = Path("config/config.toml")


def load_toml_config(path: Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Load the TOML config file, or return {} if it doesn't exist."""
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError("Invalid TOML in {0}: {1}".format(path, exc)) from exc
