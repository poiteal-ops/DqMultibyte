"""JSON scan-manifest loading (``config/scan_targets.json``).

A manifest names an exact set of table + column targets, used instead of
``owner`` / ``object`` / ``all_objects`` when ``json_entry`` is enabled. Only
the file's structure is validated here; table and column names are matched
against the Oracle data dictionary later (see cli.run), never trusted as SQL.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Tuple

from mbscan.oracle.connection import ConfigError

DEFAULT_MANIFEST_PATH = Path("config/scan_targets.json")


@dataclass(frozen=True)
class ManifestTable:
    table: str
    columns: Tuple[str, ...] = ()  # () => scan every text column of the table


@dataclass(frozen=True)
class ScanManifest:
    owner: str
    tables: Tuple[ManifestTable, ...]


def _require_non_empty_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("manifest {0} must be a non-empty string".format(what))
    return value.strip()


def _parse_columns(raw: Any, table: str) -> Tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("manifest 'columns' for table {0!r} must be a list".format(table))
    columns: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        name = _require_non_empty_str(entry, "column name for table {0!r}".format(table))
        key = name.upper()
        if key not in seen:
            seen.add(key)
            columns.append(name)
    return tuple(columns)


def load_scan_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> ScanManifest:
    if not path.exists():
        raise ConfigError("JSON scan manifest not found: {0}".format(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError("Invalid JSON in {0}: {1}".format(path, exc)) from exc
    if not isinstance(data, dict):
        raise ConfigError("manifest {0} must contain a JSON object".format(path))

    owner = _require_non_empty_str(data.get("owner"), "'owner'")

    tables_raw = data.get("tables")
    if not isinstance(tables_raw, list) or not tables_raw:
        raise ConfigError("manifest 'tables' must be a non-empty list")

    tables: list[ManifestTable] = []
    seen: set[str] = set()
    for entry in tables_raw:
        if not isinstance(entry, dict):
            raise ConfigError("each manifest 'tables' entry must be a JSON object")
        name = _require_non_empty_str(entry.get("table"), "'table' name")
        key = name.upper()
        if key in seen:
            raise ConfigError("manifest lists table {0!r} more than once".format(name))
        seen.add(key)
        tables.append(ManifestTable(table=name, columns=_parse_columns(entry.get("columns"), name)))

    return ScanManifest(owner=owner, tables=tuple(tables))
