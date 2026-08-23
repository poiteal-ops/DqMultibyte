"""CLI/config-file precedence resolution for the multibyte scan."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from mbscan.files import REPORTS_DIR
from mbscan.oracle.connection import ConfigError
from mbscan.oracle.metadata import parse_object_names
from mbscan.scan import ScanSettings

DEFAULT_TIMEOUT_SECONDS = 30
FIX_GROUPINGS = {"row", "column"}


def _validate_fix_grouping(value: Any) -> str:
    if value not in FIX_GROUPINGS:
        raise ConfigError("fix_grouping must be one of {0}, got {1!r}".format(sorted(FIX_GROUPINGS), value))
    return value


def _validate_positive_int(value: Any, key_name: str) -> int:
    """Validate that ``value`` is a positive integer, raising ``ConfigError`` if not.

    Bool is deliberately excluded even though ``bool`` is a subclass of ``int`` in
    Python, since ``timeout_seconds = true`` in TOML would otherwise silently pass.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError("{0} must be a positive integer, got {1!r}".format(key_name, value))
    return value


def _validate_optional_positive_int(value: Any, key_name: str) -> Optional[int]:
    """Like ``_validate_positive_int``, but ``None`` is allowed (means unset/exhaustive)."""
    if value is None:
        return None
    return _validate_positive_int(value, key_name)


@dataclass(frozen=True)
class ResolvedSettings:
    owner: Optional[str]
    object_names: tuple[str, ...]
    all_objects: bool
    timeout_seconds: int
    scan: ScanSettings
    output_dir: Path
    fixes_dir: Optional[Path]
    generate_fixes: bool
    fix_grouping: str = "row"


def resolve_settings(config: Dict[str, Any], args: Any) -> ResolvedSettings:
    """Resolve final settings: config is the baseline; a value from ``args``
    only overrides its matching key if it was actually supplied (non-None)."""
    owner = args.owner if args.owner is not None else config.get("owner")
    object_value = args.object_name if args.object_name is not None else config.get("object")
    object_names = parse_object_names(object_value)
    config_all_objects = config.get("all_objects", False)
    if not isinstance(config_all_objects, bool):
        raise ConfigError("all_objects must be a boolean, got {0!r}".format(config_all_objects))
    all_objects = config_all_objects or args.all_objects is True
    timeout_seconds = (
        args.timeout_seconds
        if args.timeout_seconds is not None
        else config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    )
    timeout_seconds = _validate_positive_int(timeout_seconds, "timeout_seconds")
    include_source_tables = (
        args.include_source_tables
        if args.include_source_tables is not None
        else config.get("include_source_tables", False)
    )
    row_limit = args.row_limit if args.row_limit is not None else config.get("row_limit")
    row_limit = _validate_optional_positive_int(row_limit, "row_limit")
    include_non_ascii = (
        args.include_non_ascii
        if args.include_non_ascii is not None
        else config.get("include_non_ascii", False)
    )
    sample_row_limit = (
        args.sample_row_limit if args.sample_row_limit is not None else config.get("sample_row_limit", 200)
    )
    sample_row_limit = _validate_positive_int(sample_row_limit, "sample_row_limit")
    sample_char_limit = (
        args.sample_char_limit if args.sample_char_limit is not None else config.get("sample_char_limit", 20)
    )
    sample_char_limit = _validate_positive_int(sample_char_limit, "sample_char_limit")
    detect_mojibake = (
        args.detect_mojibake if args.detect_mojibake is not None else config.get("detect_mojibake", False)
    )
    mojibake_sample_limit = (
        args.mojibake_sample_limit
        if args.mojibake_sample_limit is not None
        else config.get("mojibake_sample_limit", 10)
    )
    mojibake_sample_limit = _validate_positive_int(mojibake_sample_limit, "mojibake_sample_limit")
    output_dir = Path(args.output_dir) if args.output_dir is not None else Path(config.get("output_dir", REPORTS_DIR))
    fixes_dir_value = args.fixes_dir if args.fixes_dir is not None else config.get("fixes_dir")
    fixes_dir = Path(fixes_dir_value) if fixes_dir_value is not None else None
    generate_fixes = (
        args.generate_fixes if args.generate_fixes is not None else config.get("generate_fixes", True)
    )
    fix_grouping = args.fix_grouping if args.fix_grouping is not None else config.get("fix_grouping", "row")
    fix_grouping = _validate_fix_grouping(fix_grouping)
    return ResolvedSettings(
        owner=owner,
        object_names=object_names,
        all_objects=all_objects,
        timeout_seconds=timeout_seconds,
        scan=ScanSettings(
            scope="selected-and-sources" if include_source_tables else "selected",
            row_limit=row_limit,
            include_non_ascii=include_non_ascii,
            sample_row_limit=sample_row_limit,
            sample_char_limit=sample_char_limit,
            capture_fix_rowids=generate_fixes and fix_grouping == "row",
            detect_mojibake=detect_mojibake,
            mojibake_sample_limit=mojibake_sample_limit,
            capture_mojibake_rowids=generate_fixes and fix_grouping == "row" and detect_mojibake,
        ),
        output_dir=output_dir,
        fixes_dir=fixes_dir,
        generate_fixes=generate_fixes,
        fix_grouping=fix_grouping,
    )
