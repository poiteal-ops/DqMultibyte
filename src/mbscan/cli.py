"""Command-line interface for mbscan: Oracle multibyte character reports."""
from __future__ import annotations

import argparse
import logging
import traceback
from pathlib import Path
from typing import List, Optional

import oracledb

from mbscan.toml_config import load_toml_config
from mbscan.logging_setup import configure_logging
from mbscan.oracle.connection import ConfigError, connect, load_config
from mbscan.oracle.errors import oracle_error_code
from mbscan.progress import progress, run_complete
from mbscan.oracle.metadata import (
    DbObject,
    format_object_menu,
    list_exportable_objects,
    resolve_requested_objects,
    validate_owner,
)
from mbscan.manifest import load_scan_manifest
from mbscan.settings import resolve_settings
from mbscan.fixes import write_fix_sql
from mbscan.reporting import start_report
from mbscan.scan import scan_objects

logger = logging.getLogger(__name__)

PROG_SUMMARY = "Scan an Oracle table/view/materialized view for multibyte and non-ASCII character values"


def _positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def _progress(iterable, total, desc):
    return progress(iterable, total=total, desc=desc, unit="col")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mbscan", description=PROG_SUMMARY)
    parser.add_argument("--owner", default=None)
    parser.add_argument("--object", dest="object_name", default=None)
    parser.add_argument("--all-objects", action="store_true", default=None)
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--include-source-tables", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--row-limit", type=_positive, default=None)
    parser.add_argument("--include-non-ascii", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--timeout-seconds", type=_positive, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--fixes-dir", type=Path, default=None)
    parser.add_argument("--generate-fixes", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--fix-grouping", dest="fix_grouping", choices=("row", "column"), default=None)
    parser.add_argument("--sample-row-limit", type=_positive, default=None)
    parser.add_argument("--sample-char-limit", type=_positive, default=None)
    parser.add_argument("--detect-mojibake", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--mojibake-sample-limit", type=_positive, default=None)
    parser.add_argument(
        "--detect-truncated",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="flag rows whose stored bytes hold an incomplete multibyte "
        "character (SAS-DI truncation; Oracle ORA-29275)",
    )
    parser.add_argument(
        "--json-entry",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="scan only the tables/columns named in the JSON manifest "
        "(mutually exclusive with --object / --all-objects / --interactive)",
    )
    parser.add_argument("--json-entry-file", dest="json_entry_file", type=Path, default=None)
    return parser


def _report_configuration_error(exc: Exception, debug_level: str, log_path: Optional[Path]) -> None:
    """Print a ConfigError/ValueError to the console.

    prod (default) stays the deliberately generic line -- ConfigError/ValueError
    text can embed config-file paths and setting values, and the console must
    never echo those back out. dev is an explicit opt-in for local
    troubleshooting: it prints the real message and traceback. The full
    detail always goes to the log file either way (see logging_setup.py).
    """
    logger.error("Configuration error", exc_info=True)
    if debug_level == "dev":
        print("Configuration error: {0}".format(exc))
        print(traceback.format_exc())
        if log_path is not None:
            print("Log: {0}".format(log_path))
    else:
        print("Configuration error: invalid or unavailable configuration.")


def _report_oracle_error(exc: oracledb.Error, debug_level: str, log_path: Optional[Path]) -> None:
    """Print an Oracle error to the console.

    prod (default) stays code-only -- Oracle's own message text can carry
    connection strings, host names, and SQL fragments (see oracle/errors.py).
    dev prints the full Oracle message for local troubleshooting.
    """
    code = oracle_error_code(exc)
    if debug_level == "dev":
        logger.error("Oracle error %s", exc, exc_info=True)
        print("Oracle error {0}: {1}".format(code, exc))
        if log_path is not None:
            print("Log: {0}".format(log_path))
    else:
        logger.error("Oracle error %s", code)
        print("Oracle error {0}".format(code))


def _choose_object(cursor, owner: str) -> DbObject:
    objects = list_exportable_objects(cursor, owner)
    if not objects:
        raise ConfigError("No tables, views, or materialized views found in this schema.")
    print(format_object_menu(objects))
    while True:
        raw = input("Select an object [1-{0}]: ".format(len(objects))).strip()
        if raw.isdigit() and 1 <= int(raw) <= len(objects):
            return objects[int(raw) - 1]
        print("Invalid choice, try again.")


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    # Known before resolve_settings() so an error raised while resolving
    # settings can still be reported at the right verbosity. Best-effort: an
    # invalid value here just falls back to prod-safe reporting -- the real
    # validation (and ConfigError, if it's bad) happens inside resolve_settings.
    debug_level = "prod"
    log_path: Optional[Path] = None
    try:
        toml_config = load_toml_config()
        if toml_config.get("debug_level") == "dev":
            debug_level = "dev"

        resolved = resolve_settings(toml_config, args)
        debug_level = resolved.debug_level
        if args.interactive and resolved.all_objects:
            raise ConfigError("--interactive cannot be combined with --all-objects")
        if resolved.json_entry:
            conflicts = [
                label
                for label, present in (
                    ("--interactive", args.interactive),
                    ("all_objects", resolved.all_objects),
                    ("object", bool(resolved.object_names)),
                )
                if present
            ]
            if conflicts:
                raise ConfigError(
                    "json_entry cannot be combined with " + ", ".join(conflicts)
                )
        elif not args.interactive and (
            not resolved.owner or (not resolved.all_objects and not resolved.object_names)
        ):
            parser.error("--owner and --object are required (directly, via --interactive, or via config/config.toml)")

        log_path = configure_logging(
            "mbscan", "run",
            level=logging.DEBUG if debug_level == "dev" else logging.INFO,
        )
        logger.info(
            "Resolved settings: all_objects=%s requested_object_count=%s scope=%s row_limit=%s include_non_ascii=%s "
            "timeout_seconds=%s generate_fixes=%s fix_grouping=%s sample_row_limit=%s sample_char_limit=%s "
            "detect_mojibake=%s mojibake_sample_limit=%s detect_truncated=%s json_entry=%s debug_level=%s",
            resolved.all_objects, len(resolved.object_names), resolved.scan.scope,
            resolved.scan.row_limit, resolved.scan.include_non_ascii, resolved.timeout_seconds,
            resolved.generate_fixes, resolved.fix_grouping,
            resolved.scan.sample_row_limit, resolved.scan.sample_char_limit,
            resolved.scan.detect_mojibake, resolved.scan.mojibake_sample_limit,
            resolved.scan.detect_truncated, resolved.json_entry, resolved.debug_level,
        )
        config = load_config()
        with connect(config, resolved.timeout_seconds) as connection:
            with connection.cursor() as cursor:
                column_filter = None
                if resolved.json_entry:
                    manifest = load_scan_manifest(resolved.json_entry_file)
                    owner = validate_owner(cursor, manifest.owner)
                    selected_objects = resolve_requested_objects(
                        cursor, owner, tuple(table.table for table in manifest.tables)
                    )
                    column_filter = {
                        (obj.owner, obj.name, obj.object_type): frozenset(
                            name.upper() for name in table.columns
                        )
                        for table, obj in zip(manifest.tables, selected_objects)
                        if table.columns
                    } or None
                elif args.interactive:
                    owner = validate_owner(cursor, input("Schema [{0}]: ".format(config.username)).strip() or config.username)
                    selected_objects = (_choose_object(cursor, owner),)
                else:
                    owner = validate_owner(cursor, resolved.owner)
                    selected_objects = (
                        tuple(list_exportable_objects(cursor, owner))
                        if resolved.all_objects
                        else resolve_requested_objects(cursor, owner, resolved.object_names)
                    )
                    if not selected_objects:
                        raise ConfigError("No tables, views, or materialized views found in this schema.")
                    if resolved.all_objects and resolved.object_names:
                        message = "all_objects is enabled; the explicit object list was ignored."
                        print(message)
                        logger.info(message)
                logger.info("Connected and validated owner %s", owner)

                report_writer = start_report(
                    selected_objects,
                    resolved.output_dir,
                    batch_label="all_objects" if resolved.all_objects and len(selected_objects) > 1 else None,
                )
                path = report_writer.path
                fixes_dir = resolved.fixes_dir or resolved.output_dir / "fixes"
                fix_paths: List[Path] = []

                def _on_batch_start(selected, dependencies, charset, truncated_skip_reason):
                    report_writer.start(selected, resolved.scan.scope, dependencies, truncated_skip_reason)

                def _on_object_scanned(obj_result):
                    report_writer.append_object(obj_result)
                    for col in obj_result.columns:
                        logger.info(
                            "column %s.%s.%s: status=%s reason=%s",
                            obj_result.object.owner, obj_result.object.name, col.name, col.status, col.reason,
                        )
                    if resolved.generate_fixes:
                        fix_path = write_fix_sql(obj_result, fixes_dir, fix_grouping=resolved.fix_grouping)
                        if fix_path is not None:
                            fix_paths.append(fix_path)
                            logger.info("Fix script written")

                scan_objects(
                    cursor, selected_objects, resolved.scan,
                    progress=_progress, column_filter=column_filter,
                    on_batch_start=_on_batch_start, on_object_scanned=_on_object_scanned,
                )
                logger.info("Report written")
        print("Report written: {0}".format(path))
        for fix_path in fix_paths:
            print("Fix script written: {0}".format(fix_path))
        print("Log written: {0}".format(log_path))
        run_complete()
        return 0
    except (ConfigError, ValueError) as exc:
        # prod: full traceback goes to the log file only -- the console message
        # stays generic so it never echoes a raw config value back out.
        # dev (config/config.toml debug_level = "dev"): the real message and
        # traceback print to the console too. See _report_configuration_error.
        _report_configuration_error(exc, debug_level, log_path)
        return 2
    except oracledb.Error as exc:
        _report_oracle_error(exc, debug_level, log_path)
        return 3


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args, parser)
