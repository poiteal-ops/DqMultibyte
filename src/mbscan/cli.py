"""Command-line interface for mbscan: Oracle multibyte character reports."""
from __future__ import annotations

import argparse
import logging
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
from mbscan.settings import resolve_settings
from mbscan.fixes import write_fix_sql
from mbscan.reporting import write_report
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
    return parser


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
    try:
        resolved = resolve_settings(load_toml_config(), args)
        if args.interactive and resolved.all_objects:
            raise ConfigError("--interactive cannot be combined with --all-objects")
        if not args.interactive and (
            not resolved.owner or (not resolved.all_objects and not resolved.object_names)
        ):
            parser.error("--owner and --object are required (directly, via --interactive, or via config/config.toml)")

        log_path = configure_logging("mbscan", "run")
        logger.info(
            "Resolved settings: all_objects=%s requested_object_count=%s scope=%s row_limit=%s include_non_ascii=%s "
            "timeout_seconds=%s generate_fixes=%s fix_grouping=%s sample_row_limit=%s sample_char_limit=%s "
            "detect_mojibake=%s mojibake_sample_limit=%s",
            resolved.all_objects, len(resolved.object_names), resolved.scan.scope,
            resolved.scan.row_limit, resolved.scan.include_non_ascii, resolved.timeout_seconds,
            resolved.generate_fixes, resolved.fix_grouping,
            resolved.scan.sample_row_limit, resolved.scan.sample_char_limit,
            resolved.scan.detect_mojibake, resolved.scan.mojibake_sample_limit,
        )
        config = load_config()
        with connect(config, resolved.timeout_seconds) as connection:
            with connection.cursor() as cursor:
                if args.interactive:
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
                result = scan_objects(cursor, selected_objects, resolved.scan, progress=_progress)
                for obj_result in result.objects:
                    for col in obj_result.columns:
                        logger.info(
                            "column %s.%s.%s: status=%s reason=%s",
                            obj_result.object.owner, obj_result.object.name, col.name, col.status, col.reason,
                        )
                path = write_report(
                    result,
                    resolved.output_dir,
                    batch_label="all_objects" if resolved.all_objects and len(selected_objects) > 1 else None,
                )
                logger.info("Report written")

                fix_paths = []
                if resolved.generate_fixes:
                    fixes_dir = resolved.fixes_dir or resolved.output_dir / "fixes"
                    for obj_result in result.objects:
                        fix_path = write_fix_sql(obj_result, fixes_dir, fix_grouping=resolved.fix_grouping)
                        if fix_path is not None:
                            fix_paths.append(fix_path)
                            logger.info("Fix script written")
        print("Report written: {0}".format(path))
        for fix_path in fix_paths:
            print("Fix script written: {0}".format(fix_path))
        print("Log written: {0}".format(log_path))
        run_complete()
        return 0
    except (ConfigError, ValueError):
        logger.error("Configuration error")
        print("Configuration error: invalid or unavailable configuration.")
        return 2
    except oracledb.Error as exc:
        logger.error("Oracle error %s", oracle_error_code(exc))
        print("Oracle error {0}".format(oracle_error_code(exc)))
        return 3


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args, parser)
