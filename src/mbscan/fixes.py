"""Generates reviewable, non-executed SQL to fix multibyte text columns.

The generated UPDATE is LOSSY and IRREVERSIBLE: CONVERT(col, 'US7ASCII')
maps recognized accented characters to a close ASCII equivalent, but any
character with no US7ASCII equivalent (CJK, emoji, etc.) is replaced with
'?'. This file is never executed by mbscan itself -- it is handed to
someone with write access to review and run manually.

This is today's default fix strategy and is expected to be revisited once
verified against real transliteration results on a live schema.

Rows/columns the scan identified as mojibake (see scan.MOJIBAKE_PREDICATE_
TEMPLATE) instead get MOJIBAKE_REPAIR_EXPR_TEMPLATE, an exact (non-lossy)
repair expression for SAS-DI-style UTF-8-misread-as-WE8MSWIN1252 corruption,
validated against a live Oracle instance -- see the constant's comment for
details. Any remaining flagged rows/columns that aren't mojibake still fall
back to the lossy CONVERT(col, 'US7ASCII') path described above.

Two fix_grouping modes are supported (see render_fix_sql):
- "row" (default): one UPDATE per ROWID captured at scan time, consolidating
  every flagged column for that row into a single SET clause. Only touches
  rows the scan actually identified as flagged.
- "column": one UPDATE per flagged column, scoped by re-running the
  multibyte predicate at fix-run time (today's original behavior). Cheaper
  at scan time (no ROWID fetch) but its WHERE clause is not scoped to the
  rows the scan actually looked at -- e.g. under a bounded (row_limit) scan
  it can touch rows outside the sampled subset.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mbscan.files import TIMESTAMP_FORMAT, safe_filename_component
from mbscan.oracle.metadata import quote_identifier
from mbscan.scan import (
    ColumnScan,
    MOJIBAKE_PREDICATE_TEMPLATE,
    MULTIBYTE_PREDICATE_TEMPLATE,
    ObjectScanResult,
    safe_object_sql,
)

FIX_GROUPINGS = {"row", "column"}

# Empirically validated 2026-08-09 against a live Oracle 23c AL32UTF8 instance:
# exact recovery on both a 2-byte and a 3-byte SAS-DI-style mojibake case
# (UTF-8 text that was misread/re-encoded as WE8MSWIN1252). Assumes the target
# schema's database character set is AL32UTF8 -- if unsure, confirm with
# SELECT value FROM nls_database_parameters WHERE parameter='NLS_CHARACTERSET'
# and change the charset name here if it differs. Do NOT use
# CONVERT(col, 'AL32UTF8', 'WE8MSWIN1252') as an alternative: tested against
# the same instance and confirmed to mangle the data further, not repair it.
MOJIBAKE_REPAIR_EXPR_TEMPLATE = (
    "UTL_I18N.RAW_TO_CHAR(UTL_I18N.STRING_TO_RAW({0}, 'WE8MSWIN1252'), 'AL32UTF8')"
)

# Oracle's extended ROWID external representation: exactly 18 characters
# from this fixed alphabet. Validated as a whitelist before interpolation
# into generated SQL text -- defense in depth, consistent with
# _UNSAFE_COMMENT_CHARS below, even though a real cursor should never
# return anything else.
_ROWID_PATTERN = re.compile(r"^[A-Za-z0-9+/]{18}$")

# C0 controls, DEL, C1 controls, Unicode line/paragraph separators, and bidi
# control characters: a dictionary-derived name containing any of these could
# otherwise break out of a "--" line comment (e.g. embedded "\n") or forge
# misleading text/directionality for a reviewer, since Oracle quoted
# identifiers permit almost any character.
_UNSAFE_COMMENT_CHARS = frozenset(
    [chr(c) for c in range(0x00, 0x20)]  # C0 controls, including tab, CR, LF
    + [chr(c) for c in range(0x7F, 0xA0)]  # DEL + C1 controls
    + [chr(0x2028), chr(0x2029)]  # LINE SEPARATOR, PARAGRAPH SEPARATOR
    + [chr(0x200E), chr(0x200F)]  # LRM, RLM
    + [chr(c) for c in range(0x202A, 0x202F)]  # LRE..RLO
    + [chr(c) for c in range(0x2066, 0x206A)]  # LRI..PDI
)


def _escape_for_comment(text: str) -> str:
    """Render ``text`` safe to embed in a single-line SQL "--" comment by
    replacing unsafe characters with visible ``\\uXXXX`` escapes."""
    return "".join(
        "\\u{0:04x}".format(ord(ch)) if ch in _UNSAFE_COMMENT_CHARS else ch
        for ch in text
    )


def build_fix_path(fixes_dir: Path, owner: str, name: str, timestamp: datetime) -> Path:
    return fixes_dir / "{0}_fix_{1}_{2}.sql".format(
        timestamp.strftime(TIMESTAMP_FORMAT), safe_filename_component(owner), safe_filename_component(name)
    )


def _render_by_column(flagged: List[ColumnScan], target: str) -> List[str]:
    """One UPDATE per flagged column, scoped by re-running the multibyte
    predicate at fix-run time. Today's original behavior, unchanged for
    columns with no mojibake match.

    A column with mojibake_count > 0 instead gets a repair statement scoped
    to MOJIBAKE_PREDICATE_TEMPLATE, preceded by -- only if some flagged rows
    are not mojibake -- a lossy CONVERT statement scoped to "multibyte AND
    NOT mojibake" so it doesn't re-touch rows the repair statement handles.

    STATEMENT ORDER IS LOAD-BEARING: the CONVERT statement must be emitted
    FIRST. Its WHERE clause is evaluated when the generated script is run,
    not when it is generated, and a repaired mojibake value is still
    multibyte and no longer mojibake -- so it matches "multibyte AND NOT
    mojibake". Emitting CONVERT second (and running the file in order, as
    anyone would) would lossily flatten every row the repair had just fixed.
    Emitted first, CONVERT sees the correct pre-repair row set, its rows
    become pure ASCII (matching neither predicate afterwards), and the repair
    then runs untouched on the still-mojibake rows."""
    lines: List[str] = []
    for col in flagged:
        quoted = quote_identifier(col.name)
        safe_name = _escape_for_comment(col.name)
        mojibake_count = col.mojibake_count or 0
        if mojibake_count:
            mojibake_predicate = MOJIBAKE_PREDICATE_TEMPLATE.format(quoted)
            repair_expr = MOJIBAKE_REPAIR_EXPR_TEMPLATE.format(quoted)
            multibyte_count = col.multibyte_count or 0
            if multibyte_count > mojibake_count:
                convert_predicate = "({0}) AND NOT ({1})".format(
                    MULTIBYTE_PREDICATE_TEMPLATE.format(quoted), mojibake_predicate
                )
                lines.append(
                    "-- Column {0}: {1} flagged row(s) at scan time, {2} not mojibake".format(
                        safe_name, multibyte_count, multibyte_count - mojibake_count
                    )
                )
                lines.append(
                    "-- Run this BEFORE the repair statement below -- see the header note."
                )
                lines.append(
                    "UPDATE {0} SET {1} = CONVERT({1}, 'US7ASCII') WHERE {2};".format(
                        target, quoted, convert_predicate
                    )
                )
                lines.append("")
            lines.append(
                "-- Column {0}: {1} mojibake row(s) at scan time (repair)".format(safe_name, mojibake_count)
            )
            lines.append(
                "UPDATE {0} SET {1} = {2} WHERE {3};".format(target, quoted, repair_expr, mojibake_predicate)
            )
            lines.append("")
        else:
            predicate = MULTIBYTE_PREDICATE_TEMPLATE.format(quoted)
            lines.append("-- Column {0}: {1} flagged row(s) at scan time".format(safe_name, col.multibyte_count))
            lines.append("UPDATE {0} SET {1} = CONVERT({1}, 'US7ASCII') WHERE {2};".format(target, quoted, predicate))
            lines.append("")
    return lines


def _render_by_row(flagged: List[ColumnScan], target: str) -> List[str]:
    """One UPDATE per ROWID captured at scan time, consolidating every
    flagged column for that row into a single SET clause.

    Within a column, a rowid that's also in that column's mojibake_rowids
    gets the mojibake repair expression instead of the lossy CONVERT
    fallback -- so a single row's UPDATE can end up with one repaired column
    and one converted column, if that row has two flagged columns and only
    one of them is mojibake."""
    lines: List[str] = []
    rowid_to_assignments: "Dict[str, List[Tuple[str, str]]]" = {}
    for col in flagged:
        safe_name = _escape_for_comment(col.name)
        lines.append("-- Column {0}: {1} flagged row(s) at scan time".format(safe_name, col.multibyte_count))
        valid_rowids = [rowid for rowid in col.flagged_rowids if _ROWID_PATTERN.match(rowid)]
        invalid_count = len(col.flagged_rowids) - len(valid_rowids)
        if not valid_rowids:
            lines.append(
                "-- WARNING: Column {0} was flagged ({1} row(s)) but no ROWIDs were captured; "
                "skipping this column.".format(safe_name, col.multibyte_count)
            )
        elif invalid_count:
            lines.append(
                "-- WARNING: Column {0} had {1} ROWID(s) that failed format validation and were "
                "skipped.".format(safe_name, invalid_count)
            )
        # The two ROWID-fetch queries in scan._scan_one are separate
        # statements, each independently bounded by "WHERE ROWNUM <=
        # :row_limit" with no ORDER BY, so under a row_limit-bounded scan
        # Oracle does not guarantee they saw the same first-N rows. A
        # mojibake ROWID missing from flagged_rowids would otherwise be
        # dropped silently by the loop below -- a missed repair.
        orphan_mojibake = set(col.mojibake_rowids) - set(valid_rowids)
        if orphan_mojibake:
            lines.append(
                "-- WARNING: Column {0} had {1} mojibake ROWID(s) with no matching flagged ROWID "
                "and were skipped; re-run the scan without a row_limit to cover them.".format(
                    safe_name, len(orphan_mojibake)
                )
            )
        quoted = quote_identifier(col.name)
        mojibake_rowid_set = set(col.mojibake_rowids)
        for rowid in valid_rowids:
            if rowid in mojibake_rowid_set:
                expr = MOJIBAKE_REPAIR_EXPR_TEMPLATE.format(quoted)
            else:
                expr = "CONVERT({0}, 'US7ASCII')".format(quoted)
            rowid_to_assignments.setdefault(rowid, []).append((quoted, expr))
    lines.append("")
    for rowid in sorted(rowid_to_assignments):
        assignments = rowid_to_assignments[rowid]
        set_clause = ", ".join("{0} = {1}".format(quoted, expr) for quoted, expr in assignments)
        lines.append("UPDATE {0} SET {1} WHERE ROWID = CHARTOROWID('{2}');".format(target, set_clause, rowid))
    return lines


def render_fix_sql(obj_result: ObjectScanResult, fix_grouping: str = "row") -> Optional[str]:
    """Return UPDATE statements for every flagged column, or None if
    obj_result has no column with multibyte_count > 0 (caller must not
    write a file in that case).

    fix_grouping selects the statement shape -- see the module docstring."""
    if fix_grouping not in FIX_GROUPINGS:
        raise ValueError("fix_grouping must be one of {0}, got {1!r}".format(sorted(FIX_GROUPINGS), fix_grouping))
    flagged = [col for col in obj_result.columns if (col.multibyte_count or 0) > 0]
    if not flagged:
        return None
    target = safe_object_sql(obj_result.object)
    has_mojibake = any((col.mojibake_count or 0) > 0 for col in flagged)
    mode_description = (
        "one UPDATE per row, all of that row's flagged columns in one SET clause"
        if fix_grouping == "row"
        else "one UPDATE per flagged column"
    )
    lines = [
        "-- mbscan generated fix script for {0}".format(_escape_for_comment(target)),
        "-- DO NOT RUN WITHOUT REVIEW.",
        "--",
        "-- WARNING: this UPDATE is LOSSY and IRREVERSIBLE. CONVERT(col, 'US7ASCII')",
        "-- maps recognized accented Latin characters to their closest ASCII",
        "-- equivalent; characters with no US7ASCII equivalent (CJK, emoji, and",
        "-- similar) become '?' and the original value cannot be recovered once",
        "-- this UPDATE runs. Take a backup/export of the affected rows first.",
        "--",
        "-- NOTE: CONVERT(col, 'US7ASCII') is today's default fix strategy and is",
        "-- expected to be reconsidered after being checked against real data.",
        "--",
    ]
    if has_mojibake:
        lines.extend(
            [
                "-- MOJIBAKE REPAIR: rows flagged as SAS-DI-style mojibake (UTF-8 text",
                "-- misread/re-encoded as WE8MSWIN1252) are repaired instead of converted,",
                "-- using UTL_I18N.RAW_TO_CHAR(UTL_I18N.STRING_TO_RAW(col, 'WE8MSWIN1252'),",
                "-- 'AL32UTF8'). This assumes the target schema's database character set is",
                "-- AL32UTF8 -- if unsure, confirm with:",
                "--   SELECT value FROM nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET';",
                "-- and change the charset name in the repair statements below if it differs.",
                "-- Still take a backup first: this repair was validated against specific",
                "-- test cases, not exhaustively against all possible corrupted data.",
                "--",
                "-- RUN THE STATEMENTS BELOW IN FILE ORDER. Their WHERE clauses are",
                "-- evaluated when you run them, not when this file was generated, and a",
                "-- repaired value is still multibyte but no longer mojibake. Running a",
                "-- column's CONVERT statement after its repair statement would therefore",
                "-- re-match and lossily flatten the rows the repair had just fixed.",
                "--",
            ]
        )
    lines.extend(
        [
            "-- Fix mode: {0} ({1}).".format(fix_grouping, mode_description),
            "",
            "SET DEFINE OFF",
            "",
        ]
    )
    if fix_grouping == "row":
        lines.extend(_render_by_row(flagged, target))
    else:
        lines.extend(_render_by_column(flagged, target))
    return "\n".join(lines).rstrip() + "\n"


def write_fix_sql(
    obj_result: ObjectScanResult,
    fixes_dir: Path,
    timestamp: Optional[datetime] = None,
    fix_grouping: str = "row",
) -> Optional[Path]:
    """Write one .sql file for obj_result, or write nothing and return None
    if it has no flagged columns."""
    sql = render_fix_sql(obj_result, fix_grouping=fix_grouping)
    if sql is None:
        return None
    path = build_fix_path(
        fixes_dir,
        obj_result.object.owner,
        obj_result.object.name,
        timestamp or datetime.now(timezone.utc),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sql, encoding="utf-8")
    return path
