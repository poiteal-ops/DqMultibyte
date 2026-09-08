"""Validated, immutable evidence for fail-closed row repairs.

Fingerprints are sensitive derived data. They intentionally have no repr.
This module does not connect to Oracle or execute repairs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mbscan.scan import ColumnScan

_ROWID = re.compile(r"[A-Za-z0-9+/]{18}")
_HASH = re.compile(r"[0-9A-F]{64}")
TEXT_TYPES = {"CHAR", "VARCHAR2", "NCHAR", "NVARCHAR2"}


@dataclass(frozen=True)
class ByteFingerprint:
    byte_length: int
    window_sha256: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class CellRepairEvidence:
    rowid: str
    column_name: str
    row_scn: int
    fingerprint: ByteFingerprint = field(repr=False)
    repair_kind: str
    keep_bytes: int | None = None


@dataclass(frozen=True)
class RepairTargetEvidence:
    database_sha256: str = field(repr=False)
    object_id: int
    column_types: tuple[tuple[str, str, int], ...]


@dataclass(frozen=True)
class RowRepairEvidence:
    rowid: str
    row_scn: int
    cells: tuple[CellRepairEvidence, ...]


def _integer(value: int, minimum: int, maximum: int | None = None) -> None:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError("INVALID_INTEGER_EVIDENCE")


def valid_rowid(value: str) -> bool:
    return isinstance(value, str) and _ROWID.fullmatch(value) is not None


def _valid_hash(value: str) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def dump_window_starts(byte_length: int) -> tuple[int, ...]:
    _integer(byte_length, 1, 4000)
    return tuple(range(1, byte_length + 1, 900))


def window_hash_sql(quoted_column: str, start_byte: int) -> str:
    _integer(start_byte, 1, 4000)
    return "RAWTOHEX(STANDARD_HASH(DUMP({0}, 1010, {1}, 900), 'SHA256'))".format(quoted_column, start_byte)


def validate_cell_evidence(cell: CellRepairEvidence) -> None:
    if not isinstance(cell, CellRepairEvidence) or not valid_rowid(cell.rowid):
        raise ValueError("INVALID_CELL_EVIDENCE")
    if not isinstance(cell.column_name, str) or not cell.column_name:
        raise ValueError("INVALID_COLUMN_EVIDENCE")
    _integer(cell.row_scn, 1)
    fp = cell.fingerprint
    if not isinstance(fp, ByteFingerprint):
        raise ValueError("INVALID_FINGERPRINT")
    starts = dump_window_starts(fp.byte_length)
    if type(fp.window_sha256) is not tuple or len(fp.window_sha256) != len(starts) or not all(
        _valid_hash(h) for h in fp.window_sha256
    ):
        raise ValueError("INVALID_FINGERPRINT")
    if cell.repair_kind == "truncate":
        _integer(cell.keep_bytes, 0, fp.byte_length - 1)
    elif cell.repair_kind not in {"ascii", "mojibake"} or cell.keep_bytes is not None:
        raise ValueError("INVALID_REPAIR_KIND")


def validate_target_evidence(target: RepairTargetEvidence) -> None:
    if not isinstance(target, RepairTargetEvidence) or not _valid_hash(target.database_sha256):
        raise ValueError("INVALID_TARGET_EVIDENCE")
    _integer(target.object_id, 1)
    if type(target.column_types) is not tuple or not target.column_types:
        raise ValueError("INVALID_TARGET_COLUMNS")
    seen = set()
    for entry in target.column_types:
        if type(entry) is not tuple or len(entry) != 3:
            raise ValueError("INVALID_TARGET_COLUMNS")
        name, kind, size = entry
        if not isinstance(name, str) or not name or name in seen or kind not in TEXT_TYPES:
            raise ValueError("INVALID_TARGET_COLUMNS")
        _integer(size, 1)
        seen.add(name)


def group_row_evidence(columns: list[ColumnScan]) -> tuple[tuple[RowRepairEvidence, ...], tuple[str, ...]]:
    """Require evidence for every proposed cell; one bad cell omits its row."""
    expected: dict[str, dict[str, tuple[str, int | None]]] = {}
    evidence: dict[str, list[CellRepairEvidence]] = {}
    invalid: set[str] = set()
    unknown = False
    for col in columns:
        strips = {row.rowid: row.valid_prefix_bytes for row in col.truncated_rows}
        rowids = set(col.flagged_rowids) | set(col.mojibake_rowids) | set(strips)
        # A finding with no locator cannot be safely related to other columns.
        if ((col.multibyte_count or 0) or (col.truncated_count or 0)) and not rowids:
            unknown = True
        for rid in rowids:
            if not valid_rowid(rid):
                unknown = True
                continue
            cells = expected.setdefault(rid, {})
            if col.name in cells:
                invalid.add(rid)
            kind = "truncate" if rid in strips else "mojibake" if rid in col.mojibake_rowids else "ascii"
            cells[col.name] = (kind, strips.get(rid))
        for cell in col.repair_evidence:
            try:
                validate_cell_evidence(cell)
            except (ValueError, TypeError, AttributeError):
                rid = getattr(cell, "rowid", None)
                if valid_rowid(rid):
                    invalid.add(rid)
                else:
                    unknown = True
                continue
            if cell.column_name != col.name or cell.rowid not in rowids:
                invalid.add(cell.rowid)
            evidence.setdefault(cell.rowid, []).append(cell)
    if unknown:
        return (), ("MISSING_EVIDENCE: all proposed rows omitted",)
    rows = []
    notes = []
    for rid in sorted(expected):
        cells = evidence.get(rid, [])
        names = [c.column_name for c in cells]
        if (rid in invalid or len(names) != len(set(names)) or set(names) != set(expected[rid])
                or len({c.row_scn for c in cells}) != 1
                or any((c.repair_kind, c.keep_bytes) != expected[rid][c.column_name] for c in cells)):
            notes.append("INCONSISTENT_OR_MISSING_EVIDENCE: row " + rid)
            continue
        by_name = {c.column_name: c for c in cells}
        rows.append(RowRepairEvidence(rid, cells[0].row_scn, tuple(by_name[n] for n in expected[rid])))
    return tuple(rows), tuple(notes)


# Length-prefixed encoding avoids ambiguity without exporting database names.
DATABASE_HASH_SQL = (
    "RAWTOHEX(STANDARD_HASH("
    "TO_CHAR(LENGTH(SYS_CONTEXT('USERENV', 'DB_UNIQUE_NAME')), 'FM9999999990') || ':' || "
    "SYS_CONTEXT('USERENV', 'DB_UNIQUE_NAME') || "
    "TO_CHAR(LENGTH(SYS_CONTEXT('USERENV', 'CON_NAME')), 'FM9999999990') || ':' || "
    "SYS_CONTEXT('USERENV', 'CON_NAME'), 'SHA256'))"
)


def repair_notice(obj) -> str:
    """A scan-time count of findings with complete evidence, never runtime status."""
    findings = sum(max(c.multibyte_count or 0, c.mojibake_count or 0, c.truncated_count or 0,
        len(set(c.flagged_rowids) | set(c.mojibake_rowids) | {r.rowid for r in c.truncated_rows})) for c in obj.columns)
    try:
        if any(c.status == "error" for c in obj.columns):
            raise ValueError("INCOMPLETE_SCAN")
        validate_target_evidence(obj.repair_target)
        types = {name: kind for name, kind, _ in obj.repair_target.column_types}
        flagged = [c for c in obj.columns if c.multibyte_count or c.truncated_count]
        if any(types.get(c.name) != c.data_type for c in flagged):
            raise ValueError("INCONSISTENT_TARGET_COLUMNS")
        rows, _ = group_row_evidence(flagged)
        eligible = sum(len(row.cells) for row in rows if all(types[c.column_name] in {"CHAR", "VARCHAR2"} for c in row.cells))
    except (ValueError, TypeError, AttributeError):
        eligible = 0
    return ("Guarded repair evidence: {0} finding(s), {1} with complete evidence, {2} omitted. "
            "UPDATED/SKIPPED outcomes are available only after script execution.").format(findings, eligible, max(0, findings - eligible))
