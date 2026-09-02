"""Safe rendering for multibyte/mojibake scan summaries."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Union

from mbscan.files import TIMESTAMP_FORMAT, safe_filename_component
from mbscan.scan import ColumnScan, ScanBatchResult, ScanResult

ScanOutput = Union[ScanResult, ScanBatchResult]


def build_report_path(output_dir: Path, owner: str, name: str, timestamp: datetime) -> Path:
    return output_dir / "{0}_report_{1}_{2}.txt".format(
        timestamp.strftime(TIMESTAMP_FORMAT), safe_filename_component(owner), safe_filename_component(name)
    )


def _row_cells(col: ColumnScan) -> Tuple[str, ...]:
    return (
        col.name,
        col.data_type,
        "-" if col.multibyte_count is None else str(col.multibyte_count),
        "-" if col.mojibake_count is None else str(col.mojibake_count),
        "-" if col.truncated_count is None else str(col.truncated_count),
        "-" if col.non_ascii_count is None else str(col.non_ascii_count),
        col.status,
        col.reason or "",
    )


def _safe_char(ch: str) -> str:
    """A column value whose raw bytes were not valid text (e.g. a truncated
    multibyte character) can decode to a Python str containing an unpaired
    surrogate -- valid in memory, but impossible to write to a UTF-8 file on
    its own. Fall back to the character's escaped form rather than letting
    that one bad row crash the whole report write."""
    try:
        ch.encode("utf-8")
        return ch
    except UnicodeEncodeError:
        return repr(ch)


def _render_multibyte_samples(col: ColumnScan) -> List[str]:
    if not col.multibyte_samples:
        return []
    lines = ["    multibyte characters in {0}:".format(col.name)]
    for sample in col.multibyte_samples:
        lines.append("      {0}  {1}  {2}".format(_safe_char(sample.char), sample.codepoint, sample.name))
    if col.multibyte_samples_truncated:
        lines.append("      (additional distinct characters not shown -- increase sample limits to see more)")
    return lines


# Mojibake previews are the only place this report shows real column data --
# every other preview is character-only. A VARCHAR2 can hold 4000 characters,
# so cap each rendered value to bound both the data exposure in the plain-text
# report file and the damage to the table's line-based layout.
MOJIBAKE_SAMPLE_VALUE_MAX_CHARS = 120


def _preview_value(value: str) -> str:
    """Render one raw column value for the report, capped at a fixed width."""
    if len(value) <= MOJIBAKE_SAMPLE_VALUE_MAX_CHARS:
        return repr(value)
    return repr(value[:MOJIBAKE_SAMPLE_VALUE_MAX_CHARS]) + " ...(truncated)"


# How many flagged ROWIDs to list per column in the partial-multibyte detail
# block. The block shows only ROWID + byte offset + a few hex bytes + reason,
# never the value (it can't be decoded and may hold sensitive data).
TRUNCATED_ROW_PREVIEW_MAX = 20


def _render_truncated_rows(col: ColumnScan) -> List[str]:
    if not col.truncated_rows:
        return []
    lines = ["    incomplete multibyte characters in {0}:".format(col.name)]
    for row in col.truncated_rows[:TRUNCATED_ROW_PREVIEW_MAX]:
        lines.append(
            "      ROWID {0} : byte {1} ({2}) -- {3}".format(
                row.rowid, row.valid_prefix_bytes, row.bad_bytes_hex, row.reason
            )
        )
    remaining = len(col.truncated_rows) - TRUNCATED_ROW_PREVIEW_MAX
    if remaining > 0:
        lines.append(
            "      ({0} more row(s) not shown -- see the generated fix script for the full list)".format(
                remaining
            )
        )
    return lines


def _render_mojibake_samples(col: ColumnScan) -> List[str]:
    if not col.mojibake_samples and not col.mojibake_samples_skipped:
        return []
    lines = ["    mojibake values in {0}:".format(col.name)]
    for sample in col.mojibake_samples:
        lines.append(
            "      {0} -> {1}".format(_preview_value(sample.garbled), _preview_value(sample.repaired))
        )
    if col.mojibake_samples_truncated:
        lines.append("      (additional mojibake values not shown -- increase sample limits to see more)")
    if col.mojibake_samples_skipped:
        lines.append(
            "      ({0} value(s) could not be previewed -- contains characters outside "
            "Windows-1252)".format(col.mojibake_samples_skipped)
        )
    return lines


def _render_columns_table(columns: List[ColumnScan]) -> List[str]:
    headers = ("Column", "Type", "Multibyte", "Mojibake", "Truncated", "Non-ASCII", "Status", "Notes")
    rows = [_row_cells(col) for col in columns]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(cells: Tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths))

    lines = [fmt(headers), fmt(tuple("-" * w for w in widths))]
    for col, row in zip(columns, rows):
        lines.append(fmt(row))
        lines.extend(_render_multibyte_samples(col))
        lines.extend(_render_mojibake_samples(col))
        lines.extend(_render_truncated_rows(col))
    return lines


def _selected_objects(result: ScanOutput) -> Tuple:
    if isinstance(result, ScanResult):
        return (result.selected,)
    return result.selected


def _header_lines(selected: Tuple, scope: str, dependencies, skip_reason: Optional[str]) -> List[str]:
    if len(selected) == 1:
        selection_line = "selected: {0}.{1}".format(selected[0].owner, selected[0].name)
    else:
        selection_line = "selected objects: {0}".format(
            ", ".join("{0}.{1}".format(obj.owner, obj.name) for obj in selected)
        )
    lines = [selection_line, "scope: {0}".format(scope)]
    if skip_reason:
        lines.append(skip_reason)
    for dep in dependencies:
        lines.append("dependency: {0}.{1} {2}".format(dep.object.owner, dep.object.name, dep.access))
    return lines


def _object_lines(obj) -> List[str]:
    lines = [
        "",
        "object: {0}.{1} coverage: {2}".format(obj.object.owner, obj.object.name, obj.coverage),
    ]
    for note in getattr(obj, "notes", ()):
        lines.append("  note: {0}".format(note))
    lines.extend(_render_columns_table(obj.columns))
    return lines


def render_report(result: ScanOutput) -> str:
    selected = _selected_objects(result)
    lines = _header_lines(
        selected, result.settings.scope, result.dependencies, getattr(result, "truncated_skip_reason", None)
    )
    for obj in result.objects:
        lines.extend(_object_lines(obj))
    return "\n".join(lines) + "\n"


class IncrementalReportWriter:
    """Writes one combined report file for a batch, appending each table's
    section to disk as soon as that table's scan finishes, so a scan that's
    interrupted partway through a large schema still leaves a report with
    every table that had already completed -- instead of nothing at all."""

    def __init__(self, path: Path):
        self.path = path

    def start(self, selected: Tuple, scope: str, dependencies, skip_reason: Optional[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        header = _header_lines(selected, scope, dependencies, skip_reason)
        self.path.write_text("\n".join(header) + "\n", encoding="utf-8")

    def append_object(self, obj_result) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(_object_lines(obj_result)) + "\n")


def _report_owner_and_name(selected: Tuple, batch_label: Optional[str]) -> Tuple[str, str]:
    if not selected:
        raise ValueError("Cannot write a report without selected objects.")
    if len(selected) == 1:
        return selected[0].owner, selected[0].name
    label = batch_label or "multiple_objects"
    if label not in {"multiple_objects", "all_objects"}:
        raise ValueError("batch_label must be multiple_objects or all_objects")
    return selected[0].owner, label


def write_report(
    result: ScanOutput,
    output_dir: Path,
    timestamp: Optional[datetime] = None,
    batch_label: Optional[str] = None,
) -> Path:
    selected = _selected_objects(result)
    owner, name = _report_owner_and_name(selected, batch_label)
    path = build_report_path(
        output_dir,
        owner,
        name,
        timestamp or datetime.now(timezone.utc),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(result), encoding="utf-8")
    return path


def start_report(
    selected: Tuple,
    output_dir: Path,
    timestamp: Optional[datetime] = None,
    batch_label: Optional[str] = None,
) -> IncrementalReportWriter:
    """Build the report path up front (before scanning begins) and return a
    writer whose ``.start()``/``.append_object()`` are filled in as the scan
    progresses -- see IncrementalReportWriter."""
    owner, name = _report_owner_and_name(selected, batch_label)
    path = build_report_path(output_dir, owner, name, timestamp or datetime.now(timezone.utc))
    return IncrementalReportWriter(path)
