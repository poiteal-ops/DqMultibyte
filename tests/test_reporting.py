from datetime import datetime, timezone
from pathlib import Path

from mbscan.oracle.metadata import DbObject
from mbscan import reporting
from mbscan.reporting import build_report_path, render_report
from mbscan.scan import (
    ColumnScan,
    MojibakeSample,
    MultibyteChar,
    ObjectScanResult,
    ScanBatchResult,
    ScanResult,
    ScanSettings,
    TruncatedRow,
)


def test_report_path_is_timestamped_and_safe():
    path = build_report_path(Path("reports"), "A/..", 'x"y', datetime(2026, 7, 27, 9, 5, 1))
    assert path == Path("reports/2026-07-27-090501_report_A_x_y.txt")


class _UtcOnlyClock:
    @classmethod
    def now(cls, tz):
        assert tz is timezone.utc
        return datetime(2026, 8, 5, 9, 0, 0, tzinfo=timezone.utc)


def _result(columns):
    selected = DbObject("APP", "T1", "TABLE")
    return ScanResult(
        selected=selected,
        settings=ScanSettings(),
        dependencies=[],
        objects=[ObjectScanResult(selected, columns, "exhaustive")],
    )


def test_render_report_aligns_columns_with_differing_name_lengths():
    columns = [
        ColumnScan("ID", "VARCHAR2", None, None, "error", "Oracle error 904"),
        ColumnScan("CUSTOMER_NAME", "VARCHAR2", 3, None),
    ]
    text = render_report(_result(columns))
    lines = text.splitlines()
    header_line = next(line for line in lines if line.startswith("Column"))
    id_line = next(line for line in lines if line.startswith("ID"))
    name_line = next(line for line in lines if line.startswith("CUSTOMER_NAME"))

    name_column_width = len("CUSTOMER_NAME")
    # The widest value in the first column ("CUSTOMER_NAME") sets the width;
    # every row's second column must therefore start at the same offset.
    second_column_offset = name_column_width + 2  # + the "  " separator
    assert header_line[second_column_offset:second_column_offset + 4] == "Type"
    assert id_line[second_column_offset:second_column_offset + 8] == "VARCHAR2"
    assert name_line[second_column_offset:second_column_offset + 8] == "VARCHAR2"


def test_render_report_survives_a_multibyte_sample_that_is_an_unpaired_surrogate(tmp_path):
    """A column value whose underlying bytes were not valid text (e.g. a
    truncated multibyte character) can come back from the driver as a Python
    str containing an unpaired surrogate. That string is valid in memory but
    cannot be UTF-8-encoded on its own -- writing it straight into the report
    used to raise UnicodeEncodeError (a ValueError subclass) and abort the
    whole run, wiping out every table's report data that hadn't been written
    to disk yet. The report must fall back to an escaped form instead."""
    bad_sample = MultibyteChar(chr(0xD83D), "U+D83D", "UNKNOWN")
    columns = [ColumnScan("DESCRIPTION", "VARCHAR2", 1, None, multibyte_samples=(bad_sample,))]

    text = render_report(_result(columns))

    assert "\\ud83d" in text
    # Must be the actual bytes on disk, not just the in-memory string -- this
    # is where the original bug surfaced.
    reporting.write_report(_result(columns), tmp_path).read_text(encoding="utf-8")


def test_render_report_shows_dash_for_none_counts():
    columns = [ColumnScan("ID", "VARCHAR2", None, None, "error", "Oracle error 904")]
    text = render_report(_result(columns))
    assert "-" in text


def test_write_report_uses_the_aware_utc_clock_when_timestamp_is_omitted(monkeypatch, tmp_path):
    monkeypatch.setattr(reporting, "datetime", _UtcOnlyClock)

    path = reporting.write_report(_result([]), tmp_path)

    assert path.name.startswith("2026-08-05-090000_")


def test_render_report_lists_multibyte_samples_and_truncation_notice():
    samples = (MultibyteChar(chr(0xE9), "U+00E9", "LATIN SMALL LETTER E WITH ACUTE"),)
    columns = [
        ColumnScan(
            "NAME", "VARCHAR2", 5, None,
            multibyte_samples=samples, multibyte_samples_truncated=True,
        )
    ]
    text = render_report(_result(columns))
    assert chr(0xE9) in text
    assert "U+00E9" in text
    assert "LATIN SMALL LETTER E WITH ACUTE" in text
    assert "not shown" in text


def test_render_report_includes_column_headers_in_order():
    columns = [ColumnScan("ID", "VARCHAR2", 0, None)]
    text = render_report(_result(columns))
    header_line = next(line for line in text.splitlines() if line.startswith("Column"))
    assert header_line.split() == [
        "Column", "Type", "Multibyte", "Mojibake", "Truncated", "Non-ASCII", "Status", "Notes",
    ]


def test_render_report_shows_truncated_count_and_row_details():
    columns = [
        ColumnScan(
            "NAME", "VARCHAR2", 0, None,
            truncated_count=1,
            truncated_rows=(
                TruncatedRow("AAAv1sAAEAAAAB4AAA", 3, "C3", "unexpected end of data"),
            ),
        )
    ]

    text = render_report(_result(columns))

    name_line = next(line for line in text.splitlines() if line.startswith("NAME"))
    assert name_line.split()[4] == "1"
    assert "AAAv1sAAEAAAAB4AAA" in text
    assert "byte 3" in text
    assert "C3" in text
    assert "unexpected end of data" in text


def test_render_report_truncated_count_none_renders_dash_with_no_detail_lines():
    columns = [ColumnScan("NAME", "VARCHAR2", 5, None)]

    text = render_report(_result(columns))

    name_line = next(line for line in text.splitlines() if line.startswith("NAME"))
    assert name_line.split()[4] == "-"
    assert "incomplete multibyte" not in text


def test_render_report_shows_the_partial_multibyte_skip_reason():
    selected = DbObject("APP", "T1", "TABLE")
    result = ScanResult(
        selected=selected,
        settings=ScanSettings(),
        dependencies=[],
        objects=[ObjectScanResult(selected, [], "exhaustive")],
        truncated_skip_reason=(
            "partial-multibyte check skipped: database character set WE8MSWIN1252 is not UTF-8"
        ),
    )

    text = render_report(result)

    assert "WE8MSWIN1252" in text
    assert "skipped" in text


def test_render_report_shows_object_level_notes():
    selected = DbObject("APP", "T1", "TABLE")
    result = ScanResult(
        selected=selected,
        settings=ScanSettings(),
        dependencies=[],
        objects=[
            ObjectScanResult(
                selected,
                [ColumnScan("TAG", "NVARCHAR2", 0, None)],
                "exhaustive",
                notes=("column TAG (NVARCHAR2): partial-multibyte check supports VARCHAR2/CHAR only, skipped",),
            )
        ],
    )

    text = render_report(result)

    assert "NVARCHAR2" in text
    assert "VARCHAR2/CHAR only" in text


def test_render_report_shows_mojibake_count_and_samples_with_truncation():
    # Build the fixture via chr()/encode/decode rather than embedding a
    # literal non-ASCII character in the source.
    original = "caf" + chr(0xE9)  # "cafe" with an accented e
    garbled = original.encode("utf-8").decode("cp1252")
    samples = (MojibakeSample(garbled=garbled, repaired=original),)
    columns = [
        ColumnScan(
            "NAME", "VARCHAR2", 5, None,
            mojibake_count=3, mojibake_samples=samples, mojibake_samples_truncated=True,
        )
    ]

    text = render_report(_result(columns))

    name_line = next(line for line in text.splitlines() if line.startswith("NAME"))
    cells = name_line.split()
    assert cells[3] == "3"  # Mojibake cell, right after Multibyte's "5"
    assert repr(garbled) in text
    assert repr(original) in text
    assert "->" in text
    assert "additional mojibake values not shown" in text


def test_render_report_mojibake_count_none_renders_dash_with_no_sample_lines():
    """Regression: when mojibake detection wasn't run, the row must render
    exactly as it did before this feature -- "-" placeholder, no sample
    lines, and no reference to mojibake at all in the notes."""
    columns = [ColumnScan("NAME", "VARCHAR2", 5, None)]

    text = render_report(_result(columns))

    name_line = next(line for line in text.splitlines() if line.startswith("NAME"))
    cells = name_line.split()
    assert cells[3] == "-"
    assert "mojibake values in" not in text


def test_render_report_lists_batch_selection_and_each_object_once():
    employees = DbObject("HR", "EMPLOYEES", "TABLE")
    departments = DbObject("HR", "DEPARTMENTS", "TABLE")
    result = ScanBatchResult(
        selected=(employees, departments),
        settings=ScanSettings(),
        dependencies=(),
        objects=(
            ObjectScanResult(employees, [], "exhaustive"),
            ObjectScanResult(departments, [], "exhaustive"),
        ),
    )

    text = render_report(result)

    assert "selected objects: HR.EMPLOYEES, HR.DEPARTMENTS" in text
    assert text.count("object: HR.EMPLOYEES") == 1
    assert text.count("object: HR.DEPARTMENTS") == 1


def test_write_report_uses_batch_filename_labels(tmp_path):
    employees = DbObject("HR", "EMPLOYEES", "TABLE")
    departments = DbObject("HR", "DEPARTMENTS", "TABLE")
    result = ScanBatchResult(
        selected=(employees, departments),
        settings=ScanSettings(),
        dependencies=(),
        objects=(),
    )

    multiple_path = reporting.write_report(result, tmp_path, datetime(2026, 8, 6, tzinfo=timezone.utc))
    all_path = reporting.write_report(
        result,
        tmp_path,
        datetime(2026, 8, 6, tzinfo=timezone.utc),
        batch_label="all_objects",
    )

    assert multiple_path.name.endswith("_report_HR_multiple_objects.txt")
    assert all_path.name.endswith("_report_HR_all_objects.txt")


def test_incremental_report_writer_matches_render_report_for_a_batch(tmp_path):
    """Appending each object's section as it's scanned must produce exactly
    the same bytes as rendering the whole completed batch at once -- the
    incremental path is a streaming equivalent of render_report, not a
    different format."""
    employees = DbObject("HR", "EMPLOYEES", "TABLE")
    departments = DbObject("HR", "DEPARTMENTS", "TABLE")
    employees_result = ObjectScanResult(
        employees, [ColumnScan("NAME", "VARCHAR2", 3, None)], "exhaustive"
    )
    departments_result = ObjectScanResult(departments, [], "exhaustive", notes=("note",))

    batch = ScanBatchResult(
        selected=(employees, departments),
        settings=ScanSettings(),
        dependencies=(),
        objects=(employees_result, departments_result),
    )

    writer = reporting.start_report(
        (employees, departments), tmp_path, datetime(2026, 8, 6, tzinfo=timezone.utc)
    )
    writer.start((employees, departments), batch.settings.scope, batch.dependencies, None)
    writer.append_object(employees_result)
    writer.append_object(departments_result)

    assert writer.path.read_text(encoding="utf-8") == render_report(batch)


def test_incremental_report_writer_creates_parent_directory(tmp_path):
    nested = tmp_path / "reports" / "nested"
    writer = reporting.IncrementalReportWriter(nested / "report.txt")

    writer.start((DbObject("APP", "T1", "TABLE"),), "selected", (), None)

    assert writer.path.exists()


def test_a_crash_partway_through_a_batch_still_leaves_earlier_tables_on_disk(tmp_path):
    """The motivating scenario: a multi-table scan that dies partway through
    (session timeout, Ctrl-C, whatever) must not lose the tables that had
    already finished -- their sections must already be on disk, appended as
    each table completed, not held in memory waiting for the whole run."""
    from mbscan.scan import ScanSettings, scan_objects

    employees = DbObject("HR", "EMPLOYEES", "TABLE")
    departments = DbObject("HR", "DEPARTMENTS", "TABLE")

    class _CrashingCursor:
        def execute(self, sql, parameters=None):
            self._rows = [("NAME", "VARCHAR2")] if "all_tab_columns" in sql else [(0,)]

        def fetchall(self):
            return self._rows

        def fetchone(self):
            return self._rows[0]

    writer = reporting.start_report((employees, departments), tmp_path)

    def on_object_scanned(obj_result):
        writer.append_object(obj_result)
        if obj_result.object.name == "EMPLOYEES":
            raise RuntimeError("the database or network closed the connection")

    try:
        scan_objects(
            _CrashingCursor(), [employees, departments], ScanSettings(),
            on_batch_start=lambda selected, deps, charset, skip: writer.start(selected, "selected", deps, skip),
            on_object_scanned=on_object_scanned,
        )
    except RuntimeError:
        pass

    text = writer.path.read_text(encoding="utf-8")
    assert "object: HR.EMPLOYEES" in text
    assert "object: HR.DEPARTMENTS" not in text


def test_start_report_builds_the_same_path_as_write_report(tmp_path):
    selected = (DbObject("HR", "EMPLOYEES", "TABLE"),)
    timestamp = datetime(2026, 8, 6, tzinfo=timezone.utc)

    writer = reporting.start_report(selected, tmp_path, timestamp)

    assert writer.path == build_report_path(tmp_path, "HR", "EMPLOYEES", timestamp)


def test_render_report_truncates_long_mojibake_sample_values():
    """Finding 3: mojibake previews are the only place the report shows real
    column data (every other preview is character-only). A VARCHAR2 holds up
    to 4000 characters, so each rendered value must be capped to bound the
    data exposure in the plain-text report and keep the table's line-based
    layout intact."""
    original = "x" * 500 + chr(0xE9)
    garbled = original.encode("utf-8").decode("cp1252")
    columns = [
        ColumnScan(
            "NAME", "VARCHAR2", 1, None,
            mojibake_count=1,
            mojibake_samples=(MojibakeSample(garbled=garbled, repaired=original),),
        )
    ]

    text = render_report(_result(columns))

    assert repr(garbled) not in text
    assert repr(original) not in text
    assert "...(truncated)" in text
    sample_line = next(line for line in text.splitlines() if "...(truncated)" in line)
    assert repr(garbled[:reporting.MOJIBAKE_SAMPLE_VALUE_MAX_CHARS]) in sample_line
    assert repr(original[:reporting.MOJIBAKE_SAMPLE_VALUE_MAX_CHARS]) in sample_line


def test_render_report_leaves_short_mojibake_sample_values_untruncated():
    original = "caf" + chr(0xE9)
    garbled = original.encode("utf-8").decode("cp1252")
    columns = [
        ColumnScan(
            "NAME", "VARCHAR2", 1, None,
            mojibake_count=1,
            mojibake_samples=(MojibakeSample(garbled=garbled, repaired=original),),
        )
    ]

    text = render_report(_result(columns))

    assert repr(garbled) in text
    assert repr(original) in text
    assert "truncated" not in text


def test_render_report_notes_mojibake_values_that_could_not_be_previewed():
    """Finding 4: when _repair_mojibake_samples skips a value, mojibake_count
    and the number of rendered pairs disagree -- the report must say why
    rather than leave the reviewer to notice the shortfall."""
    original = "caf" + chr(0xE9)
    garbled = original.encode("utf-8").decode("cp1252")
    columns = [
        ColumnScan(
            "NAME", "VARCHAR2", 2, None,
            mojibake_count=2,
            mojibake_samples=(MojibakeSample(garbled=garbled, repaired=original),),
            mojibake_samples_skipped=1,
        )
    ]

    text = render_report(_result(columns))

    assert "1 value(s) could not be previewed" in text
    assert "outside Windows-1252" in text


def test_render_report_notes_skipped_previews_even_when_no_sample_pair_survived():
    columns = [
        ColumnScan("NAME", "VARCHAR2", 1, None, mojibake_count=1, mojibake_samples_skipped=1)
    ]

    text = render_report(_result(columns))

    assert "mojibake values in NAME:" in text
    assert "1 value(s) could not be previewed" in text


def test_render_report_omits_the_skipped_note_when_nothing_was_skipped():
    original = "caf" + chr(0xE9)
    garbled = original.encode("utf-8").decode("cp1252")
    columns = [
        ColumnScan(
            "NAME", "VARCHAR2", 1, None,
            mojibake_count=1,
            mojibake_samples=(MojibakeSample(garbled=garbled, repaired=original),),
        )
    ]

    text = render_report(_result(columns))

    assert "could not be previewed" not in text
