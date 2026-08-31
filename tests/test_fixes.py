from datetime import datetime, timezone
from pathlib import Path

import pytest

from mbscan.oracle.metadata import DbObject, quote_identifier
from mbscan import fixes
from mbscan.fixes import (
    MOJIBAKE_REPAIR_EXPR_TEMPLATE,
    build_fix_path,
    render_fix_sql,
    write_fix_sql,
)
from mbscan.scan import (
    ColumnScan,
    MOJIBAKE_PREDICATE_TEMPLATE,
    MULTIBYTE_PREDICATE_TEMPLATE,
    ObjectScanResult,
    TruncatedRow,
)


class _UtcOnlyClock:
    @classmethod
    def now(cls, tz):
        assert tz is timezone.utc
        return datetime(2026, 8, 5, 9, 0, 0, tzinfo=timezone.utc)


def test_build_fix_path_is_timestamped_and_safe():
    path = build_fix_path(Path("reports/fixes"), "A/..", 'x"y', datetime(2026, 7, 27, 9, 5, 1))
    assert path == Path("reports/fixes/2026-07-27-090501_fix_A_x_y.sql")


def test_render_fix_sql_returns_none_when_nothing_flagged():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("ID", "NUMBER", None, None, "skipped", "unsupported data type")],
        "exhaustive",
    )
    assert render_fix_sql(obj_result) is None


def test_render_fix_sql_emits_one_update_per_flagged_column_and_skips_clean_columns():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan("CLEAN", "VARCHAR2", 0, None),
            ColumnScan("NAME", "VARCHAR2", 3, None),
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert len(update_statements) == 1
    quoted = quote_identifier("NAME")
    expected_predicate = MULTIBYTE_PREDICATE_TEMPLATE.format(quoted)
    expected_statement = 'UPDATE "APP"."T1" SET {0} = CONVERT({0}, \'US7ASCII\') WHERE {1};'.format(
        quoted, expected_predicate
    )
    assert expected_statement in sql
    assert '"CLEAN"' not in sql
    assert "DO NOT RUN WITHOUT REVIEW" in sql
    assert "provisional" in sql.lower() or "reconsidered" in sql.lower()


def test_render_fix_sql_quotes_dictionary_object_and_column_names():
    obj_result = ObjectScanResult(
        DbObject('A"B', 'C"D', "TABLE"),
        [ColumnScan('E"F', "VARCHAR2", 1, None)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    assert '"A""B"."C""D"' in sql
    assert '"E""F"' in sql


def test_render_fix_sql_defaults_to_row_grouping():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 1, None, flagged_rowids=("AAAv1sAAEAAAAB4AAA",))],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result)

    assert "WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');" in sql


def test_render_fix_sql_row_grouping_emits_rowid_scoped_update_and_never_the_old_predicate():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 1, None, flagged_rowids=("AAAv1sAAEAAAAB4AAA",))],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    quoted = quote_identifier("NAME")
    expected_statement = "UPDATE \"APP\".\"T1\" SET {0} = CONVERT({0}, 'US7ASCII') WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');".format(
        quoted
    )
    assert expected_statement in sql
    assert "LENGTHB" not in sql
    assert MULTIBYTE_PREDICATE_TEMPLATE.format(quoted) not in sql


def test_render_fix_sql_row_grouping_consolidates_shared_rowid_across_columns():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan(
                "NAME", "VARCHAR2", 2, None,
                flagged_rowids=("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAB"),
            ),
            ColumnScan(
                "ADDR", "VARCHAR2", 2, None,
                flagged_rowids=("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAC"),
            ),
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    # Rows ordered ascending by ROWID: AAA (shared), AAB (NAME only), AAC (ADDR only).
    assert update_statements == [
        'UPDATE "APP"."T1" SET "NAME" = CONVERT("NAME", \'US7ASCII\'), "ADDR" = CONVERT("ADDR", \'US7ASCII\') '
        "WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');",
        'UPDATE "APP"."T1" SET "NAME" = CONVERT("NAME", \'US7ASCII\') WHERE ROWID = CHARTOROWID(\'AAAv1sAAEAAAAB4AAB\');',
        'UPDATE "APP"."T1" SET "ADDR" = CONVERT("ADDR", \'US7ASCII\') WHERE ROWID = CHARTOROWID(\'AAAv1sAAEAAAAB4AAC\');',
    ]


def test_render_fix_sql_row_grouping_orders_updates_by_rowid_regardless_of_fetch_order():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 2, None, flagged_rowids=("AAAv1sAAEAAAAB4AAB", "AAAv1sAAEAAAAB4AAA"))],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert [stmt for stmt in update_statements] == [
        "UPDATE \"APP\".\"T1\" SET \"NAME\" = CONVERT(\"NAME\", 'US7ASCII') WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');",
        "UPDATE \"APP\".\"T1\" SET \"NAME\" = CONVERT(\"NAME\", 'US7ASCII') WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAB');",
    ]


def test_render_fix_sql_row_grouping_warns_and_skips_when_no_rowids_were_captured():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 3, None)],  # flagged_rowids defaults to ()
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    assert sql is not None
    assert not any(line.startswith("UPDATE ") for line in sql.splitlines())
    assert "WARNING" in sql
    assert "NAME" in sql
    assert "3" in sql


def test_render_fix_sql_row_grouping_skips_a_rowid_that_fails_format_validation():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 1, None, flagged_rowids=("not-a-rowid",))],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    assert "not-a-rowid" not in sql
    assert not any(line.startswith("UPDATE ") for line in sql.splitlines())
    assert "WARNING" in sql


def test_render_fix_sql_rejects_an_unknown_fix_grouping():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 1, None)],
        "exhaustive",
    )

    with pytest.raises(ValueError, match="fix_grouping"):
        render_fix_sql(obj_result, fix_grouping="bogus")


def test_write_fix_sql_writes_a_file_when_something_needs_fixing(tmp_path):
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 3, None, flagged_rowids=("AAAv1sAAEAAAAB4AAA",))],
        "exhaustive",
    )

    path = write_fix_sql(obj_result, tmp_path, timestamp=datetime(2026, 7, 27, 9, 5, 1))

    assert path == tmp_path / "2026-07-27-090501_fix_APP_T1.sql"
    assert path.exists()
    assert "UPDATE" in path.read_text(encoding="utf-8")


def test_write_fix_sql_writes_a_file_in_column_grouping_mode(tmp_path):
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 3, None)],
        "exhaustive",
    )

    path = write_fix_sql(
        obj_result, tmp_path, timestamp=datetime(2026, 7, 27, 9, 5, 1), fix_grouping="column"
    )

    assert path.exists()
    assert "UPDATE" in path.read_text(encoding="utf-8")


def test_write_fix_sql_uses_the_aware_utc_clock_when_timestamp_is_omitted(monkeypatch, tmp_path):
    monkeypatch.setattr(fixes, "datetime", _UtcOnlyClock)
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 3, None)],
        "exhaustive",
    )

    path = fixes.write_fix_sql(obj_result, tmp_path)

    assert path.name.startswith("2026-08-05-090000_")


def test_render_fix_sql_escapes_control_characters_in_comments():
    """A column name containing a newline must not be able to break out of the
    generated "--" comment and inject an uncommented line into the script.

    The raw name still legitimately appears, unescaped, inside the actual
    UPDATE statement quoted identifier -- that is correct (Oracle identifiers
    may contain newlines and it stays inside the quotes) and is not checked
    here; only the comment text is required to be clean.
    """
    name = "A" + chr(0x0A) + "PROMPT_INJECTED"
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan(name, "VARCHAR2", 1, None)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result)

    expected_comment = "-- Column A" + chr(0x5C) + "u000aPROMPT_INJECTED: 1 flagged row(s) at scan time"
    assert expected_comment in sql.splitlines()


def test_render_fix_sql_escapes_carriage_return_and_bidi_controls_in_comments():
    name = "A" + chr(0x0D) + "B" + chr(0x2028) + "C" + chr(0x202E) + "D"
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan(name, "VARCHAR2", 1, None)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result)
    comment_text = chr(0x0A).join(line for line in sql.splitlines() if line.startswith("--"))

    assert chr(0x0D) not in comment_text
    assert chr(0x2028) not in comment_text
    assert chr(0x202E) not in comment_text
    assert (chr(0x5C) + "u000d") in comment_text
    assert (chr(0x5C) + "u2028") in comment_text
    assert (chr(0x5C) + "u202e") in comment_text


def test_render_fix_sql_emits_set_define_off():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 3, None)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result)

    assert "SET DEFINE OFF" in sql.splitlines()


def test_write_fix_sql_writes_nothing_when_no_column_is_flagged(tmp_path):
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("ID", "NUMBER", None, None, "skipped", "unsupported data type")],
        "exhaustive",
    )

    path = write_fix_sql(obj_result, tmp_path, timestamp=datetime(2026, 7, 27, 9, 5, 1))

    assert path is None
    assert list(tmp_path.iterdir()) == []


# --- Mojibake repair -------------------------------------------------------


def test_render_fix_sql_row_grouping_splits_repair_and_convert_within_one_column():
    """A single column with some flagged rows that are mojibake and some
    that aren't must get the repair expression only for the mojibake rowids
    and CONVERT for the rest, within one UPDATE per rowid."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan(
                "NAME", "VARCHAR2", 3, None,
                flagged_rowids=("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAB", "AAAv1sAAEAAAAB4AAC"),
                mojibake_count=2,
                mojibake_rowids=("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAB"),
            ),
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    quoted = quote_identifier("NAME")
    repair_expr = MOJIBAKE_REPAIR_EXPR_TEMPLATE.format(quoted)
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert update_statements == [
        "UPDATE \"APP\".\"T1\" SET {0} = {1} WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');".format(
            quoted, repair_expr
        ),
        "UPDATE \"APP\".\"T1\" SET {0} = {1} WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAB');".format(
            quoted, repair_expr
        ),
        "UPDATE \"APP\".\"T1\" SET {0} = CONVERT({0}, 'US7ASCII') WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAC');".format(
            quoted
        ),
    ]


def test_render_fix_sql_row_grouping_one_row_gets_a_repaired_column_and_a_converted_column():
    """Edge case called out in the task brief: a single row has two flagged
    columns, only one of which is mojibake for that row -- the consolidated
    SET clause must use the repair expression for one column and CONVERT for
    the other, in the same UPDATE statement."""
    rowid = "AAAv1sAAEAAAAB4AAA"
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan(
                "NAME", "VARCHAR2", 1, None,
                flagged_rowids=(rowid,), mojibake_count=1, mojibake_rowids=(rowid,),
            ),
            ColumnScan(
                "ADDR", "VARCHAR2", 1, None,
                flagged_rowids=(rowid,),  # mojibake_count defaults to None -- plain multibyte only
            ),
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    quoted_name = quote_identifier("NAME")
    quoted_addr = quote_identifier("ADDR")
    repair_expr = MOJIBAKE_REPAIR_EXPR_TEMPLATE.format(quoted_name)
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert update_statements == [
        "UPDATE \"APP\".\"T1\" SET {0} = {1}, {2} = CONVERT({2}, 'US7ASCII') WHERE ROWID = CHARTOROWID('{3}');".format(
            quoted_name, repair_expr, quoted_addr, rowid
        ),
    ]


def test_render_fix_sql_column_grouping_emits_convert_before_repair_for_mixed_column():
    """Finding 1 (Critical): a column with mojibake_count > 0 but
    multibyte_count > mojibake_count emits a CONVERT UPDATE scoped to
    "multibyte AND NOT mojibake" and a repair UPDATE scoped to the mojibake
    predicate. The CONVERT statement MUST come first: those WHERE clauses are
    evaluated at run time, and a repaired value is still multibyte and no
    longer mojibake -- so a CONVERT emitted second would re-match and lossily
    flatten every row the repair had just fixed."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 5, None, mojibake_count=2)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    quoted = quote_identifier("NAME")
    mojibake_predicate = MOJIBAKE_PREDICATE_TEMPLATE.format(quoted)
    repair_expr = MOJIBAKE_REPAIR_EXPR_TEMPLATE.format(quoted)
    convert_predicate = "({0}) AND NOT ({1})".format(MULTIBYTE_PREDICATE_TEMPLATE.format(quoted), mojibake_predicate)
    convert_statement = "UPDATE \"APP\".\"T1\" SET {0} = CONVERT({0}, 'US7ASCII') WHERE {1};".format(
        quoted, convert_predicate
    )
    repair_statement = "UPDATE \"APP\".\"T1\" SET {0} = {1} WHERE {2};".format(
        quoted, repair_expr, mojibake_predicate
    )
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert update_statements == [convert_statement, repair_statement]
    # Assert on file position too, not just list order, so the guarantee
    # holds for however the surrounding comments are laid out.
    assert sql.index(convert_statement) < sql.index(repair_statement)


def test_render_fix_sql_header_warns_that_statements_must_run_in_file_order():
    """The ordering in the file only protects the data if it is preserved
    when a human runs it, so the mojibake header block must say so."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 5, None, mojibake_count=2)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    assert "RUN THE STATEMENTS BELOW IN FILE ORDER" in sql
    # Only one mojibake header block -- the note extends it, never duplicates it.
    assert sql.count("MOJIBAKE REPAIR") == 1


def test_render_fix_sql_column_grouping_omits_convert_statement_when_all_flagged_rows_are_mojibake():
    """When multibyte_count == mojibake_count there are no non-mojibake rows
    left for CONVERT to touch, so only the repair statement should appear."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 2, None, mojibake_count=2)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    quoted = quote_identifier("NAME")
    mojibake_predicate = MOJIBAKE_PREDICATE_TEMPLATE.format(quoted)
    repair_expr = MOJIBAKE_REPAIR_EXPR_TEMPLATE.format(quoted)
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert update_statements == [
        "UPDATE \"APP\".\"T1\" SET {0} = {1} WHERE {2};".format(quoted, repair_expr, mojibake_predicate),
    ]
    assert not any("CONVERT" in stmt for stmt in update_statements)


def test_render_fix_sql_column_grouping_never_uses_the_reverted_convert_alternative():
    """The brief explicitly rules out CONVERT(col, 'AL32UTF8', 'WE8MSWIN1252')
    as a repair expression -- it was tested live and confirmed to make the
    corruption worse. Lock in that it never appears in generated output."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 2, None, mojibake_count=2)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    assert "'AL32UTF8', 'WE8MSWIN1252'" not in sql
    assert "UTL_I18N.RAW_TO_CHAR" in sql


def test_render_fix_sql_column_grouping_mojibake_count_zero_is_byte_for_byte_unchanged():
    """Backward-compatibility anchor: a column with mojibake_count=0 (an
    explicit zero, distinct from the default None) must render identically
    to the pre-mojibake-feature CONVERT-only statement."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 3, None, mojibake_count=0)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    quoted = quote_identifier("NAME")
    expected_predicate = MULTIBYTE_PREDICATE_TEMPLATE.format(quoted)
    expected_statement = 'UPDATE "APP"."T1" SET {0} = CONVERT({0}, \'US7ASCII\') WHERE {1};'.format(
        quoted, expected_predicate
    )
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert update_statements == [expected_statement]
    assert "MOJIBAKE" not in sql
    assert "UTL_I18N" not in sql


def test_render_fix_sql_row_grouping_mojibake_count_none_is_byte_for_byte_unchanged():
    """Backward-compatibility anchor for row grouping: the default
    mojibake_count=None/mojibake_rowids=() must produce the exact same
    CONVERT-only UPDATE as before this feature existed."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan(
                "NAME", "VARCHAR2", 2, None,
                flagged_rowids=("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAB"),
            ),
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    quoted = quote_identifier("NAME")
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert update_statements == [
        "UPDATE \"APP\".\"T1\" SET {0} = CONVERT({0}, 'US7ASCII') WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');".format(
            quoted
        ),
        "UPDATE \"APP\".\"T1\" SET {0} = CONVERT({0}, 'US7ASCII') WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAB');".format(
            quoted
        ),
    ]
    assert "MOJIBAKE" not in sql
    assert "UTL_I18N" not in sql


def test_render_fix_sql_header_omits_mojibake_note_when_nothing_is_mojibake():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 3, None)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result)

    assert "MOJIBAKE REPAIR" not in sql


def test_render_fix_sql_header_includes_mojibake_note_and_nls_charset_check_when_mojibake_present():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [ColumnScan("NAME", "VARCHAR2", 2, None, mojibake_count=2)],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    assert "MOJIBAKE REPAIR" in sql
    assert "NLS_CHARACTERSET" in sql
    assert "AL32UTF8" in sql


def test_render_by_row_warns_about_mojibake_rowids_missing_from_the_flagged_set():
    """Finding 5: scan._scan_one fetches flagged and mojibake ROWIDs with two
    separate ROWNUM-bounded statements and no ORDER BY, so under a bounded
    scan they can see different rows. A mojibake ROWID with no matching
    flagged ROWID is dropped by the per-column loop -- a missed repair, which
    must not be silent."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan(
                "NAME", "VARCHAR2", 1, None,
                flagged_rowids=("AAAv1sAAEAAAAB4AAA",),
                mojibake_count=2,
                mojibake_rowids=("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAZ"),
            ),
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    assert "-- WARNING: Column NAME had 1 mojibake ROWID(s) with no matching flagged ROWID" in sql
    # The one rowid present in both sets is still repaired, not skipped.
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert len(update_statements) == 1
    assert "AAAv1sAAEAAAAB4AAA" in update_statements[0]
    assert "UTL_I18N.RAW_TO_CHAR" in update_statements[0]
    assert "AAAv1sAAEAAAAB4AAZ" not in update_statements[0]


# --- Partial / truncated multibyte byte-strip ----------------------------


def _truncated_col(name="NAME", rows=()):
    return ColumnScan(name, "VARCHAR2", 0, None, truncated_count=len(rows), truncated_rows=tuple(rows))


def test_render_fix_sql_row_grouping_emits_a_byte_strip_update_for_a_truncated_row():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [_truncated_col(rows=[TruncatedRow("AAAv1sAAEAAAAB4AAA", 3, "C3", "unexpected end of data")])],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    quoted = quote_identifier("NAME")
    expected = (
        "UPDATE \"APP\".\"T1\" SET {0} = "
        "UTL_RAW.CAST_TO_VARCHAR2(UTL_RAW.SUBSTR(UTL_RAW.CAST_TO_RAW({0}), 1, 3)) "
        "WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');".format(quoted)
    )
    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert update_statements == [expected]


def test_render_fix_sql_row_grouping_truncated_row_with_zero_valid_prefix_sets_null():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [_truncated_col(rows=[TruncatedRow("AAAv1sAAEAAAAB4AAA", 0, "80", "invalid start byte")])],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    quoted = quote_identifier("NAME")
    assert (
        "UPDATE \"APP\".\"T1\" SET {0} = NULL WHERE ROWID = CHARTOROWID('AAAv1sAAEAAAAB4AAA');".format(quoted)
        in sql
    )


def test_render_fix_sql_row_grouping_byte_strip_wins_over_convert_for_a_shared_rowid():
    """A row that is both LENGTHB>LENGTH multibyte and has a truncated tail
    must be byte-stripped, not CONVERT-flattened."""
    rowid = "AAAv1sAAEAAAAB4AAA"
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan(
                "NAME", "VARCHAR2", 1, None,
                flagged_rowids=(rowid,),
                truncated_count=1,
                truncated_rows=(TruncatedRow(rowid, 4, "E4 B8", "unexpected end of data"),),
            )
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    update_statements = [line for line in sql.splitlines() if line.startswith("UPDATE ")]
    assert len(update_statements) == 1
    assert "UTL_RAW.CAST_TO_RAW" in update_statements[0]
    assert "CONVERT(" not in update_statements[0]


def test_render_fix_sql_column_grouping_emits_a_comment_block_and_no_update_for_truncated():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [_truncated_col(rows=[TruncatedRow("AAAv1sAAEAAAAB4AAA", 3, "C3", "unexpected end of data")])],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="column")

    assert not any(line.startswith("UPDATE ") for line in sql.splitlines())
    assert "ORA-29275" in sql
    assert "--fix-grouping row" in sql
    assert "AAAv1sAAEAAAAB4AAA" in sql


def test_render_fix_sql_header_warns_that_the_byte_strip_is_lossy_when_truncated_present():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [_truncated_col(rows=[TruncatedRow("AAAv1sAAEAAAAB4AAA", 3, "C3", "unexpected end of data")])],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    assert "byte" in sql.lower() and "strip" in sql.lower()
    assert "DO NOT RUN WITHOUT REVIEW" in sql


def test_render_fix_sql_returns_content_for_a_truncated_only_column():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [_truncated_col(rows=[TruncatedRow("AAAv1sAAEAAAAB4AAA", 3, "C3", "unexpected end of data")])],
        "exhaustive",
    )

    assert render_fix_sql(obj_result, fix_grouping="row") is not None


def test_render_fix_sql_row_grouping_skips_a_truncated_rowid_that_fails_format_validation():
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [_truncated_col(rows=[TruncatedRow("not-a-rowid", 3, "C3", "unexpected end of data")])],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    assert "not-a-rowid" not in sql
    assert not any(line.startswith("UPDATE ") for line in sql.splitlines())
    assert "WARNING" in sql


def test_render_by_row_emits_no_orphan_warning_when_mojibake_rowids_are_a_subset():
    """The invariant holds on an unbounded scan, so the common case must stay
    warning-free."""
    obj_result = ObjectScanResult(
        DbObject("APP", "T1", "TABLE"),
        [
            ColumnScan(
                "NAME", "VARCHAR2", 2, None,
                flagged_rowids=("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAB"),
                mojibake_count=1,
                mojibake_rowids=("AAAv1sAAEAAAAB4AAA",),
            ),
        ],
        "exhaustive",
    )

    sql = render_fix_sql(obj_result, fix_grouping="row")

    assert "no matching flagged ROWID" not in sql
