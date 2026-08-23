from types import SimpleNamespace

import oracledb

from mbscan.oracle.metadata import DbObject, quote_identifier
from mbscan.scan import (
    MOJIBAKE_PREDICATE_TEMPLATE,
    MojibakeSample,
    MultibyteChar,
    ScanSettings,
    _extract_multibyte_chars,
    _repair_mojibake_samples,
    _scan_one,
    safe_object_sql,
    scan_object,
    scan_objects,
)


class FakeCursor:
    """Routes column-listing and count queries to predetermined results,
    keyed by a substring of the SQL."""

    def __init__(self, results_by_keyword):
        self._results_by_keyword = results_by_keyword
        self._last_rows = []
        self.executions = []

    def execute(self, sql, parameters=None):
        self.executions.append(sql)
        for keyword, rows in self._results_by_keyword.items():
            if keyword in sql:
                self._last_rows = rows
                return
        self._last_rows = []

    def fetchall(self):
        return self._last_rows

    def fetchone(self):
        return self._last_rows[0] if self._last_rows else None


def test_scan_settings_rejects_invalid_scope_and_limit():
    for kwargs in (
        {"scope": "bad"},
        {"row_limit": 0},
        {"sample_row_limit": 0},
        {"sample_char_limit": 0},
        {"mojibake_sample_limit": 0},
    ):
        try:
            ScanSettings(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid settings accepted")


def test_safe_object_sql_quotes_dictionary_object_names():
    assert safe_object_sql(DbObject('A"B', 'C"D', "TABLE")) == '"A""B"."C""D"'


def test_scan_one_non_ascii_predicate_avoids_the_invalid_ascii_posix_class():
    """Oracle's REGEXP_LIKE does not support a POSIX [:ASCII:] character
    class (ORA-12729: invalid character class in regular expression) --
    confirmed against a live Oracle Database Free container. The emitted
    SQL must not contain that literal."""
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(include_non_ascii=True))

    non_ascii_sql = [sql for sql in cursor.executions if "COUNT(*)" in sql][1]
    assert "[:ASCII:]" not in non_ascii_sql


def test_scan_one_progress_factory_receives_columns_total_and_desc_and_output_is_unaffected():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )
    calls = []

    def spy_progress(columns, total, desc):
        calls.append((list(columns), total, desc))
        return columns

    with_progress = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(), progress=spy_progress)
    without_progress = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings())

    assert calls == [([("VALUE", "VARCHAR2")], 1, "APP.T1")]
    assert with_progress.columns == without_progress.columns


def test_scan_one_progress_factory_handles_zero_columns():
    cursor = FakeCursor({"all_tab_columns": []})
    calls = []

    def spy_progress(columns, total, desc):
        calls.append((list(columns), total, desc))
        return columns

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(), progress=spy_progress)

    assert calls == [([], 0, "APP.T1")]
    assert result.columns == []


def test_scan_omits_non_text_and_lob_columns():
    """A change that reintroduces skipped NUMBER/CLOB rows must fail this test."""
    cursor = FakeCursor(
        {
            "all_tab_columns": [
                ("NAME", "VARCHAR2"),
                ("AGE", "NUMBER"),
                ("NOTES", "CLOB"),
            ],
            "COUNT(*)": [(0,)],
        }
    )

    result = scan_object(cursor, DbObject("HR", "EMPLOYEES", "TABLE"), ScanSettings())

    assert [column.name for column in result.objects[0].columns] == ["NAME"]


def test_scan_objects_includes_every_selected_object_in_order():
    """A batch implementation that drops or reorders selections must fail this test."""
    employees = DbObject("HR", "EMPLOYEES", "TABLE")
    departments = DbObject("HR", "DEPARTMENTS", "TABLE")
    cursor = FakeCursor(
        {
            "all_tab_columns": [("NAME", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = scan_objects(cursor, [employees, departments], ScanSettings())

    assert [item.object.name for item in result.objects] == ["EMPLOYEES", "DEPARTMENTS"]
    assert result.selected == (employees, departments)


def test_scan_object_forwards_progress_to_every_scan_one_call_including_dependencies():
    selected = DbObject("APP", "V1", "VIEW")
    cursor = FakeCursor(
        {
            "all_dependencies": [("APP", "T1", "TABLE", None)],
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )
    descriptions = []

    def spy_progress(columns, total, desc):
        descriptions.append(desc)
        return columns

    scan_object(cursor, selected, ScanSettings(scope="selected-and-sources"), progress=spy_progress)

    assert descriptions == ["APP.V1", "APP.T1"]


def test_scan_one_samples_multibyte_characters_when_flagged():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(2,)],
            "ROWNUM <= :sample_limit": [("Café",), ("日本語",)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings())

    col = result.columns[0]
    chars = {sample.char for sample in col.multibyte_samples}
    assert "é" in chars
    assert "日" in chars
    sample_by_char = {sample.char: sample for sample in col.multibyte_samples}
    assert sample_by_char["é"].codepoint == "U+00E9"
    assert sample_by_char["é"].name == "LATIN SMALL LETTER E WITH ACUTE"


def test_scan_one_skips_sampling_when_count_is_zero():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings())

    assert result.columns[0].multibyte_samples == ()
    assert not any("sample_limit" in sql for sql in cursor.executions)


class _RaisingCursor(FakeCursor):
    """Like FakeCursor, but raises on any SQL containing raise_on_keyword."""

    def __init__(self, results_by_keyword, raise_on_keyword, error):
        super().__init__(results_by_keyword)
        self._raise_on_keyword = raise_on_keyword
        self._error = error

    def execute(self, sql, parameters=None):
        if self._raise_on_keyword in sql:
            raise self._error
        super().execute(sql, parameters)


def test_scan_one_fetches_rowids_instead_of_count_when_capture_fix_rowids_is_true():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "SELECT ROWID FROM": [("AAAv1sAAEAAAAB4AAA",), ("AAAv1sAAEAAAAB4AAB",)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(capture_fix_rowids=True))

    col = result.columns[0]
    assert col.flagged_rowids == ("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAB")
    assert col.multibyte_count == 2
    assert not any("COUNT(*)" in sql for sql in cursor.executions)


def test_scan_one_fetches_rowids_bounded_by_row_limit():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "AS rid": [("AAAv1sAAEAAAAB4AAA",)],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(capture_fix_rowids=True, row_limit=100),
    )

    col = result.columns[0]
    assert col.flagged_rowids == ("AAAv1sAAEAAAAB4AAA",)
    assert col.multibyte_count == 1
    rowid_sql = next(sql for sql in cursor.executions if "AS rid" in sql)
    assert "ROWNUM <= :row_limit" in rowid_sql


def test_scan_one_default_capture_fix_rowids_false_preserves_count_only_behavior():
    """Regression guard: the flag-off path must be byte-for-byte unchanged
    from before ROWID capture existed."""
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(2,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings())

    col = result.columns[0]
    assert col.flagged_rowids == ()
    assert col.multibyte_count == 2


def test_scan_one_degrades_to_error_status_when_rowid_fetch_fails():
    error = oracledb.Error(SimpleNamespace(full_code="ORA-01446", code=1446))
    cursor = _RaisingCursor(
        {"all_tab_columns": [("VALUE", "VARCHAR2")]},
        raise_on_keyword="SELECT ROWID FROM",
        error=error,
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(capture_fix_rowids=True))

    col = result.columns[0]
    assert col.status == "error"
    assert col.reason == "Oracle error 1446"


def test_extract_multibyte_chars_truncates_at_char_limit():
    samples, truncated = _extract_multibyte_chars(["Café", "日本語"], char_limit=1)

    assert len(samples) == 1
    assert truncated is True


def test_extract_multibyte_chars_skips_ascii_and_duplicates():
    samples, truncated = _extract_multibyte_chars(["café", "café"], char_limit=20)

    assert samples == (MultibyteChar("é", "U+00E9", "LATIN SMALL LETTER E WITH ACUTE"),)
    assert truncated is False


def test_mojibake_predicate_template_format_succeeds_with_literal_quantifier():
    """The 3-byte branch's Oracle regex quantifier must survive the
    constant's own .format() call in _scan_one as a literal {2}, not the
    {{2}} escape it's written with in source.

    The template now references {0} four times (two REGEXP_LIKE branches
    plus two in the cp1252 round-trip guard); repeated positional references
    are legal in str.format(), but a single .format(quoted) call must still
    substitute every one of them without IndexError."""
    quoted = quote_identifier("X")

    predicate = MOJIBAKE_PREDICATE_TEMPLATE.format(quoted)

    assert "{2}" in predicate
    assert "{{2}}" not in predicate
    assert "{0}" not in predicate
    assert MOJIBAKE_PREDICATE_TEMPLATE.count("{0}") == 4
    assert predicate.count(quoted) == 4


def test_mojibake_predicate_template_ands_a_cp1252_roundtrip_guard_onto_both_branches():
    """Finding 2 (Critical): UTL_I18N.STRING_TO_RAW(col, 'WE8MSWIN1252')
    substitutes byte 0xBF for characters outside cp1252, so a value holding
    genuine mojibake next to a correctly-stored non-cp1252 character would
    "repair" into invalid UTF-8. The guard must be ANDed once onto the whole
    (branch1 OR branch2) group -- not per-branch -- so detection, counts,
    ROWIDs and both fix modes inherit one consistent exclusion."""
    quoted = quote_identifier("X")

    predicate = MOJIBAKE_PREDICATE_TEMPLATE.format(quoted)

    guard = (
        "{0} = UTL_I18N.RAW_TO_CHAR(UTL_I18N.STRING_TO_RAW({0}, 'WE8MSWIN1252'), 'WE8MSWIN1252')"
    ).format(quoted)
    assert predicate.count(guard) == 1
    assert predicate.endswith(guard + ")")
    # The OR group is parenthesised and the guard sits outside it, so the
    # AND binds to the whole group rather than only the second branch.
    assert predicate.startswith("((REGEXP_LIKE(")
    or_group, _, tail = predicate.partition(" AND " + guard)
    assert tail == ")"
    assert or_group.count(" OR REGEXP_LIKE(") == 1
    assert or_group.endswith("))")


def test_repair_mojibake_samples_roundtrips_two_byte_utf8_misread_as_cp1252():
    original = chr(0xE9)  # LATIN SMALL LETTER E WITH ACUTE -- 2 UTF-8 bytes
    garbled = original.encode("utf-8").decode("cp1252")

    samples, truncated, skipped = _repair_mojibake_samples([garbled], limit=10)

    assert samples == (MojibakeSample(garbled=garbled, repaired=original),)
    assert truncated is False


def test_repair_mojibake_samples_roundtrips_three_byte_utf8_misread_as_cp1252():
    original = chr(0x65E5)  # CJK UNIFIED IDEOGRAPH-65E5 -- 3 UTF-8 bytes
    garbled = original.encode("utf-8").decode("cp1252")

    samples, truncated, skipped = _repair_mojibake_samples([garbled], limit=10)

    assert samples == (MojibakeSample(garbled=garbled, repaired=original),)
    assert truncated is False


def test_repair_mojibake_samples_skips_values_that_dont_round_trip():
    """UnicodeEncodeError (a genuinely different multibyte character lives
    in the value) and UnicodeDecodeError (the predicate matched something
    that isn't real mojibake) must both be skipped, never raised -- but the
    skip is now counted so the report can explain the shortfall instead of
    silently rendering fewer pairs than mojibake_count claims."""
    not_encodable_in_cp1252 = chr(0x65E5)
    incomplete_utf8_lead_byte = chr(0xE9)

    samples, truncated, skipped = _repair_mojibake_samples(
        [not_encodable_in_cp1252, incomplete_utf8_lead_byte], limit=10
    )

    assert samples == ()
    assert truncated is False
    assert skipped == 2


def test_repair_mojibake_samples_truncates_at_limit():
    original_a = chr(0xE9)
    original_b = chr(0xF1)  # LATIN SMALL LETTER N WITH TILDE -- 2 UTF-8 bytes
    garbled_a = original_a.encode("utf-8").decode("cp1252")
    garbled_b = original_b.encode("utf-8").decode("cp1252")

    samples, truncated, skipped = _repair_mojibake_samples([garbled_a, garbled_b], limit=1)

    assert samples == (MojibakeSample(garbled=garbled_a, repaired=original_a),)
    assert truncated is True
    assert skipped == 0


def test_scan_one_threads_the_skipped_preview_count_onto_the_column_scan():
    """Finding 4: a value the Python-side repair can't preview must surface
    as mojibake_samples_skipped, so mojibake_count and the number of
    rendered sample pairs can never silently disagree."""
    original = chr(0xE9)
    garbled = original.encode("utf-8").decode("cp1252")
    unpreviewable = chr(0x65E5)  # real CJK -- not encodable in cp1252
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "ROWNUM <= :sample_limit": [(garbled,), (unpreviewable,)],
            "UNISTR": [(2,)],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(detect_mojibake=True))

    col = result.columns[0]
    assert col.mojibake_count == 2
    assert col.mojibake_samples == (MojibakeSample(garbled=garbled, repaired=original),)
    assert col.mojibake_samples_skipped == 1


def test_scan_one_counts_mojibake_when_detect_mojibake_is_true():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "UNISTR": [(0,)],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(detect_mojibake=True))

    col = result.columns[0]
    assert col.mojibake_count == 0
    assert col.mojibake_rowids == ()
    assert col.mojibake_samples == ()
    mojibake_sql = [sql for sql in cursor.executions if "UNISTR" in sql]
    assert len(mojibake_sql) == 1
    assert not any("sample_limit" in sql for sql in cursor.executions)


def test_scan_one_samples_and_repairs_mojibake_when_flagged():
    original = chr(0xE9)
    garbled = original.encode("utf-8").decode("cp1252")
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "ROWNUM <= :sample_limit": [(garbled,)],
            "UNISTR": [(1,)],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings(detect_mojibake=True))

    col = result.columns[0]
    assert col.mojibake_count == 1
    assert col.mojibake_samples == (MojibakeSample(garbled=garbled, repaired=original),)
    assert col.mojibake_samples_truncated is False


def test_scan_one_fetches_mojibake_rowids_when_capture_mojibake_rowids_is_true():
    original = chr(0xE9)
    garbled = original.encode("utf-8").decode("cp1252")
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
            "SELECT ROWID FROM": [("AAAv1sAAEAAAAB4AAA",), ("AAAv1sAAEAAAAB4AAB",)],
            "ROWNUM <= :sample_limit": [(garbled,)],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_mojibake=True, capture_mojibake_rowids=True),
    )

    col = result.columns[0]
    assert col.mojibake_rowids == ("AAAv1sAAEAAAAB4AAA", "AAAv1sAAEAAAAB4AAB")
    assert col.mojibake_count == 2
    assert col.mojibake_samples == (MojibakeSample(garbled=garbled, repaired=original),)


def test_scan_one_default_detect_mojibake_false_preserves_prior_behavior():
    """Regression guard: detect_mojibake defaults to False and must leave
    _scan_one's SQL and result shape byte-for-byte unchanged from before
    the mojibake feature existed -- no UNISTR predicate is ever built, and
    the new mojibake_* fields stay at their inert defaults."""
    accented = "Caf" + chr(0xE9)  # e-acute, i.e. "Cafe" + LATIN SMALL LETTER E WITH ACUTE
    cjk = chr(0x65E5) + chr(0x672C) + chr(0x8A9E)  # three CJK ideographs (sun/book/language)
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(2,)],
            "ROWNUM <= :sample_limit": [(accented,), (cjk,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings())

    assert not any("UNISTR" in sql for sql in cursor.executions)
    col = result.columns[0]
    assert col.multibyte_count == 2
    assert col.mojibake_count is None
    assert col.mojibake_rowids == ()
    assert col.mojibake_samples == ()
    assert col.mojibake_samples_truncated is False
    assert col.mojibake_samples_skipped == 0
