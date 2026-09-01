from types import SimpleNamespace

import oracledb

from mbscan.oracle.metadata import DbObject, quote_identifier
from mbscan.scan import (
    MOJIBAKE_PREDICATE_TEMPLATE,
    MojibakeSample,
    MultibyteChar,
    ScanSettings,
    TRUNCATION_CANDIDATE_PREDICATE_TEMPLATE,
    TruncatedRow,
    _extract_multibyte_chars,
    _parse_dump_decimal_bytes,
    _repair_mojibake_samples,
    _scan_one,
    find_incomplete_utf8,
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

    The template now references {0} five times (two REGEXP_LIKE branches plus
    three in the cp1252 round-trip guard: its LENGTH gate and two in the
    equality); repeated positional references are legal in str.format(), but a
    single .format(quoted) call must still substitute every one of them without
    IndexError."""
    quoted = quote_identifier("X")

    predicate = MOJIBAKE_PREDICATE_TEMPLATE.format(quoted)

    assert "{2}" in predicate
    assert "{{2}}" not in predicate
    assert "{0}" not in predicate
    assert MOJIBAKE_PREDICATE_TEMPLATE.count("{0}") == 5
    assert predicate.count(quoted) == 5


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
        "(LENGTH({0}) <= 2000 AND {0} = "
        "UTL_I18N.RAW_TO_CHAR(UTL_I18N.STRING_TO_RAW({0}, 'WE8MSWIN1252'), 'WE8MSWIN1252'))"
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


def test_find_incomplete_utf8_accepts_a_valid_two_byte_sequence():
    assert find_incomplete_utf8("café".encode("utf-8"), strict=True) is None


def test_find_incomplete_utf8_flags_a_lead_byte_cut_off_at_end_of_value():
    """The SAS-DI signature: 'caf' + a lone 0xC3 -- the second byte of the
    e-acute sequence was sliced off. The reported offset is the start of the
    broken sequence, which is also the safe byte length to truncate to."""
    offset, bad_bytes, reason = find_incomplete_utf8(b"caf\xc3", strict=True)

    assert offset == 3
    assert bad_bytes == b"\xc3"
    assert "end of data" in reason


def test_find_incomplete_utf8_flags_a_three_byte_sequence_missing_its_last_byte():
    offset, bad_bytes, reason = find_incomplete_utf8(b"\xe4\xb8", strict=True)

    assert offset == 0
    assert bad_bytes == b"\xe4\xb8"


def test_find_incomplete_utf8_flags_an_orphan_continuation_byte():
    offset, bad_bytes, _ = find_incomplete_utf8(b"ab\x80cd", strict=True)

    assert offset == 2
    assert bad_bytes == b"\x80"


def test_find_incomplete_utf8_accepts_a_valid_four_byte_sequence_in_both_modes():
    emoji = "\U0001f4a9".encode("utf-8")

    assert find_incomplete_utf8(emoji, strict=True) is None
    assert find_incomplete_utf8(emoji, strict=False) is None


def test_find_incomplete_utf8_accepts_pure_ascii():
    assert find_incomplete_utf8(b"hello world", strict=True) is None


def test_find_incomplete_utf8_lenient_mode_accepts_a_cesu8_surrogate_pair():
    """On a UTF8 (CESU-8) database a supplementary character is stored as two
    3-byte surrogate sequences. Strict UTF-8 rejects them; lenient mode must
    not, or every emoji row on such a database is a false positive."""
    cesu8_pile_of_poo = b"\xed\xa0\xbd\xed\xb2\xa9"

    assert find_incomplete_utf8(cesu8_pile_of_poo, strict=False) is None
    assert find_incomplete_utf8(cesu8_pile_of_poo, strict=True) is not None


def test_find_incomplete_utf8_lenient_mode_still_flags_a_truncated_tail():
    offset, _, reason = find_incomplete_utf8(b"ok\xe4\xb8", strict=False)

    assert offset == 2
    assert "end of data" in reason


def test_scan_one_flags_a_partial_multibyte_row_in_strict_mode():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
            "CAST_TO_RAW": [("AAAv1sAAEAAAAB4AAA", 4, b"caf\xc3")],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    col = result.columns[0]
    assert col.truncated_count == 1
    row = col.truncated_rows[0]
    assert row.rowid == "AAAv1sAAEAAAAB4AAA"
    assert row.valid_prefix_bytes == 3
    assert row.bad_bytes_hex == "C3"
    assert "end of data" in row.reason


def test_truncation_candidate_predicate_catches_both_truncation_shapes():
    """Verified live against Oracle 23 AL32UTF8: a value ending in a lone lead
    byte is not seen as a non-ASCII *character* by REGEXP_LIKE, so the regex
    alone misses trailing truncation -- the exact SAS-DI signature. A
    mid-string orphan continuation byte, conversely, keeps LENGTHB == LENGTH.
    The predicate must OR a byte-vs-char length test with the non-ASCII regex
    so both shapes become candidates."""
    predicate = TRUNCATION_CANDIDATE_PREDICATE_TEMPLATE.format(quote_identifier("V"))

    assert "LENGTHB(" in predicate and "LENGTH(" in predicate
    assert "REGEXP_LIKE(" in predicate
    assert " OR " in predicate
    # US7ASCII CONVERT must not be used here: it raises ORA-12703 on a value
    # that holds an incomplete multibyte sequence.
    assert "US7ASCII" not in predicate


def test_detect_truncated_is_exclusive_and_skips_every_other_check():
    """When detect_truncated is on it is the ONLY thing the scan looks for --
    no multibyte count, no mojibake, no non-ASCII, no sampling."""
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(9,)],
            "CAST_TO_RAW": [("AAAv1sAAEAAAAB4AAA", 4, b"caf\xc3")],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(
            detect_truncated=True,
            detect_mojibake=True,
            include_non_ascii=True,
            capture_fix_rowids=True,
        ),
        truncation_mode="strict",
    )

    col = result.columns[0]
    assert col.truncated_count == 1
    assert col.multibyte_count is None
    assert col.mojibake_count is None
    assert col.non_ascii_count is None
    assert not any("COUNT(*)" in sql for sql in cursor.executions)
    assert not any("UNISTR" in sql for sql in cursor.executions)
    assert not any("SELECT ROWID FROM" in sql for sql in cursor.executions)


def test_scan_one_partial_multibyte_ignores_valid_multibyte_rows():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
            "CAST_TO_RAW": [
                ("r1", 5, "café".encode("utf-8")),
                ("r2", 9, "日本語".encode("utf-8")),
            ],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    col = result.columns[0]
    assert col.truncated_count == 0
    assert col.truncated_rows == ()


def test_scan_one_default_detect_truncated_false_runs_no_raw_fetch():
    """Regression guard: with the flag off, no UTL_RAW fetch is issued and
    the new fields stay at their inert defaults."""
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings())

    col = result.columns[0]
    assert col.truncated_count is None
    assert col.truncated_rows == ()
    assert not any("CAST_TO_RAW" in sql for sql in cursor.executions)


def test_scan_one_partial_multibyte_skips_nvarchar2_columns_with_a_note():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "NVARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    assert result.columns[0].truncated_count is None
    assert any("NVARCHAR2" in note for note in result.notes)
    assert not any("CAST_TO_RAW" in sql for sql in cursor.executions)


def test_scan_objects_skips_partial_multibyte_check_on_a_non_utf8_database():
    cursor = FakeCursor(
        {
            "nls_database_parameters": [("WE8MSWIN1252",)],
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = scan_objects(
        cursor, [DbObject("APP", "T1", "TABLE")], ScanSettings(detect_truncated=True)
    )

    assert "WE8MSWIN1252" in result.truncated_skip_reason
    assert result.objects[0].columns[0].truncated_count is None
    assert not any("CAST_TO_RAW" in sql for sql in cursor.executions)


def test_scan_objects_runs_partial_multibyte_check_in_strict_mode_for_al32utf8():
    cursor = FakeCursor(
        {
            "nls_database_parameters": [("AL32UTF8",)],
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
            "CAST_TO_RAW": [("r1", 2, b"\xe4\xb8")],
        }
    )

    result = scan_objects(
        cursor, [DbObject("APP", "T1", "TABLE")], ScanSettings(detect_truncated=True)
    )

    col = result.objects[0].columns[0]
    assert col.truncated_count == 1
    assert result.charset == "AL32UTF8"
    assert result.truncated_skip_reason is None


def test_scan_objects_partial_multibyte_lenient_mode_accepts_cesu8_on_a_utf8_database():
    cursor = FakeCursor(
        {
            "nls_database_parameters": [("UTF8",)],
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "COUNT(*)": [(0,)],
            "CAST_TO_RAW": [("r1", 6, b"\xed\xa0\xbd\xed\xb2\xa9")],
        }
    )

    result = scan_objects(
        cursor, [DbObject("APP", "T1", "TABLE")], ScanSettings(detect_truncated=True)
    )

    assert result.objects[0].columns[0].truncated_count == 0


# --- Over-2000-byte partial-multibyte read (ORA-06502 fix) --------------------


class _DumpCursor(FakeCursor):
    """FakeCursor that also answers byte-range DUMP() windows from a stored
    byte string, honouring the :start_byte / :len_bytes binds so the chunked
    reconstruction path can be exercised without a real Oracle."""

    def __init__(self, results_by_keyword, dump_bytes=b"", charset="AL32UTF8"):
        super().__init__(results_by_keyword)
        self._dump_bytes = dump_bytes
        self._charset = charset

    def execute(self, sql, parameters=None):
        if "DUMP(" in sql:
            self.executions.append(sql)
            start = parameters["start_byte"]
            length = parameters["len_bytes"]
            window = self._dump_bytes[start - 1:start - 1 + length]
            tail = ",".join(str(byte) for byte in window)
            self._last_rows = [
                (
                    "Typ=1 Len={0} CharacterSet={1}: {2}".format(
                        len(self._dump_bytes), self._charset, tail
                    ),
                )
            ]
            return
        super().execute(sql, parameters)


def test_truncation_main_query_guards_cast_to_raw_with_a_lengthb_case():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "CAST_TO_RAW": [("r1", 4, b"caf\xc3")],
        }
    )

    _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    sql = next(s for s in cursor.executions if "CAST_TO_RAW" in s)
    assert "CASE WHEN LENGTHB(" in sql
    assert "<= 2000" in sql
    assert "UTL_RAW.CAST_TO_RAW(" in sql
    # One LENGTHB for the projected byte length, one inside the CASE guard.
    assert sql.count("LENGTHB(") >= 2


def test_truncation_reads_small_values_inline_without_dump():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "CAST_TO_RAW": [("r1", 4, b"caf\xc3")],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    col = result.columns[0]
    assert col.truncated_count == 1
    assert col.truncated_rows[0].valid_prefix_bytes == 3
    assert not any("DUMP(" in sql for sql in cursor.executions)


def test_truncation_reconstructs_over_limit_value_via_dump_windows():
    payload = b"a" * 2001 + b"\xc3"  # clean ASCII prefix + lone lead byte
    cursor = _DumpCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            # CASE guard returns NULL for the >2000-byte value.
            "CAST_TO_RAW": [("r1", len(payload), None)],
        },
        dump_bytes=payload,
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    col = result.columns[0]
    assert col.truncated_count == 1
    row = col.truncated_rows[0]
    assert row.valid_prefix_bytes == 2001
    assert row.bad_bytes_hex == "C3"
    assert any("DUMP(" in sql for sql in cursor.executions)
    assert result.notes == ()


def test_truncation_over_limit_clean_value_via_dump_reports_no_truncation():
    payload = "あ".encode("utf-8") * 800  # 2400 bytes, valid UTF-8
    cursor = _DumpCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "CAST_TO_RAW": [("r1", len(payload), None)],
        },
        dump_bytes=payload,
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    col = result.columns[0]
    assert col.truncated_count == 0
    assert col.truncated_rows == ()
    assert not any("could not byte-inspect" in note for note in result.notes)


def test_truncation_dump_length_mismatch_degrades_row_to_a_note():
    cursor = _DumpCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            # Claimed byte length far exceeds what DUMP can reassemble.
            "CAST_TO_RAW": [("r1", 5000, None)],
        },
        dump_bytes=b"a" * 2400,
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    col = result.columns[0]
    assert col.truncated_count == 0
    assert col.truncated_rows == ()
    assert any("could not byte-inspect row r1" in note for note in result.notes)
    assert any("boundary mismatch" in note for note in result.notes)


def test_parse_dump_decimal_bytes_accepts_valid_output():
    assert _parse_dump_decimal_bytes("Typ=1 Len=3: 99,97,102") == b"caf"
    assert (
        _parse_dump_decimal_bytes("Typ=1 Len=3 CharacterSet=AL32UTF8: 99,97,102")
        == b"caf"
    )
    assert _parse_dump_decimal_bytes("Typ=1 Len=0 CharacterSet=AL32UTF8: ") == b""
    assert _parse_dump_decimal_bytes("Typ=1 Len=1: 255") == b"\xff"


def test_parse_dump_decimal_bytes_rejects_malformed_output():
    assert _parse_dump_decimal_bytes(None) is None
    assert _parse_dump_decimal_bytes("garbage") is None
    assert _parse_dump_decimal_bytes("Typ=1 Len=3 99,97,102") is None  # no ": "
    assert _parse_dump_decimal_bytes("Typ=1 Len=3: 99,300,1") is None  # byte > 255
    assert _parse_dump_decimal_bytes("Typ=1 Len=2: 99,9a") is None  # not decimal
    assert _parse_dump_decimal_bytes("nope: 1,2,3") is None  # bad header


def test_truncation_dump_query_binds_rowid_and_offsets_no_identifier_interpolation():
    payload = b"a" * 2001 + b"\xc3"
    cursor = _DumpCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "CAST_TO_RAW": [("AAAv1sAAEAAAAB4AAA", len(payload), None)],
        },
        dump_bytes=payload,
    )

    _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True),
        truncation_mode="strict",
    )

    dump_sql = next(s for s in cursor.executions if "DUMP(" in s)
    assert "WHERE ROWID = CHARTOROWID(:rid)" in dump_sql
    assert ":start_byte" in dump_sql and ":len_bytes" in dump_sql
    assert "AAAv1sAAEAAAAB4AAA" not in dump_sql  # rowid is bound, not interpolated


def test_truncation_over_limit_path_targets_base_table_not_the_row_limit_wrapper():
    payload = b"a" * 2001 + b"\xc3"
    cursor = _DumpCursor(
        {
            "all_tab_columns": [("VALUE", "VARCHAR2")],
            "CAST_TO_RAW": [("r1", len(payload), None)],
        },
        dump_bytes=payload,
    )

    _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(detect_truncated=True, row_limit=100),
        truncation_mode="strict",
    )

    main_sql = next(s for s in cursor.executions if "CAST_TO_RAW" in s)
    assert "ROWNUM <= :row_limit" in main_sql
    dump_sql = next(s for s in cursor.executions if "DUMP(" in s)
    assert "ROWNUM" not in dump_sql
    assert '"APP"."T1"' in dump_sql


def test_scan_one_column_filter_restricts_scanned_columns_to_the_allowlist():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("NAME", "VARCHAR2"), ("CITY", "VARCHAR2"), ("AGE", "NUMBER")],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(),
        column_allowlist=frozenset({"NAME"}),
    )

    assert [col.name for col in result.columns] == ["NAME"]


def test_scan_one_column_filter_notes_an_unknown_column_and_scans_the_rest():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("NAME", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(),
        column_allowlist=frozenset({"NAME", "NOPE"}),
    )

    assert [col.name for col in result.columns] == ["NAME"]
    assert any("NOPE" in note and "not found" in note for note in result.notes)


def test_scan_one_column_filter_notes_a_non_text_column_and_scans_the_rest():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("NAME", "VARCHAR2"), ("AGE", "NUMBER")],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(
        cursor,
        DbObject("APP", "T1", "TABLE"),
        ScanSettings(),
        column_allowlist=frozenset({"NAME", "AGE"}),
    )

    assert [col.name for col in result.columns] == ["NAME"]
    assert any("AGE" in note and "NUMBER" in note for note in result.notes)


def test_scan_one_without_a_column_filter_scans_every_text_column():
    cursor = FakeCursor(
        {
            "all_tab_columns": [("NAME", "VARCHAR2"), ("CITY", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = _scan_one(cursor, DbObject("APP", "T1", "TABLE"), ScanSettings())

    assert [col.name for col in result.columns] == ["NAME", "CITY"]


def test_scan_objects_applies_the_column_filter_keyed_by_object():
    obj = DbObject("APP", "T1", "TABLE")
    cursor = FakeCursor(
        {
            "all_tab_columns": [("NAME", "VARCHAR2"), ("CITY", "VARCHAR2")],
            "COUNT(*)": [(0,)],
        }
    )

    result = scan_objects(
        cursor,
        [obj],
        ScanSettings(),
        column_filter={("APP", "T1", "TABLE"): frozenset({"CITY"})},
    )

    assert [col.name for col in result.objects[0].columns] == ["CITY"]


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
