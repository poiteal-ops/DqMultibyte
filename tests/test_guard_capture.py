from mbscan.oracle.metadata import DbObject, repair_target_evidence
from mbscan.scan import ScanSettings, _capture_repair_column


class Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return self.rows


def test_capture_decision_and_hashes_from_one_statement():
    cursor = Cursor([("AAAAAAAAAAAAAAAAAA", 42, 2, 1, "A" * 64, None, None, None, None)])
    col = _capture_repair_column(cursor, DbObject("APP", "T", "TABLE"), "C", "VARCHAR2",
        ScanSettings(capture_fix_rowids=True, detect_mojibake=True, row_limit=10), None, [])
    assert col.mojibake_rowids == ("AAAAAAAAAAAAAAAAAA",)
    assert col.repair_evidence[0].repair_kind == "mojibake"
    assert col.repair_evidence[0].row_scn == 42
    assert len(cursor.calls) == 1
    sql, params = cursor.calls[0]
    assert "ORA_ROWSCN AS scn" in sql and "STANDARD_HASH" in sql and "CASE WHEN" in sql
    assert params == {"row_limit": 10}
    assert not any(word in sql.upper() for word in ("FOR UPDATE", "COMMIT", "UPDATE ", "CREATE "))


def test_truncation_uses_same_statement_dump_and_rejects_bad_length():
    row = ("AAAAAAAAAAAAAAAAAA", 42, 2, 0, "A" * 64, None, None, None, None,
           "Typ=1 Len=2 CharacterSet=AL32UTF8: 65,195", None, None, None, None)
    cursor = Cursor([row])
    notes = []
    col = _capture_repair_column(cursor, DbObject("APP", "T", "TABLE"), "C", "VARCHAR2",
        ScanSettings(capture_fix_rowids=True, detect_truncated=True), "strict", notes)
    assert col.truncated_rows[0].valid_prefix_bytes == 1
    assert col.repair_evidence[0].keep_bytes == 1
    assert len(cursor.calls) == 1
    cursor.rows = [(row[0], row[1], 3, *row[3:])]
    col = _capture_repair_column(cursor, DbObject("APP", "T", "TABLE"), "C", "VARCHAR2",
        ScanSettings(capture_fix_rowids=True, detect_truncated=True), "strict", notes)
    assert col.repair_evidence == ()
    assert any("INCONSISTENT_EVIDENCE" in n for n in notes)


def test_missing_marker_does_not_hide_finding_or_emit_evidence():
    cursor = Cursor([("AAAAAAAAAAAAAAAAAA", None, 2, 0, "A" * 64, None, None, None, None)])
    notes = []
    col = _capture_repair_column(cursor, DbObject("APP", "T", "TABLE"), "C", "VARCHAR2",
        ScanSettings(capture_fix_rowids=True), None, notes)
    assert col.multibyte_count == 1 and col.repair_evidence == ()
    assert "MISSING_MARKER" in notes[0]


def test_unsupported_object_does_not_attempt_marker_query():
    cursor = Cursor([])
    assert repair_target_evidence(cursor, DbObject("APP", "V", "VIEW"), [("C", "VARCHAR2")]) is None
    assert cursor.calls == []


def test_preview_failure_preserves_already_captured_assignments(monkeypatch):
    from types import SimpleNamespace
    import oracledb
    from mbscan import scan
    from mbscan.repair_guards import RepairTargetEvidence
    monkeypatch.setattr(scan, "_columns", lambda *a: [("C", "VARCHAR2")])
    monkeypatch.setattr(scan, "repair_target_evidence", lambda *a: RepairTargetEvidence("B" * 64, 42, (("C", "VARCHAR2", 4000),)))
    def fail_preview(*args):
        raise oracledb.DatabaseError(SimpleNamespace(code=29275))
    monkeypatch.setattr(scan, "_sample_flagged_values", fail_preview)
    cur = Cursor([("AAAAAAAAAAAAAAAAAA", 42, 2, 0, "A" * 64, None, None, None, None)])
    result = scan._scan_one(cur, DbObject("APP", "T", "TABLE"), ScanSettings(capture_fix_rowids=True))
    assert result.columns[0].multibyte_count == 1
    assert len(result.columns[0].repair_evidence) == 1
    assert "PREVIEW_UNAVAILABLE" in result.notes[0]
