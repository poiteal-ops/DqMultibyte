from dataclasses import replace

import pytest

from mbscan.fixes import render_fix_sql
from mbscan.oracle.metadata import DbObject
from mbscan.repair_guards import ByteFingerprint, CellRepairEvidence, RepairTargetEvidence
from mbscan.scan import ColumnScan, ObjectScanResult, TruncatedRow

RID = "AAAAAAAAAAAAAAAAAA"


def guarded_result(kind="ascii", keep=None):
    cell = CellRepairEvidence(RID, "C", 42, ByteFingerprint(2, ("A" * 64,)), kind, keep)
    col = ColumnScan("C", "VARCHAR2", 1, None, flagged_rowids=(RID,),
        mojibake_count=1 if kind == "mojibake" else None,
        mojibake_rowids=(RID,) if kind == "mojibake" else (),
        truncated_count=1 if kind == "truncate" else None,
        truncated_rows=(TruncatedRow(RID, keep, "C3", "incomplete"),) if kind == "truncate" else (),
        repair_evidence=(cell,))
    return ObjectScanResult(DbObject("APP", "T", "TABLE"), [col], "exhaustive",
        repair_target=RepairTargetEvidence("B" * 64, 123, (("C", "VARCHAR2", 4000),)))


@pytest.mark.parametrize("kind,keep,expression", [
    ("ascii", None, "CONVERT"), ("mojibake", None, "UTL_I18N.RAW_TO_CHAR"),
    ("truncate", 1, "SUBSTRB"), ("truncate", 0, '"C" = NULL'),
])
def test_guarded_repair_orders_lock_fresh_verify_update(kind, keep, expression):
    sql = render_fix_sql(guarded_result(kind, keep))
    lock = sql.index("FOR UPDATE NOWAIT")
    check = sql.index("SELECT CASE WHEN", lock)
    update = sql.index('UPDATE "APP"."T" SET', check)
    assert lock < check < update
    assert expression in sql[update:]
    assert "ORA_ROWSCN = 42" in sql[check:update]
    assert "A" * 64 in sql[check:update]
    assert "LENGTHB" in sql[update:]
    assert "SET AUTOCOMMIT OFF" in sql
    assert "WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK" in sql
    assert not any(line.strip() in {"COMMIT;", "EXIT", "EXIT SUCCESS"} for line in sql.splitlines())
    assert "SQL%ROWCOUNT <> 1" in sql
    assert "ROLLBACK TO mbscan_row" in sql
    assert "CHANGED_OR_UNVERIFIABLE" in sql and "BUSY" in sql and "MISSING" in sql


def test_legacy_evidence_never_produces_executable_row_repair():
    obj = guarded_result()
    obj.columns[0] = replace(obj.columns[0], repair_evidence=())
    sql = render_fix_sql(obj)
    assert not any(line.lstrip().startswith("UPDATE ") for line in sql.splitlines())
    assert "MISSING_EVIDENCE" in sql


def test_one_missing_column_suppresses_entire_row():
    obj = guarded_result()
    obj.columns.append(ColumnScan("D", "VARCHAR2", 1, None, flagged_rowids=(RID,)))
    sql = render_fix_sql(obj)
    assert not any(line.lstrip().startswith("UPDATE ") for line in sql.splitlines())


def test_wrong_target_evidence_never_embedded():
    obj = guarded_result()
    obj = replace(obj, repair_target=replace(obj.repair_target, object_id=True))
    sql = render_fix_sql(obj)
    assert not any(line.lstrip().startswith("UPDATE ") for line in sql.splitlines())


def test_column_mode_warns_about_stale_data():
    assert "not protected against changes since the scan" in render_fix_sql(guarded_result(), "column")


def test_mixed_repair_row_is_one_assignment_group_and_sorted_by_rowid():
    obj = guarded_result("mojibake")
    other = guarded_result("truncate", 1).columns[0]
    other = replace(other, name="D", repair_evidence=(replace(other.repair_evidence[0], column_name="D"),))
    obj.columns.append(other)
    last = "AAAAAAAAAAAAAAAAAB"
    first = obj.columns[0]
    obj.columns[0] = replace(first, multibyte_count=2, flagged_rowids=(last, RID),
        repair_evidence=first.repair_evidence + (replace(first.repair_evidence[0], rowid=last, repair_kind="ascii"),))
    obj = replace(obj, repair_target=replace(obj.repair_target,
        column_types=(("C", "VARCHAR2", 4000), ("D", "VARCHAR2", 4000))))
    updates = [line for line in render_fix_sql(obj).splitlines() if line.startswith("UPDATE ")]
    assert len(updates) == 2
    assert RID in updates[0] and last in updates[1]
    assert '"C" = UTL_I18N.RAW_TO_CHAR' in updates[0]
    assert '"D" = SUBSTRB("D", 1, 1)' in updates[0]
    assert '"C" = CONVERT' in updates[1] and '"D"' not in updates[1]


def test_long_truncation_compares_suffix_beyond_keep_boundary():
    obj = guarded_result("truncate", 1)
    original = obj.columns[0].repair_evidence[0]
    fp = ByteFingerprint(4000, tuple(c * 64 for c in "ACDEF"))
    obj.columns[0] = replace(obj.columns[0],
        truncated_rows=(TruncatedRow(RID, 3500, "C3", "incomplete"),),
        repair_evidence=(replace(original, keep_bytes=3500, fingerprint=fp),))
    sql = render_fix_sql(obj)
    update = next(line for line in sql.splitlines() if line.startswith("UPDATE "))
    assert 'SUBSTRB("C", 1, 3500)' in update
    assert 'DUMP("C", 1010, 3601, 900)' in update and "F" * 64 in update


def test_invalid_newline_rowid_never_reaches_sql():
    obj = guarded_result()
    obj.columns[0] = replace(obj.columns[0], flagged_rowids=(RID + "\n",),
        repair_evidence=(replace(obj.columns[0].repair_evidence[0], rowid=RID + "\n"),))
    assert not any(line.startswith("UPDATE ") for line in render_fix_sql(obj).splitlines())


def test_report_notice_counts_omitted_findings_without_fingerprints():
    from mbscan.reporting import _object_lines
    from mbscan.repair_guards import repair_notice
    obj = guarded_result()
    obj.columns[0] = replace(obj.columns[0], repair_evidence=())
    notice = repair_notice(obj)
    assert "1 finding(s), 0 with complete evidence, 1 omitted" in notice
    report = "\n".join(_object_lines(obj))
    assert notice in report
    assert "A" * 64 not in report and "B" * 64 not in report


def test_scan_error_cannot_hide_potential_assignments_from_grouping():
    obj = guarded_result()
    obj.columns.append(ColumnScan("D", "VARCHAR2", None, None, "error", "Oracle error 1"))
    sql = render_fix_sql(obj)
    assert not any(line.startswith("UPDATE ") for line in sql.splitlines())
