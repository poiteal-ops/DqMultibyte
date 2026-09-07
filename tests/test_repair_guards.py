"""Guard evidence must never turn incomplete scan results into a repair."""
from dataclasses import replace

import pytest

from mbscan.repair_guards import (
    ByteFingerprint, CellRepairEvidence, RepairTargetEvidence,
    dump_window_starts, group_row_evidence, validate_cell_evidence,
    validate_target_evidence, window_hash_sql,
)
from mbscan.scan import ColumnScan

RID = "AAAAAAAAAAAAAAAAAA"


def cell(length=1, **changes):
    return replace(CellRepairEvidence(RID, "C", 42,
        ByteFingerprint(length, ("A" * 64,) * len(range(1, length + 1, 900))),
        "ascii"), **changes)


@pytest.mark.parametrize("length,starts", [
    (1, (1,)), (900, (1,)), (901, (1, 901)), (2000, (1, 901, 1801)),
    (2001, (1, 901, 1801)), (4000, (1, 901, 1801, 2701, 3601)),
])
def test_complete_window_coverage(length, starts):
    assert dump_window_starts(length) == starts
    validate_cell_evidence(cell(length))


@pytest.mark.parametrize("changes", [
    {"rowid": RID + "\n"}, {"row_scn": True}, {"row_scn": 0},
    {"fingerprint": ByteFingerprint(0, ())},
    {"fingerprint": ByteFingerprint(4001, ("A" * 64,) * 5)},
    {"fingerprint": ByteFingerprint(901, ("A" * 64,))},
    {"fingerprint": ByteFingerprint(1, ("G" * 64,))},
    {"fingerprint": ByteFingerprint(True, ("A" * 64,))},
    {"keep_bytes": 0}, {"repair_kind": "truncate", "keep_bytes": True},
    {"repair_kind": "truncate", "keep_bytes": 1}, {"repair_kind": "unknown"},
])
def test_reject_invalid_evidence(changes):
    with pytest.raises(ValueError):
        validate_cell_evidence(cell(**changes))


def test_zero_keep_requires_valid_original_fingerprint():
    validate_cell_evidence(cell(repair_kind="truncate", keep_bytes=0))
    with pytest.raises(ValueError):
        validate_cell_evidence(cell(repair_kind="truncate", keep_bytes=0,
            fingerprint=ByteFingerprint(1, ())))


@pytest.mark.parametrize("other", [None, cell(column_name="D", row_scn=43)])
def test_missing_or_inconsistent_cell_suppresses_whole_row(other):
    cols = [ColumnScan("C", "VARCHAR2", 1, None, flagged_rowids=(RID,), repair_evidence=(cell(),)),
            ColumnScan("D", "VARCHAR2", 1, None, flagged_rowids=(RID,),
                       repair_evidence=() if other is None else (other,))]
    rows, notes = group_row_evidence(cols)
    assert rows == ()
    assert notes


def test_duplicate_cell_suppresses_whole_row():
    rows, notes = group_row_evidence([ColumnScan("C", "VARCHAR2", 1, None,
        flagged_rowids=(RID,), repair_evidence=(cell(), cell()))])
    assert rows == ()
    assert notes


def test_complete_row_is_consolidated_in_column_order():
    cols = [ColumnScan(n, "VARCHAR2", 1, None, flagged_rowids=(RID,),
                       repair_evidence=(cell(column_name=n),)) for n in ("D", "C")]
    rows, notes = group_row_evidence(cols)
    assert len(rows) == 1
    assert tuple(c.column_name for c in rows[0].cells) == ("D", "C")
    assert notes == ()


def test_hashes_are_not_exposed_by_repr():
    assert "A" * 64 not in repr(cell())
    assert "A" * 64 not in repr(cell().fingerprint)


def test_sql_builder_validates_numeric_input():
    assert window_hash_sql('"C"', 901) == "RAWTOHEX(STANDARD_HASH(DUMP(\"C\", 1010, 901, 900), 'SHA256'))"
    for start in (True, 0, -1, "1); DROP TABLE T", 4001):
        with pytest.raises(ValueError):
            window_hash_sql('"C"', start)


def test_target_metadata_is_validated():
    target = RepairTargetEvidence("B" * 64, 5, (("C", "VARCHAR2", 4000),))
    validate_target_evidence(target)
    for changed in (replace(target, object_id=True), replace(target, database_sha256="bad"),
                    replace(target, column_types=(("C", "CLOB", 4000),))):
        with pytest.raises(ValueError):
            validate_target_evidence(changed)
