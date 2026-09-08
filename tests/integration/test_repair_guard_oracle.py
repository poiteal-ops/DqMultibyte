"""Opt-in destructive tests confined to exact, newly created fixture tables.

Never imports the application's credential loader or uses ORACLE_* credentials.
"""
from __future__ import annotations

import os
import uuid
import subprocess
from pathlib import Path

import oracledb
import pytest
from dotenv import dotenv_values

from mbscan.repair_guards import window_hash_sql
from mbscan.scan import _parse_dump_decimal_bytes
from mbscan.scan import ScanSettings, _scan_one
from mbscan.oracle.metadata import DbObject
from mbscan.fixes import render_fix_sql

pytestmark = pytest.mark.skipif(os.environ.get("MBSCAN_ORACLE_GUARD_TEST") != "1",
    reason="requires explicit disposable Oracle target opt-in")


@pytest.fixture
def oracle_guard():
    values = dotenv_values(Path("config/.env"))
    keys = ("TGT_ORACLE_USERNAME", "TGT_ORACLE_PASSWORD", "TGT_ORACLE_DSN")
    if not all(values.get(k) for k in keys):
        pytest.fail("Missing dedicated TGT_ORACLE_* configuration", pytrace=False)
    expected = os.environ.get("MBSCAN_ORACLE_GUARD_SCHEMA")
    if not expected:
        pytest.fail("Disposable schema confirmation is required", pytrace=False)
    if values[keys[2]] == values.get("ORACLE_DSN"):
        pytest.fail("Target DSN must differ from main DSN", pytrace=False)
    connections = []
    created = []
    try:
        for _ in range(2):
            conn = oracledb.connect(user=values[keys[0]], password=values[keys[1]],
                dsn=values[keys[2]], tcp_connect_timeout=10)
            connections.append(conn)
            conn.autocommit = False
            conn.call_timeout = 10000
            with conn.cursor() as cur:
                cur.execute("SELECT SYS_CONTEXT('USERENV','SESSION_USER'), SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual")
                if cur.fetchone() != (expected, expected):
                    pytest.fail("Target identity does not match designated schema", pytrace=False)
        def create(rowdependencies=False):
            name = "MBG_" + uuid.uuid4().hex[:24].upper()
            with connections[0].cursor() as cur:
                cur.execute('CREATE TABLE "' + name + '" (C VARCHAR2(4000), D NUMBER, E VARCHAR2(4000), P CHAR(10), N NCHAR(10), V NVARCHAR2(1000))' +
                    (" ROWDEPENDENCIES" if rowdependencies else " NOROWDEPENDENCIES"))
            created.append(name)  # register only AFTER our CREATE succeeds
            return '"' + name + '"'
        yield connections, create
    finally:
        for conn in connections:
            conn.rollback()
        if connections:
            with connections[0].cursor() as cur:
                for name in reversed(created):
                    cur.execute('DROP TABLE "' + name + '" PURGE')
        for conn in connections:
            conn.close()


def snapshot(cur, table, rid, col='"C"'):
    expressions = ["ORA_ROWSCN", "LENGTHB(" + col + ")"]
    expressions.extend(window_hash_sql(col, n) for n in (1, 901, 1801, 2701, 3601))
    cur.execute("SELECT " + ", ".join(expressions) + " FROM " + table + " WHERE ROWID=CHARTOROWID(:rid)", rid=rid)
    return cur.fetchone()


def lock_check_update(cur, table, rid, original):
    cur.execute("SAVEPOINT mbscan_row")
    try:
        cur.execute("SELECT ROWID FROM " + table + " WHERE ROWID=CHARTOROWID(:rid) FOR UPDATE NOWAIT", rid=rid)
        if cur.fetchone() is None:
            cur.execute("ROLLBACK TO mbscan_row")
            return "MISSING"
    except oracledb.Error as exc:
        if exc.args[0].code != 54:
            raise
        cur.execute("ROLLBACK TO mbscan_row")
        return "BUSY"
    current = snapshot(cur, table, rid)  # mandatory separate statement after lock
    if current != original:
        cur.execute("ROLLBACK TO mbscan_row")
        return "CHANGED_OR_UNVERIFIABLE"
    cur.execute("UPDATE " + table + " SET C=SUBSTRB(C,1,1) WHERE ROWID=CHARTOROWID(:rid)", rid=rid)
    assert cur.rowcount == 1
    return "UPDATED"


@pytest.mark.parametrize("rowdependencies", [False, True])
def test_lock_fresh_check_change_busy_and_unrelated_column(oracle_guard, rowdependencies):
    (first, second), create = oracle_guard
    table = create(rowdependencies)
    with first.cursor() as a, second.cursor() as b:
        a.execute("INSERT INTO " + table + " (C,D) VALUES ('AB',1)")
        first.commit()
        a.execute("SELECT ROWID FROM " + table)
        rid = a.fetchone()[0]
        old = snapshot(a, table, rid)
        b.execute("UPDATE " + table + " SET C='AC'")
        assert lock_check_update(a, table, rid, old) == "BUSY"
        second.commit()
        assert lock_check_update(a, table, rid, old) == "CHANGED_OR_UNVERIFIABLE"
        current = snapshot(a, table, rid)
        b.execute("UPDATE " + table + " SET D=2")
        second.commit()
        assert lock_check_update(a, table, rid, current) == "CHANGED_OR_UNVERIFIABLE"
        current = snapshot(a, table, rid)
        assert lock_check_update(a, table, rid, current) == "UPDATED"
        # Successful rows keep their lock; no implicit commit.
        with pytest.raises(oracledb.Error) as busy:
            b.execute("SELECT ROWID FROM " + table + " FOR UPDATE NOWAIT")
        assert busy.value.args[0].code == 54
        first.rollback()
        b.execute("SELECT C FROM " + table)
        assert b.fetchone()[0] == "AC"
        current = snapshot(a, table, rid)
        assert lock_check_update(a, table, rid, current) == "UPDATED"
        first.commit()
        assert lock_check_update(a, table, rid, current) == "CHANGED_OR_UNVERIFIABLE"


@pytest.mark.parametrize("expression,length", [
    ("UNISTR('caf\\00E9')", 5), ("UNISTR('caf\\00C3\\00A9')", 7),
    ("UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('41C3'))", 2),
    ("UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('418042'))", 3),
    ("RPAD('A',2001,'A')", 2001), ("RPAD('A',4000,'A')", 4000),
])
def test_complete_dump_fingerprint_bytes(oracle_guard, expression, length):
    (first, _), create = oracle_guard
    table = create()
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (C) VALUES (" + expression + ")")
        first.commit()
        cur.execute("SELECT LENGTHB(C), " + ", ".join(
            "DUMP(C,1010,{0},900), {1}".format(n, window_hash_sql('"C"', n))
            for n in range(1, length + 1, 900)) + " FROM " + table)
        row = cur.fetchone()
        assert row[0] == length
        assert len(b"".join(_parse_dump_decimal_bytes(d) for d in row[1::2])) == length
        assert all(len(h) == 64 for h in row[2::2])


def test_national_char_padding_and_null(oracle_guard):
    (first, _), create = oracle_guard
    table = create()
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (P,N,V) VALUES ('A',UNISTR('\\00E9'),UNISTR('\\00E9'))")
        first.commit()
        cur.execute("SELECT LENGTHB(P),LENGTHB(N),LENGTHB(V)," +
            ",".join(window_hash_sql(c, 1) for c in ('"P"', '"N"', '"V"', '"C"')) + " FROM " + table)
        row = cur.fetchone()
        assert row[:3] == (10, 20, 2)
        assert all(len(h) == 64 for h in row[3:6])
        # STANDARD_HASH(NULL) yields a digest on this Oracle version. Length
        # and explicit CASE comparisons, rather than hash-nullness, reject NULL.
        cur.execute("SELECT CASE WHEN LENGTHB(C)=2 AND " + window_hash_sql('"C"', 1) +
            "=:digest THEN 1 ELSE 0 END FROM " + table, digest=row[6])
        assert cur.fetchone()[0] == 0


@pytest.mark.parametrize("rowdependencies", [False, True])
def test_deleted_row_and_observed_reuse(oracle_guard, record_property, rowdependencies):
    (first, _), create = oracle_guard
    table = create(rowdependencies)
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (C) VALUES ('AB')")
        first.commit()
        cur.execute("SELECT ROWID FROM " + table)
        rid = cur.fetchone()[0]
        old = snapshot(cur, table, rid)
        cur.execute("DELETE FROM " + table)
        first.commit()
        assert lock_check_update(cur, table, rid, old) == "MISSING"
        cur.execute("INSERT INTO " + table + " (C) VALUES ('AB')")
        first.commit()
        cur.execute("SELECT ROWID FROM " + table)
        reused = cur.fetchone()[0] == rid
        if not reused:
            # Fill and recycle several heap blocks; a one-row delete/insert
            # usually chooses a previously unused slot on ASSM storage.
            cur.executemany("INSERT INTO " + table + " (C,D) VALUES ('AB',:n)", [(n,) for n in range(1024)])
            first.commit()
            cur.execute("SELECT ROWID, ORA_ROWSCN FROM " + table)
            markers = dict(cur.fetchall())
            cur.execute("DELETE FROM " + table)
            first.commit()
            cur.executemany("INSERT INTO " + table + " (C,D) VALUES ('AB',:n)", [(n,) for n in range(1024)])
            first.commit()
            cur.execute("SELECT ROWID FROM " + table)
            overlap = sorted({row[0] for row in cur.fetchall()} & markers.keys())
            if overlap:
                rid = overlap[0]
                now = snapshot(cur, table, rid)
                old = (markers[rid], *now[1:])  # identical cell bytes, old marker
                reused = True
        record_property("rowid_reuse_observed", reused)
        print("ROWID_REUSE_OBSERVED=" + str(reused) + " ROWDEPENDENCIES=" + str(rowdependencies))
        assert lock_check_update(cur, table, rid, old) == ("CHANGED_OR_UNVERIFIABLE" if reused else "MISSING")


def sqlplus_script(sql, finish="ROLLBACK;"):
    """Use the existing target-container client; credentials travel over stdin."""
    if os.environ.get("MBSCAN_ORACLE_SQLPLUS_CONTAINER") != "oracle-free-target":
        pytest.skip("requires explicit target-container SQL*Plus opt-in")
    values = dotenv_values(Path("config/.env"))
    # Driver login accepted unquoted lowercase spelling; SQL*Plus quotes need
    # the exact session username already confirmed by this fixture.
    username, password = os.environ["MBSCAN_ORACLE_GUARD_SCHEMA"], values["TGT_ORACLE_PASSWORD"]
    if any(c in username + password for c in ('"', '\n', '\r')):
        pytest.fail("Fixture credentials contain unsupported SQL*Plus login characters", pytrace=False)
    # Container/service were verified read-only against the designated target.
    login = 'CONNECT "{0}"/"{1}"@//localhost:1521/FREEPDB1\n'.format(username, password)
    result = subprocess.run(["docker", "exec", "-i", "oracle-free-target", "sqlplus", "-S", "/nolog"],
        input="SET ECHO OFF\nWHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK\n" + login + sql + "\n" + finish + "\nEXIT SUCCESS ROLLBACK\n",
        text=True, capture_output=True, timeout=40)
    output = (result.stdout + result.stderr).replace(password, "[REDACTED]")
    return result.returncode, output


def scanned_script(cur, table, truncated=False, mojibake=False):
    obj = DbObject(os.environ["MBSCAN_ORACLE_GUARD_SCHEMA"], table.strip('"'), "TABLE")
    result = _scan_one(cur, obj, ScanSettings(capture_fix_rowids=True,
        detect_truncated=truncated, detect_mojibake=mojibake, capture_mojibake_rowids=mojibake),
        truncation_mode="strict" if truncated else None)
    assert result.repair_target is not None
    assert any(c.repair_evidence for c in result.columns), (
        [(c.name, c.status, c.reason, c.truncated_count) for c in result.columns], result.notes)
    return render_fix_sql(result)


@pytest.mark.parametrize("expression,truncated,mojibake,expected", [
    ("UNISTR('caf\\00E9')", False, False, "cafe"),
    ("UNISTR('caf\\00C3\\00A9')", False, True, "café"),
    ("UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('41C3'))", True, False, "A"),
    ("UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('C3'))", True, False, None),
])
def test_actual_generated_script_repairs_and_cannot_repeat(oracle_guard, expression, truncated, mojibake, expected):
    (first, _), create = oracle_guard
    table = create(True)
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (C) VALUES (" + expression + ")")
        first.commit()
        sql = scanned_script(cur, table, truncated, mojibake)
        code, output = sqlplus_script(sql, "COMMIT;")
        assert code == 0, output
        assert "attempted=1 updated=1 changed_or_unverifiable=0 missing=0 busy=0" in output
        cur.execute("SELECT C FROM " + table)
        assert cur.fetchone()[0] == expected
        code, output = sqlplus_script(sql)
        assert code == 0, output
        assert "attempted=1 updated=0 changed_or_unverifiable=1 missing=0 busy=0" in output


@pytest.mark.parametrize("change,outcome", [
    ("SET C=UNISTR('caf\\00E8')", "changed_or_unverifiable=1"),
    ("SET C=NULL", "changed_or_unverifiable=1"),
    ("SET D=2", "changed_or_unverifiable=1"),
    ("DELETE", "missing=1"),
    ("BUSY", "busy=1"),
])
def test_actual_generated_script_skips_stale_missing_and_busy(oracle_guard, change, outcome):
    (first, second), create = oracle_guard
    table = create(True)
    with first.cursor() as a, second.cursor() as b:
        a.execute("INSERT INTO " + table + " (C) VALUES (UNISTR('caf\\00E9'))")
        first.commit()
        sql = scanned_script(a, table)
        if change == "DELETE":
            b.execute("DELETE FROM " + table)
        else:
            b.execute("UPDATE " + table + " " + ("SET D=3" if change == "BUSY" else change))
        if change != "BUSY":
            second.commit()
        code, output = sqlplus_script(sql)
        assert code == 0, output
        assert "updated=0" in output and outcome in output


def test_actual_generated_script_rolls_back_on_fatal_error(oracle_guard):
    (first, _), create = oracle_guard
    table = create(True)
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (C) VALUES (UNISTR('caf\\00E9'))")
        first.commit()
        sql = scanned_script(cur, table)
        code, output = sqlplus_script(sql + "\nBEGIN RAISE_APPLICATION_ERROR(-20099, 'SYNTHETIC_FATAL'); END;\n/\n", "COMMIT;")
        assert code != 0
        assert "SYNTHETIC_FATAL" in output
        cur.execute("SELECT C FROM " + table)
        assert cur.fetchone()[0] == "café"


def test_actual_generated_script_skips_whole_stale_row_and_repairs_other(oracle_guard):
    (first, second), create = oracle_guard
    table = create(True)
    with first.cursor() as a, second.cursor() as b:
        for n in (1, 2):
            a.execute("INSERT INTO " + table + " (C,E,D) VALUES (UNISTR('caf\\00E9'),UNISTR('caf\\00E9'),:n)", n=n)
        first.commit()
        sql = scanned_script(a, table)
        b.execute("UPDATE " + table + " SET C='corrected' WHERE D=1")
        second.commit()
        code, output = sqlplus_script(sql, "COMMIT;")
        assert code == 0, output
        assert "attempted=2 updated=1 changed_or_unverifiable=1" in output
        a.execute("SELECT C,E FROM " + table + " ORDER BY D")
        assert a.fetchall() == [("corrected", "café"), ("cafe", "cafe")]


@pytest.mark.parametrize("metadata", ["database", "object", "column"])
def test_actual_generated_script_rejects_wrong_target_metadata(oracle_guard, metadata):
    from dataclasses import replace
    (first, _), create = oracle_guard
    table = create(True)
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (C) VALUES (UNISTR('caf\\00E9'))")
        first.commit()
        obj = _scan_one(cur, DbObject(os.environ["MBSCAN_ORACLE_GUARD_SCHEMA"], table.strip('"'), "TABLE"), ScanSettings(capture_fix_rowids=True))
        target = obj.repair_target
        if metadata == "database":
            target = replace(target, database_sha256="0" * 64)
        elif metadata == "object":
            target = replace(target, object_id=target.object_id + 1000000)
        else:
            target = replace(target, column_types=tuple((n, t, size + 1) for n, t, size in target.column_types))
        code, output = sqlplus_script(render_fix_sql(replace(obj, repair_target=target)), "COMMIT;")
        assert code != 0 and "TARGET_MISMATCH" in output
        cur.execute("SELECT C FROM " + table)
        assert cur.fetchone()[0] == "café"


def test_actual_generated_script_rejects_changed_suffix_after_keep_boundary(oracle_guard):
    (first, second), create = oracle_guard
    table = create(True)
    with first.cursor() as a, second.cursor() as b:
        a.execute("BEGIN INSERT INTO " + table + " (C) VALUES (UTL_RAW.CAST_TO_VARCHAR2(:raw)); END;", raw=b"A\x80" + b"B" * 3998)
        first.commit()
        a.execute("SELECT DUMP(C,1010,1,3),LENGTHB(C) FROM " + table)
        stored, length = a.fetchone()
        assert _parse_dump_decimal_bytes(stored) == b"A\x80B" and length == 4000
        sql = scanned_script(a, table, truncated=True)
        b.execute("BEGIN UPDATE " + table + " SET C=UTL_RAW.CAST_TO_VARCHAR2(:raw); END;", raw=b"A\x80" + b"B" * 3997 + b"C")
        second.commit()
        code, output = sqlplus_script(sql, "COMMIT;")
        assert code == 0, output
        assert "updated=0 changed_or_unverifiable=1" in output
        a.execute("SELECT LENGTHB(C) FROM " + table)
        assert a.fetchone()[0] == 4000


def test_national_repair_is_omitted_without_hiding_scan_findings(oracle_guard):
    (first, _), create = oracle_guard
    table = create(True)
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (C,N,V) VALUES (UNISTR('caf\\00E9'),UNISTR('caf\\00E9'),UNISTR('caf\\00E9'))")
        first.commit()
        obj = _scan_one(cur, DbObject(os.environ["MBSCAN_ORACLE_GUARD_SCHEMA"], table.strip('"'), "TABLE"), ScanSettings(capture_fix_rowids=True))
        national = [c for c in obj.columns if c.name in {"N", "V"}]
        assert all(c.multibyte_count == 1 and c.repair_evidence == () for c in national)
        sql = render_fix_sql(obj)
        assert not any(line.startswith("UPDATE ") for line in sql.splitlines())
        assert any("UNSUPPORTED_DATATYPE" in note for note in obj.notes)


def test_actual_generated_script_preserves_char_padding(oracle_guard):
    (first, _), create = oracle_guard
    table = create(True)
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (P) VALUES (UNISTR('caf\\00E9'))")
        first.commit()
        code, output = sqlplus_script(scanned_script(cur, table), "COMMIT;")
        assert code == 0, output
        assert "updated=1" in output
        cur.execute("SELECT P FROM " + table)
        assert cur.fetchone()[0] == "cafe      "


def test_user_column_cannot_shadow_change_marker(oracle_guard):
    (first, _), create = oracle_guard
    table = create(True)
    with first.cursor() as cur:
        cur.execute('ALTER TABLE ' + table + ' ADD ("ORA_ROWSCN" NUMBER DEFAULT 42)')
        cur.execute("INSERT INTO " + table + " (C) VALUES (UNISTR('caf\\00E9'))")
        first.commit()
        cur.execute("SELECT ORA_ROWSCN FROM " + table)
        assert cur.fetchone()[0] == 42
        obj = _scan_one(cur, DbObject(os.environ["MBSCAN_ORACLE_GUARD_SCHEMA"], table.strip('"'), "TABLE"), ScanSettings(capture_fix_rowids=True))
        assert obj.repair_target is None
        assert not any(line.startswith("UPDATE ") for line in render_fix_sql(obj).splitlines())


def test_script_rejects_change_marker_column_added_after_scan(oracle_guard):
    (first, _), create = oracle_guard
    table = create(True)
    with first.cursor() as cur:
        cur.execute("INSERT INTO " + table + " (C) VALUES (UNISTR('caf\\00E9'))")
        first.commit()
        sql = scanned_script(cur, table)
        cur.execute('ALTER TABLE ' + table + ' ADD ("ORA_ROWSCN" NUMBER DEFAULT 42)')
        code, output = sqlplus_script(sql, "COMMIT;")
        assert code != 0 and "TARGET_MISMATCH" in output
        cur.execute("SELECT C FROM " + table)
        assert cur.fetchone()[0] == "café"


def test_multiple_same_block_candidates_account_for_conservative_skips(oracle_guard, record_property):
    (first, _), create = oracle_guard
    table = create(False)
    with first.cursor() as cur:
        cur.executemany(
            "INSERT INTO " + table + " (C,D) VALUES (UNISTR('caf\\00E9'),:n)",
            [(1,), (2,)],
        )
        first.commit()
        cur.execute("SELECT COUNT(DISTINCT DBMS_ROWID.ROWID_BLOCK_NUMBER(ROWID)) FROM " + table)
        assert cur.fetchone()[0] == 1
        code, output = sqlplus_script(scanned_script(cur, table), "ROLLBACK;")
        assert code == 0, output
        assert "attempted=2" in output
        updated = int(output.split("updated=")[1].split()[0])
        changed = int(output.split("changed_or_unverifiable=")[1].split()[0])
        assert updated + changed == 2
        record_property("same_block_updated", updated)
        record_property("same_block_conservative_skips", changed)
        print("SAME_BLOCK_UPDATED={0} CONSERVATIVE_SKIPS={1}".format(updated, changed))
        cur.execute("SELECT C FROM " + table + " ORDER BY D")
        assert cur.fetchall() == [("café",), ("café",)]
