"""SQL*Plus/SQLcl transaction wrapper for validated row evidence."""
from __future__ import annotations

from mbscan.oracle.metadata import quote_identifier
from mbscan.repair_guards import (
    DATABASE_HASH_SQL, dump_window_starts, group_row_evidence,
    validate_target_evidence, window_hash_sql,
)


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _target_check(obj) -> str:
    evidence = obj.repair_target
    owner, name = _literal(obj.object.owner), _literal(obj.object.name)
    conditions = [
        "o.owner = " + owner, "o.object_name = " + name,
        "o.object_id = " + str(evidence.object_id), "o.object_type = 'TABLE'",
        "o.subobject_name IS NULL", "t.iot_type IS NULL", "t.cluster_name IS NULL",
        "t.temporary = 'N'", "t.partitioned = 'NO'", "t.nested = 'NO'", "t.secondary = 'N'",
        "NOT EXISTS (SELECT 1 FROM all_external_tables e WHERE e.owner=o.owner AND e.table_name=o.object_name)",
        "NOT EXISTS (SELECT 1 FROM all_mviews m WHERE m.owner=o.owner AND m.mview_name=o.object_name)",
        "NOT EXISTS (SELECT 1 FROM all_triggers g WHERE g.table_owner=o.owner AND g.table_name=o.object_name AND g.status='ENABLED')",
        "NOT EXISTS (SELECT 1 FROM all_policies p WHERE p.object_owner=o.owner AND p.object_name=o.object_name AND p.enable='YES')",
        "NOT EXISTS (SELECT 1 FROM all_tab_cols mc WHERE mc.owner=o.owner AND mc.table_name=o.object_name AND mc.column_name='ORA_ROWSCN')",
        "EXISTS (SELECT 1 FROM nls_database_parameters WHERE parameter='NLS_CHARACTERSET' AND value='AL32UTF8')",
        DATABASE_HASH_SQL + " = " + _literal(evidence.database_sha256),
    ]
    for column, kind, length in evidence.column_types:
        conditions.append("EXISTS (SELECT 1 FROM all_tab_cols c WHERE c.owner=o.owner "
            "AND c.table_name=o.object_name AND c.virtual_column='NO' AND c.hidden_column='NO' AND c.column_name={0} AND c.data_type={1} AND c.data_length={2})".format(
                _literal(column), _literal(kind), length))
    return "SELECT COUNT(*) INTO l_target FROM all_objects o JOIN all_tables t ON t.owner=o.owner AND t.table_name=o.object_name WHERE " + " AND ".join(conditions) + ";"


def _matches(row) -> str:
    predicates = ["ORA_ROWSCN = " + str(row.row_scn)]
    for cell in row.cells:
        ref = quote_identifier(cell.column_name)
        fp = cell.fingerprint
        predicates.append("LENGTHB({0}) = {1}".format(ref, fp.byte_length))
        predicates.extend("{0} = '{1}'".format(window_hash_sql(ref, start), digest)
            for start, digest in zip(dump_window_starts(fp.byte_length), fp.window_sha256))
    return " AND ".join(predicates)


def render_guarded_rows(obj, flagged) -> list[str]:
    # Lazy import avoids a module cycle: fixes owns the existing repair recipes.
    from mbscan.fixes import MOJIBAKE_REPAIR_EXPR_TEMPLATE, TRUNCATED_STRIP_EXPR_TEMPLATE

    if any(c.status == "error" for c in obj.columns):
        return ["-- WARNING: INCOMPLETE_SCAN; no executable row repairs."]
    try:
        validate_target_evidence(obj.repair_target)
    except (ValueError, TypeError, AttributeError):
        return ["-- WARNING: UNSUPPORTED_OR_MISSING_TARGET_EVIDENCE; no executable row repairs."]
    names = [obj.object.owner, obj.object.name] + [n for n, _, _ in obj.repair_target.column_types]
    if any(any(ord(ch) < 32 or ord(ch) in {127, 0x2028, 0x2029} for ch in name) for name in names):
        return ["-- WARNING: UNSUPPORTED_IDENTIFIER; no executable row repairs."]
    rows, notes = group_row_evidence(flagged)
    lines = ["-- " + note for note in notes]
    types = {name: kind for name, kind, _ in obj.repair_target.column_types}
    if any(types.get(c.name) != c.data_type for c in flagged):
        return ["-- WARNING: INCONSISTENT_TARGET_COLUMNS; no executable row repairs."]
    supported = tuple(row for row in rows if all(types[c.column_name] in {"CHAR", "VARCHAR2"} for c in row.cells))
    if len(supported) != len(rows):
        lines.append("-- UNSUPPORTED_DATATYPE: national-character row repairs omitted.")
    rows = supported
    if not rows:
        return lines + ["-- WARNING: MISSING_EVIDENCE; no eligible guarded rows. Rescan before repair."]
    lines += [
        "-- Fingerprints are sensitive derived data. Protect this artifact like source data.",
        "-- Use a dedicated READ COMMITTED session in SQL*Plus/SQLcl script mode.",
        "-- Keep this wrapper intact. Successful updates retain locks until manual COMMIT/ROLLBACK.",
        "-- CHANGED_OR_UNVERIFIABLE can include conservative block-level false skips.",
        "-- Do not reuse across restore, refresh, flashback or migration operations.",
        "SET AUTOCOMMIT OFF", "SET SERVEROUTPUT ON", "SET SQLBLANKLINES ON",
        "WHENEVER OSERROR EXIT FAILURE ROLLBACK",
        "WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK",
        "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;",
    ]
    counters = ("attempted", "updated", "changed_or_unverifiable", "missing", "busy")
    lines += ["VARIABLE mbscan_" + counter + " NUMBER" for counter in counters]
    lines += ["BEGIN"] + ["  :mbscan_" + counter + " := 0;" for counter in counters] + ["END;", "/"]
    check_target = _target_check(obj)
    lines += ["DECLARE", "  l_target NUMBER;", "BEGIN", "  " + check_target,
        "  IF l_target <> 1 THEN RAISE_APPLICATION_ERROR(-20001, 'TARGET_MISMATCH'); END IF;", "END;", "/"]
    target = quote_identifier(obj.object.owner) + "." + quote_identifier(obj.object.name)
    for row in rows:
        locator = "ROWID = CHARTOROWID('" + row.rowid + "')"
        matches = _matches(row)
        assignments = []
        for cell in row.cells:
            ref = quote_identifier(cell.column_name)
            if cell.repair_kind == "truncate":
                expr = "NULL" if cell.keep_bytes == 0 else TRUNCATED_STRIP_EXPR_TEMPLATE.format(ref, cell.keep_bytes)
            elif cell.repair_kind == "mojibake":
                expr = MOJIBAKE_REPAIR_EXPR_TEMPLATE.format(ref)
            else:
                expr = "CONVERT({0}, 'US7ASCII')".format(ref)
            assignments.append(ref + " = " + expr)
        lines += [
            "DECLARE", "  l_rid ROWID;", "  l_match NUMBER;", "  l_target NUMBER;",
            "  l_state VARCHAR2(32) := 'LOCKED';", "  e_busy EXCEPTION;",
            "  PRAGMA EXCEPTION_INIT(e_busy, -54);", "BEGIN", "  SAVEPOINT mbscan_row;",
            "  :mbscan_attempted := :mbscan_attempted + 1;", "  BEGIN",
            "    SELECT ROWID INTO l_rid FROM " + target + " WHERE " + locator + " FOR UPDATE NOWAIT;",
            "  EXCEPTION", "    WHEN NO_DATA_FOUND THEN l_state := 'MISSING';",
            "    WHEN e_busy THEN l_state := 'BUSY';", "  END;",
            "  IF l_state = 'LOCKED' THEN", "    " + check_target,
            "    IF l_target <> 1 THEN RAISE_APPLICATION_ERROR(-20001, 'TARGET_MISMATCH'); END IF;",
            "    SELECT CASE WHEN " + matches + " THEN 1 ELSE 0 END INTO l_match FROM " + target + " WHERE " + locator + ";",
            "    IF l_match = 1 THEN",
            "UPDATE " + target + " SET " + ", ".join(assignments) + " WHERE " + locator + " AND " + matches + ";",
            "      IF SQL%ROWCOUNT <> 1 THEN RAISE_APPLICATION_ERROR(-20002, 'UNEXPECTED_ROWCOUNT'); END IF;",
            "      l_state := 'UPDATED';", "    ELSE", "      l_state := 'CHANGED_OR_UNVERIFIABLE';",
            "    END IF;", "  END IF;",
            "  IF l_state <> 'UPDATED' THEN ROLLBACK TO mbscan_row; END IF;",
            "  CASE l_state",
            "    WHEN 'UPDATED' THEN :mbscan_updated := :mbscan_updated + 1;",
            "    WHEN 'CHANGED_OR_UNVERIFIABLE' THEN :mbscan_changed_or_unverifiable := :mbscan_changed_or_unverifiable + 1;",
            "    WHEN 'MISSING' THEN :mbscan_missing := :mbscan_missing + 1;",
            "    WHEN 'BUSY' THEN :mbscan_busy := :mbscan_busy + 1;",
            "  END CASE;",
            "  DBMS_OUTPUT.PUT_LINE('" + row.rowid + " ' || l_state);",
            "EXCEPTION WHEN OTHERS THEN", "  ROLLBACK TO mbscan_row;", "  RAISE;", "END;", "/",
        ]
    lines += ["BEGIN",
        "  IF :mbscan_attempted <> :mbscan_updated + :mbscan_changed_or_unverifiable + :mbscan_missing + :mbscan_busy THEN",
        "    RAISE_APPLICATION_ERROR(-20003, 'COUNTER_MISMATCH');", "  END IF;",
        "  DBMS_OUTPUT.PUT_LINE('attempted=' || :mbscan_attempted || ' updated=' || :mbscan_updated || ' changed_or_unverifiable=' || :mbscan_changed_or_unverifiable || ' missing=' || :mbscan_missing || ' busy=' || :mbscan_busy);",
        "  DBMS_OUTPUT.PUT_LINE('Updates are UNCOMMITTED. Choose COMMIT or ROLLBACK; then rescan skipped rows.');",
        "END;", "/"]
    return lines
