# Disposable Oracle guard tests

These tests create and drop only randomly named `MBG_` tables registered after
their own successful CREATE. They never clean up by prefix or use the main
Oracle credentials. Use a dedicated disposable account with CREATE TABLE quota.

The target credentials are `TGT_ORACLE_USERNAME`, `TGT_ORACLE_PASSWORD`, and
`TGT_ORACLE_DSN` in `config/.env`. No credentials are accepted in test output.
Explicitly opt in and confirm the exact username/schema:

```powershell
$env:MBSCAN_ORACLE_GUARD_TEST = '1'
$env:MBSCAN_ORACLE_GUARD_SCHEMA = '<disposable schema>'
$env:MBSCAN_ORACLE_SQLPLUS_CONTAINER = 'oracle-free-target'
$guardTemp = Join-Path (Get-Location) ('test-artifacts/oracle-guard-' + [guid]::NewGuid().ToString('N'))
& .venv314/Scripts/python.exe -m pytest tests/integration -q -p no:cacheprovider --basetemp=$guardTemp
Remove-Item Env:MBSCAN_ORACLE_GUARD_TEST, Env:MBSCAN_ORACLE_GUARD_SCHEMA, Env:MBSCAN_ORACLE_SQLPLUS_CONTAINER
```

`test-artifacts/` is git-ignored and is the only repository location intended
for these disposable pytest trees. Never place `--basetemp` output under
`docs/`.

Normal pytest runs skip these tests. A target DSN identical to the main DSN is
rejected. Distinct DSNs can alias the same database: the operator must designate
the target as disposable and check the read-only connection identity first.

The verified target matrix on 2026-09-07 is Oracle Database and SQL*Plus
23.26.2.0.0, AL32UTF8 database charset, AL16UTF16 national charset, ordinary
nonpartitioned heap tables with and without ROWDEPENDENCIES, and CHAR/VARCHAR2
values through 4000 bytes. Generated scripts were executed through SQL*Plus.

The tests cover unchanged repairs, reruns, same-length/suffix changes, NULL
transitions, unrelated-column changes, busy and missing rows, whole-row
consolidation, fatal rollback, target identity/type changes, CHAR padding,
malformed UTF-8 and actual ROWID reuse. Block recycling observed reused ROWIDs
with and without ROWDEPENDENCIES; old evidence was rejected.

NCHAR/NVARCHAR2 repair is explicitly excluded: a live generated-script test
showed the legacy conversion can change byte interpretation. These columns are
still scanned. Partitioned/IOT/external/temporary/clustered tables, views,
materialized views, virtual columns, enabled triggers, VPD policies, tables with
a real ORA_ROWSCN column, other Oracle versions/character sets, and SQLcl remain
outside the verified executable scope.

The fixture records, rather than assumes, conservative same-block skips. It
also tests that adding an ORA_ROWSCN user column after scanning fails target
preflight. Distinct DSNs can still alias one database, so always verify the
endpoint and session identity before opting in.
