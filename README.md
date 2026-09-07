# mbscan

Scan an Oracle table/view/materialized view for multibyte, mojibake, and
truncated-multibyte character corruption (plus optional non-ASCII counts),
and generate a reviewable (never auto-run) fix script.

Runs on Linux and Windows, requires Python 3.11+. No notebook, no other
data-quality tooling -- this is a standalone extraction of the multibyte-scan
feature.

## Install

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
cp config/config.example.toml config/config.toml
cp config/env.example config/.env   # fill in ORACLE_USERNAME/PASSWORD/DSN
```

For running the test suite too:

```bash
pip install -e ".[dev]"
pytest --basetemp=test-artifacts/pytest
```

Keep temporary test output under the git-ignored `test-artifacts/` directory.
Do not use `docs/` for pytest `--basetemp` paths; that directory is reserved for
human-readable project documentation.

## Configuration

Connection credentials come from `config/.env` (loaded via `python-dotenv`):

```
ORACLE_USERNAME=...
ORACLE_PASSWORD=...
ORACLE_DSN=...
```

Everything else is set in `config/config.toml`. Each key can also be passed
as a CLI flag; a flag only overrides its matching key if you actually pass
it.

| Key | Meaning | Default if unset |
|---|---|---|
| `owner` | Oracle schema to scan | none -- must be supplied here, on the CLI, or interactively |
| `object` | One or more comma-separated table/view/materialized view names | none -- same as above |
| `all_objects` | Scan every visible table, view, and materialized view; overrides `object` when true | `false` |
| `timeout_seconds` | Oracle call timeout for every query the scan issues | `30` |
| `include_source_tables` | Also scan base tables behind a view/materialized view | `false` |
| `row_limit` | Cap each column scan to this many rows (omit for an exhaustive scan) | unset (exhaustive) |
| `include_non_ascii` | Also report non-ASCII character counts, not just multibyte counts | `false` |
| `output_dir` | Where scan reports are written | `output/reports` |
| `fixes_dir` | Where fix `.sql` scripts are written | `<output_dir>/fixes` |
| `generate_fixes` | Write a fix `.sql` script for tables with flagged columns | `true` |
| `fix_grouping` | `"row"`: guarded, consolidated updates requiring unchanged original-byte evidence after a row lock. Unsupported or unverifiable rows receive no executable repair. `"column"`: legacy predicate updates at execution time, without scan-time stale-data protection; can touch rows outside a bounded scan | `"row"` |
| `sample_row_limit` | Max flagged rows fetched per column to search for multibyte characters | `200` |
| `sample_char_limit` | Max distinct multibyte characters shown per column | `20` |
| `detect_mojibake` | Also scan for mojibake (SAS DI-style UTF-8-misread-as-Windows-1252 corruption) and report a repaired preview alongside each garbled sample. **Unlike every other check, this writes real column data into the report** -- see "Note on report contents" below | `false` |
| `mojibake_sample_limit` | Max flagged rows fetched per column to search for mojibake values | `10` |
| `detect_truncated` | Detect rows whose stored bytes hold an **incomplete** multibyte character -- the SAS DI "character cut in half" corruption Oracle reports as `ORA-29275: partial multibyte character`. This is the tool's primary purpose, so **when true it is the only check that runs** (multibyte counts, mojibake, and non-ASCII are skipped). `VARCHAR2`/`CHAR` only; self-skips unless the database character set is `AL32UTF8` or `UTF8` | `false` |
| `json_entry` | Read the exact table+column targets from a JSON manifest instead of `owner`/`object`/`all_objects`. Mutually exclusive with all three and with `--interactive` | `false` |
| `json_entry_file` | Path to that manifest | `config/scan_targets.json` |
| `debug_level` | `"prod"` or `"dev"`. `"dev"` raises the log level to `DEBUG` and lets real error text (Oracle messages, config values, tracebacks) reach the console and log -- local troubleshooting only, see [Logging](#logging). Config-file only, no CLI flag | `"prod"` |

Object names are matched case-insensitively against Oracle's dictionary
(exact case wins if there's a tie); comma-separated lists are trimmed and
de-duplicated.

### Partial / truncated multibyte characters (`detect_truncated`)

SAS character variables are sized in **bytes**, not characters, so a DI job
that resizes or `SUBSTR`s a column can slice a UTF-8 character in the middle
of its byte sequence. The value loads into Oracle looking fine but later
raises `ORA-29275` on any read that transcodes it. The other scans can't see
this: they inspect the value *after* python-oracledb has decoded it, and an
incomplete sequence can't be decoded. `detect_truncated` instead pulls the
raw bytes for every non-ASCII row and validates the UTF-8 byte structure in
Python. Values up to 2000 bytes come back inline via `UTL_RAW.CAST_TO_RAW`;
longer ones (a multibyte `VARCHAR2(4000)` easily exceeds the 2000-byte SQL
`RAW` limit, which used to raise `ORA-06502`) are reconstructed byte-window by
byte-window with `DUMP`. The report lists each flagged ROWID with the byte
offset, the offending bytes in hex, and the reason -- never the value. If a
row's bytes can't be reassembled reliably it is dropped with a note rather
than reported clean.

Because catching this corruption is what the tool exists for, **`detect_truncated
= true` makes it the only check that runs** -- the multibyte `LENGTHB > LENGTH`
count, mojibake detection, non-ASCII counts, and character sampling are all
skipped, and those columns show `-` in the report.

In `--fix-grouping row` mode, eligible rows with complete guard evidence get a per-ROWID
byte-strip `UPDATE` (`SET col = SUBSTRB(col, 1, <n>)`), which is **lossy** --
the half character and anything after it in that value is discarded (a value
broken at its first byte becomes `NULL`). `SUBSTRB` returns `VARCHAR2`, so it
works up to 4000 bytes; a keep-length beyond that (`MAX_STRING_SIZE=EXTENDED`)
is out of scope. Guarded repairs initially require the entire original value to
fit within 4000 bytes, even when the keep-length is smaller. `--fix-grouping column` can't express a
per-row keep-length, so it emits a comment block listing the ROWIDs and no
`UPDATE`. Exhaustive runs fetch raw bytes for every non-ASCII row of each
scanned column; use `--row-limit` for a first pass on a large table.

### JSON scan manifest (`json_entry`)

Set `json_entry = true` to scan an explicit list of tables and columns.
Copy `config/scan_targets.example.json` to `config/scan_targets.json`
(git-ignored) and edit:

```json
{
  "owner": "DQ_TEST",
  "tables": [
    { "table": "CUSTOMER_ADDRESSES", "columns": ["ADDRESS_LINE_1", "CITY"] },
    { "table": "EMPLOYEES", "columns": ["EMAIL"] }
  ]
}
```

- One `owner` for the whole file (single schema per manifest).
- Omit `columns` (or use `[]`) to scan every text column of that table.
- A listed column that doesn't exist, or isn't a `CHAR`/`VARCHAR2`/`NCHAR`/
  `NVARCHAR2` column, is **warned about in the report and skipped** -- the
  rest of the manifest still runs. An unknown *table* name is a hard error.
- `json_entry = true` together with `owner`/`object`/`all_objects`/
  `--interactive` is a configuration error.
- Table and column names are matched against Oracle's data dictionary before
  any SQL is built -- the manifest strings are never interpolated directly.
- Column spelling is preserved. Exact matches take priority; a case-insensitive
  fallback must be unique. For coexisting `Email` and `EMAIL`, `email` is
  ambiguous and rejected. Both exact names can be explicitly selected.

Boolean configuration values must be TOML `true` or `false`, without quotes.
Strings such as `"false"` and numeric substitutes are rejected.

## CLI usage

Every example below uses the installed `mbscan` console script. Without an
install on `PATH` -- e.g. running straight from a cloned repo on Linux --
substitute `python -m mbscan`, which takes identical flags:

```bash
python -m mbscan --row-limit 500
```

```bash
# Everything from config/config.toml
mbscan

# Override just the row limit for one run
mbscan --row-limit 500

# Fully explicit, ignoring config/config.toml
mbscan --owner SCOTT --object CUSTOMER_ADDRESSES --row-limit 500 --include-non-ascii

# Scan several named objects in one run
mbscan --owner SCOTT --object EMPLOYEES,DEPARTMENTS

# Scan every eligible object in the schema
mbscan --owner SCOTT --all-objects

# Pick the schema and object from a menu instead of naming them
mbscan --interactive

# Write the report and fix script somewhere else, or skip fix-script generation entirely
mbscan --output-dir /tmp/dq-reports --fixes-dir /tmp/dq-fixes
mbscan --no-generate-fixes

# Fall back to the legacy one-UPDATE-per-column fix script instead of the
# default one-UPDATE-per-row (ROWID-scoped) script
mbscan --fix-grouping column

# Widen how many rows/characters are sampled for the multibyte character detail
mbscan --sample-row-limit 1000 --sample-char-limit 50

# Also scan for mojibake (SAS DI-style UTF-8-misread-as-Windows-1252
# corruption) and widen how many mojibake rows are sampled per column
mbscan --detect-mojibake --mojibake-sample-limit 25
mbscan --no-detect-mojibake

# Also flag rows with an incomplete/truncated multibyte character (ORA-29275)
mbscan --owner SCOTT --object CUSTOMER_ADDRESSES --detect-truncated --row-limit 100000

# Scan the exact tables/columns listed in config/scan_targets.json
mbscan --json-entry
mbscan --json-entry --json-entry-file config/prod_targets.json
```

Each run writes:
- a scan report to `output/reports/<timestamp>_report_<owner>_<object>_<identity>_<run>.txt`
- an operational log appended to `output/logs/mbscan-<YYYY-MM-DD>.log`
- for each scanned table with at least one flagged column, a fix script to
  `output/reports/fixes/<timestamp>_fix_<owner>_<table>_<identity>_<run>.sql`

Timestamps lead the filename so directory listings sort chronologically.
Readable owner/object components are capped at 48 characters. An exact-identity
digest and a fresh random identifier distinguish normalized names and repeated
runs; exclusive creation rejects any remaining collision instead of overwriting.
For a single-object run, `<object>` is the resolved object name. Batch runs
use `multiple_objects` for an explicit multi-object list. Schema-wide mode
uses `all_objects` when more than one eligible object is found; with one
eligible object, the resolved object name remains in the filename.

The scan shows progress bars while scanning objects and eligible columns,
then prints `Run complete`. It scans and reports only `CHAR`, `VARCHAR2`,
`NCHAR`, and `NVARCHAR2` columns; numeric, date, binary, and LOB columns are
omitted. A multi-object selection is consolidated into one text report,
while generated fix scripts remain separate per object/table.

**Note on report contents:** the multibyte preview lists only the distinct
characters found, never whole values. The mojibake preview (`detect_mojibake`)
is the exception -- it shows real column data, each garbled/repaired value
truncated to 120 characters. Treat those reports accordingly. This isn't
only documented here: with `detect_mojibake` on, `mbscan` also prints a
warning to the console at the start of the run, and the report file itself
opens with the same warning as its first line, so anyone who only sees the
report (not this README) still gets it.

**The fix script is generated, never executed by mbscan.** Row-mode updates are
wrapped in PL/SQL with locking and revalidation, meant to be reviewed and run by someone
with write access to the scanned tables, after taking a backup. Which repair
expression a row or column gets depends on how the scan flagged it. Three
are emitted:

- **Plain multibyte -> `CONVERT(col, 'US7ASCII')`.** The default, for any
  flagged row that is neither mojibake nor truncated. A lossy, irreversible
  transliteration to 7-bit ASCII: recognized accented letters are mapped to
  a close ASCII equivalent (`é` -> `e`), but any character with no ASCII
  equivalent -- CJK, emoji -- becomes `?`.

- **Mojibake -> `UTL_I18N.RAW_TO_CHAR(UTL_I18N.STRING_TO_RAW(col,
  'WE8MSWIN1252'), 'AL32UTF8')`.** A non-lossy, exact repair: it re-encodes
  the string to the Windows-1252 bytes it was misread as, then decodes those
  bytes correctly as UTF-8. Assumes the target schema's database character
  set is `AL32UTF8` -- confirm with `SELECT value FROM
  nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET'` if unsure.
  `UTL_I18N.STRING_TO_RAW` returns Oracle's `RAW` type, capped at 2000 bytes
  on a non-`EXTENDED` database, and the expression inherits that cap. **That
  2000-character ceiling is a mojibake-only limitation:** a mojibake value
  longer than 2000 characters is not flagged as mojibake at all and falls
  through to the `CONVERT` path, which needs hand repair if exact recovery
  matters.

- **Truncated (`detect_truncated`) -> `SUBSTRB(col, 1, <n>)`.** A byte-strip.
  It keeps the first `<n>` bytes and discards the rest, where `<n>` is the
  byte offset of the first broken byte -- by construction a clean character
  boundary, so no whole character is split and no blank padding is added.
  This does **not** recover the half character: the missing bytes are gone
  (a lone lead byte `C3` could have been `é`, `è`, `ç` or many others), so
  the fix amputates the value at the last intact character and drops the
  mangled tail. Lossy and irreversible. If the value is broken at its very
  first byte -- nothing intact to keep -- the row is set to `NULL` instead.
  No 2000-character *detection* ceiling: over-2000-byte values are
  byte-window reconstructed with `DUMP` (see the `detect_truncated` section
  above) and validated in full. `SUBSTRB` returns `VARCHAR2`, so the repair
  itself works up to 4000 bytes; a keep-length beyond that
  (`MAX_STRING_SIZE=EXTENDED`) is out of scope. Emitted in `--fix-grouping
  row` mode only; the keep-length differs per row, so `--fix-grouping column`
  mode can only list the affected ROWIDs in a comment block with no `UPDATE`.

When one row is flagged more than one way, the byte-strip wins -- an
incomplete byte sequence is structural corruption that must be resolved
before any other repair can even read the value.

### Guarded row repairs and transactions

Normal scanning is read-only: it needs no CREATE TABLE privilege or tablespace
quota. Those permissions are used only by the opt-in disposable integration
tests in [tests/integration](tests/integration/README.md).

Each proposed repair captures its decision, conservative `ORA_ROWSCN`, byte
length, and SHA-256 hashes of every 900-byte DUMP window in one SELECT. At repair
time, the script locks the row with NOWAIT, checks target metadata, performs a
separate fresh SELECT, and updates only if all proposed cells still match.
It supports tables without primary keys. ROWID and ORA_ROWSCN are not a globally
unique identity or an exact last-change timestamp.

Use SQL*Plus/SQLcl **script mode in a dedicated READ COMMITTED session** with
autocommit off, and keep the wrapper intact. Back up the affected data first.
The script does not commit: successful rows remain locked until you manually
choose COMMIT or ROLLBACK. Unexpected SQL/OS failures stop the script and roll
back the transaction. Changed/unverifiable, missing, and busy rows are counted
and skipped; one failed cell skips every assignment for that row.

The report counts scan-time findings and omissions. Only the executed script
can report UPDATED/SKIPPED outcomes. Finish the transaction before rescanning
skipped rows. Block-level markers, delayed cleanout, or earlier repairs in the
same transaction may cause conservative false skips, including on unchanged
rows. Do not reuse scripts after restores, refreshes, flashback or migrations.
Database/container name checks catch ordinary wrong targets, but cloned
databases can share those names; verify the actual connection endpoint too.

Current executable scope is ordinary, nonpartitioned heap tables, AL32UTF8,
CHAR/VARCHAR2 source values of 1–4000 bytes, with or without ROWDEPENDENCIES.
Views, materialized views, IOTs, external/temporary/clustered/partitioned tables,
virtual columns, enabled table triggers, VPD policies, and unavailable metadata
are excluded. Tables with a real `ORA_ROWSCN` column are excluded because it
shadows Oracle's change marker. NCHAR/NVARCHAR2 remain scannable but receive no guarded row repair:
live tests exposed datatype corruption in the existing national conversion.
If such a column is proposed for a row, that whole row is omitted.

The implementation has been exercised against Oracle 23.26.2.0.0 and its
SQL*Plus client. Other versions and SQLcl require their own compatibility run.
The heap-block recycling fixture observed ROWID reuse and rejected the old
marker with and without ROWDEPENDENCIES. This is compatibility evidence for the
tested version/storage, not a permanent identity guarantee. See the integration
README for the exact proof limits.

Column mode retains its legacy execution-time predicates and is **not protected
against changes since the scan**. It can touch rows outside the scanned subset.
Its national-character conversion can corrupt NCHAR/NVARCHAR2 data; do not run
those statements. It is not a safe fallback for an omitted guarded repair.

Fingerprints are sensitive derived data and can permit guessing attacks against
low-entropy values. They do not make SQL artifacts safe to publish. No full
original values or complete DUMP output are persisted for guards.

### Output access and file safety

Use an output root owned and controlled by the scanner operator. Report and SQL
files are created exclusively; linked/reparse directory components are rejected,
and incremental reports retain their original file handle. POSIX files start at
0600 and new directories at 0700. Existing directory modes are preserved; shared
writable paths and unsafe existing daily log files are rejected. On Windows,
confidentiality depends on NTFS/share ACLs: the program does not configure them.

Daily logs append only after handle/type/link checks. Windows denies concurrent
writers to the same daily log while it is open; close the other scanner process
before retrying. Filesystem safety assumes other users cannot modify the trusted
output root or exercise administrator privileges.

## Logging

Every run appends to a daily log file at
`output/logs/mbscan-<YYYY-MM-DD>.log`, created with restricted permissions.
One file aggregates every run for that day, so anything written to it
persists across the whole day's activity.

How much detail is logged (and echoed to the console on failure) is
controlled by `debug_level` in `config/config.toml`. It is a config-file
setting only -- there is no CLI flag -- and its values are `"prod"`
(default) and `"dev"`.

**`prod` (default)** -- log level `INFO`. Oracle failures are recorded as a
bare `ORA-NNNNN` code only, never Oracle's own message text, which can embed
host, port, service name, schema, and SQL fragments. Console error output is
a generic line. Configuration failures also use a stable category in both the
console and log, including failures before logging starts. Raw values and
tracebacks are emitted only in explicit development mode. The application logger
does not propagate initialized records to a host application's root handlers.

**`dev`** -- a local-troubleshooting opt-in. Log level is raised to `DEBUG`.
On failure the console prints the real error detail instead of the generic
line -- the full Oracle message, or the configuration-error text plus a
Python traceback -- followed by the log file path. The Oracle message and
its traceback are written to the log too.

> **Warning: do not set `debug_level = "dev"` outside a local machine you
> control.** It deliberately disables the redaction that keeps connection
> details, schema names, SQL fragments, raw config values, and stack traces
> out of the console and the shared daily log -- and whatever it writes then
> persists in `output/logs/mbscan-<date>.log` for the rest of the day. Use
> it only to reproduce a failure locally, then set it back to `"prod"` and
> delete or rotate that day's log file.
