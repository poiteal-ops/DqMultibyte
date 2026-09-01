# mbscan

Scan an Oracle table/view/materialized view for multibyte and non-ASCII
character values, and generate a reviewable (never auto-run) fix script.

Runs on Linux and Windows. No notebook, no other data-quality tooling --
this is a standalone extraction of the multibyte-scan feature.

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
pytest
```

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
| `fix_grouping` | `"row"`: one `UPDATE` per ROWID captured at scan time, consolidating all of that row's flagged columns into one `SET` clause. `"column"`: one `UPDATE` per flagged column, scoped by re-running the multibyte predicate at fix time (its `WHERE` clause is not scoped to the rows the scan actually looked at, e.g. under a bounded `row_limit` scan it can touch rows outside the sampled subset) | `"row"` |
| `sample_row_limit` | Max flagged rows fetched per column to search for multibyte characters | `200` |
| `sample_char_limit` | Max distinct multibyte characters shown per column | `20` |
| `detect_mojibake` | Also scan for mojibake (SAS DI-style UTF-8-misread-as-Windows-1252 corruption) and report a repaired preview alongside each garbled sample | `false` |
| `mojibake_sample_limit` | Max flagged rows fetched per column to search for mojibake values | `10` |
| `detect_truncated` | Detect rows whose stored bytes hold an **incomplete** multibyte character -- the SAS DI "character cut in half" corruption Oracle reports as `ORA-29275: partial multibyte character`. This is the tool's primary purpose, so **when true it is the only check that runs** (multibyte counts, mojibake, and non-ASCII are skipped). `VARCHAR2`/`CHAR` only; self-skips unless the database character set is `AL32UTF8` or `UTF8` | `false` |
| `json_entry` | Read the exact table+column targets from a JSON manifest instead of `owner`/`object`/`all_objects`. Mutually exclusive with all three and with `--interactive` | `false` |
| `json_entry_file` | Path to that manifest | `config/scan_targets.json` |

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

In `--fix-grouping row` mode the generated fix script adds a per-ROWID
byte-strip `UPDATE` (`SET col = SUBSTRB(col, 1, <n>)`), which is **lossy** --
the half character and anything after it in that value is discarded (a value
broken at its first byte becomes `NULL`). `SUBSTRB` returns `VARCHAR2`, so it
works up to 4000 bytes; a keep-length beyond that (`MAX_STRING_SIZE=EXTENDED`)
is out of scope. `--fix-grouping column` can't express a
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
- a scan report to `output/reports/<timestamp>_report_<owner>_<object>.txt`
- an operational log appended to `output/logs/mbscan-<YYYY-MM-DD>.log`
- for each scanned table with at least one flagged column, a fix script to
  `output/reports/fixes/<timestamp>_fix_<owner>_<table>.sql`

Timestamps lead the filename so directory listings sort chronologically.
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
truncated to 120 characters. Treat those reports accordingly.

**The fix script is generated, never executed.** It contains one
set-based `UPDATE ... SET col = CONVERT(col, 'US7ASCII') WHERE ...` per
flagged column -- a lossy, irreversible transliteration to ASCII (characters
with no ASCII equivalent, like CJK or emoji, become `?`). It's meant to be
reviewed and run by someone with write access to the scanned tables, after
taking a backup. Rows flagged as mojibake instead get a non-lossy repair
expression (`UTL_I18N.RAW_TO_CHAR(UTL_I18N.STRING_TO_RAW(col,
'WE8MSWIN1252'), 'AL32UTF8')`), which assumes the target schema's database
character set is `AL32UTF8` -- confirm with `SELECT value FROM
nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET'` if unsure.
`UTL_I18N.STRING_TO_RAW` is capped at 2000 bytes, so only values up to 2000
characters are flagged as mojibake; a longer mojibake value falls through to
the lossy `CONVERT` path instead and needs hand repair if exact recovery
matters. Rows flagged by `detect_truncated` get the byte-strip repair
described above (row grouping only).

## Logging

Every run appends to a daily log file at
`output/logs/mbscan-<YYYY-MM-DD>.log`. Only object/column metadata and bare
Oracle error codes are logged -- never credentials or raw Oracle error text,
which can embed host, port, service name, and schema detail.
