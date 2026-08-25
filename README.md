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

Object names are matched case-insensitively against Oracle's dictionary
(exact case wins if there's a tie); comma-separated lists are trimmed and
de-duplicated.

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

## Logging

Every run appends to a daily log file at
`output/logs/mbscan-<YYYY-MM-DD>.log`. Only object/column metadata and bare
Oracle error codes are logged -- never credentials or raw Oracle error text,
which can embed host, port, service name, and schema detail.
