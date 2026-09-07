# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Row-grouped repair scripts now carry scan-time row evidence and revalidate
  the target object, row lock, change marker, byte length, and complete value
  hashes immediately before each consolidated update. Rows with incomplete or
  changed evidence are skipped, and generated scripts require an explicit
  operator `COMMIT` or `ROLLBACK`.
- An opt-in integration suite exercises generated repair scripts against a
  separately configured disposable Oracle schema, including concurrent
  changes, deleted and busy rows, rollback behavior, and actual ROWID reuse.
- A multi-object scan now writes the combined report, per-column log lines,
  and fix SQL as each table's scan finishes, instead of holding everything
  in memory until the whole batch completes. A scan that's interrupted
  partway through a large schema (session timeout, Ctrl-C, crash) no longer
  loses the tables that had already finished.
- The CLI prints `[i/N] Scanning OWNER.NAME` as each table starts when
  scanning more than one object, so it's visible which table is currently
  running instead of only a generic progress count.

### Fixed

- Production-mode startup and scan failures no longer expose exception details
  or tracebacks through the console or logger propagation.
- Boolean configuration values must now be real TOML booleans; quoted strings
  and numeric substitutes are rejected.
- Manifest column matching now preserves exact case and rejects ambiguous
  case-insensitive matches instead of silently expanding scan scope.
- Reports, repair scripts, and logs now use collision-resistant names and
  handle-validated, no-follow file creation. Existing hard-linked or reparse
  targets are rejected before writing.
- Row repair generation now fails closed for unsupported or unverifiable Oracle
  objects, preview-query failures, and tables containing a real `ORA_ROWSCN`
  column. Executable guarded repairs currently support `CHAR` and `VARCHAR2`;
  `NCHAR` and `NVARCHAR2` remain scan-only because live testing demonstrated
  unsafe byte conversion.
- A column whose stored bytes contain an incomplete/invalid multibyte
  character (e.g. a truncated UTF-8 sequence) could crash the entire scan
  with an unhandled `UnicodeDecodeError` while sampling values for the
  report -- python-oracledb refuses to auto-decode invalid UTF-8 during a
  plain `SELECT`. Affected columns are now read as raw bytes and decoded
  leniently, so a broken byte span shows up as U+FFFD (the "�" replacement
  character) in the report instead of aborting the run.
- A sampled multibyte character that decoded to an unpaired surrogate
  codepoint (possible for the same kind of corrupted data above) could
  crash the report writer with `UnicodeEncodeError` when the report file
  was saved. It now falls back to the character's escaped form.

[Unreleased]: https://github.com/poiteal-ops/DqMultibyte/compare/main...HEAD
