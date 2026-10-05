# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-10-05

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

### Changed

- `detect_truncated` and `detect_mojibake` are now mutually exclusive: enabling
  both -- in `config/config.toml`, on the command line, or one in each (a CLI
  flag overrides only its own key) -- is rejected with a `ConfigError` before
  anything is scanned, instead of silently ignoring `detect_mojibake`.
  **Behaviour change** for configs that set both; pass `--no-detect-truncated`
  or `--no-detect-mojibake` to resolve it. Documented in the README, the example
  config and `AGENTS.md`.
- `config/config.example.toml` and the README option table now list
  `detect_truncated`, then `detect_mojibake`, first.

### Fixed

- Mojibake detection missed two kinds of SAS-DI-style corruption, so those rows
  were neither counted nor given an exact repair:
  - values containing the cp1252 "undefined" bytes 0x81/0x8D/0x8F/0x90/0x9D
    passed through as C1 characters (garbled `Á`, `Í`, `Ý`, `Ł`, `”`);
  - 4-byte UTF-8 sequences (emoji and other supplementary characters, e.g.
    `ðŸ˜€`), via a new F0-F4 branch in `MOJIBAKE_PREDICATE_TEMPLATE`.
  The cp1252 round-trip guard and repair expression are unchanged. Verified
  against Oracle 23c AL32UTF8 with synthetic values (garbled values flagged,
  genuine text and mojibake-plus-CJK values still not). The `DQ_TEST` tables
  contain none of these patterns, so a scan there gives identical counts
  before and after. Still not detected: values over 2000 characters and
  mojibake mixed with non-cp1252 characters (both fall to the lossy `CONVERT`
  bucket), and corruption whose undefined bytes were dropped or replaced by
  the source system.
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
