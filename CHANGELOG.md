# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- A multi-object scan now writes the combined report, per-column log lines,
  and fix SQL as each table's scan finishes, instead of holding everything
  in memory until the whole batch completes. A scan that's interrupted
  partway through a large schema (session timeout, Ctrl-C, crash) no longer
  loses the tables that had already finished.
- The CLI prints `[i/N] Scanning OWNER.NAME` as each table starts when
  scanning more than one object, so it's visible which table is currently
  running instead of only a generic progress count.

### Fixed

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
