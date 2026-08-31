"""Aggregate-only Oracle character encoding scans."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, List, Optional, Sequence, Set, Tuple

import oracledb

from mbscan.progress import progress as object_progress
from mbscan.oracle.metadata import DbObject, database_character_set, quote_identifier

# Column types the partial-multibyte check can read via UTL_RAW.CAST_TO_RAW,
# which operates on the database (not national) character set. NCHAR/NVARCHAR2
# are AL16UTF16 and out of scope for v1.
RAW_READABLE_TEXT_TYPES = {"CHAR", "VARCHAR2"}

TEXT_TYPES = {"CHAR", "VARCHAR2", "NCHAR", "NVARCHAR2"}

MULTIBYTE_PREDICATE_TEMPLATE = "LENGTHB({0}) > LENGTH({0})"

_MOJIBAKE_CONTINUATION_SPECIAL_CODEPOINTS = (
    338, 339, 352, 353, 376, 381, 382, 402, 710, 732, 8211, 8212, 8216, 8217,
    8218, 8220, 8221, 8222, 8224, 8225, 8226, 8230, 8240, 8249, 8250, 8364, 8482,
)


def _unistr_class(codepoints):
    """Build a UNISTR(...) literal for a REGEXP_LIKE character class.
    UNISTR is charset-independent, unlike CHR(n > 127): confirmed
    empirically against a live Oracle AL32UTF8 instance that CHR(n>127)
    returns a single raw byte equal to n (invalid UTF-8 on its own) rather
    than a properly UTF-8-encoded character, and a REGEXP_LIKE predicate
    built from CHR() matches nothing -- not even genuine mojibake."""
    escapes = "".join("\\{0:04X}".format(cp) for cp in codepoints)
    return "UNISTR('" + escapes + "')"


_MOJIBAKE_CONTINUATION_CLASS_SQL = _unistr_class(
    list(range(0xA0, 0xC0)) + list(_MOJIBAKE_CONTINUATION_SPECIAL_CODEPOINTS)
)
_MOJIBAKE_LEAD2_CLASS_SQL = _unistr_class(list(range(0xC2, 0xE0)))
_MOJIBAKE_LEAD3_CLASS_SQL = _unistr_class(list(range(0xE0, 0xF0)))

# Windows-1252 round-trip guard. UTL_I18N.STRING_TO_RAW(col, 'WE8MSWIN1252')
# -- the first half of the repair expression -- silently substitutes byte 0xBF
# for any character outside Windows-1252's repertoire. A value holding genuine
# mojibake *plus* a correctly-stored non-cp1252 character (e.g. real CJK next
# to garbled Latin text) matches the REGEXP_LIKE branches below, and
# "repairing" it would write literal invalid UTF-8 bytes into the VARCHAR2 --
# verified live against Oracle 23c AL32UTF8 on 2026-08-09: repairing
# "cafA-tilde-copyright + CJK" yields bytes ending 'BF', which later raises
# UnicodeDecodeError on fetch. ANDing this equality onto the detection
# predicate excludes those values at the SQL level, so detection, counts,
# ROWIDs and both fix modes all inherit one consistent exclusion. Excluded
# rows fall through to the generic multibyte CONVERT bucket instead: lossy,
# but safe. Re-verified live 2026-08-09: keeps both the 2-byte and 3-byte
# genuine mojibake cases, excludes the mixed mojibake+CJK case.
_MOJIBAKE_CP1252_ROUNDTRIP_GUARD = (
    "{0} = UTL_I18N.RAW_TO_CHAR(UTL_I18N.STRING_TO_RAW({0}, 'WE8MSWIN1252'), 'WE8MSWIN1252')"
)

MOJIBAKE_PREDICATE_TEMPLATE = (
    "((REGEXP_LIKE({0}, '[' || " + _MOJIBAKE_LEAD2_CLASS_SQL + " || '][' || "
    + _MOJIBAKE_CONTINUATION_CLASS_SQL + " || ']')"
    " OR REGEXP_LIKE({0}, '[' || " + _MOJIBAKE_LEAD3_CLASS_SQL + " || '][' || "
    + _MOJIBAKE_CONTINUATION_CLASS_SQL + " || ']{{2}}'))"
    " AND " + _MOJIBAKE_CP1252_ROUNDTRIP_GUARD + ")"
)

ProgressFactory = Callable[[Sequence[Tuple[str, str]], int, str], Iterable[Tuple[str, str]]]


@dataclass(frozen=True)
class ScanSettings:
    scope: str = "selected"
    row_limit: Optional[int] = None
    include_non_ascii: bool = False
    sample_row_limit: int = 200
    sample_char_limit: int = 20
    capture_fix_rowids: bool = False
    detect_mojibake: bool = False
    mojibake_sample_limit: int = 10
    capture_mojibake_rowids: bool = False
    detect_truncated: bool = False

    def __post_init__(self) -> None:
        if self.scope not in {"selected", "selected-and-sources"}:
            raise ValueError("scope must be selected or selected-and-sources")
        if self.row_limit is not None and self.row_limit <= 0:
            raise ValueError("row_limit must be positive")
        if self.sample_row_limit <= 0:
            raise ValueError("sample_row_limit must be positive")
        if self.sample_char_limit <= 0:
            raise ValueError("sample_char_limit must be positive")
        if self.mojibake_sample_limit <= 0:
            raise ValueError("mojibake_sample_limit must be positive")


@dataclass(frozen=True)
class Dependency:
    object: DbObject
    access: str
    error_code: Optional[int] = None


@dataclass(frozen=True)
class MultibyteChar:
    char: str
    codepoint: str
    name: str


@dataclass(frozen=True)
class MojibakeSample:
    garbled: str
    repaired: str


@dataclass(frozen=True)
class TruncatedRow:
    """One row whose stored bytes hold an incomplete/invalid multibyte
    sequence -- the SAS-DI 'character cut in half' corruption Oracle reports
    as ORA-29275. valid_prefix_bytes is the byte offset of the first bad
    byte, i.e. the length the value can be safely truncated to."""

    rowid: str
    valid_prefix_bytes: int
    bad_bytes_hex: str
    reason: str


@dataclass(frozen=True)
class ColumnScan:
    name: str
    data_type: str
    multibyte_count: Optional[int]
    non_ascii_count: Optional[int]
    status: str = "scanned"
    reason: Optional[str] = None
    multibyte_samples: Tuple[MultibyteChar, ...] = ()
    multibyte_samples_truncated: bool = False
    flagged_rowids: Tuple[str, ...] = ()
    mojibake_count: Optional[int] = None
    mojibake_rowids: Tuple[str, ...] = ()
    mojibake_samples: Tuple[MojibakeSample, ...] = ()
    mojibake_samples_truncated: bool = False
    mojibake_samples_skipped: int = 0
    truncated_count: Optional[int] = None
    truncated_rows: Tuple[TruncatedRow, ...] = ()


@dataclass(frozen=True)
class ObjectScanResult:
    object: DbObject
    columns: List[ColumnScan]
    coverage: str
    error_code: Optional[int] = None
    notes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanResult:
    selected: DbObject
    settings: ScanSettings
    dependencies: List[Dependency]
    objects: List[ObjectScanResult]
    charset: Optional[str] = None
    truncated_skip_reason: Optional[str] = None


@dataclass(frozen=True)
class ScanBatchResult:
    selected: Tuple[DbObject, ...]
    settings: ScanSettings
    dependencies: Tuple[Dependency, ...]
    objects: Tuple[ObjectScanResult, ...]
    charset: Optional[str] = None
    truncated_skip_reason: Optional[str] = None


def safe_object_sql(obj: DbObject) -> str:
    return "{0}.{1}".format(quote_identifier(obj.owner), quote_identifier(obj.name))


def _error_code(exc: Exception) -> Optional[int]:
    args = getattr(exc, "args", ())
    return getattr(args[0], "code", None) if args else None


def _access(cursor: Any, obj: DbObject) -> Dependency:
    try:
        cursor.execute("SELECT 1 FROM {0} WHERE 1 = 0".format(safe_object_sql(obj)))
        return Dependency(obj, "accessible")
    except oracledb.Error as exc:
        return Dependency(obj, "inaccessible", _error_code(exc))


def resolve_dependencies(cursor: Any, selected: DbObject) -> List[Dependency]:
    """Recursively find visible base tables without trusting input identifiers."""
    if selected.object_type == "TABLE":
        return [_access(cursor, selected)]
    queue: List[DbObject] = [selected]
    seen: Set[Tuple[str, str, str]] = set()
    tables: List[Dependency] = []
    while queue:
        current = queue.pop(0)
        key = (current.owner, current.name, current.object_type)
        if key in seen:
            continue
        seen.add(key)
        cursor.execute(
            "SELECT referenced_owner, referenced_name, referenced_type, referenced_link_name "
            "FROM all_dependencies WHERE owner = :owner AND name = :name AND type = :type",
            {"owner": current.owner, "name": current.name, "type": current.object_type},
        )
        rows = list(cursor.fetchall())
        if current.object_type == "MVIEW":
            cursor.execute(
                "SELECT detailobj_owner, detailobj_name, detailobj_type, NULL "
                "FROM all_mview_detail_relations WHERE owner = :owner AND mview_name = :name",
                {"owner": current.owner, "name": current.name},
            )
            rows.extend(cursor.fetchall())
        for owner, name, object_type, link in rows:
            if link or not owner or not name or object_type not in {"TABLE", "VIEW", "MVIEW", "MATERIALIZED VIEW"}:
                continue
            normalized = "MVIEW" if object_type == "MATERIALIZED VIEW" else object_type
            obj = DbObject(owner, name, normalized)
            if normalized == "TABLE":
                tables.append(_access(cursor, obj))
            else:
                queue.append(obj)
    return tables


def _columns(cursor: Any, obj: DbObject) -> List[Tuple[str, str]]:
    cursor.execute(
        "SELECT column_name, data_type FROM all_tab_columns "
        "WHERE owner = :owner AND table_name = :name ORDER BY column_id",
        {"owner": obj.owner, "name": obj.name},
    )
    return list(cursor.fetchall())


def _count(cursor: Any, obj: DbObject, column: str, predicate: str, limit: Optional[int]) -> int:
    quoted_column = quote_identifier(column)
    params = {}
    source = safe_object_sql(obj)
    if limit is not None:
        source = "(SELECT {0} AS v FROM {1} WHERE ROWNUM <= :row_limit)".format(quoted_column, source)
        predicate = predicate.replace(quoted_column, "v")
        params["row_limit"] = limit
    cursor.execute("SELECT COUNT(*) FROM {0} WHERE {1}".format(source, predicate), params)
    return cursor.fetchone()[0]


def _fetch_flagged_rowids(
    cursor: Any, obj: DbObject, column: str, predicate: str, limit: Optional[int]
) -> List[str]:
    """Fetch the ROWID of every row matching predicate, reusing the same
    row_limit-bounding trick as _count(), except the bounding subquery must
    also project ROWID -- a derived table has no ROWID of its own."""
    quoted_column = quote_identifier(column)
    params: dict = {}
    source = safe_object_sql(obj)
    if limit is not None:
        source = "(SELECT ROWID AS rid, {0} AS v FROM {1} WHERE ROWNUM <= :row_limit)".format(quoted_column, source)
        select_expr = "rid"
        predicate = predicate.replace(quoted_column, "v")
        params["row_limit"] = limit
    else:
        select_expr = "ROWID"
    cursor.execute("SELECT {0} FROM {1} WHERE {2}".format(select_expr, source, predicate), params)
    return [row[0] for row in cursor.fetchall()]


# Candidate rows for the partial-multibyte check: anything that isn't plain
# 7-bit ASCII. Two conditions are OR'd because neither is sufficient alone
# (verified live against Oracle 23 AL32UTF8):
#   - a value ending in a lone lead byte (the SAS-DI signature) is NOT seen
#     as a non-ASCII character by REGEXP_LIKE, but its byte length exceeds
#     its character length;
#   - a mid-string orphan continuation byte keeps LENGTHB == LENGTH, but
#     REGEXP_LIKE does match it.
# CONVERT(col, 'US7ASCII') is deliberately not used: it raises ORA-12703 on a
# value that already holds an incomplete multibyte sequence.
TRUNCATION_CANDIDATE_PREDICATE_TEMPLATE = (
    "{0} IS NOT NULL AND ("
    "LENGTHB({0}) <> NVL(LENGTH({0}), 0) "
    "OR REGEXP_LIKE({0}, '[^' || CHR(1) || '-' || CHR(127) || ']')"
    ")"
)


def _fetch_truncation_candidates(
    cursor: Any, obj: DbObject, column: str, limit: Optional[int]
) -> List[Tuple[str, Any]]:
    """Fetch (ROWID, raw bytes) for every non-ASCII row, reusing the same
    row_limit-bounding trick as _fetch_flagged_rowids(). The bytes come back
    via UTL_RAW.CAST_TO_RAW so python-oracledb hands them over untouched --
    a value with an incomplete multibyte sequence cannot be decoded to str,
    which is exactly why the SQL-only checks never see this corruption."""
    quoted_column = quote_identifier(column)
    predicate = TRUNCATION_CANDIDATE_PREDICATE_TEMPLATE.format(quoted_column)
    params: dict = {}
    source = safe_object_sql(obj)
    raw_expr = "UTL_RAW.CAST_TO_RAW({0})".format(quoted_column)
    if limit is not None:
        source = "(SELECT ROWID AS rid, {0} AS v FROM {1} WHERE ROWNUM <= :row_limit)".format(
            quoted_column, source
        )
        select_expr = "rid"
        predicate = predicate.replace(quoted_column, "v")
        raw_expr = "UTL_RAW.CAST_TO_RAW(v)"
        params["row_limit"] = limit
    else:
        select_expr = "ROWID"
    cursor.execute(
        "SELECT {0}, {1} FROM {2} WHERE {3}".format(select_expr, raw_expr, source, predicate),
        params,
    )
    return [(row[0], row[1]) for row in cursor.fetchall()]


def _detect_truncated_rows(
    cursor: Any, obj: DbObject, column: str, row_limit: Optional[int], strict: bool
) -> Tuple[TruncatedRow, ...]:
    found: List[TruncatedRow] = []
    for rowid, raw in _fetch_truncation_candidates(cursor, obj, column, row_limit):
        raw_bytes = bytes(raw) if raw is not None else b""
        problem = find_incomplete_utf8(raw_bytes, strict=strict)
        if problem is None:
            continue
        offset, bad_bytes, reason = problem
        found.append(
            TruncatedRow(
                rowid=rowid,
                valid_prefix_bytes=offset,
                bad_bytes_hex=" ".join("{0:02X}".format(byte) for byte in bad_bytes[:4]),
                reason=reason,
            )
        )
    return tuple(found)


def _sample_flagged_values(
    cursor: Any,
    obj: DbObject,
    column: str,
    predicate: str,
    row_limit: Optional[int],
    sample_limit: int,
) -> List[str]:
    """Fetch up to sample_limit actual values from rows matching predicate,
    reusing the same row_limit-bounding trick as _count()."""
    quoted_column = quote_identifier(column)
    params = {"sample_limit": sample_limit}
    source = safe_object_sql(obj)
    if row_limit is not None:
        source = "(SELECT {0} AS v FROM {1} WHERE ROWNUM <= :row_limit)".format(quoted_column, source)
        predicate = predicate.replace(quoted_column, "v")
        quoted_column = "v"
        params["row_limit"] = row_limit
    sql = "SELECT {col} FROM (SELECT {col} FROM {source} WHERE {predicate}) WHERE ROWNUM <= :sample_limit".format(
        col=quoted_column, source=source, predicate=predicate
    )
    cursor.execute(sql, params)
    return [row[0] for row in cursor.fetchall() if row[0] is not None]


def _extract_multibyte_chars(
    values: Iterable[str], char_limit: int
) -> Tuple[Tuple[MultibyteChar, ...], bool]:
    """Return (distinct multibyte characters found, whether char_limit truncated the list)."""
    seen: "dict[str, MultibyteChar]" = {}
    truncated = False
    for value in values:
        for ch in value:
            if ord(ch) < 128 or ch in seen:
                continue
            if len(seen) >= char_limit:
                truncated = True
                continue
            seen[ch] = MultibyteChar(ch, "U+{0:04X}".format(ord(ch)), unicodedata.name(ch, "UNKNOWN"))
    return tuple(seen.values()), truncated


def _repair_mojibake_samples(
    values: Iterable[str], limit: int
) -> Tuple[Tuple[MojibakeSample, ...], bool, int]:
    """Attempt to repair each raw value as SAS-DI-style mojibake (UTF-8
    misread as Windows-1252). Values that don't round-trip are skipped --
    either a genuinely different multibyte character shares the value
    (UnicodeEncodeError) or the predicate matched something that isn't real
    mojibake (UnicodeDecodeError). Truncates at limit, same truncation-flag
    convention as multibyte_samples_truncated.

    Returns (samples, truncated, skipped_count). The skipped count is
    surfaced in the report so mojibake_count and the number of rendered
    sample pairs can never silently disagree. Since the SQL predicate gained
    its cp1252 round-trip guard this path should rarely trigger, but it is
    kept as a defensive net."""
    samples: List[MojibakeSample] = []
    truncated = False
    skipped = 0
    for value in values:
        try:
            repaired = value.encode("cp1252").decode("utf-8")
        except UnicodeError:
            skipped += 1
            continue
        if len(samples) >= limit:
            truncated = True
            continue
        samples.append(MojibakeSample(garbled=value, repaired=repaired))
    return tuple(samples), truncated, skipped


def _find_incomplete_utf8_lenient(raw: bytes) -> Optional[Tuple[int, bytes, str]]:
    """Byte-structure walk that tolerates CESU-8 (Oracle's older 'UTF8'
    charset stores a supplementary character as two 3-byte surrogate
    sequences, which strict UTF-8 rejects). Flags only the corruption that
    matters here: a lead byte whose continuation bytes run off the end of the
    value, an orphan continuation byte, or an illegal start byte."""
    length = len(raw)
    index = 0
    while index < length:
        byte = raw[index]
        if byte < 0x80:
            index += 1
            continue
        if 0xC2 <= byte <= 0xDF:
            needed = 1
        elif 0xE0 <= byte <= 0xEF:
            needed = 2
        elif 0xF0 <= byte <= 0xF4:
            needed = 3
        else:
            return index, raw[index:index + 1], "invalid start byte"
        if index + needed >= length:
            return index, bytes(raw[index:length]), "unexpected end of data"
        for offset in range(1, needed + 1):
            if not 0x80 <= raw[index + offset] <= 0xBF:
                return index, bytes(raw[index:index + offset]), "invalid continuation byte"
        index += needed + 1
    return None


def find_incomplete_utf8(raw: bytes, *, strict: bool) -> Optional[Tuple[int, bytes, str]]:
    """Return (byte_offset, bad_bytes, reason) for the first structurally
    invalid or incomplete UTF-8 in ``raw``, or None if it is clean.

    ``byte_offset`` is the start of the broken sequence, which is also the
    number of leading bytes that are safe to keep. ``strict`` (AL32UTF8) uses
    Python's UTF-8 decoder, which additionally rejects overlong forms, lone
    surrogates and illegal bytes; ``strict=False`` (UTF8 / CESU-8) tolerates
    surrogate-pair encodings -- see ``_find_incomplete_utf8_lenient``."""
    if not strict:
        return _find_incomplete_utf8_lenient(raw)
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return exc.start, bytes(raw[exc.start:exc.end]), exc.reason
    return None


def _apply_column_allowlist(
    all_columns: List[Tuple[str, str]],
    allowlist: Optional[Set[str]],
    obj: DbObject,
    notes: List[str],
) -> List[Tuple[str, str]]:
    """Filter (name, data_type) pairs to the manifest's requested columns.
    A requested name that is missing, or present but not a text type, is
    dropped with an explanatory note rather than failing the run."""
    text_columns = [(name, dt) for name, dt in all_columns if dt in TEXT_TYPES]
    if allowlist is None:
        return text_columns
    by_upper = {name.upper(): dt for name, dt in all_columns}
    kept = [(name, dt) for name, dt in text_columns if name.upper() in allowlist]
    kept_upper = {name.upper() for name, _ in kept}
    for wanted in sorted(allowlist):
        if wanted in kept_upper:
            continue
        if wanted in by_upper:
            notes.append(
                "column {0} ({1}): not a scannable text type, skipped".format(wanted, by_upper[wanted])
            )
        else:
            notes.append(
                "column {0}: not found in {1}.{2}, skipped".format(wanted, obj.owner, obj.name)
            )
    return kept


def _scan_one_truncated_only(
    cursor: Any,
    obj: DbObject,
    name: str,
    data_type: str,
    row_limit: Optional[int],
    truncation_mode: Optional[str],
    notes: List[str],
) -> ColumnScan:
    """Build a ColumnScan carrying only the partial-multibyte result; every
    other count is left as None. ``truncation_mode`` is None when the database
    character set isn't UTF-8 (the whole check is skipped for the run)."""
    truncated_count: Optional[int] = None
    truncated_rows: Tuple[TruncatedRow, ...] = ()
    if truncation_mode is not None:
        if data_type in RAW_READABLE_TEXT_TYPES:
            truncated_rows = _detect_truncated_rows(
                cursor, obj, name, row_limit, truncation_mode == "strict"
            )
            truncated_count = len(truncated_rows)
        else:
            notes.append(
                "column {0} ({1}): partial-multibyte check supports "
                "VARCHAR2/CHAR only, skipped".format(name, data_type)
            )
    return ColumnScan(
        name, data_type, None, None,
        truncated_count=truncated_count, truncated_rows=truncated_rows,
    )


def _scan_one(
    cursor: Any,
    obj: DbObject,
    settings: ScanSettings,
    progress: Optional[ProgressFactory] = None,
    *,
    truncation_mode: Optional[str] = None,
    column_allowlist: Optional[Set[str]] = None,
) -> ObjectScanResult:
    columns: List[ColumnScan] = []
    notes: List[str] = []
    columns_meta = _apply_column_allowlist(
        list(_columns(cursor, obj)), column_allowlist, obj, notes
    )
    iterator = columns_meta if progress is None else progress(
        columns_meta, len(columns_meta), "{0}.{1}".format(obj.owner, obj.name)
    )
    for name, data_type in iterator:
        try:
            if settings.detect_truncated:
                # Exclusive mode: the partial-multibyte check is this tool's
                # main purpose, so when it is on it is the ONLY thing we run --
                # no multibyte count, mojibake, non-ASCII, or sampling.
                columns.append(
                    _scan_one_truncated_only(
                        cursor, obj, name, data_type, settings.row_limit, truncation_mode, notes
                    )
                )
                continue
            quoted = quote_identifier(name)
            predicate = MULTIBYTE_PREDICATE_TEMPLATE.format(quoted)
            if settings.capture_fix_rowids:
                rowids = _fetch_flagged_rowids(cursor, obj, name, predicate, settings.row_limit)
                multi = len(rowids)
            else:
                rowids = ()
                multi = _count(cursor, obj, name, predicate, settings.row_limit)
            ascii_count = None
            if settings.include_non_ascii:
                ascii_count = _count(
                    cursor, obj, name,
                    "REGEXP_LIKE({0}, '[^' || CHR(1) || '-' || CHR(127) || ']')".format(quoted),
                    settings.row_limit,
                )
            samples: Tuple[MultibyteChar, ...] = ()
            samples_truncated = False
            if multi:
                raw_values = _sample_flagged_values(
                    cursor, obj, name, predicate, settings.row_limit, settings.sample_row_limit
                )
                samples, char_cap_hit = _extract_multibyte_chars(raw_values, settings.sample_char_limit)
                samples_truncated = char_cap_hit or multi > len(raw_values)
            mojibake_count: Optional[int] = None
            mojibake_rowids: Tuple[str, ...] = ()
            mojibake_samples: Tuple[MojibakeSample, ...] = ()
            mojibake_samples_truncated = False
            mojibake_samples_skipped = 0
            if settings.detect_mojibake:
                mojibake_predicate = MOJIBAKE_PREDICATE_TEMPLATE.format(quoted)
                if settings.capture_mojibake_rowids:
                    mojibake_rowids = tuple(
                        _fetch_flagged_rowids(cursor, obj, name, mojibake_predicate, settings.row_limit)
                    )
                    mojibake_count = len(mojibake_rowids)
                else:
                    mojibake_count = _count(cursor, obj, name, mojibake_predicate, settings.row_limit)
                if mojibake_count:
                    raw_mojibake_values = _sample_flagged_values(
                        cursor, obj, name, mojibake_predicate, settings.row_limit, settings.mojibake_sample_limit
                    )
                    mojibake_samples, repair_truncated, mojibake_samples_skipped = _repair_mojibake_samples(
                        raw_mojibake_values, settings.mojibake_sample_limit
                    )
                    mojibake_samples_truncated = repair_truncated or mojibake_count > len(raw_mojibake_values)
            columns.append(
                ColumnScan(
                    name, data_type, multi, ascii_count,
                    multibyte_samples=samples, multibyte_samples_truncated=samples_truncated,
                    flagged_rowids=tuple(rowids),
                    mojibake_count=mojibake_count, mojibake_rowids=mojibake_rowids,
                    mojibake_samples=mojibake_samples, mojibake_samples_truncated=mojibake_samples_truncated,
                    mojibake_samples_skipped=mojibake_samples_skipped,
                )
            )
        except oracledb.Error as exc:
            columns.append(ColumnScan(name, data_type, None, None, "error", "Oracle error {0}".format(_error_code(exc))))
    return ObjectScanResult(
        obj, columns, "bounded" if settings.row_limit else "exhaustive", notes=tuple(notes)
    )


def _object_key(obj: DbObject) -> Tuple[str, str, str]:
    return (obj.owner, obj.name, obj.object_type)


def scan_objects(
    cursor: Any,
    selected: Sequence[DbObject],
    settings: ScanSettings,
    progress: Optional[ProgressFactory] = None,
    *,
    column_filter: Optional[dict] = None,
) -> ScanBatchResult:
    """Scan selected objects, optionally followed by their accessible source tables.

    ``column_filter`` (JSON-manifest mode) maps ``_object_key(obj)`` to a set of
    upper-cased column names; only those columns of that object are scanned.
    Objects with no entry -- including resolved source tables -- are scanned in
    full, exactly as without a filter."""
    selected_objects = tuple(selected)
    dependencies: List[Dependency] = []
    dependency_keys: Set[Tuple[str, str, str]] = set()
    for obj in selected_objects:
        if obj.object_type == "TABLE":
            continue
        for dependency in resolve_dependencies(cursor, obj):
            key = _object_key(dependency.object)
            if key not in dependency_keys:
                dependency_keys.add(key)
                dependencies.append(dependency)

    selected_keys = {_object_key(obj) for obj in selected_objects}
    source_objects = [
        dependency.object
        for dependency in dependencies
        if dependency.access == "accessible" and _object_key(dependency.object) not in selected_keys
    ]
    scan_targets = list(selected_objects)
    if settings.scope == "selected-and-sources":
        scan_targets.extend(source_objects)

    charset, truncation_mode, truncated_skip_reason = _resolve_truncation_mode(cursor, settings)

    scanned_keys: Set[Tuple[str, str, str]] = set()
    results: List[ObjectScanResult] = []
    for obj in object_progress(scan_targets, total=len(scan_targets), desc="Scanning objects", unit="object"):
        key = _object_key(obj)
        if key in scanned_keys:
            continue
        scanned_keys.add(key)
        allowlist = None if column_filter is None else column_filter.get(key)
        results.append(
            _scan_one(
                cursor, obj, settings, progress,
                truncation_mode=truncation_mode, column_allowlist=allowlist,
            )
        )
    return ScanBatchResult(
        selected_objects, settings, tuple(dependencies), tuple(results),
        charset=charset, truncated_skip_reason=truncated_skip_reason,
    )


def _resolve_truncation_mode(
    cursor: Any, settings: ScanSettings
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (database charset, validation mode, skip reason). Mode is
    'strict' for AL32UTF8, 'lenient' for UTF8/CESU-8, and None for any other
    charset (with a skip reason set). Only consults the database when the
    partial-multibyte check is actually enabled."""
    if not settings.detect_truncated:
        return None, None, None
    charset = database_character_set(cursor)
    normalized = (charset or "").upper()
    if normalized == "AL32UTF8":
        return charset, "strict", None
    if normalized == "UTF8":
        return charset, "lenient", None
    return charset, None, (
        "partial-multibyte check skipped: database character set {0} is not UTF-8".format(
            charset or "unknown"
        )
    )


def scan_object(
    cursor: Any,
    selected: DbObject,
    settings: ScanSettings,
    progress: Optional[ProgressFactory] = None,
) -> ScanResult:
    batch = scan_objects(cursor, (selected,), settings, progress)
    return ScanResult(
        selected, batch.settings, list(batch.dependencies), list(batch.objects),
        charset=batch.charset, truncated_skip_reason=batch.truncated_skip_reason,
    )
