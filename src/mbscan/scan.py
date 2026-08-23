"""Aggregate-only Oracle character encoding scans."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, List, Optional, Sequence, Set, Tuple

import oracledb

from mbscan.progress import progress as object_progress
from mbscan.oracle.metadata import DbObject, quote_identifier

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


@dataclass(frozen=True)
class ObjectScanResult:
    object: DbObject
    columns: List[ColumnScan]
    coverage: str
    error_code: Optional[int] = None


@dataclass(frozen=True)
class ScanResult:
    selected: DbObject
    settings: ScanSettings
    dependencies: List[Dependency]
    objects: List[ObjectScanResult]


@dataclass(frozen=True)
class ScanBatchResult:
    selected: Tuple[DbObject, ...]
    settings: ScanSettings
    dependencies: Tuple[Dependency, ...]
    objects: Tuple[ObjectScanResult, ...]


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


def _scan_one(
    cursor: Any,
    obj: DbObject,
    settings: ScanSettings,
    progress: Optional[ProgressFactory] = None,
) -> ObjectScanResult:
    columns: List[ColumnScan] = []
    columns_meta = [
        (name, data_type) for name, data_type in _columns(cursor, obj) if data_type in TEXT_TYPES
    ]
    iterator = columns_meta if progress is None else progress(
        columns_meta, len(columns_meta), "{0}.{1}".format(obj.owner, obj.name)
    )
    for name, data_type in iterator:
        try:
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
    return ObjectScanResult(obj, columns, "bounded" if settings.row_limit else "exhaustive")


def _object_key(obj: DbObject) -> Tuple[str, str, str]:
    return (obj.owner, obj.name, obj.object_type)


def scan_objects(
    cursor: Any,
    selected: Sequence[DbObject],
    settings: ScanSettings,
    progress: Optional[ProgressFactory] = None,
) -> ScanBatchResult:
    """Scan selected objects, optionally followed by their accessible source tables."""
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

    scanned_keys: Set[Tuple[str, str, str]] = set()
    results: List[ObjectScanResult] = []
    for obj in object_progress(scan_targets, total=len(scan_targets), desc="Scanning objects", unit="object"):
        key = _object_key(obj)
        if key in scanned_keys:
            continue
        scanned_keys.add(key)
        results.append(_scan_one(cursor, obj, settings, progress))
    return ScanBatchResult(selected_objects, settings, tuple(dependencies), tuple(results))


def scan_object(
    cursor: Any,
    selected: DbObject,
    settings: ScanSettings,
    progress: Optional[ProgressFactory] = None,
) -> ScanResult:
    batch = scan_objects(cursor, (selected,), settings, progress)
    return ScanResult(selected, batch.settings, list(batch.dependencies), list(batch.objects))
