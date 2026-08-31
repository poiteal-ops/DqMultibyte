"""Oracle data-dictionary helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

from mbscan.oracle.connection import ConfigError


@dataclass(frozen=True)
class DbObject:
    """A visible Oracle table, view, or materialized view."""

    owner: str
    name: str
    object_type: str


def parse_object_names(value: str | None, key_name: str = "object") -> tuple[str, ...]:
    """Parse one or more comma-separated object names."""
    if value is None:
        return ()
    if not isinstance(value, str):
        raise ConfigError("{0} must be a string or unset.".format(key_name))
    names = []
    seen = set()
    for raw_name in value.split(","):
        name = raw_name.strip()
        if not name:
            raise ConfigError("{0} must not contain blank entries.".format(key_name))
        normalized = name.upper()
        if normalized not in seen:
            seen.add(normalized)
            names.append(name)
    return tuple(names)


def resolve_unique_case_insensitive_match(candidates: List[str], requested: str, kind: str) -> str:
    """Resolve ``requested`` against ``candidates`` that already match it
    case-insensitively, preferring an exact match and rejecting ambiguity when
    more than one case-insensitive candidate remains.

    Callers must pre-filter ``candidates`` to names where
    ``name.upper() == requested.upper()`` (e.g. via a SQL ``UPPER(...)``
    predicate, or an equivalent Python filter) before calling this. Oracle
    permits quoted-case identifiers (``Foo``, ``FOO``, ``foo``) to coexist as
    distinct objects in the same namespace; silently picking an arbitrary
    candidate when more than one remains would let the caller scan or report
    on a different object than the one the operator intended, so this raises
    ``ConfigError`` instead.
    """
    if not candidates:
        raise ConfigError(
            "{0} '{1}' does not exist or is not visible to this account.".format(kind, requested)
        )
    exact = [name for name in candidates if name == requested]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise ConfigError(
            "{0} '{1}' matches multiple identically-named objects; this indicates "
            "a data dictionary inconsistency.".format(kind, requested)
        )
    if len(candidates) > 1:
        raise ConfigError(
            "{0} '{1}' is ambiguous: it matches multiple visible names that differ only "
            "by case ({2}). Specify the exact case to disambiguate.".format(
                kind, requested, ", ".join(sorted(candidates))
            )
        )
    return candidates[0]


def validate_owner(cursor: Any, owner: str) -> str:
    """Return a visible schema name exactly as supplied by Oracle's dictionary.

    ``owner`` is bound as a value and matched case-insensitively, since a
    caller-supplied name (e.g. from .env or config) may not match Oracle's
    uppercase-stored dictionary casing. The returned dictionary-sourced
    identifier must still be escaped with :func:`quote_identifier` before SQL
    interpolation. If more than one visible schema matches case-insensitively
    (e.g. quoted-case ``"Foo"`` and ``"FOO"`` both exist), this raises
    ``ConfigError`` rather than silently picking one.
    """
    cursor.execute(
        "SELECT username FROM all_users WHERE UPPER(username) = UPPER(:owner)",
        {"owner": owner},
    )
    names = [row[0] for row in cursor.fetchall()]
    return resolve_unique_case_insensitive_match(names, owner, "Schema/owner")


def database_character_set(cursor: Any) -> str:
    """Return the database character set (e.g. ``AL32UTF8``), read from
    ``nls_database_parameters``. Used to decide whether the partial-multibyte
    check can run and, if so, how strictly to validate byte structure."""
    cursor.execute(
        "SELECT value FROM nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET'"
    )
    row = cursor.fetchone()
    return row[0] if row else ""


def list_exportable_objects(cursor: Any, owner: str) -> List[DbObject]:
    """List visible tables, views, and materialized views for ``owner``.

    The table query omits materialized-view container tables, preventing a
    materialized view from appearing twice. ``owner`` remains a bound value.
    """
    queries = (
        (
            "TABLE",
            "SELECT t.table_name FROM all_tables t "
            "WHERE t.owner = :owner AND NOT EXISTS ("
            "  SELECT 1 FROM all_mviews m "
            "  WHERE m.owner = t.owner AND m.mview_name = t.table_name"
            ")",
        ),
        ("VIEW", "SELECT view_name FROM all_views WHERE owner = :owner"),
        ("MVIEW", "SELECT mview_name FROM all_mviews WHERE owner = :owner"),
    )
    objects: List[DbObject] = []
    for object_type, sql in queries:
        cursor.execute(sql, {"owner": owner})
        objects.extend(
            DbObject(owner=owner, name=row[0], object_type=object_type)
            for row in cursor.fetchall()
        )
    return sorted(objects, key=lambda obj: (obj.name, obj.object_type))


def resolve_requested_objects(cursor: Any, owner: str, names: tuple[str, ...]) -> tuple[DbObject, ...]:
    """Resolve requested names against one dictionary listing in request order."""
    objects = list_exportable_objects(cursor, owner)
    resolved = []
    for requested in names:
        candidates = [obj for obj in objects if obj.name.upper() == requested.upper()]
        resolved_name = resolve_unique_case_insensitive_match(
            [obj.name for obj in candidates], requested, "Object"
        )
        resolved.append(next(obj for obj in candidates if obj.name == resolved_name))
    return tuple(resolved)


def format_object_menu(objects: List[DbObject]) -> str:
    """Render numbered object choices without performing interactive input."""
    return "\n".join(
        "{0:>3}. [{1}] {2}".format(index, obj.object_type, obj.name)
        for index, obj in enumerate(objects, start=1)
    )


def quote_identifier(identifier: str) -> str:
    """Safely quote an Oracle identifier that must be interpolated into SQL.

    Oracle identifiers cannot be bound. This function therefore wraps an
    identifier in double quotes and doubles embedded quotes; callers must use
    it only after obtaining the name from Oracle's data dictionary.
    """
    return '"' + identifier.replace('"', '""') + '"'
