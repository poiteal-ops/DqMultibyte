"""Sanitised Oracle error reporting.

Oracle exception messages can carry connection strings, host names, and
fragments of the failing SQL. Everything user-facing -- logs, CLI output --
goes through this helper instead, so only the error *code* ever escapes.
"""
from __future__ import annotations

from typing import Optional


def oracle_error_code(exc: Exception) -> Optional[str]:
    """Return an ``ORA-NNNNN`` code (or the bare number) without any detail."""
    args = getattr(exc, "args", ())
    if not args:
        return None
    error = args[0]
    full_code = getattr(error, "full_code", None)
    if full_code:
        return full_code
    code = getattr(error, "code", None)
    return str(code) if code else None
