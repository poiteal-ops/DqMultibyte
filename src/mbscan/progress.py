"""Shared command-line progress helpers."""
from __future__ import annotations

from typing import Iterable, Optional, TypeVar

from tqdm import tqdm


T = TypeVar("T")


def progress(
    iterable: Iterable[T],
    total: Optional[int] = None,
    desc: str = "",
    unit: str = "it",
):
    """Wrap an iterable in the project's standard progress display."""
    return tqdm(iterable, total=total, desc=desc, unit=unit, leave=False, disable=None)


def run_complete() -> None:
    """Print the standard completion message."""
    print("Run complete")
