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


def write_line(text: str) -> None:
    """Print a persistent line to stdout without corrupting any active
    progress bar (tqdm temporarily clears active bars, prints, then redraws)."""
    tqdm.write(text)


def run_complete() -> None:
    """Print the standard completion message."""
    print("Run complete")
