"""Shared test isolation for process-wide mbscan logging state."""

import logging

import pytest

from mbscan import logging_setup


@pytest.fixture(autouse=True)
def _isolate_mbscan_logging(monkeypatch, tmp_path):
    monkeypatch.setattr(logging_setup, "LOG_DIR", tmp_path / "logs")
    yield

    logger = logging.getLogger("mbscan")
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
