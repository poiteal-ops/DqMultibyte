import logging
import os
import stat

import pytest

from mbscan.logging_setup import configure_logging

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file permission bits only; Windows uses NTFS ACLs"
)


def test_configure_logging_restricts_log_dir_and_file_to_the_owner(tmp_path):
    log_dir = tmp_path / "logs"

    path = configure_logging("mbscan", "test", log_dir=log_dir)
    logging.getLogger("mbscan").handlers[0].close()

    assert stat.S_IMODE(log_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
