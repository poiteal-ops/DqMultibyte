import os
import stat

import pytest

from mbscan.files import secure_chmod_file, secure_mkdir

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file permission bits only; Windows uses NTFS ACLs"
)


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_secure_mkdir_creates_owner_only_directory(tmp_path):
    target = tmp_path / "reports" / "fixes"

    secure_mkdir(target)

    assert target.is_dir()
    assert _mode(target) == 0o700


def test_secure_mkdir_tightens_an_existing_looser_directory(tmp_path):
    target = tmp_path / "reports"
    target.mkdir()
    target.chmod(0o755)

    secure_mkdir(target)

    assert _mode(target) == 0o700


def test_secure_chmod_file_restricts_an_existing_file(tmp_path):
    target = tmp_path / "report.txt"
    target.write_text("data", encoding="utf-8")
    target.chmod(0o644)

    secure_chmod_file(target)

    assert _mode(target) == 0o600
