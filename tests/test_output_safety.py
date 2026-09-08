import os
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import pytest

from mbscan.files import open_private_text, secure_mkdir
from mbscan.fixes import write_fix_sql
from mbscan.oracle.metadata import DbObject
from mbscan.scan import ObjectScanResult, ColumnScan
from mbscan.reporting import IncrementalReportWriter


def result(name="A B"):
    return ObjectScanResult(DbObject("APP", name, "TABLE"), [ColumnScan("C", "VARCHAR2", 1, None)], "exhaustive")


def test_preexisting_hardlink_cannot_overwrite_victim(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    destination = tmp_path / "artifact"
    os.link(victim, destination)
    with pytest.raises(FileExistsError):
        with open_private_text(destination) as handle:
            handle.write("overwrite")
    assert victim.read_text() == "keep"


def test_daily_append_rejects_hardlink(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    destination = tmp_path / "daily.log"
    os.link(victim, destination)
    with pytest.raises(OSError):
        with open_private_text(destination, append=True) as handle:
            handle.write("append")
    assert victim.read_text() == "keep"


def test_repeated_and_normalized_names_remain_separate(tmp_path):
    timestamp = datetime(2026, 9, 7)
    names = ["A B", "A_B", "a_b", "A_B"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        paths = list(pool.map(lambda n: write_fix_sql(result(n), tmp_path, timestamp), names))
    assert len(set(paths)) == 4
    for name, path in zip(names, paths):
        assert '"' + name + '"' in path.read_text()


def test_incremental_writer_does_not_reopen_replaced_path(tmp_path):
    path = tmp_path / "report.txt"
    writer = IncrementalReportWriter(path)
    writer.start((DbObject("APP", "T", "TABLE"),), "selected", (), None)
    moved = tmp_path / "original.txt"
    try:
        path.rename(moved)
    except PermissionError:
        # Windows deliberately denies replacement while our handle is open.
        writer.append_object(result())
        writer.close()
        assert "object:" in path.read_text()
    else:
        path.write_text("replacement")
        writer.append_object(result())
        writer.close()
        assert path.read_text() == "replacement"
        assert "object:" in moved.read_text()


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_existing_directory_permissions_are_preserved(tmp_path):
    target = tmp_path / "reports"
    target.mkdir(mode=0o755)
    secure_mkdir(target)
    assert target.stat().st_mode & 0o777 == 0o755


@pytest.mark.skipif(os.name != "nt", reason="Windows junction")
def test_junction_parent_is_rejected_before_artifact_creation(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "junction"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)], check=True, capture_output=True)
    with pytest.raises(OSError):
        with open_private_text(link / "artifact") as handle:
            handle.write("unexpected")
    assert list(real.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink/modes")
def test_symlink_and_public_append_file_are_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(OSError):
        open_private_text(link / "artifact")
    log = real / "daily.log"
    log.write_text("keep")
    log.chmod(0o644)
    with pytest.raises(PermissionError):
        open_private_text(log, append=True)
    assert log.read_text() == "keep"
