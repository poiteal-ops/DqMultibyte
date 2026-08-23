import argparse
import logging
from pathlib import Path
from types import SimpleNamespace

import oracledb
import pytest

from mbscan.oracle.metadata import DbObject
from mbscan.oracle.connection import ConfigError
from mbscan import cli


def _register() -> argparse.ArgumentParser:
    return cli.build_parser()


def _run(argv):
    parser = _register()
    return cli.run(parser.parse_args(argv), parser)


class _ContextManager:
    """Minimal context manager stub standing in for a live Oracle connection/cursor."""

    def __init__(self, value):
        self._value = value

    def __enter__(self):
        return self._value

    def __exit__(self, *exc_info):
        return False


def _stub_successful_run(monkeypatch, obj, connect_spy=None):
    fake_cursor = object()
    fake_connection = SimpleNamespace(cursor=lambda: _ContextManager(fake_cursor))

    def fake_connect(config, timeout_seconds):
        if connect_spy is not None:
            connect_spy(timeout_seconds)
        return _ContextManager(fake_connection)

    monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace(username="scott"))
    monkeypatch.setattr(cli, "connect", fake_connect)
    monkeypatch.setattr(cli, "validate_owner", lambda cursor, owner: owner)
    monkeypatch.setattr(cli, "list_exportable_objects", lambda cursor, owner: [obj])
    monkeypatch.setattr(cli, "resolve_requested_objects", lambda cursor, owner, names: (obj,))
    monkeypatch.setattr(
        cli, "scan_objects",
        lambda cursor, selected, settings, progress=None: SimpleNamespace(
            selected=tuple(selected), settings=settings, dependencies=(), objects=[]
        ),
    )
    monkeypatch.setattr(cli, "write_report", lambda result, output_dir, **kwargs: output_dir / "report.txt")
    monkeypatch.setattr(cli, "write_fix_sql", lambda obj_result, fixes_dir, **kwargs: None)
    monkeypatch.setattr(cli, "configure_logging", lambda owner, object_name: Path("unused.log"))


def _with_config(monkeypatch, config):
    monkeypatch.setattr(cli, "load_toml_config", lambda: config)


def test_unknown_flag_is_rejected_by_the_parser():
    with pytest.raises(SystemExit):
        _register().parse_args(["--full"])


def test_all_objects_flag_defaults_to_none_and_sets_true_when_supplied():
    assert _register().parse_args([]).all_objects is None
    assert _register().parse_args(["--all-objects"]).all_objects is True


def test_fix_grouping_flag_defaults_to_none_and_accepts_row_or_column():
    assert _register().parse_args([]).fix_grouping is None
    assert _register().parse_args(["--fix-grouping", "row"]).fix_grouping == "row"
    assert _register().parse_args(["--fix-grouping", "column"]).fix_grouping == "column"


def test_fix_grouping_flag_rejects_an_unknown_value():
    with pytest.raises(SystemExit):
        _register().parse_args(["--fix-grouping", "per_char"])


def test_run_takes_owner_and_object_from_config_when_no_cli_flags_are_passed(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    _stub_successful_run(monkeypatch, obj)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    assert exit_code == 0


def test_run_matches_object_name_case_insensitively(monkeypatch, tmp_path):
    """A lowercase-typed object name (e.g. from config/config.toml) must still
    match Oracle's uppercase-stored dictionary name, not just an exact-case one."""
    obj = DbObject("SCOTT", "T1", "TABLE")
    _stub_successful_run(monkeypatch, obj)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "t1"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    assert exit_code == 0


def test_run_lets_a_cli_flag_override_one_config_key(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["settings"] = settings
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=[])

    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1", "row_limit": 500})

    exit_code = _run(["--row-limit", "10", "--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert captured["settings"].row_limit == 10


def test_run_lets_a_cli_flag_override_a_true_config_value_back_to_false(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["settings"] = settings
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=[])

    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1", "include_source_tables": True})

    exit_code = _run(["--no-include-source-tables", "--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert captured["settings"].scope == "selected"


def test_run_rejects_ambiguous_quoted_case_object_match(monkeypatch, capsys, tmp_path):
    """Two visible objects that differ only by quoted-case ("Foo" vs "FOO"),
    neither matching the requested case exactly, must not be resolved by
    silently taking the first one -- that could scan the wrong object."""
    fake_cursor = object()
    fake_connection = SimpleNamespace(cursor=lambda: _ContextManager(fake_cursor))
    monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace(username="scott"))
    monkeypatch.setattr(cli, "connect", lambda config, timeout_seconds: _ContextManager(fake_connection))
    monkeypatch.setattr(cli, "validate_owner", lambda cursor, owner: owner)
    monkeypatch.setattr(
        cli, "list_exportable_objects",
        lambda cursor, owner: [DbObject("SCOTT", "Foo", "TABLE"), DbObject("SCOTT", "FOO", "VIEW")],
    )
    monkeypatch.setattr(
        cli,
        "resolve_requested_objects",
        lambda cursor, owner, names: (_ for _ in ()).throw(
            ConfigError("Object 'foo' is ambiguous")
        ),
    )
    monkeypatch.setattr(cli, "configure_logging", lambda owner, object_name: Path("unused.log"))
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "foo"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == "Configuration error: invalid or unavailable configuration.\n"


def test_run_resolves_exact_case_match_even_when_a_case_insensitive_duplicate_exists(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "FOO", "VIEW")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["selected"] = tuple(selected)
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=[])

    fake_cursor = object()
    fake_connection = SimpleNamespace(cursor=lambda: _ContextManager(fake_cursor))
    monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace(username="scott"))
    monkeypatch.setattr(cli, "connect", lambda config, timeout_seconds: _ContextManager(fake_connection))
    monkeypatch.setattr(cli, "validate_owner", lambda cursor, owner: owner)
    monkeypatch.setattr(
        cli, "list_exportable_objects",
        lambda cursor, owner: [DbObject("SCOTT", "Foo", "TABLE"), obj],
    )
    monkeypatch.setattr(cli, "resolve_requested_objects", lambda cursor, owner, names: (obj,))
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    monkeypatch.setattr(cli, "write_report", lambda result, output_dir, **kwargs: output_dir / "report.txt")
    monkeypatch.setattr(cli, "write_fix_sql", lambda obj_result, fixes_dir, **kwargs: None)
    monkeypatch.setattr(cli, "configure_logging", lambda owner, object_name: Path("unused.log"))
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "FOO"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert captured["selected"] == (obj,)


def test_run_requires_owner_and_object_unless_interactive(monkeypatch, tmp_path):
    _with_config(monkeypatch, {})

    with pytest.raises(SystemExit):
        _run(["--output-dir", str(tmp_path)])


def test_run_rejects_interactive_mode_with_resolved_all_objects_before_connect(monkeypatch, capsys, tmp_path):
    _with_config(monkeypatch, {"owner": "SCOTT", "all_objects": True})
    monkeypatch.setattr(cli, "connect", lambda *args: pytest.fail("must not connect"))

    exit_code = _run(["--interactive", "--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == "Configuration error: invalid or unavailable configuration.\n"


def test_run_all_objects_scans_every_exportable_object(monkeypatch, tmp_path):
    first = DbObject("SCOTT", "T1", "TABLE")
    second = DbObject("SCOTT", "T2", "VIEW")
    scanned = []

    def fake_scan_objects(cursor, selected, settings, progress=None):
        scanned.extend(selected)
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=[])

    _stub_successful_run(monkeypatch, first)
    monkeypatch.setattr(cli, "list_exportable_objects", lambda cursor, owner: [first, second])
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1", "all_objects": True})

    exit_code = _run(["--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert scanned == [first, second]


def test_run_does_not_log_raw_requested_object_input(monkeypatch, tmp_path, caplog, capsys):
    requested = "T1\nFORGED_LOG_RECORD=secret"
    object_labels = []
    _stub_successful_run(monkeypatch, DbObject("SCOTT", "T1", "TABLE"))
    monkeypatch.setattr(
        cli,
        "configure_logging",
        lambda owner, object_name: object_labels.append((owner, object_name)) or Path("unused.log"),
    )
    _with_config(monkeypatch, {"owner": "SCOTT", "object": requested})

    with caplog.at_level(logging.INFO, logger="mbscan.cli"):
        exit_code = _run(["--output-dir", str(tmp_path)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert object_labels == [("mbscan", "run")]
    assert requested not in caplog.text
    assert requested not in output


def test_run_resolves_explicit_object_list_and_scans_once_as_a_batch(monkeypatch, tmp_path):
    first = DbObject("SCOTT", "T1", "TABLE")
    second = DbObject("SCOTT", "T2", "VIEW")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["selected"] = tuple(selected)
        captured["progress"] = progress
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=())

    _stub_successful_run(monkeypatch, first)
    monkeypatch.setattr(cli, "resolve_requested_objects", lambda cursor, owner, names: (first, second))
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1,T2"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert captured["selected"] == (first, second)
    assert callable(captured["progress"])


def test_multibyte_all_objects_ignores_object_list_and_notifies(monkeypatch, capsys, tmp_path):
    first = DbObject("HR", "EMPLOYEES", "TABLE")
    second = DbObject("HR", "DEPARTMENTS", "TABLE")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["selected"] = tuple(selected)
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=())

    _stub_successful_run(monkeypatch, first)
    monkeypatch.setattr(cli, "list_exportable_objects", lambda cursor, owner: [first, second])
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "HR", "object": "EMPLOYEES,DEPARTMENTS", "all_objects": True})

    assert _run(["--output-dir", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert captured["selected"] == (first, second)
    assert "all_objects" in output and "ignored" in output
    assert "Run complete" in output


def test_run_passes_resolved_timeout_into_connect(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    seen_timeouts = []
    _stub_successful_run(monkeypatch, obj, connect_spy=seen_timeouts.append)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(["--timeout-seconds", "90", "--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert seen_timeouts == [90]


def test_run_reports_a_bad_config_value_as_a_clean_configuration_error(monkeypatch, capsys, tmp_path):
    """A malformed value from config/config.toml (e.g. timeout_seconds = 0) must
    produce the same clean 'Configuration error: ...' + exit 2 as any other
    ConfigError, not an unhandled traceback."""
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1", "timeout_seconds": 0})

    exit_code = _run(["--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Configuration error" in captured.out
    assert "timeout_seconds" not in captured.out


def test_run_passes_a_callable_progress_factory_into_scan_objects(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["progress"] = progress
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=[])

    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert callable(captured["progress"])


def test_progress_wraps_an_iterable_with_a_tqdm_bar_without_changing_its_items():
    # pytest's captured stdout isn't a TTY, so disable=None auto-disables the bar here too.
    bar = cli._progress(["a", "b"], 2, "OWNER.T1")

    assert list(bar) == ["a", "b"]


def test_run_reports_oracle_errors_without_leaking_raw_details(monkeypatch, capsys, tmp_path):
    def fail_to_connect(config, timeout_seconds):
        raise oracledb.Error(
            SimpleNamespace(
                code=12541,
                message="TNS:no listener (HOST=db.internal.example.com)(PORT=1521)",
            )
        )

    monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace(username="scott"))
    monkeypatch.setattr(cli, "connect", fail_to_connect)
    monkeypatch.setattr(cli, "configure_logging", lambda owner, object_name: Path("unused.log"))
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 3
    assert "db.internal.example.com" not in captured.out
    assert "12541" in captured.out


def test_run_reports_driver_level_errors_by_full_code_not_zero(monkeypatch, capsys, tmp_path):
    """Driver-level failures (DPY-...: connection refused, timeout, TLS, ...)
    report code == 0 in python-oracledb -- only full_code identifies them.
    Regression test for a real live-DB failure that printed the
    undiagnosable "Oracle error 0" for every connection-layer problem."""
    def fail_to_connect(config, timeout_seconds):
        raise oracledb.Error(
            SimpleNamespace(
                code=0,
                full_code="DPY-4011",
                message="the database or network closed the connection",
            )
        )

    monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace(username="scott"))
    monkeypatch.setattr(cli, "connect", fail_to_connect)
    monkeypatch.setattr(cli, "configure_logging", lambda owner, object_name: Path("unused.log"))
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 3
    assert "DPY-4011" in captured.out
    assert "Oracle error 0" not in captured.out


def test_run_derives_fixes_dir_from_output_dir_when_not_given(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    obj_result = SimpleNamespace(columns=[])
    captured = {}

    def fake_write_fix_sql(result, fixes_dir, **kwargs):
        captured["fixes_dir"] = fixes_dir
        return None

    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(
        cli, "scan_objects",
        lambda cursor, selected, settings, progress=None: SimpleNamespace(
            selected=tuple(selected), settings=settings, dependencies=(), objects=[obj_result]
        ),
    )
    monkeypatch.setattr(cli, "write_fix_sql", fake_write_fix_sql)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(["--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert captured["fixes_dir"] == tmp_path / "fixes"


def test_run_lets_explicit_fixes_dir_override_the_derived_default(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    obj_result = SimpleNamespace(columns=[])
    captured = {}

    def fake_write_fix_sql(result, fixes_dir, **kwargs):
        captured["fixes_dir"] = fixes_dir
        return None

    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(
        cli, "scan_objects",
        lambda cursor, selected, settings, progress=None: SimpleNamespace(
            selected=tuple(selected), settings=settings, dependencies=(), objects=[obj_result]
        ),
    )
    monkeypatch.setattr(cli, "write_fix_sql", fake_write_fix_sql)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})
    explicit_fixes_dir = tmp_path / "elsewhere"

    exit_code = _run(["--output-dir", str(tmp_path), "--fixes-dir", str(explicit_fixes_dir)])

    assert exit_code == 0
    assert captured["fixes_dir"] == explicit_fixes_dir


def test_run_no_generate_fixes_suppresses_all_fix_writing(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    obj_result = SimpleNamespace(columns=[])
    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(
        cli, "scan_objects",
        lambda cursor, selected, settings, progress=None: SimpleNamespace(
            selected=tuple(selected), settings=settings, dependencies=(), objects=[obj_result]
        ),
    )
    calls = []
    monkeypatch.setattr(cli, "write_fix_sql", lambda result, fixes_dir, **kwargs: calls.append(result))
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(["--output-dir", str(tmp_path), "--no-generate-fixes"])

    assert exit_code == 0
    assert calls == []


def test_run_passes_sample_row_and_char_limits_into_scan_settings(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["settings"] = settings
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=[])

    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(
        ["--sample-row-limit", "50", "--sample-char-limit", "5", "--output-dir", str(tmp_path)]
    )

    assert exit_code == 0
    assert captured["settings"].sample_row_limit == 50
    assert captured["settings"].sample_char_limit == 5


def test_detect_mojibake_flag_defaults_to_none_and_supports_negation():
    assert _register().parse_args([]).detect_mojibake is None
    assert _register().parse_args(["--detect-mojibake"]).detect_mojibake is True
    assert _register().parse_args(["--no-detect-mojibake"]).detect_mojibake is False


def test_mojibake_sample_limit_flag_defaults_to_none_and_accepts_a_positive_int():
    assert _register().parse_args([]).mojibake_sample_limit is None
    assert _register().parse_args(["--mojibake-sample-limit", "3"]).mojibake_sample_limit == 3


def test_mojibake_sample_limit_flag_rejects_a_non_positive_value():
    with pytest.raises(SystemExit):
        _register().parse_args(["--mojibake-sample-limit", "0"])


def test_run_passes_mojibake_settings_into_scan_settings(monkeypatch, tmp_path):
    obj = DbObject("SCOTT", "T1", "TABLE")
    captured = {}

    def fake_scan_objects(cursor, selected, settings, progress=None):
        captured["settings"] = settings
        return SimpleNamespace(selected=tuple(selected), settings=settings, dependencies=(), objects=[])

    _stub_successful_run(monkeypatch, obj)
    monkeypatch.setattr(cli, "scan_objects", fake_scan_objects)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    exit_code = _run(
        ["--detect-mojibake", "--mojibake-sample-limit", "3", "--output-dir", str(tmp_path)]
    )

    assert exit_code == 0
    assert captured["settings"].detect_mojibake is True
    assert captured["settings"].mojibake_sample_limit == 3


def test_run_logs_resolved_mojibake_settings(monkeypatch, tmp_path, caplog):
    obj = DbObject("SCOTT", "T1", "TABLE")
    _stub_successful_run(monkeypatch, obj)
    _with_config(monkeypatch, {"owner": "SCOTT", "object": "T1"})

    with caplog.at_level(logging.INFO, logger="mbscan.cli"):
        exit_code = _run(
            ["--detect-mojibake", "--mojibake-sample-limit", "3", "--output-dir", str(tmp_path)]
        )

    assert exit_code == 0
    resolved_log = next(
        record.getMessage() for record in caplog.records if "Resolved settings" in record.getMessage()
    )
    assert "detect_mojibake=True" in resolved_log
    assert "mojibake_sample_limit=3" in resolved_log
