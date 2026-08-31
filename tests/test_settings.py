from types import SimpleNamespace

import pytest

from mbscan.oracle.connection import ConfigError
from mbscan import settings


def _args(**overrides):
    defaults = dict(
        owner=None,
        object_name=None,
        all_objects=None,
        timeout_seconds=None,
        include_source_tables=None,
        row_limit=None,
        include_non_ascii=None,
        output_dir=None,
        fixes_dir=None,
        generate_fixes=None,
        sample_row_limit=None,
        sample_char_limit=None,
        fix_grouping=None,
        detect_mojibake=None,
        mojibake_sample_limit=None,
        detect_truncated=None,
        json_entry=None,
        json_entry_file=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_resolve_settings_uses_config_values_when_no_cli_flags_are_passed():
    resolved = settings.resolve_settings(
        {"owner": "SCOTT", "object": "T1", "row_limit": 500}, _args()
    )

    assert resolved.owner == "SCOTT"
    assert resolved.object_names == ("T1",)
    assert resolved.all_objects is False
    assert resolved.timeout_seconds == 30
    assert resolved.scan.row_limit == 500
    assert resolved.scan.scope == "selected"
    assert resolved.scan.include_non_ascii is False


def test_resolve_settings_lets_a_passed_cli_flag_override_one_config_key():
    resolved = settings.resolve_settings(
        {"owner": "SCOTT", "object": "T1", "row_limit": 500},
        _args(row_limit=10),
    )

    assert resolved.owner == "SCOTT"
    assert resolved.scan.row_limit == 10


def test_resolve_settings_falls_back_to_hardcoded_defaults_when_nothing_is_set():
    resolved = settings.resolve_settings({}, _args())

    assert resolved.owner is None
    assert resolved.object_names == ()
    assert resolved.all_objects is False
    assert resolved.timeout_seconds == 30
    assert resolved.scan.row_limit is None
    assert resolved.scan.scope == "selected"
    assert resolved.scan.include_non_ascii is False


def test_resolve_settings_maps_include_source_tables_to_scan_scope():
    resolved = settings.resolve_settings({}, _args(include_source_tables=True))

    assert resolved.scan.scope == "selected-and-sources"


def test_resolve_settings_lets_a_cli_flag_override_a_true_config_value_back_to_false():
    resolved = settings.resolve_settings(
        {"include_source_tables": True}, _args(include_source_tables=False)
    )

    assert resolved.scan.scope == "selected"


def test_resolve_settings_rejects_a_zero_timeout_seconds_from_config():
    with pytest.raises(ConfigError, match="timeout_seconds"):
        settings.resolve_settings({"timeout_seconds": 0}, _args())


def test_resolve_settings_rejects_a_negative_timeout_seconds_from_config():
    with pytest.raises(ConfigError, match="timeout_seconds"):
        settings.resolve_settings({"timeout_seconds": -5}, _args())


def test_resolve_settings_rejects_a_string_row_limit_from_config():
    with pytest.raises(ConfigError, match="row_limit"):
        settings.resolve_settings({"row_limit": "1000"}, _args())


def test_resolve_settings_rejects_a_zero_row_limit_from_config():
    with pytest.raises(ConfigError, match="row_limit"):
        settings.resolve_settings({"row_limit": 0}, _args())


def test_resolve_settings_rejects_a_string_timeout_seconds_from_cli_args():
    # args.timeout_seconds normally arrives as an int via argparse's _positive
    # type, but resolve_settings should not trust that blindly either.
    with pytest.raises(ConfigError, match="timeout_seconds"):
        settings.resolve_settings({}, _args(timeout_seconds="30"))


def test_resolve_settings_defaults_output_dir_to_reports_and_fixes_dir_to_none():
    from pathlib import Path

    resolved = settings.resolve_settings({}, _args())

    assert resolved.output_dir == Path("output") / "reports"
    assert resolved.fixes_dir is None
    assert resolved.generate_fixes is True
    assert resolved.scan.sample_row_limit == 200
    assert resolved.scan.sample_char_limit == 20


def test_resolve_settings_uses_config_values_for_output_and_fixes_dirs():
    from pathlib import Path

    resolved = settings.resolve_settings(
        {"output_dir": "custom_reports", "fixes_dir": "custom_fixes", "generate_fixes": False,
         "sample_row_limit": 50, "sample_char_limit": 5},
        _args(),
    )

    assert resolved.output_dir == Path("custom_reports")
    assert resolved.fixes_dir == Path("custom_fixes")
    assert resolved.generate_fixes is False
    assert resolved.scan.sample_row_limit == 50
    assert resolved.scan.sample_char_limit == 5


def test_resolve_settings_lets_cli_flags_override_output_and_fixes_config():
    from pathlib import Path

    resolved = settings.resolve_settings(
        {"output_dir": "custom_reports", "fixes_dir": "custom_fixes", "generate_fixes": False},
        _args(output_dir="cli_reports", fixes_dir="cli_fixes", generate_fixes=True),
    )

    assert resolved.output_dir == Path("cli_reports")
    assert resolved.fixes_dir == Path("cli_fixes")
    assert resolved.generate_fixes is True


def test_resolve_settings_rejects_a_zero_sample_row_limit_from_config():
    with pytest.raises(ConfigError, match="sample_row_limit"):
        settings.resolve_settings({"sample_row_limit": 0}, _args())


def test_resolve_settings_rejects_a_zero_sample_char_limit_from_config():
    with pytest.raises(ConfigError, match="sample_char_limit"):
        settings.resolve_settings({"sample_char_limit": 0}, _args())


def test_multibyte_all_objects_is_available_and_wins_over_configured_object():
    resolved = settings.resolve_settings(
        {"owner": "HR", "object": "EMPLOYEES, DEPARTMENTS", "all_objects": True},
        _args(),
    )

    assert resolved.object_names == ("EMPLOYEES", "DEPARTMENTS")
    assert resolved.all_objects is True


def test_multibyte_cli_object_list_overrides_configured_object_list():
    resolved = settings.resolve_settings(
        {"object": "T1, T2"}, _args(object_name="T3, T4")
    )

    assert resolved.object_names == ("T3", "T4")
    assert resolved.all_objects is False


def test_multibyte_cli_all_objects_wins_over_configured_object_list():
    resolved = settings.resolve_settings({"object": "T1, T2"}, _args(all_objects=True))

    assert resolved.object_names == ("T1", "T2")
    assert resolved.all_objects is True


def test_resolve_settings_defaults_fix_grouping_to_row_and_captures_rowids():
    resolved = settings.resolve_settings({}, _args())

    assert resolved.fix_grouping == "row"
    assert resolved.scan.capture_fix_rowids is True  # generate_fixes defaults to True


def test_resolve_settings_uses_configured_fix_grouping():
    resolved = settings.resolve_settings({"fix_grouping": "column"}, _args())

    assert resolved.fix_grouping == "column"
    assert resolved.scan.capture_fix_rowids is False


def test_resolve_settings_lets_cli_fix_grouping_override_config():
    resolved = settings.resolve_settings({"fix_grouping": "row"}, _args(fix_grouping="column"))

    assert resolved.fix_grouping == "column"
    assert resolved.scan.capture_fix_rowids is False


def test_resolve_settings_capture_fix_rowids_is_false_when_generate_fixes_is_off():
    resolved = settings.resolve_settings({}, _args(generate_fixes=False))

    assert resolved.fix_grouping == "row"
    assert resolved.scan.capture_fix_rowids is False


def test_resolve_settings_rejects_an_unknown_fix_grouping():
    with pytest.raises(ConfigError, match="fix_grouping"):
        settings.resolve_settings({"fix_grouping": "per_char"}, _args())


def test_resolve_settings_defaults_detect_mojibake_to_false_and_sample_limit_to_ten():
    resolved = settings.resolve_settings({}, _args())

    assert resolved.scan.detect_mojibake is False
    assert resolved.scan.mojibake_sample_limit == 10


def test_resolve_settings_uses_configured_detect_mojibake_and_sample_limit():
    resolved = settings.resolve_settings(
        {"detect_mojibake": True, "mojibake_sample_limit": 3}, _args()
    )

    assert resolved.scan.detect_mojibake is True
    assert resolved.scan.mojibake_sample_limit == 3


def test_resolve_settings_lets_cli_detect_mojibake_override_config():
    resolved = settings.resolve_settings(
        {"detect_mojibake": True}, _args(detect_mojibake=False)
    )

    assert resolved.scan.detect_mojibake is False


def test_resolve_settings_lets_cli_mojibake_sample_limit_override_config():
    resolved = settings.resolve_settings(
        {"mojibake_sample_limit": 3}, _args(mojibake_sample_limit=7)
    )

    assert resolved.scan.mojibake_sample_limit == 7


def test_resolve_settings_rejects_a_zero_mojibake_sample_limit_from_config():
    with pytest.raises(ConfigError, match="mojibake_sample_limit"):
        settings.resolve_settings({"mojibake_sample_limit": 0}, _args())


def test_resolve_settings_rejects_a_string_mojibake_sample_limit_from_config():
    with pytest.raises(ConfigError, match="mojibake_sample_limit"):
        settings.resolve_settings({"mojibake_sample_limit": "10"}, _args())


def test_resolve_settings_defaults_detect_truncated_to_false():
    resolved = settings.resolve_settings({}, _args())

    assert resolved.scan.detect_truncated is False


def test_resolve_settings_uses_configured_detect_truncated():
    resolved = settings.resolve_settings({"detect_truncated": True}, _args())

    assert resolved.scan.detect_truncated is True


def test_resolve_settings_lets_cli_detect_truncated_override_config():
    resolved = settings.resolve_settings(
        {"detect_truncated": True}, _args(detect_truncated=False)
    )

    assert resolved.scan.detect_truncated is False


def test_resolve_settings_defaults_json_entry_off_with_the_standard_file(tmp_path):
    from pathlib import Path

    resolved = settings.resolve_settings({}, _args())

    assert resolved.json_entry is False
    assert resolved.json_entry_file == Path("config/scan_targets.json")


def test_resolve_settings_uses_configured_json_entry_and_file():
    from pathlib import Path

    resolved = settings.resolve_settings(
        {"json_entry": True, "json_entry_file": "config/prod_targets.json"}, _args()
    )

    assert resolved.json_entry is True
    assert resolved.json_entry_file == Path("config/prod_targets.json")


def test_resolve_settings_lets_cli_json_entry_override_config():
    resolved = settings.resolve_settings({"json_entry": True}, _args(json_entry=False))

    assert resolved.json_entry is False


def test_resolve_settings_rejects_a_non_boolean_json_entry():
    with pytest.raises(ConfigError, match="json_entry"):
        settings.resolve_settings({"json_entry": "yes"}, _args())


@pytest.mark.parametrize(
    "generate_fixes, fix_grouping, detect_mojibake, expected",
    [
        (True, "row", True, True),
        (True, "row", False, False),
        (True, "column", True, False),
        (True, "column", False, False),
        (False, "row", True, False),
        (False, "column", True, False),
    ],
)
def test_resolve_settings_capture_mojibake_rowids_derivation(
    generate_fixes, fix_grouping, detect_mojibake, expected
):
    resolved = settings.resolve_settings(
        {},
        _args(
            generate_fixes=generate_fixes,
            fix_grouping=fix_grouping,
            detect_mojibake=detect_mojibake,
        ),
    )

    assert resolved.scan.capture_mojibake_rowids is expected
