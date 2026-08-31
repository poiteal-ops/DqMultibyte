import json

import pytest

from mbscan.oracle.connection import ConfigError
from mbscan.manifest import ManifestTable, ScanManifest, load_scan_manifest


def _write(tmp_path, payload):
    path = tmp_path / "scan_targets.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_scan_manifest_parses_owner_and_tables(tmp_path):
    path = _write(
        tmp_path,
        {
            "owner": "DQ_TEST",
            "tables": [
                {"table": "CUSTOMER_ADDRESSES", "columns": ["ADDRESS_LINE_1", "CITY"]},
                {"table": "EMPLOYEES", "columns": ["EMAIL"]},
            ],
        },
    )

    manifest = load_scan_manifest(path)

    assert manifest == ScanManifest(
        owner="DQ_TEST",
        tables=(
            ManifestTable("CUSTOMER_ADDRESSES", ("ADDRESS_LINE_1", "CITY")),
            ManifestTable("EMPLOYEES", ("EMAIL",)),
        ),
    )


def test_load_scan_manifest_treats_missing_columns_as_scan_all(tmp_path):
    path = _write(tmp_path, {"owner": "DQ_TEST", "tables": [{"table": "EMPLOYEES"}]})

    manifest = load_scan_manifest(path)

    assert manifest.tables[0].columns == ()


def test_load_scan_manifest_treats_empty_columns_list_as_scan_all(tmp_path):
    path = _write(
        tmp_path, {"owner": "DQ_TEST", "tables": [{"table": "EMPLOYEES", "columns": []}]}
    )

    assert load_scan_manifest(path).tables[0].columns == ()


def test_load_scan_manifest_dedupes_columns_case_insensitively_keeping_order(tmp_path):
    path = _write(
        tmp_path,
        {"owner": "DQ_TEST", "tables": [{"table": "T", "columns": ["A", "b", "a", "B"]}]},
    )

    assert load_scan_manifest(path).tables[0].columns == ("A", "b")


def test_load_scan_manifest_rejects_a_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_scan_manifest(tmp_path / "nope.json")


def test_load_scan_manifest_rejects_invalid_json(tmp_path):
    path = tmp_path / "scan_targets.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_scan_manifest(path)


def test_load_scan_manifest_rejects_a_non_object_top_level(tmp_path):
    path = _write(tmp_path, ["DQ_TEST"])

    with pytest.raises(ConfigError):
        load_scan_manifest(path)


@pytest.mark.parametrize("owner", [None, "", "   ", 5])
def test_load_scan_manifest_rejects_a_bad_owner(tmp_path, owner):
    path = _write(tmp_path, {"owner": owner, "tables": [{"table": "T"}]})

    with pytest.raises(ConfigError, match="owner"):
        load_scan_manifest(path)


@pytest.mark.parametrize("tables", [None, [], "T1", {}])
def test_load_scan_manifest_rejects_bad_tables(tmp_path, tables):
    path = _write(tmp_path, {"owner": "DQ_TEST", "tables": tables})

    with pytest.raises(ConfigError, match="tables"):
        load_scan_manifest(path)


def test_load_scan_manifest_rejects_a_table_entry_that_is_not_an_object(tmp_path):
    path = _write(tmp_path, {"owner": "DQ_TEST", "tables": ["EMPLOYEES"]})

    with pytest.raises(ConfigError):
        load_scan_manifest(path)


def test_load_scan_manifest_rejects_a_table_entry_without_a_name(tmp_path):
    path = _write(tmp_path, {"owner": "DQ_TEST", "tables": [{"columns": ["A"]}]})

    with pytest.raises(ConfigError, match="table"):
        load_scan_manifest(path)


def test_load_scan_manifest_rejects_duplicate_tables_case_insensitively(tmp_path):
    path = _write(
        tmp_path,
        {"owner": "DQ_TEST", "tables": [{"table": "Employees"}, {"table": "EMPLOYEES"}]},
    )

    with pytest.raises(ConfigError, match="more than once"):
        load_scan_manifest(path)


def test_load_scan_manifest_rejects_non_list_columns(tmp_path):
    path = _write(
        tmp_path, {"owner": "DQ_TEST", "tables": [{"table": "T", "columns": "A,B"}]}
    )

    with pytest.raises(ConfigError, match="columns"):
        load_scan_manifest(path)


def test_load_scan_manifest_rejects_blank_column_names(tmp_path):
    path = _write(
        tmp_path, {"owner": "DQ_TEST", "tables": [{"table": "T", "columns": ["A", "  "]}]}
    )

    with pytest.raises(ConfigError):
        load_scan_manifest(path)
