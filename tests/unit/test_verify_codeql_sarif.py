from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import verify_codeql_sarif as gate


def _write_sarif(path: Path, *, results: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "CodeQL"}},
                        "results": results,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_zero_findings_passes(tmp_path: Path) -> None:
    _write_sarif(tmp_path / "python.sarif", results=[])

    result = gate.verify_zero_findings(tmp_path)

    assert result["result"] == "PASS"
    assert result["findings"] == 0
    assert result["analysis_runs"] == 1


def test_any_codeql_result_fails_closed(tmp_path: Path) -> None:
    _write_sarif(
        tmp_path / "python.sarif",
        results=[
            {
                "ruleId": "py/clear-text-logging-sensitive-data",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": ".github/scripts/security_autoheal.py"}
                        }
                    }
                ],
            }
        ],
    )

    with pytest.raises(ValueError, match="rejected 1 finding"):
        gate.verify_zero_findings(tmp_path)


def test_multiple_sarif_files_are_aggregated(tmp_path: Path) -> None:
    _write_sarif(tmp_path / "python.sarif", results=[])
    _write_sarif(tmp_path / "actions.sarif", results=[])

    result = gate.verify_zero_findings(tmp_path)

    assert result["sarif_files"] == 2
    assert result["analysis_runs"] == 2


def test_missing_sarif_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="produced no SARIF"):
        gate.verify_zero_findings(tmp_path)


def test_wrong_tool_fails_closed(tmp_path: Path) -> None:
    payload = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "OtherScanner"}}, "results": []}],
    }
    (tmp_path / "python.sarif").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="exact CodeQL scanner identity"):
        gate.verify_zero_findings(tmp_path)


def test_deceptive_codeql_like_tool_name_fails_closed(tmp_path: Path) -> None:
    payload = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "FakeCodeQL"}}, "results": []}],
    }
    (tmp_path / "python.sarif").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="exact CodeQL scanner identity"):
        gate.verify_zero_findings(tmp_path)


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "python.sarif").write_text(
        '{"version":"2.1.0","version":"2.1.0","runs":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate object key"):
        gate.verify_zero_findings(tmp_path)


def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "python.sarif").write_text('{"version":"2.1.0",', encoding="utf-8")

    with pytest.raises(ValueError, match="not strict JSON SARIF"):
        gate.verify_zero_findings(tmp_path)


def test_empty_runs_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "python.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="SARIF runs are missing"):
        gate.verify_zero_findings(tmp_path)


def test_result_without_rule_id_fails_closed(tmp_path: Path) -> None:
    _write_sarif(tmp_path / "python.sarif", results=[{}])

    with pytest.raises(ValueError, match="result has no ruleId"):
        gate.verify_zero_findings(tmp_path)


def test_symlinked_sarif_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "real.sarif"
    _write_sarif(target, results=[])
    link = tmp_path / "linked.sarif"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="unexpected symlink"):
        gate.verify_zero_findings(tmp_path)


def test_symlinked_output_directory_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "real-output"
    target.mkdir()
    _write_sarif(target / "python.sarif", results=[])
    link = tmp_path / "linked-output"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="real directory"):
        gate.verify_zero_findings(link)


def test_nested_output_entry_fails_closed(tmp_path: Path) -> None:
    _write_sarif(tmp_path / "python.sarif", results=[])
    (tmp_path / "nested").mkdir()

    with pytest.raises(ValueError, match="unexpected non-file"):
        gate.verify_zero_findings(tmp_path)


def test_non_sarif_output_file_fails_closed(tmp_path: Path) -> None:
    _write_sarif(tmp_path / "python.sarif", results=[])
    (tmp_path / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected non-SARIF"):
        gate.verify_zero_findings(tmp_path)


def test_file_count_bound_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate, "MAX_SARIF_FILES", 1)
    _write_sarif(tmp_path / "python.sarif", results=[])
    _write_sarif(tmp_path / "actions.sarif", results=[])

    with pytest.raises(ValueError, match="file-count bound"):
        gate.verify_zero_findings(tmp_path)


def test_per_file_size_bound_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate, "MAX_SARIF_FILE_BYTES", 32)
    (tmp_path / "python.sarif").write_text("x" * 33, encoding="utf-8")

    with pytest.raises(ValueError, match="bounded SARIF file size"):
        gate.verify_zero_findings(tmp_path)


def test_total_size_bound_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "python.sarif"
    second = tmp_path / "actions.sarif"
    _write_sarif(first, results=[])
    _write_sarif(second, results=[])
    total = first.stat().st_size + second.stat().st_size
    monkeypatch.setattr(gate, "MAX_TOTAL_SARIF_BYTES", total - 1)

    with pytest.raises(ValueError, match="total-byte bound"):
        gate.verify_zero_findings(tmp_path)


def test_scan_to_read_file_replacement_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "python.sarif"
    _write_sarif(path, results=[])
    expected = gate._file_identity(path.stat(follow_symlinks=False))
    replacement = tmp_path / "replacement.sarif"
    _write_sarif(replacement, results=[])
    replacement.replace(path)

    with pytest.raises(ValueError, match="changed after CodeQL SARIF directory scan"):
        gate._read_regular_utf8(path, expected)
