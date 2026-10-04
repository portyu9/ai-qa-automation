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
                            "artifactLocation": {
                                "uri": ".github/scripts/security_autoheal.py"
                            }
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

    with pytest.raises(ValueError, match="not produced by CodeQL"):
        gate.verify_zero_findings(tmp_path)


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "python.sarif").write_text(
        '{"version":"2.1.0","version":"2.1.0","runs":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate object key"):
        gate.verify_zero_findings(tmp_path)


def test_symlinked_sarif_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "real.sarif"
    _write_sarif(target, results=[])
    link = tmp_path / "linked.sarif"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="unexpected symlink"):
        gate.verify_zero_findings(tmp_path)
