from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ci_cd_documents_certified_python_lanes_and_external_maintenance_path() -> None:
    text = (ROOT / "docs" / "CI_CD.md").read_text(encoding="utf-8")

    assert "Python 3.11.16" in text
    assert "Python 3.14.7" in text
    assert "Python 3.13.15" not in text
    assert "external App webhook ingress" in text
    assert (
        "There is no repository-owned `repository_dispatch` protected-maintenance authority."
        in text
    )


def test_trusted_control_plane_documents_exact_dynamodb_runtime_authority() -> None:
    text = (ROOT / "docs" / "TRUSTED_PR_CONTROL_PLANE.md").read_text(encoding="utf-8")

    assert "DynamoDB: `GetItem`, `UpdateItem`, and `TransactWriteItems`" in text
    assert "underlying `PutItem`/`UpdateItem` actions" not in text
