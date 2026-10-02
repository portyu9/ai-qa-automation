from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ci_cd_documents_certified_python_lanes_and_github_native_maintenance() -> None:
    text = (ROOT / "docs" / "CI_CD.md").read_text(encoding="utf-8")

    assert "Python 3.11.16" in text
    assert "Python 3.14.7" in text
    assert "Python 3.13.15" not in text
    assert "There is no external cloud compatibility gate in the production architecture." in text
    assert "an active App webhook is not required for this path" in text
    assert "external App webhook ingress" not in text
    assert (
        "There is no repository-owned `repository_dispatch` protected-maintenance authority."
        in text
    )


def test_trusted_control_plane_documents_github_native_terminal_authority() -> None:
    text = (ROOT / "docs" / "TRUSTED_PR_CONTROL_PLANE.md").read_text(encoding="utf-8")

    assert "The production trust boundary is entirely GitHub-native." in text
    assert (
        "The former `scripts/trusted_gate_service/` runtime is retired and intentionally absent"
        in text
    )
    assert (
        "The dedicated Trusted PR Gate App does not require an active webhook for the production path."
        in text
    )
    assert "**same status context ≠ required App integration**" in text
    assert "DynamoDB: direct `GetItem`" not in text
    assert "AWS Lambda + DynamoDB adapter" not in text
    assert "The external compatibility service remains available" not in text
