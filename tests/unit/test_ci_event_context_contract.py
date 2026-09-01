from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]
SAFE_CONCURRENCY_GROUP = "  group: ai-qa-ci-${{ github.event_name }}-${{ github.ref }}"
OLD_EVENT_PAYLOAD_GROUP = (
    "  group: ai-qa-ci-${{ github.event.pull_request.number || "
    "github.event.client_payload.pr_number || github.ref }}"
)
UNIQUE_DISPATCH_GROUP = (
    "  group: ai-qa-ci-${{ github.event_name == 'repository_dispatch' "
    "&& github.run_id || github.ref }}"
)


def _copy_workflows(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    return root


def test_automatic_ci_concurrency_uses_event_and_ref_only() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    concurrency = ci_contract._top_level_block(text, "concurrency")

    assert SAFE_CONCURRENCY_GROUP in concurrency
    assert OLD_EVENT_PAYLOAD_GROUP not in concurrency
    assert UNIQUE_DISPATCH_GROUP not in concurrency
    assert "github.event.pull_request" not in concurrency
    assert "github.event.client_payload" not in concurrency
    assert "github.run_id" not in concurrency


@pytest.mark.parametrize(
    ("unsafe_group", "expected_error"),
    [
        (OLD_EVENT_PAYLOAD_GROUP, "forbidden authority token: github.event.client_payload"),
        (UNIQUE_DISPATCH_GROUP, "ci.yml bytes differ from the exact reviewed ordinary CI definition"),
    ],
)
def test_ci_contract_rejects_weakened_event_concurrency(
    tmp_path: Path,
    unsafe_group: str,
    expected_error: str,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    assert SAFE_CONCURRENCY_GROUP in text
    path.write_text(
        text.replace(SAFE_CONCURRENCY_GROUP, unsafe_group, 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=expected_error):
        ci_contract.verify_ci_contract(root)
