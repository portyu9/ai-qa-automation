from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest

from scripts.trusted_gate_service.github import (
    GitHubProtocolError,
    _decode_github_contents_base64_utf8,
    _select_current_attempt_artifact,
)


def _wrapped(payload: bytes, *, width: int = 8) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    return (
        "\n".join(encoded[index : index + width] for index in range(0, len(encoded), width)) + "\n"
    )


def test_github_line_wrapped_base64_is_strictly_admitted() -> None:
    raw = b"name: CI\non: pull_request\n"
    assert _decode_github_contents_base64_utf8(_wrapped(raw)) == raw.decode("utf-8")


def test_unwrapped_canonical_base64_is_admitted() -> None:
    raw = b"permissions:\n  contents: read\n"
    encoded = base64.b64encode(raw).decode("ascii")
    assert _decode_github_contents_base64_utf8(encoded) == raw.decode("utf-8")


@pytest.mark.parametrize(
    "encoded",
    [
        "YQ==\r\n",
        "YQ ==",
        "YQ\t==",
        "YQ==\n\n",
        "YQ==\n\nYg==",
        "YQ==!",
        "YQ===",
        "éQ==",
    ],
)
def test_noncanonical_github_base64_is_rejected(encoded: str) -> None:
    with pytest.raises(GitHubProtocolError, match="canonical base64 UTF-8"):
        _decode_github_contents_base64_utf8(encoded)


def test_base64_decoding_to_invalid_utf8_is_rejected() -> None:
    encoded = base64.b64encode(b"\xff").decode("ascii")
    with pytest.raises(GitHubProtocolError, match="canonical base64 UTF-8"):
        _decode_github_contents_base64_utf8(encoded)


def _artifact(
    artifact_id: int,
    *,
    created_at: str,
    updated_at: str | None = None,
) -> dict[str, object]:
    return {
        "id": artifact_id,
        "name": "supply-chain-evidence",
        "created_at": created_at,
        "updated_at": updated_at or created_at,
        "workflow_run": {
            "id": 36137916238,
            "head_sha": "b" * 40,
            "head_branch": "fix/codeql-default-branch-status-anchor",
        },
    }


def test_artifact_selection_is_bound_to_current_workflow_attempt() -> None:
    payload = {
        "total_count": 2,
        "artifacts": [
            _artifact(1, created_at="2026-09-25T12:58:38Z"),
            _artifact(2, created_at="2026-09-25T13:08:50Z"),
        ],
    }

    selected = _select_current_attempt_artifact(
        payload,
        run_id=36137916238,
        head_sha="b" * 40,
        head_ref="fix/codeql-default-branch-status-anchor",
        attempt_started_at=datetime(2026, 9, 25, 13, 7, 3, tzinfo=UTC),
        attempt_completed_at=datetime(2026, 9, 25, 13, 11, 47, tzinfo=UTC),
    )

    assert selected["id"] == 2


def test_artifact_selection_rejects_ambiguity_inside_current_attempt() -> None:
    payload = {
        "total_count": 2,
        "artifacts": [
            _artifact(1, created_at="2026-09-25T13:08:20Z"),
            _artifact(2, created_at="2026-09-25T13:08:50Z"),
        ],
    }

    with pytest.raises(
        GitHubProtocolError,
        match="exactly one supply-chain evidence artifact is required for current workflow attempt",
    ):
        _select_current_attempt_artifact(
            payload,
            run_id=36137916238,
            head_sha="b" * 40,
            head_ref="fix/codeql-default-branch-status-anchor",
            attempt_started_at=datetime(2026, 9, 25, 13, 7, 3, tzinfo=UTC),
            attempt_completed_at=datetime(2026, 9, 25, 13, 11, 47, tzinfo=UTC),
        )


def test_artifact_selection_rejects_incomplete_listing() -> None:
    payload = {
        "total_count": 3,
        "artifacts": [
            _artifact(1, created_at="2026-09-25T12:58:38Z"),
            _artifact(2, created_at="2026-09-25T13:08:50Z"),
        ],
    }

    with pytest.raises(GitHubProtocolError, match="listing is incomplete or outside bounds"):
        _select_current_attempt_artifact(
            payload,
            run_id=36137916238,
            head_sha="b" * 40,
            head_ref="fix/codeql-default-branch-status-anchor",
            attempt_started_at=datetime(2026, 9, 25, 13, 7, 3, tzinfo=UTC),
            attempt_completed_at=datetime(2026, 9, 25, 13, 11, 47, tzinfo=UTC),
        )
