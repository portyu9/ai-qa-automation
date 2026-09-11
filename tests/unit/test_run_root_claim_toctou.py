from __future__ import annotations

import os
from pathlib import Path

import pytest

import ai_qa_automation.state as state_module
from ai_qa_automation.state import StateStore


def test_parent_path_replacement_during_run_root_claim_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not state_module.descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow authority is unavailable on this platform")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    state_path = artifacts / "run-parent-race" / "state.json"
    displaced = tmp_path / "artifacts-original"
    attacker_marker = b"attacker-owned\n"
    real_mkdir = os.mkdir
    swapped = False

    def racing_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        real_mkdir(path, mode, dir_fd=dir_fd)
        if not swapped and dir_fd is not None and os.fspath(path) == "run-parent-race":
            swapped = True
            artifacts.rename(displaced)
            real_mkdir(artifacts, 0o755)
            real_mkdir(artifacts / "run-parent-race", 0o755)
            (artifacts / "run-parent-race" / "marker.bin").write_bytes(attacker_marker)

    monkeypatch.setattr(state_module.os, "mkdir", racing_mkdir)

    with pytest.raises(ValueError, match="persistence root changed identity"):
        StateStore(state_path, claim_parent_exclusively=True)

    assert swapped is True
    assert (artifacts / "run-parent-race" / "marker.bin").read_bytes() == attacker_marker
    assert not (artifacts / "run-parent-race" / "state.json").exists()
    assert not (displaced / "run-parent-race" / "state.json").exists()
