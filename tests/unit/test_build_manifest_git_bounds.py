from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import generate_build_manifest as build_manifest

ROOT = Path(__file__).resolve().parents[2]


def test_git_capture_rejects_truncated_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        del args
        assert kwargs["max_stdout_bytes"] == 4
        assert kwargs["max_stderr_bytes"] == build_manifest.MAX_GIT_STDERR_BYTES
        return SimpleNamespace(
            returncode=0,
            stdout=b"data",
            stderr=b"",
            stdout_truncated=True,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr(build_manifest, "run_bounded_binary_subprocess", fake_run)

    with pytest.raises(build_manifest._GitCommandError, match="output budget"):
        build_manifest._run_git_bytes(
            "cat-file",
            "blob",
            "0" * 40,
            cwd=ROOT,
            max_stdout_bytes=4,
        )


def test_git_blob_read_is_bounded_to_preflight_size(monkeypatch: pytest.MonkeyPatch) -> None:
    source_sha = build_manifest._git("rev-parse", "--verify", "HEAD", cwd=ROOT)
    expected = (ROOT / "pyproject.toml").read_bytes()
    observed_limits: list[int] = []
    original = build_manifest.run_bounded_binary_subprocess

    def recording_run(*args: object, **kwargs: object) -> object:
        command = args[0]
        if command[1:3] == ["cat-file", "blob"]:
            observed_limits.append(int(kwargs["max_stdout_bytes"]))
        return original(*args, **kwargs)

    monkeypatch.setattr(build_manifest, "run_bounded_binary_subprocess", recording_run)

    observed = build_manifest._git_blob_bytes(
        ROOT,
        source_sha=source_sha,
        relative_path="pyproject.toml",
        max_bytes=build_manifest.MAX_SOURCE_INPUT_BYTES,
        label="pyproject.toml",
    )

    assert observed == expected
    assert observed_limits == [len(expected)]


def test_git_blob_read_rejects_content_address_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        build_manifest,
        "_git",
        lambda *args, **kwargs: "sha1" if args == ("rev-parse", "--show-object-format") else "4",
    )
    monkeypatch.setattr(build_manifest, "_git_blob_oid", lambda *args, **kwargs: "0" * 40)
    monkeypatch.setattr(build_manifest, "_run_git_bytes", lambda *args, **kwargs: b"evil")

    with pytest.raises(ValueError, match="do not match their Git object identity"):
        build_manifest._git_blob_bytes(
            ROOT,
            source_sha="1" * 40,
            relative_path="pyproject.toml",
            max_bytes=1024,
            label="pyproject.toml",
        )
