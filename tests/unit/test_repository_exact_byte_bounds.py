from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.tools.execution_env import BoundedBinarySubprocessResult
from ai_qa_automation.tools.repository import RepositoryInspector


def test_read_file_at_rejects_requested_limit_over_framework_capture_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)
    git_called = False

    def forbidden_git(*args: str, **kwargs: object) -> str:
        nonlocal git_called
        git_called = True
        raise AssertionError(f"Git preflight must not run for invalid max_bytes: {args}, {kwargs}")

    monkeypatch.setattr(inspector, "_git", forbidden_git)

    with pytest.raises(ValueError, match="max_bytes must be an integer between"):
        inspector.read_file_at(
            "a" * 40,
            "payload.bin",
            max_bytes=repository_module._MAX_GIT_EXACT_STDOUT_BYTES + 1,
        )

    assert git_called is False


def test_read_file_at_rejects_object_larger_than_framework_capture_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)
    object_size = repository_module._MAX_GIT_EXACT_STDOUT_BYTES + 1
    capture_called = False

    def fake_git(*args: str, allow_failure: bool = False) -> str:
        assert args == ("cat-file", "-s", f"{'a' * 40}:payload.bin")
        assert allow_failure is False
        return str(object_size)

    def forbidden_git_bytes(
        *args: str,
        max_stdout_bytes: int,
        allow_failure: bool = False,
    ) -> bytes:
        nonlocal capture_called
        capture_called = True
        raise AssertionError(
            f"Git blob capture must not run after oversized preflight: {args}, "
            f"{max_stdout_bytes}, {allow_failure}"
        )

    monkeypatch.setattr(inspector, "_git", fake_git)
    monkeypatch.setattr(inspector, "_git_bytes", forbidden_git_bytes)

    with pytest.raises(ValueError, match="baseline file exceeds"):
        inspector.read_file_at(
            "a" * 40,
            "payload.bin",
            max_bytes=repository_module._MAX_GIT_EXACT_STDOUT_BYTES,
        )

    assert capture_called is False


@pytest.mark.parametrize(
    ("size", "payload", "capture_limit"),
    [
        (0, b"", 1),
        (4, b"\x00\xffA\n", 4),
    ],
)
def test_read_file_at_binds_capture_limit_to_preflight_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size: int,
    payload: bytes,
    capture_limit: int,
) -> None:
    inspector = RepositoryInspector(tmp_path)
    commit_sha = "b" * 40
    object_name = f"{commit_sha}:payload.bin"

    def fake_git(*args: str, allow_failure: bool = False) -> str:
        assert args == ("cat-file", "-s", object_name)
        assert allow_failure is False
        return str(size)

    def fake_git_bytes(
        *args: str,
        max_stdout_bytes: int,
        allow_failure: bool = False,
    ) -> bytes:
        assert args == ("cat-file", "blob", object_name)
        assert max_stdout_bytes == capture_limit
        assert allow_failure is True
        return payload

    monkeypatch.setattr(inspector, "_git", fake_git)
    monkeypatch.setattr(inspector, "_git_bytes", fake_git_bytes)

    assert inspector.read_file_at(commit_sha, "payload.bin") == payload


def test_read_file_at_rejects_bytes_inconsistent_with_preflight_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)

    monkeypatch.setattr(inspector, "_git", lambda *args, **kwargs: "4")
    monkeypatch.setattr(inspector, "_git_bytes", lambda *args, **kwargs: b"abc")

    with pytest.raises(RuntimeError, match="inconsistent with preflight object size"):
        inspector.read_file_at("c" * 40, "payload.bin")


def test_git_bytes_fails_closed_when_binary_capture_is_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)

    def truncated_run(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> BoundedBinarySubprocessResult:
        assert command[-3:] == ["cat-file", "blob", "object"]
        assert cwd.exists()
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert timeout_seconds == inspector.timeout_seconds
        assert max_stdout_bytes == 8
        assert max_stderr_bytes == repository_module._MAX_GIT_EXACT_STDERR_BYTES
        return BoundedBinarySubprocessResult(
            returncode=0,
            stdout=b"x" * 8,
            stderr=b"",
            stdout_truncated=True,
            stderr_truncated=False,
            timed_out=False,
        )

    monkeypatch.setattr(repository_module, "run_bounded_binary_subprocess", truncated_run)

    with pytest.raises(RuntimeError, match="exact-byte output exceeded bounded capture limit"):
        inspector._git_bytes("cat-file", "blob", "object", max_stdout_bytes=8)


def test_git_bytes_fails_closed_on_truncated_stderr_even_for_allowed_git_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)

    def truncated_failure(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> BoundedBinarySubprocessResult:
        del command, cwd, env, timeout_seconds, max_stdout_bytes, max_stderr_bytes
        return BoundedBinarySubprocessResult(
            returncode=1,
            stdout=b"",
            stderr=b"e" * 32,
            stdout_truncated=False,
            stderr_truncated=True,
            timed_out=False,
        )

    monkeypatch.setattr(repository_module, "run_bounded_binary_subprocess", truncated_failure)

    with pytest.raises(RuntimeError, match="exact-byte output exceeded bounded capture limit"):
        inspector._git_bytes(
            "cat-file",
            "blob",
            "missing-object",
            max_stdout_bytes=8,
            allow_failure=True,
        )
