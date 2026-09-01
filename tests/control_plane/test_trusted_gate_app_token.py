from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.trusted_gate_service.github import MAX_PRIVATE_KEY_BYTES, AppTokenProvider

PEM_LABEL = "PRIVATE" + " KEY"


def _pem(body: str) -> str:
    return f"-----BEGIN {PEM_LABEL}-----\n{body}\n-----END {PEM_LABEL}-----\n"


PRIVATE_KEY = _pem("unit-test-key")


def _provider(private_key: str = PRIVATE_KEY) -> AppTokenProvider:
    return AppTokenProvider(
        app_id="123456",
        installation_id=12345,
        repository="portyu9/ai-qa-automation",
        private_key_pem=private_key,
        openssl_bin=sys.executable,
    )


def test_app_jwt_signing_uses_only_anonymous_inherited_key_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def fake_run(
        args: list[str],
        *,
        input: bytes,
        capture_output: bool,
        check: bool,
        timeout: int,
        env: dict[str, str],
        pass_fds: tuple[int, ...],
    ) -> subprocess.CompletedProcess[bytes]:
        assert args[:4] == [str(Path(sys.executable).resolve()), "dgst", "-sha256", "-sign"]
        assert len(pass_fds) == 1
        key_fd = pass_fds[0]
        assert args[4] == f"/proc/self/fd/{key_fd}"
        assert list(tmp_path.iterdir()) == []
        assert Path(args[4]).read_bytes() == PRIVATE_KEY.encode("ascii")
        assert input.count(b".") == 1
        assert capture_output is True
        assert check is False
        assert timeout == 5
        assert env == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        observed["pass_fds"] = pass_fds
        return subprocess.CompletedProcess(args, 0, stdout=b"signature", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    token = _provider()._mint_app_jwt(now=1_700_000_000)

    assert token.count(".") == 2
    assert observed["pass_fds"]
    assert list(tmp_path.iterdir()) == []


def test_inherited_fd_path_falls_back_only_to_reviewed_dev_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def fake_stat(path: str) -> SimpleNamespace:
        observed.append(path)
        if path == "/proc/self/fd/7":
            raise FileNotFoundError(path)
        if path == "/dev/fd/7":
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
        raise AssertionError(path)

    monkeypatch.setattr(os, "stat", fake_stat)
    assert AppTokenProvider._inherited_fd_path(7) == "/dev/fd/7"
    assert observed == ["/proc/self/fd/7", "/dev/fd/7"]


def test_inherited_fd_path_fails_closed_when_descriptor_namespaces_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(path: str) -> None:
        raise FileNotFoundError(path)

    monkeypatch.setattr(os, "stat", missing)
    with pytest.raises(RuntimeError, match="anonymous inherited key descriptor"):
        AppTokenProvider._inherited_fd_path(7)


@pytest.mark.parametrize(
    "private_key",
    [
        _pem("é"),
        _pem("\x00"),
        _pem("a" * MAX_PRIVATE_KEY_BYTES),
    ],
)
def test_app_private_key_input_rejects_non_ascii_nul_and_oversize(private_key: str) -> None:
    with pytest.raises(ValueError):
        _provider(private_key)
