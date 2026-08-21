from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RepositorySnapshot:
    workspace: str
    git_sha: str | None
    branch: str | None
    status: str
    changed_files: tuple[str, ...]


class RepositoryInspector:
    def __init__(self, workspace: Path, timeout_seconds: int = 20) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.timeout_seconds = timeout_seconds

    def snapshot(self) -> RepositorySnapshot:
        sha = self._git("rev-parse", "HEAD", allow_failure=True)
        branch = self._git("branch", "--show-current", allow_failure=True)
        status = self._git("status", "--porcelain=v1", allow_failure=True) or ""
        changed = tuple(line[3:] for line in status.splitlines() if len(line) > 3)
        return RepositorySnapshot(
            workspace=str(self.workspace),
            git_sha=sha or None,
            branch=branch or None,
            status=status,
            changed_files=changed,
        )

    def diff(self, *paths: str) -> str:
        args = ["diff", "--"]
        args.extend(paths)
        return self._git(*args, allow_failure=True) or ""

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        result = subprocess.run(
            ["git", *args],
            cwd=self.workspace,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if result.returncode != 0:
            if allow_failure:
                return None
            raise RuntimeError(result.stderr.strip() or f"git command failed: {args}")
        return result.stdout.strip()
