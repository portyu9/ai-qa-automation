from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .execution_env import restricted_subprocess_env


@dataclass(frozen=True)
class RepositorySnapshot:
    workspace: str
    git_sha: str | None
    branch: str | None
    status: str
    changed_files: tuple[str, ...]
    fingerprint: str


class RepositoryInspector:
    """Read-only Git/repository inspection with deterministic workspace fingerprints."""

    def __init__(self, workspace: Path, timeout_seconds: int = 20) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.timeout_seconds = timeout_seconds

    def snapshot(self) -> RepositorySnapshot:
        sha = self._git("rev-parse", "HEAD", allow_failure=True)
        branch = self._git("branch", "--show-current", allow_failure=True)
        status = self._git(
            "status", "--porcelain=v1", "--untracked-files=all", allow_failure=True
        ) or ""
        changed = self._changed_paths(status)
        fingerprint = self._fingerprint(sha, status, changed)
        return RepositorySnapshot(
            workspace=str(self.workspace),
            git_sha=sha or None,
            branch=branch or None,
            status=status,
            changed_files=changed,
            fingerprint=fingerprint,
        )

    def diff(self, *paths: str) -> str:
        args = ["diff", "--no-ext-diff", "--no-textconv", "--"]
        args.extend(paths)
        return self._git(*args, allow_failure=True) or ""

    @staticmethod
    def _changed_paths(status: str) -> tuple[str, ...]:
        paths: set[str] = set()
        for line in status.splitlines():
            if len(line) < 4:
                continue
            raw = line[3:].strip()
            if " -> " in raw:
                raw = raw.split(" -> ", 1)[1]
            raw = raw.strip('"')
            if raw:
                paths.add(raw)
        return tuple(sorted(paths))

    def _fingerprint(
        self,
        git_sha: str | None,
        status: str,
        changed_files: tuple[str, ...],
    ) -> str:
        """Hash Git state plus current bytes for dirty/untracked files.

        This is intentionally stronger than HEAD alone: autonomous mutations are
        rejected if another process changes the working tree between observation
        and write.
        """
        file_rows: list[dict[str, object]] = []
        for relative in changed_files[:1000]:
            candidate = (self.workspace / relative).resolve()
            try:
                candidate.relative_to(self.workspace)
            except ValueError:
                file_rows.append({"path": relative, "state": "outside-workspace"})
                continue
            if candidate.is_symlink():
                file_rows.append({"path": relative, "state": "symlink"})
                continue
            if not candidate.exists():
                file_rows.append({"path": relative, "state": "deleted"})
                continue
            if not candidate.is_file():
                file_rows.append({"path": relative, "state": "non-file"})
                continue
            digest = hashlib.sha256()
            size = 0
            try:
                with candidate.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        size += len(chunk)
                        digest.update(chunk)
            except OSError:
                file_rows.append({"path": relative, "state": "unreadable"})
                continue
            file_rows.append(
                {"path": relative, "size": size, "sha256": digest.hexdigest()}
            )
        if len(changed_files) > 1000:
            file_rows.append(
                {"state": "changed-file-overflow", "count": len(changed_files)}
            )
        payload = {
            "git_sha": git_sha,
            "status": status,
            "files": file_rows,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={"GIT_CONFIG_NOSYSTEM": "1"},
            )
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.untrackedCache=false",
                    *args,
                ],
                cwd=self.workspace,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
        if result.returncode != 0:
            if allow_failure:
                return None
            raise RuntimeError(result.stderr.strip() or f"git command failed: {args}")
        return result.stdout.rstrip("\r\n")
