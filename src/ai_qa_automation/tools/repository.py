from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .execution_env import restricted_subprocess_env

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")


@dataclass(frozen=True)
class RepositorySnapshot:
    workspace: str
    git_sha: str | None
    branch: str | None
    status: str
    changed_files: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class RepositoryChangeSet:
    """Diff-aware change set anchored to an explicit trusted baseline ref."""

    requested_base_ref: str
    baseline_sha: str
    merge_base_sha: str
    head_sha: str
    committed_files: tuple[str, ...]
    worktree_files: tuple[str, ...]
    changed_files: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "requested_base_ref": self.requested_base_ref,
            "baseline_sha": self.baseline_sha,
            "merge_base_sha": self.merge_base_sha,
            "head_sha": self.head_sha,
            "committed_files": list(self.committed_files),
            "worktree_files": list(self.worktree_files),
            "changed_files": list(self.changed_files),
        }


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

    def change_set(self, base_ref: str) -> RepositoryChangeSet:
        """Resolve a baseline, merge-base it with HEAD, and union committed/worktree changes.

        The baseline is an explicit trusted runtime input. It is resolved to immutable
        commit IDs before use so the model or target repository cannot silently move
        the comparison point during the run.
        """
        safe_ref = self._validate_ref(base_ref)
        head = self._git("rev-parse", "HEAD")
        if head is None:
            raise RuntimeError("target workspace is not a Git repository")
        baseline = self._git("rev-parse", "--verify", f"{safe_ref}^{{commit}}")
        if baseline is None:
            raise RuntimeError(f"baseline ref could not be resolved: {safe_ref}")
        merge_base = self._git("merge-base", baseline, head)
        if merge_base is None:
            raise RuntimeError(f"baseline ref has no merge base with HEAD: {safe_ref}")

        raw_committed = self._git(
            "diff",
            "--name-only",
            "--diff-filter=ACDMRTUXB",
            merge_base,
            head,
            "--",
        ) or ""
        committed = tuple(sorted({line for line in raw_committed.splitlines() if line.strip()}))
        worktree = self.snapshot().changed_files
        changed = tuple(sorted(set(committed) | set(worktree)))
        return RepositoryChangeSet(
            requested_base_ref=safe_ref,
            baseline_sha=baseline,
            merge_base_sha=merge_base,
            head_sha=head,
            committed_files=committed,
            worktree_files=worktree,
            changed_files=changed,
        )

    def read_file_at(self, commit_sha: str, relative_path: str, *, max_bytes: int = 2_000_000) -> bytes:
        """Read one bounded tracked file from an immutable commit without checkout."""
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if not _HEX_SHA.fullmatch(commit_sha):
            raise ValueError("commit_sha must be a full hexadecimal object id")
        path = self._validate_relative_path(relative_path)
        object_name = f"{commit_sha}:{path}"
        size_text = self._git("cat-file", "-s", object_name)
        if size_text is None:
            raise FileNotFoundError(path)
        try:
            size = int(size_text)
        except ValueError as exc:
            raise RuntimeError("Git returned an invalid object size") from exc
        if size > max_bytes:
            raise ValueError(f"baseline file exceeds {max_bytes} byte limit: {path}")
        result = self._git_bytes("show", object_name, allow_failure=True)
        if result is None:
            raise FileNotFoundError(path)
        return result

    def diff(self, *paths: str) -> str:
        args = ["diff", "--no-ext-diff", "--no-textconv", "--"]
        args.extend(paths)
        return self._git(*args, allow_failure=True) or ""

    @staticmethod
    def _validate_ref(base_ref: str) -> str:
        value = base_ref.strip()
        if not _SAFE_REF.fullmatch(value) or value.startswith("-") or ".." in value:
            raise ValueError("baseline ref contains unsupported characters or revision-range syntax")
        return value

    @staticmethod
    def _validate_relative_path(relative_path: str) -> str:
        raw = relative_path.strip().replace("\\", "/")
        path = PurePosixPath(raw)
        if not raw or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("repository path must be a normalized relative path")
        return path.as_posix()

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
        """Hash Git state plus current bytes for dirty/untracked files."""
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
            file_rows.append({"path": relative, "size": size, "sha256": digest.hexdigest()})
        if len(changed_files) > 1000:
            file_rows.append({"state": "changed-file-overflow", "count": len(changed_files)})
        payload = {"git_sha": git_sha, "status": status, "files": file_rows}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home), extra={"GIT_CONFIG_NOSYSTEM": "1"}
            )
            result = subprocess.run(
                ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
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

    def _git_bytes(self, *args: str, allow_failure: bool = False) -> bytes | None:
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home), extra={"GIT_CONFIG_NOSYSTEM": "1"}
            )
            result = subprocess.run(
                ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                cwd=self.workspace,
                text=False,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
        if result.returncode != 0:
            if allow_failure:
                return None
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(stderr or f"git command failed: {args}")
        return result.stdout
