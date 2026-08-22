from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .execution_env import restricted_subprocess_env, run_bounded_subprocess

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_MAX_FINGERPRINT_CHANGED_FILES = 1000
_MAX_GIT_TEXT_OUTPUT_BYTES = 8_000_000


@dataclass(frozen=True)
class RepositorySnapshot:
    workspace: str
    git_sha: str | None
    branch: str | None
    status: str
    changed_files: tuple[str, ...]
    fingerprint: str
    fingerprint_complete: bool
    fingerprint_incomplete_reasons: tuple[str, ...]


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
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds < 1
        ):
            raise ValueError("repository inspection timeout_seconds must be a positive integer")
        self.workspace = workspace.expanduser().resolve()
        self.timeout_seconds = timeout_seconds

    def snapshot(self) -> RepositorySnapshot:
        try:
            sha = self._git("rev-parse", "HEAD", allow_failure=True)
            branch = self._git("branch", "--show-current", allow_failure=True)
            status = self._git(
                "status", "--porcelain=v1", "--untracked-files=all", allow_failure=True
            ) or ""
        except RuntimeError as exc:
            message = str(exc).casefold()
            reason = (
                "git-inspection-timeout"
                if "exceeded" in message and "budget" in message
                else "git-inspection-incomplete"
            )
            return self._incomplete_snapshot(reason)
        changed = self._changed_paths(status)
        fingerprint, complete, incomplete_reasons = self._fingerprint(sha, status, changed)
        return RepositorySnapshot(
            workspace=str(self.workspace),
            git_sha=sha or None,
            branch=branch or None,
            status=status,
            changed_files=changed,
            fingerprint=fingerprint,
            fingerprint_complete=complete,
            fingerprint_incomplete_reasons=incomplete_reasons,
        )

    def _incomplete_snapshot(self, reason: str) -> RepositorySnapshot:
        payload = {
            "workspace": str(self.workspace),
            "fingerprint_complete": False,
            "fingerprint_incomplete_reasons": [reason],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return RepositorySnapshot(
            workspace=str(self.workspace),
            git_sha=None,
            branch=None,
            status="!! GIT_INSPECTION_INCOMPLETE",
            changed_files=(),
            fingerprint=f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}",
            fingerprint_complete=False,
            fingerprint_incomplete_reasons=(reason,),
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
        worktree_snapshot = self.snapshot()
        if not worktree_snapshot.fingerprint_complete:
            raise RuntimeError("worktree status inspection is incomplete")
        worktree = worktree_snapshot.changed_files
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
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
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
        if len(result) > max_bytes:
            raise RuntimeError("Git returned more baseline bytes than the preflight object size allowed")
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
    ) -> tuple[str, bool, tuple[str, ...]]:
        """Hash Git state plus current bytes and expose whether that proof is complete."""
        file_rows: list[dict[str, object]] = []
        incomplete_reasons: set[str] = set()
        if len(changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
            incomplete_reasons.add("changed-file-limit-exceeded")
        for line in status.splitlines():
            if len(line) >= 4:
                raw = line[3:].strip()
                if raw.startswith('"') or ' -> "' in raw:
                    incomplete_reasons.add("quoted-git-path-not-byte-bound")

        for relative in changed_files[:_MAX_FINGERPRINT_CHANGED_FILES]:
            raw_candidate = self.workspace / relative
            if raw_candidate.is_symlink():
                file_rows.append({"path": relative, "state": "symlink"})
                incomplete_reasons.add("changed-symlink-not-byte-bound")
                continue
            candidate = raw_candidate.resolve()
            try:
                candidate.relative_to(self.workspace)
            except ValueError:
                file_rows.append({"path": relative, "state": "outside-workspace"})
                incomplete_reasons.add("changed-path-outside-workspace")
                continue
            if not candidate.exists():
                file_rows.append({"path": relative, "state": "deleted"})
                continue
            if not candidate.is_file():
                file_rows.append({"path": relative, "state": "non-file"})
                incomplete_reasons.add("changed-non-file-not-byte-bound")
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
                incomplete_reasons.add("changed-file-unreadable")
                continue
            file_rows.append({"path": relative, "size": size, "sha256": digest.hexdigest()})
        if len(changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
            file_rows.append({"state": "changed-file-overflow", "count": len(changed_files)})

        reasons = tuple(sorted(incomplete_reasons))
        payload = {
            "git_sha": git_sha,
            "status": status,
            "files": file_rows,
            "fingerprint_complete": not reasons,
            "fingerprint_incomplete_reasons": list(reasons),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return (
            f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}",
            not reasons,
            reasons,
        )

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home), extra={"GIT_CONFIG_NOSYSTEM": "1"}
            )
            result = run_bounded_subprocess(
                ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                cwd=self.workspace,
                env=env,
                timeout_seconds=self.timeout_seconds,
                max_output_bytes=_MAX_GIT_TEXT_OUTPUT_BYTES,
            )
        if result.timed_out:
            raise RuntimeError(f"git command exceeded {self.timeout_seconds}s inspection budget")
        if result.stdout_truncated or result.stderr_truncated:
            raise RuntimeError("git inspection output exceeded bounded capture limit")
        if result.returncode != 0:
            if allow_failure:
                return None
            raise RuntimeError(result.stderr.strip() or f"git command failed: {args}")
        return result.stdout.rstrip("\r\n")

    def _git_bytes(self, *args: str, allow_failure: bool = False) -> bytes | None:
        # This exact-byte path is used after read_file_at() preflights the immutable
        # Git object's size. Keeping bytes exact avoids UTF-8 replacement while the
        # preceding object-size gate keeps capture_output bounded.
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home), extra={"GIT_CONFIG_NOSYSTEM": "1"}
            )
            try:
                result = subprocess.run(
                    ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                    cwd=self.workspace,
                    text=False,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"git command exceeded {self.timeout_seconds}s inspection budget"
                ) from exc
        if result.returncode != 0:
            if allow_failure:
                return None
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(stderr or f"git command failed: {args}")
        return result.stdout
