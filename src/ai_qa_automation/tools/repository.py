from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
)
from ..io_safety import open_regular_binary
from .execution_env import resolve_executable, restricted_subprocess_env, run_bounded_subprocess
from .subprocess_subject import active_workspace_authority, descriptor_bound_cwd

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_MAX_FINGERPRINT_CHANGED_FILES = 1000
_MAX_FINGERPRINT_FILE_BYTES = 16_000_000
_MAX_FINGERPRINT_TOTAL_BYTES = 128_000_000
_MAX_GIT_TEXT_OUTPUT_BYTES = 8_000_000


class RepositorySubjectError(RuntimeError):
    """Raised when Git inspection cannot remain bound to the authorized workspace subject."""


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

    def __init__(
        self,
        workspace: Path,
        timeout_seconds: int = 20,
        *,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds < 1
        ):
            raise ValueError("repository inspection timeout_seconds must be a positive integer")
        if expected_root_identity is not None and (
            not isinstance(expected_root_identity, tuple)
            or len(expected_root_identity) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in expected_root_identity
            )
        ):
            raise ValueError("expected_root_identity must be a pair of non-negative integers")

        # Do not resolve the target after lease acquisition. Resolving here would follow
        # a replacement symlink before consulting the lease-authority registry and could
        # silently change both the registry key and the repository subject.
        self.workspace = workspace.expanduser().absolute()
        self.timeout_seconds = timeout_seconds
        active_identity = active_workspace_authority(self.workspace)
        if (
            expected_root_identity is not None
            and active_identity is not None
            and expected_root_identity != active_identity
        ):
            raise RepositorySubjectError(
                "explicit repository authority conflicts with the active workspace lease"
            )
        authorized_identity = expected_root_identity or active_identity
        self.workspace_root_identity: tuple[int, int] | None = None
        if descriptor_relative_authority_supported():
            try:
                current_identity = pin_directory_identity(
                    self.workspace,
                    label="repository inspection workspace",
                )
            except (OSError, RuntimeError, ValueError) as exc:
                raise RepositorySubjectError(
                    "repository workspace identity could not be pinned"
                ) from exc
            if authorized_identity is not None and current_identity != authorized_identity:
                raise RepositorySubjectError(
                    "repository workspace changed identity since authorization"
                )
            self.workspace_root_identity = current_identity
        elif authorized_identity is not None:
            raise RepositorySubjectError(
                "authorized repository inspection requires descriptor-bound filesystem authority"
            )

    def snapshot(self) -> RepositorySnapshot:
        try:
            sha = self._git("rev-parse", "HEAD", allow_failure=True)
            branch = self._git("branch", "--show-current", allow_failure=True)
            status = (
                self._git("status", "--porcelain=v1", "--untracked-files=all", allow_failure=True)
                or ""
            )
        except RepositorySubjectError:
            raise
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

        raw_committed = (
            self._git(
                "diff",
                "--name-only",
                "--diff-filter=ACDMRTUXB",
                merge_base,
                head,
                "--",
            )
            or ""
        )
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

    def read_file_at(
        self, commit_sha: str, relative_path: str, *, max_bytes: int = 2_000_000
    ) -> bytes:
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
            raise RuntimeError(
                "Git returned more baseline bytes than the preflight object size allowed"
            )
        return result

    def diff(self, *paths: str) -> str:
        args = ["diff", "--no-ext-diff", "--no-textconv", "--"]
        args.extend(paths)
        return self._git(*args, allow_failure=True) or ""

    @staticmethod
    def _validate_ref(base_ref: str) -> str:
        value = base_ref.strip()
        if not _SAFE_REF.fullmatch(value) or value.startswith("-") or ".." in value:
            raise ValueError(
                "baseline ref contains unsupported characters or revision-range syntax"
            )
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

    def _read_fingerprint_bytes(
        self,
        relative: str,
        *,
        max_bytes: int,
    ) -> tuple[bytes | None, str | None]:
        """Read one changed-file subject under the same root identity as Git inspection."""

        try:
            normalized = self._validate_relative_path(relative)
        except ValueError:
            return None, "changed-path-outside-workspace"

        if self.workspace_root_identity is not None:
            try:
                data = read_bytes_confined(
                    self.workspace,
                    normalized,
                    max_bytes=max_bytes,
                    label=f"workspace fingerprint subject {normalized}",
                    expected_root_identity=self.workspace_root_identity,
                )
            except FileNotFoundError:
                return None, "deleted"
            except OSError:
                return None, "changed-file-unreadable"
            except ValueError as exc:
                message = str(exc).casefold()
                if "trusted root" in message:
                    raise RepositorySubjectError(
                        "workspace fingerprint subject changed root identity during inspection"
                    ) from exc
                if "symlink" in message and "parent component" not in message:
                    return None, "changed-symlink-not-byte-bound"
                if "must be a regular file" in message:
                    return None, "changed-non-file-not-byte-bound"
                if "exceeds" in message and "ingestion limit" in message:
                    return None, "byte-limit-exceeded"
                return None, "changed-path-ownership-ambiguous"
            return data, None

        # Compatibility fallback for platforms without descriptor-relative authority.
        # Live lease-bound authority is never silently downgraded into this path because
        # __init__ rejects an authorized identity on such platforms.
        raw_candidate = self.workspace / normalized
        if raw_candidate.is_symlink():
            return None, "changed-symlink-not-byte-bound"
        candidate = raw_candidate.resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError:
            return None, "changed-path-outside-workspace"
        if not candidate.exists():
            return None, "deleted"
        if not candidate.is_file():
            return None, "changed-non-file-not-byte-bound"
        try:
            size_hint = candidate.stat().st_size
        except OSError:
            return None, "changed-file-unreadable"
        if size_hint > max_bytes:
            return None, "byte-limit-exceeded"
        chunks: list[bytes] = []
        size = 0
        try:
            with open_regular_binary(
                candidate,
                label=f"workspace fingerprint subject {normalized}",
            ) as stream:
                while size <= max_bytes:
                    chunk = stream.read(min(1024 * 1024, max_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
        except OSError:
            return None, "changed-file-unreadable"
        except ValueError:
            return None, "changed-path-ownership-ambiguous"
        if size > max_bytes:
            return None, "byte-limit-exceeded"
        return b"".join(chunks), None

    def _fingerprint(
        self,
        git_sha: str | None,
        status: str,
        changed_files: tuple[str, ...],
    ) -> tuple[str, bool, tuple[str, ...]]:
        """Hash Git state plus bounded current bytes and expose proof completeness."""
        file_rows: list[dict[str, object]] = []
        incomplete_reasons: set[str] = set()
        total_hashed_bytes = 0
        if len(changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
            incomplete_reasons.add("changed-file-limit-exceeded")
        for line in status.splitlines():
            if len(line) >= 4:
                raw = line[3:].strip()
                if raw.startswith('"') or ' -> "' in raw:
                    incomplete_reasons.add("quoted-git-path-not-byte-bound")

        for relative in changed_files[:_MAX_FINGERPRINT_CHANGED_FILES]:
            remaining_total = _MAX_FINGERPRINT_TOTAL_BYTES - total_hashed_bytes
            if remaining_total <= 0:
                file_rows.append({"path": relative, "state": "total-byte-limit-exceeded"})
                incomplete_reasons.add("changed-total-byte-limit-exceeded")
                continue
            read_limit = min(_MAX_FINGERPRINT_FILE_BYTES, remaining_total)
            data, failure = self._read_fingerprint_bytes(relative, max_bytes=read_limit)
            if failure == "deleted":
                file_rows.append({"path": relative, "state": "deleted"})
                continue
            if failure == "byte-limit-exceeded":
                reason = (
                    "changed-total-byte-limit-exceeded"
                    if read_limit < _MAX_FINGERPRINT_FILE_BYTES
                    else "changed-file-byte-limit-exceeded"
                )
                state = (
                    "total-byte-limit-exceeded"
                    if reason == "changed-total-byte-limit-exceeded"
                    else "file-byte-limit-exceeded"
                )
                file_rows.append({"path": relative, "state": state})
                incomplete_reasons.add(reason)
                continue
            if failure is not None:
                file_rows.append({"path": relative, "state": failure})
                incomplete_reasons.add(failure)
                continue
            if data is None:  # pragma: no cover - helper contract
                raise RuntimeError("fingerprint reader returned neither data nor a failure reason")
            size = len(data)
            total_hashed_bytes += size
            file_rows.append(
                {
                    "path": relative,
                    "size": size,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
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

    @contextmanager
    def _git_cwd(self) -> Iterator[Path]:
        if self.workspace_root_identity is None:
            yield self.workspace
            return
        try:
            with descriptor_bound_cwd(
                self.workspace,
                expected_root_identity=self.workspace_root_identity,
                label="Git repository inspection",
            ) as cwd:
                yield cwd
        except RepositorySubjectError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise RepositorySubjectError(
                "Git repository subject could not be bound to the authorized workspace"
            ) from exc

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home), extra={"GIT_CONFIG_NOSYSTEM": "1"}
            )
            with self._git_cwd() as git_cwd:
                result = run_bounded_subprocess(
                    ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                    cwd=git_cwd,
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
                home=Path(temp_home), extra={"GIT_CONFIG_NOSYSTEM": "1")
            )
            git_executable = resolve_executable("git", env=env)
            try:
                with self._git_cwd() as git_cwd:
                    result = subprocess.run(
                        [
                            git_executable,
                            "-c",
                            "core.fsmonitor=false",
                            "-c",
                            "core.untrackedCache=false",
                            *args,
                        ],
                        cwd=git_cwd,
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
