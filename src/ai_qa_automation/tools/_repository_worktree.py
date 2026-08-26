from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath

from ..io_safety import open_regular_binary
from ._repository_common import (
    _GIT_MODE,
    _HEX_SHA,
    _MAX_FINGERPRINT_CHANGED_FILES,
    _MAX_FINGERPRINT_FILE_BYTES,
    _MAX_FINGERPRINT_TOTAL_BYTES,
    _MAX_GIT_EXACT_STDOUT_BYTES,
    _MAX_GIT_INDEX_BYTES,
    _MAX_GIT_PATHS,
    _MAX_GIT_TEXT_OUTPUT_BYTES,
    _SAFE_REF,
    RepositorySubjectError,
)


class RepositoryWorktreeMixin:
    workspace: Path
    workspace_root_identity: tuple[int, int] | None
    git_dir_identity: tuple[int, int] | None

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        raise NotImplementedError

    def _git_bytes(
        self,
        *args: str,
        max_stdout_bytes: int,
        allow_failure: bool = False,
    ) -> bytes | None:
        raise NotImplementedError

    def _assert_git_subject_current(self) -> None:
        raise NotImplementedError

    def _assert_workspace_subject_current(self) -> None:
        raise NotImplementedError

    def _read_bytes_confined_adapter(
        self,
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        raise NotImplementedError

    def _stat_confined_entry_adapter(
        self,
        root: Path,
        relative_path: str | Path,
        *,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> os.stat_result:
        raise NotImplementedError

    def _read_index_bytes(self) -> bytes:
        if self.git_dir_identity is None:
            return b""
        try:
            data = self._read_bytes_confined_adapter(
                self.workspace / ".git",
                "index",
                max_bytes=_MAX_GIT_INDEX_BYTES,
                label="Git index",
                expected_root_identity=self.git_dir_identity,
            )
        except FileNotFoundError:
            return b""
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                "Git index could not be read through confined metadata authority"
            ) from exc
        return data

    def _git_path_list(self, *args: str) -> tuple[str, ...]:
        raw = self._git_bytes(*args, max_stdout_bytes=_MAX_GIT_EXACT_STDOUT_BYTES)
        if raw is None:
            raise RuntimeError("Git path-list inspection returned no result")
        paths: list[str] = []
        seen: set[str] = set()
        for item in raw.split(b"\0"):
            if not item:
                continue
            try:
                decoded = self._validate_relative_path(item.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise RuntimeError("Git returned an unsafe repository path") from exc
            if decoded in seen:
                raise RuntimeError("Git returned duplicate repository paths")
            if len(paths) >= _MAX_GIT_PATHS:
                raise RuntimeError("Git path-list inspection exceeded its bounded path budget")
            seen.add(decoded)
            paths.append(decoded)
        return tuple(paths)

    def _parse_index_entries(
        self, raw: bytes
    ) -> tuple[dict[str, tuple[str, str]], set[str]]:
        entries: dict[str, tuple[str, str]] = {}
        unmerged: set[str] = set()
        seen_records: set[tuple[str, int]] = set()
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            if not separator:
                raise RuntimeError("Git returned a malformed index entry")
            try:
                fields = metadata.decode("ascii").split()
                path = self._validate_relative_path(raw_path.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise RuntimeError("Git returned invalid index metadata/path") from exc
            if len(fields) != 3:
                raise RuntimeError("Git returned a malformed index entry")
            mode, oid, raw_stage = fields
            try:
                stage = int(raw_stage)
            except ValueError as exc:
                raise RuntimeError("Git returned a malformed index stage") from exc
            key = (path, stage)
            if (
                not _GIT_MODE.fullmatch(mode)
                or not _HEX_SHA.fullmatch(oid)
                or stage not in {0, 1, 2, 3}
                or key in seen_records
                or len(seen_records) >= _MAX_GIT_PATHS * 4
            ):
                raise RuntimeError("Git index enumeration exceeded bounds or was malformed")
            seen_records.add(key)
            if stage != 0:
                unmerged.add(path)
                continue
            if path in entries:
                raise RuntimeError("Git returned duplicate stage-zero index entries")
            entries[path] = (mode, oid.lower())
        return entries, unmerged

    def _flagged_index_paths(self, raw: bytes) -> set[str]:
        flagged: set[str] = set()
        count = 0
        for record in raw.split(b"\0"):
            if not record:
                continue
            tag, separator, raw_path = record.partition(b" ")
            if not separator or len(tag) != 1 or not tag.isalpha():
                raise RuntimeError("Git returned a malformed index-flag entry")
            try:
                path = self._validate_relative_path(raw_path.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise RuntimeError("Git returned an unsafe index-flag path") from exc
            count += 1
            if count > _MAX_GIT_PATHS:
                raise RuntimeError("Git index-flag inspection exceeded its bounded path budget")
            if tag != b"H":
                flagged.add(path)
        return flagged

    @staticmethod
    def _raw_blob_oid(data: bytes, object_format: str) -> str:
        header = f"blob {len(data)}\0".encode("ascii")
        if object_format == "sha1":
            return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()
        if object_format == "sha256":
            return hashlib.sha256(header + data).hexdigest()
        raise RuntimeError("unsupported Git object format")

    def _raw_worktree_changes(
        self,
        candidates: set[str],
        index_entries: dict[str, tuple[str, str]],
        *,
        object_format: str,
    ) -> tuple[dict[str, str], tuple[str, ...]]:
        """Verify only Git-discovered candidates through confined raw bytes and modes."""
        changes: dict[str, str] = {}
        reasons: set[str] = set()
        compared_bytes = 0
        for path in sorted(candidates):
            entry = index_entries.get(path)
            if entry is None:
                try:
                    observed = self._stat_confined_entry_adapter(
                        self.workspace,
                        path,
                        label=f"workspace status subject {path}",
                        expected_root_identity=self.workspace_root_identity,
                    )
                except FileNotFoundError:
                    continue
                except (OSError, ValueError):
                    changes[path] = "M"
                    reasons.add("tracked-path-observation-failed")
                    continue
                changes[path] = "M"
                if not stat.S_ISREG(observed.st_mode):
                    reasons.add("tracked-nonregular-worktree-unverified")
                continue

            mode, oid = entry
            if mode not in {"100644", "100755"}:
                changes[path] = "M"
                reasons.add("tracked-nonregular-worktree-unverified")
                continue
            try:
                observed = self._stat_confined_entry_adapter(
                    self.workspace,
                    path,
                    label=f"workspace status subject {path}",
                    expected_root_identity=self.workspace_root_identity,
                )
            except FileNotFoundError:
                changes[path] = "D"
                continue
            except (OSError, ValueError):
                changes[path] = "M"
                reasons.add("tracked-path-observation-failed")
                continue
            if not stat.S_ISREG(observed.st_mode):
                changes[path] = "M"
                reasons.add("tracked-nonregular-worktree-unverified")
                continue

            expected_executable = mode == "100755"
            actual_executable = bool(observed.st_mode & 0o111)
            mode_changed = actual_executable != expected_executable
            if observed.st_size > _MAX_FINGERPRINT_FILE_BYTES:
                changes[path] = "M"
                reasons.add("worktree-file-byte-limit-exceeded")
                continue
            if compared_bytes + observed.st_size > _MAX_FINGERPRINT_TOTAL_BYTES:
                changes[path] = "M"
                reasons.add("worktree-total-byte-limit-exceeded")
                continue
            try:
                current = self._read_bytes_confined_adapter(
                    self.workspace,
                    path,
                    max_bytes=max(1, observed.st_size),
                    label=f"workspace status subject {path}",
                    expected_root_identity=self.workspace_root_identity,
                )
            except FileNotFoundError:
                changes[path] = "D"
                continue
            except (OSError, ValueError):
                changes[path] = "M"
                reasons.add("tracked-path-observation-failed")
                continue
            compared_bytes += len(current)
            if mode_changed or self._raw_blob_oid(current, object_format) != oid:
                changes[path] = "M"
        return changes, tuple(sorted(reasons))

    def _worktree_status(
        self, head_sha: str | None, object_format: str
    ) -> tuple[str, tuple[str, ...], str, tuple[str, ...]]:
        """Observe index/worktree deltas without content-rendering Git commands."""
        before_index = self._read_index_bytes()
        index_bytes = self._git_bytes(
            "ls-files", "--stage", "-z", "--", max_stdout_bytes=_MAX_GIT_EXACT_STDOUT_BYTES
        )
        flag_bytes = self._git_bytes(
            "ls-files", "-v", "-z", "--", max_stdout_bytes=_MAX_GIT_EXACT_STDOUT_BYTES
        )
        if index_bytes is None or flag_bytes is None:
            raise RuntimeError("Git index inspection returned no result")
        after_index = self._read_index_bytes()
        if before_index != after_index:
            raise RuntimeError("Git index changed during index enumeration")

        index_entries, unmerged = self._parse_index_entries(index_bytes)
        head_entries = self._tree_entries_at(head_sha) if head_sha else {}
        flagged_paths = self._flagged_index_paths(flag_bytes)
        reasons: set[str] = set()
        status_codes: dict[str, list[str]] = {}

        for path in sorted(set(head_entries) | set(index_entries) | unmerged):
            if path in unmerged:
                status_codes[path] = ["U", "U"]
                reasons.add("index-unmerged-entry")
                continue
            head_entry = head_entries.get(path)
            index_entry = index_entries.get(path)
            if head_entry == index_entry:
                continue
            if head_entry is None:
                code = "A"
            elif index_entry is None:
                code = "D"
            else:
                code = "M"
            status_codes.setdefault(path, [" ", " "])[0] = code

        unstaged_candidates = set(
            self._git_path_list(
                "diff-files",
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=all",
                "--",
            )
        )
        unstaged_candidates.update(flagged_paths)
        unstaged_candidates.update(
            path for path, (mode, _oid) in index_entries.items() if mode not in {"100644", "100755"}
        )
        unstaged_candidates.update(
            path for path, codes in status_codes.items() if codes[0] == "D"
        )
        raw_changes, raw_reasons = self._raw_worktree_changes(
            unstaged_candidates,
            index_entries,
            object_format=object_format,
        )
        reasons.update(raw_reasons)
        for path, code in raw_changes.items():
            codes = status_codes.setdefault(path, [" ", " "])
            if codes != ["U", "U"]:
                codes[1] = code

        untracked = self._git_path_list(
            "ls-files", "--others", "--exclude-standard", "-z", "--"
        )
        for path in untracked:
            if path not in status_codes:
                status_codes[path] = ["?", "?"]

        status_lines: list[str] = []
        status_bytes = 0
        changed: list[str] = []
        for path in sorted(status_codes):
            x, y = status_codes[path]
            if x == " " and y == " ":
                continue
            changed.append(path)
            line = f"{x}{y} {self._render_status_path(path)}"
            encoded_size = len(line.encode("utf-8")) + (1 if status_lines else 0)
            if status_bytes + encoded_size <= _MAX_GIT_TEXT_OUTPUT_BYTES:
                status_lines.append(line)
                status_bytes += encoded_size
            else:
                reasons.add("worktree-status-byte-limit-exceeded")

        return (
            "\n".join(status_lines),
            tuple(changed),
            hashlib.sha256(before_index).hexdigest(),
            tuple(sorted(reasons)),
        )

    @staticmethod
    def _render_status_path(path: str) -> str:
        if (
            path[:1].isspace()
            or path[-1:].isspace()
            or any(
                ord(char) < 0x20 or 0xD800 <= ord(char) <= 0xDFFF or char in {'"', "\\"}
                for char in path
            )
        ):
            return json.dumps(path, ensure_ascii=True)
        return path

    @staticmethod
    def _parse_status_path(rendered: str) -> str:
        if not rendered.startswith('"'):
            return rendered
        try:
            parsed = json.loads(rendered)
        except json.JSONDecodeError as exc:
            raise RuntimeError("repository status contains a malformed quoted path") from exc
        if not isinstance(parsed, str):
            raise RuntimeError("repository status contains a malformed quoted path")
        return parsed

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
        if not isinstance(relative_path, str) or not relative_path or "\0" in relative_path:
            raise ValueError("repository path must be a normalized relative path")
        path = PurePosixPath(relative_path)
        normalized = path.as_posix()
        if (
            path.is_absolute()
            or normalized != relative_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("repository path must be a normalized relative path")
        return normalized

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
                data = self._read_bytes_confined_adapter(
                    self.workspace,
                    normalized,
                    max_bytes=max_bytes,
                    label=f"workspace fingerprint subject {normalized}",
                    expected_root_identity=self.workspace_root_identity,
                )
            except FileNotFoundError:
                self._assert_workspace_subject_current()
                return None, "deleted"
            except OSError:
                self._assert_workspace_subject_current()
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
        # A live authorized identity is never downgraded into this path: __init__ rejects
        # authorized inspection when descriptor-backed authority is unavailable.
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
        *,
        index_digest: str | None = None,
        initial_incomplete_reasons: tuple[str, ...] = (),
    ) -> tuple[str, bool, tuple[str, ...]]:
        """Hash Git state plus bounded current bytes and expose proof completeness."""
        file_rows: list[dict[str, object]] = []
        incomplete_reasons: set[str] = set(initial_incomplete_reasons)
        total_hashed_bytes = 0
        if len(changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
            incomplete_reasons.add("changed-file-limit-exceeded")

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
            "index_sha256": index_digest,
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
