from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..fs_authority import pin_directory_identity, read_bytes_confined
from ..fs_observation import scan_regular_files_confined
from ..redaction import redact_text

_MAX_MODEL_SOURCE_BYTES = 1_000_000
_MAX_COVERAGE_SCAN_ENTRIES = 5_000
_MAX_COVERAGE_SOURCE_BYTES = 16_000_000
_IGNORED_COVERAGE_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        ".tox",
        ".pytest_cache",
        "__pycache__",
    }
)
_TEST_CODE_SUFFIXES = frozenset({".py", ".js", ".ts", ".java", ".cs"})


@dataclass(frozen=True)
class ConfinedSourceObservation:
    text: str
    sha256: str
    size_bytes: int
    root_identity: tuple[int, int]


@dataclass(frozen=True)
class CoverageMatch:
    path: str
    matches: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"path": redact_text(self.path), "matches": list(self.matches)}


@dataclass(frozen=True)
class CoverageSearchObservation:
    results: tuple[CoverageMatch, ...]
    complete: bool
    incomplete_reasons: tuple[str, ...]
    observed_entries: int
    examined_test_files: int
    observed_source_bytes: int
    unsafe_path_count: int
    unreadable_path_count: int
    skipped_source_count: int
    skipped_source_paths: tuple[str, ...]
    skipped_source_paths_truncated: bool
    root_identity: tuple[int, int]

    def as_structured_data(self, *, query: str) -> dict[str, Any]:
        return {
            "query": query,
            "results": [item.as_dict() for item in self.results],
            "complete": self.complete,
            "incomplete_reasons": list(self.incomplete_reasons),
            "observed_entries": self.observed_entries,
            "examined_test_files": self.examined_test_files,
            "observed_source_bytes": self.observed_source_bytes,
            "unsafe_path_count": self.unsafe_path_count,
            "unreadable_path_count": self.unreadable_path_count,
            "skipped_source_count": self.skipped_source_count,
            "skipped_source_paths": [redact_text(path) for path in self.skipped_source_paths],
            "skipped_source_paths_truncated": self.skipped_source_paths_truncated,
            "root_identity": list(self.root_identity),
        }


def _validated_root_identity(
    workspace: Path,
    *,
    expected_root_identity: tuple[int, int] | None,
    label: str,
) -> tuple[int, int]:
    current = pin_directory_identity(workspace, label=label)
    if expected_root_identity is not None and current != expected_root_identity:
        raise ValueError(f"{label} root changed identity since authorization")
    return current


def _validated_relative_file(relative_path: str | Path, *, label: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"{label} must be a relative file path below the workspace")
    return relative


def is_test_code_path(path: Path) -> bool:
    if path.suffix.lower() not in _TEST_CODE_SUFFIXES:
        return False
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return (
        bool(parts & {"tests", "test", "generated_tests"})
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".spec." in name
        or ".test." in name
    )


def read_model_source_confined(
    workspace: Path,
    relative_path: str | Path,
    *,
    expected_root_identity: tuple[int, int] | None = None,
    max_bytes: int = _MAX_MODEL_SOURCE_BYTES,
    label: str = "model-facing source file",
) -> ConfinedSourceObservation:
    relative = _validated_relative_file(relative_path, label=label)
    root_identity = _validated_root_identity(
        workspace,
        expected_root_identity=expected_root_identity,
        label=f"{label} workspace",
    )
    content = read_bytes_confined(
        workspace,
        relative,
        max_bytes=max_bytes,
        label=label,
        expected_root_identity=root_identity,
    )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnicodeError(f"{label} is not valid UTF-8") from exc
    return ConfinedSourceObservation(
        text=text,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        root_identity=root_identity,
    )


def search_test_coverage_confined(
    workspace: Path,
    *,
    query: str,
    max_results: int = 100,
    max_scan_entries: int = _MAX_COVERAGE_SCAN_ENTRIES,
    max_source_bytes: int = _MAX_COVERAGE_SOURCE_BYTES,
    expected_root_identity: tuple[int, int] | None = None,
) -> CoverageSearchObservation:
    if (
        isinstance(max_results, bool)
        or not isinstance(max_results, int)
        or not 1 <= max_results <= 200
    ):
        raise ValueError("max_results must be between 1 and 200")
    if (
        isinstance(max_scan_entries, bool)
        or not isinstance(max_scan_entries, int)
        or max_scan_entries < 1
    ):
        raise ValueError("max_scan_entries must be a positive integer")
    if (
        isinstance(max_source_bytes, bool)
        or not isinstance(max_source_bytes, int)
        or max_source_bytes < 1
    ):
        raise ValueError("max_source_bytes must be a positive integer")
    if len(query) > 200:
        raise ValueError("coverage search query exceeds 200 characters")

    root_identity = _validated_root_identity(
        workspace,
        expected_root_identity=expected_root_identity,
        label="test coverage search workspace",
    )
    scan = scan_regular_files_confined(
        workspace,
        max_entries=max_scan_entries,
        ignored_names=_IGNORED_COVERAGE_NAMES,
        label="test coverage search",
        expected_root_identity=root_identity,
    )
    needle = query.casefold().strip()
    rows: list[CoverageMatch] = []
    reasons: set[str] = set()
    if scan.truncated:
        reasons.add("filesystem_scan_incomplete")
    if scan.unsafe_paths:
        reasons.add("unsafe_or_special_paths_skipped")
    if scan.unreadable_paths:
        reasons.add("unreadable_paths_skipped")

    examined_test_files = 0
    observed_source_bytes = 0
    skipped_source_count = 0
    skipped_source_paths: list[str] = []

    for observed in scan.files:
        relative_text = observed.path.as_posix()
        relative = Path(relative_text)
        if not is_test_code_path(relative):
            continue
        examined_test_files += 1

        if not needle:
            candidate = CoverageMatch(path=relative_text, matches=())
        else:
            remaining = max_source_bytes - observed_source_bytes
            if remaining <= 0:
                reasons.add("coverage_source_byte_budget_exhausted")
                break
            try:
                source = read_model_source_confined(
                    workspace,
                    relative,
                    expected_root_identity=root_identity,
                    max_bytes=min(_MAX_MODEL_SOURCE_BYTES, remaining),
                    label=f"coverage source {relative_text}",
                )
            except (OSError, UnicodeError, ValueError):
                skipped_source_count += 1
                if len(skipped_source_paths) < 20:
                    skipped_source_paths.append(relative_text)
                reasons.add("coverage_source_read_incomplete")
                continue
            observed_source_bytes += source.size_bytes
            matches: list[str] = []
            for line_no, line in enumerate(source.text.splitlines(), 1):
                if needle in line.casefold():
                    matches.append(f"{line_no}: {redact_text(line[:240])}")
                    if len(matches) >= 3:
                        break
            if not matches and needle not in relative_text.casefold():
                continue
            candidate = CoverageMatch(path=relative_text, matches=tuple(matches))

        if len(rows) >= max_results:
            reasons.add("result_limit_reached")
            break
        rows.append(candidate)

    return CoverageSearchObservation(
        results=tuple(rows),
        complete=not reasons,
        incomplete_reasons=tuple(sorted(reasons)),
        observed_entries=scan.observed_entries,
        examined_test_files=examined_test_files,
        observed_source_bytes=observed_source_bytes,
        unsafe_path_count=len(scan.unsafe_paths),
        unreadable_path_count=len(scan.unreadable_paths),
        skipped_source_count=skipped_source_count,
        skipped_source_paths=tuple(skipped_source_paths),
        skipped_source_paths_truncated=skipped_source_count > len(skipped_source_paths),
        root_identity=root_identity,
    )
