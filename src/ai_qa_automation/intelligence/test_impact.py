from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_TOKEN = re.compile(r"[A-Za-z0-9_]+")
_TEST_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".cs", ".rb", ".go"}
_IGNORED = {".git", ".venv", "venv", "node_modules", "dist", "build", ".tox", ".pytest_cache", "__pycache__"}
_STOPWORDS = {"src", "lib", "app", "test", "tests", "spec", "specs", "index", "main", "common", "utils", "util"}


@dataclass(frozen=True)
class TestImpactCandidate:
    path: str
    score: float
    signals: tuple[str, ...]
    matched_changes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "score": self.score,
            "signals": list(self.signals),
            "matched_changes": list(self.matched_changes),
        }


@dataclass(frozen=True)
class TestImpactAssessment:
    changed_files: tuple[str, ...]
    scanned_test_files: int
    candidates: tuple[TestImpactCandidate, ...]
    scan_truncated: bool
    confidence: float
    rationale: str

    def as_dict(self) -> dict[str, object]:
        return {
            "changed_files": list(self.changed_files),
            "scanned_test_files": self.scanned_test_files,
            "candidates": [item.as_dict() for item in self.candidates],
            "scan_truncated": self.scan_truncated,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


class TestImpactMapper:
    """Build deterministic test relevance signals from paths and bounded source references.

    The result is deliberately a candidate map, not an authorization to omit any
    tests. A low-confidence or truncated map should broaden regression rather than
    being interpreted as proof that non-selected tests are irrelevant.
    """

    def map(
        self,
        workspace: Path,
        changed_files: list[str] | tuple[str, ...],
        *,
        max_test_files: int = 2000,
        max_file_bytes: int = 256_000,
        max_candidates: int = 150,
        max_scan_files: int = 20_000,
    ) -> TestImpactAssessment:
        if max_test_files < 1:
            raise ValueError("max_test_files must be at least 1")
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be at least 1")
        if max_candidates < 1:
            raise ValueError("max_candidates must be at least 1")
        if max_scan_files < 1:
            raise ValueError("max_scan_files must be at least 1")

        root = workspace.expanduser().resolve()
        normalized_changes = tuple(
            sorted(
                {
                    PurePosixPath(str(path).replace("\\", "/")).as_posix()
                    for path in changed_files
                    if str(path).strip()
                }
            )
        )
        if not normalized_changes:
            return TestImpactAssessment(
                changed_files=(),
                scanned_test_files=0,
                candidates=(),
                scan_truncated=False,
                confidence=0.2,
                rationale="No changed files were available for deterministic test-impact mapping.",
            )

        change_features = {path: self._features(path) for path in normalized_changes}
        rows: list[TestImpactCandidate] = []
        scanned_tests = 0
        scanned_files = 0
        truncated = False

        stop_scan = False
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            dirnames[:] = sorted(name for name in dirnames if name not in _IGNORED)
            current_dir = Path(dirpath)
            for filename in sorted(filenames):
                if scanned_files >= max_scan_files:
                    truncated = True
                    stop_scan = True
                    break
                scanned_files += 1
                path = current_dir / filename
                try:
                    relative = path.relative_to(root)
                except ValueError:
                    continue
                if not self._is_test_file(relative):
                    continue
                if scanned_tests >= max_test_files:
                    truncated = True
                    stop_scan = True
                    break
                scanned_tests += 1
                try:
                    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_file_bytes:
                        continue
                    source = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    source = ""
                candidate = self._score_candidate(relative.as_posix(), source, change_features)
                if candidate.score > 0:
                    rows.append(candidate)
            if stop_scan:
                break

        rows.sort(key=lambda item: (-item.score, item.path))
        selected = tuple(rows[:max_candidates])
        if truncated or scanned_tests == 0:
            confidence = 0.35
        elif not selected:
            confidence = 0.45
        else:
            top = selected[0].score
            density = min(1.0, len(selected) / max(1, scanned_tests))
            confidence = min(0.92, 0.5 + (top * 0.3) + (density * 0.12))
        return TestImpactAssessment(
            changed_files=normalized_changes,
            scanned_test_files=scanned_tests,
            candidates=selected,
            scan_truncated=truncated,
            confidence=round(confidence, 2),
            rationale=(
                "Candidate relevance is based on deterministic path/component overlap and bounded textual references; it must not be used as proof that omitted tests are safe."
            ),
        )

    def _score_candidate(
        self,
        test_path: str,
        source: str,
        change_features: dict[str, tuple[set[str], str, str]],
    ) -> TestImpactCandidate:
        test_tokens = self._tokens(test_path)
        source_folded = source.casefold()
        score = 0.0
        signals: set[str] = set()
        matched: list[str] = []

        test_top = PurePosixPath(test_path).parts[0].casefold() if PurePosixPath(test_path).parts else ""
        for changed, (tokens, stem, top) in change_features.items():
            local = 0.0
            local_signals: list[str] = []
            normalized_change = changed.casefold()
            if normalized_change in source_folded:
                local = max(local, 0.98)
                local_signals.append("exact_changed_path_reference")
            if stem and len(stem) >= 4 and re.search(rf"\b{re.escape(stem)}\b", source_folded):
                local = max(local, 0.86)
                local_signals.append("changed_module_reference")
            overlap = test_tokens & tokens
            if overlap:
                weighted = min(0.72, 0.32 + (len(overlap) * 0.1))
                local = max(local, weighted)
                local_signals.append(f"path_token_overlap:{','.join(sorted(overlap)[:5])}")
            if top and top == test_top and top not in _STOPWORDS:
                local = max(local, 0.52)
                local_signals.append("same_top_level_component")
            if local > 0:
                score = max(score, local)
                signals.update(local_signals)
                matched.append(changed)

        return TestImpactCandidate(
            path=test_path,
            score=round(score, 2),
            signals=tuple(sorted(signals)),
            matched_changes=tuple(sorted(matched)[:20]),
        )

    def _features(self, path: str) -> tuple[set[str], str, str]:
        posix = PurePosixPath(path)
        tokens = self._tokens(path)
        stem = posix.stem.casefold()
        for prefix in ("test_", "spec_", "test-", "spec-"):
            if stem.startswith(prefix):
                stem = stem[len(prefix) :]
        top = posix.parts[0].casefold() if posix.parts else ""
        return tokens, stem, top

    @staticmethod
    def _tokens(value: str) -> set[str]:
        return {
            token.casefold()
            for token in _TOKEN.findall(value)
            if len(token) >= 3 and token.casefold() not in _STOPWORDS
        }

    @staticmethod
    def _is_test_file(path: PurePosixPath) -> bool:
        if path.suffix.casefold() not in _TEST_SUFFIXES:
            return False
        lower = path.name.casefold()
        parts = {part.casefold() for part in path.parts}
        return (
            bool(parts & {"test", "tests", "spec", "specs", "e2e", "integration"})
            or lower.startswith(("test_", "spec_"))
            or ".spec." in lower
            or ".test." in lower
            or lower.endswith(("_test.py", "_test.go"))
        )
