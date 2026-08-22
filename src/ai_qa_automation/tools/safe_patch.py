from __future__ import annotations

import ast
import difflib
import hashlib
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..models import ToolDecision
from ..policy import PolicyEngine
from .locators import parse_locator_expression


@dataclass(frozen=True)
class PatchResult:
    path: str
    old_sha256: str
    new_sha256: str
    diff: str


class SafeTestPatcher:
    """Optimistic-concurrency test patcher with intent and filesystem guards."""

    _SUPPORTED_SUFFIXES = {".py", ".js", ".ts"}
    _MAX_TEST_FILE_BYTES = 1_000_000
    _NON_PYTHON_ASSERTION = re.compile(
        r"(?:"
        r"\bexpect\s*\([^;{}]*?\)\s*\.(?:not\.)?to[A-Z_a-z][A-Za-z0-9_]*\s*\("
        r"|\bassert\.(?:equal|strictEqual|deepEqual|ok|match|throws|rejects)\s*\("
        r"|\.should\s*\("
        r")",
        re.I,
    )

    def __init__(self, workspace: Path, policy: PolicyEngine) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.policy = policy

    @staticmethod
    def sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _resolve_owned_path(self, relative_path: str) -> tuple[Path, Path]:
        """Resolve a mutation path without accepting traversal or symlink aliases.

        RuntimeControl enforces the same ownership rule for live agent mutations.
        Keeping the invariant here as well prevents direct library use from
        weakening the filesystem boundary.
        """

        path = Path(relative_path)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise PermissionError("mutation path must be a non-traversing relative workspace path")

        cursor = self.workspace
        for part in path.parts:
            if part in {"", "."}:
                continue
            cursor = cursor / part
            if cursor.is_symlink():
                raise PermissionError("mutation path contains a symlink and has ambiguous ownership")

        destination = (self.workspace / path).resolve()
        try:
            destination.relative_to(self.workspace)
        except ValueError as exc:
            raise PermissionError("mutation path escapes the target workspace") from exc
        return path, destination

    def replace_once(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
        old_text: str,
        new_text: str,
    ) -> PatchResult:
        path, destination = self._resolve_owned_path(relative_path)
        decision = self.policy.authorize_path(path, write=True)
        if decision.decision != ToolDecision.ALLOW:
            raise PermissionError(f"{decision.rule_id}: {decision.reason}")

        if destination.suffix not in self._SUPPORTED_SUFFIXES:
            raise PermissionError(
                "safe test patching supports Python/JavaScript/TypeScript test files only"
            )
        if not destination.is_file():
            raise FileNotFoundError(destination)
        if destination.stat().st_size > self._MAX_TEST_FILE_BYTES:
            raise ValueError(f"test file exceeds {self._MAX_TEST_FILE_BYTES} byte patch limit")
        original = destination.read_text(encoding="utf-8")
        actual_sha = self.sha256_text(original)
        if actual_sha != expected_sha256:
            raise RuntimeError("test file changed since proposal; refusing stale patch")
        if original.count(old_text) != 1:
            raise ValueError("old_text must match exactly once")

        updated = original.replace(old_text, new_text, 1)
        self._validate_python_quality(destination, original, updated)
        normalized_relative = path.as_posix()
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{normalized_relative}",
                tofile=f"b/{normalized_relative}",
            )
        )
        violations = self.policy.validate_patch(diff)
        if violations:
            raise PermissionError(f"unsafe patch rejected: {', '.join(violations)}")

        self._atomic_replace(destination, updated)
        return PatchResult(
            path=normalized_relative,
            old_sha256=actual_sha,
            new_sha256=self.sha256_text(updated),
            diff=diff,
        )

    def replace_locator_once(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
        old_locator: str,
        new_locator: str,
    ) -> PatchResult:
        """Replace exactly one supported locator expression and nothing else.

        This is the autonomous existing-test mutation surface. General-purpose
        exact-text replacement remains an internal primitive and is not exposed
        to the live agent because assertion/setup/value edits need human review.
        """
        if old_locator == new_locator:
            raise ValueError("replacement locator must differ from the original")
        if parse_locator_expression(old_locator) is None:
            raise PermissionError("original text is not a supported literal locator expression")
        if parse_locator_expression(new_locator) is None:
            raise PermissionError("replacement text is not a supported literal locator expression")
        return self.replace_once(
            relative_path=relative_path,
            expected_sha256=expected_sha256,
            old_text=old_locator,
            new_text=new_locator,
        )

    @staticmethod
    def _mask_js_ts_literals_and_comments(source: str) -> str:
        """Mask comment/string bodies while preserving syntax punctuation/newlines."""
        chars = list(source)
        i = 0
        state = "code"
        quote = ""
        while i < len(chars):
            ch = chars[i]
            nxt = chars[i + 1] if i + 1 < len(chars) else ""
            if state == "code":
                if ch == "/" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    state = "line_comment"
                    i += 2
                    continue
                if ch == "/" and nxt == "*":
                    chars[i] = chars[i + 1] = " "
                    state = "block_comment"
                    i += 2
                    continue
                if ch in {"'", '"', "`"}:
                    quote = ch
                    state = "string"
                    i += 1
                    continue
            elif state == "line_comment":
                if ch == "\n":
                    state = "code"
                else:
                    chars[i] = " "
            elif state == "block_comment":
                if ch == "*" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    state = "code"
                    i += 2
                    continue
                if ch != "\n":
                    chars[i] = " "
            elif state == "string":
                if ch == "\\":
                    if i + 1 < len(chars):
                        chars[i] = " "
                        if chars[i + 1] != "\n":
                            chars[i + 1] = " "
                        i += 2
                        continue
                if ch == quote:
                    state = "code"
                    quote = ""
                elif ch != "\n":
                    chars[i] = " "
            i += 1
        return "".join(chars)

    @classmethod
    def _has_non_python_assertion(cls, source: str) -> bool:
        return bool(cls._NON_PYTHON_ASSERTION.search(cls._mask_js_ts_literals_and_comments(source)))

    def create_test(self, *, relative_path: str, content: str) -> PatchResult:
        """Create a new test only after path, syntax, quality, and no-overwrite checks."""
        from ..intelligence.quality_review import review_python_test_source

        if len(content.encode("utf-8")) > self._MAX_TEST_FILE_BYTES:
            raise ValueError(f"generated test exceeds {self._MAX_TEST_FILE_BYTES} byte limit")
        path, destination = self._resolve_owned_path(relative_path)
        decision = self.policy.authorize_path(path, write=True)
        if decision.decision != ToolDecision.ALLOW:
            raise PermissionError(f"{decision.rule_id}: {decision.reason}")
        if destination.suffix not in self._SUPPORTED_SUFFIXES:
            raise PermissionError("generated tests support Python/JavaScript/TypeScript files only")
        if destination.exists():
            raise FileExistsError(destination)
        if destination.suffix == ".py":
            ast.parse(content)
            blockers = [
                finding
                for finding in review_python_test_source(content)
                if finding.severity in {"HIGH", "CRITICAL"}
            ]
            if blockers:
                raise PermissionError(
                    "generated test failed deterministic quality review: "
                    + ", ".join(f"{item.code}@{item.line}" for item in blockers)
                )
        elif not self._has_non_python_assertion(content):
            raise PermissionError("generated JavaScript/TypeScript test has no observable assertion")
        synthetic_diff = "".join(f"+{line}" for line in content.splitlines(keepends=True))
        violations = self.policy.validate_patch(synthetic_diff)
        if violations:
            raise PermissionError(f"unsafe generated test rejected: {', '.join(violations)}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_create(destination, content)
        digest = self.sha256_text(content)
        return PatchResult(
            path=path.as_posix(),
            old_sha256="ABSENT",
            new_sha256=digest,
            diff=synthetic_diff,
        )

    @staticmethod
    def _validate_python_quality(destination: Path, original: str, updated: str) -> None:
        if destination.suffix != ".py":
            return
        ast.parse(updated)
        from ..intelligence.quality_review import review_python_test_source

        before = Counter((item.code, item.severity) for item in review_python_test_source(original))
        introduced = []
        for finding in review_python_test_source(updated):
            key = (finding.code, finding.severity)
            if before[key]:
                before[key] -= 1
            elif finding.severity in {"HIGH", "CRITICAL"}:
                introduced.append(finding)
        if introduced:
            raise PermissionError(
                "patch introduced deterministic test-quality blockers: "
                + ", ".join(f"{item.code}@{item.line}" for item in introduced)
            )

    @staticmethod
    def _write_secure_temp(destination: Path, content: str) -> Path:
        handle, raw_path = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".aiqa.tmp",
            text=True,
        )
        temp = Path(raw_path)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            temp.unlink(missing_ok=True)
            raise
        return temp

    @classmethod
    def _atomic_replace(cls, destination: Path, content: str) -> None:
        temp = cls._write_secure_temp(destination, content)
        try:
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)

    @classmethod
    def _atomic_create(cls, destination: Path, content: str) -> None:
        temp = cls._write_secure_temp(destination, content)
        try:
            os.link(temp, destination)
        except FileExistsError:
            raise FileExistsError(destination) from None
        finally:
            temp.unlink(missing_ok=True)
