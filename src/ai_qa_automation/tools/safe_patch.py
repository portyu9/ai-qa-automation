from __future__ import annotations

import ast
import difflib
import hashlib
from dataclasses import dataclass
from pathlib import Path

from ..models import ToolDecision
from ..policy import PolicyEngine


@dataclass(frozen=True)
class PatchResult:
    path: str
    old_sha256: str
    new_sha256: str
    diff: str


class SafeTestPatcher:
    """Atomic, optimistic-concurrency test patcher with intent-eroding diff guards."""

    def __init__(self, workspace: Path, policy: PolicyEngine) -> None:
        self.workspace = workspace.resolve()
        self.policy = policy

    @staticmethod
    def sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def replace_once(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
        old_text: str,
        new_text: str,
    ) -> PatchResult:
        path = Path(relative_path)
        decision = self.policy.authorize_path(path, write=True)
        if decision.decision != ToolDecision.ALLOW:
            raise PermissionError(f"{decision.rule_id}: {decision.reason}")

        destination = (self.workspace / path).resolve()
        if not destination.is_file():
            raise FileNotFoundError(destination)
        original = destination.read_text(encoding="utf-8")
        actual_sha = self.sha256_text(original)
        if actual_sha != expected_sha256:
            raise RuntimeError("test file changed since proposal; refusing stale patch")
        if original.count(old_text) != 1:
            raise ValueError("old_text must match exactly once")

        updated = original.replace(old_text, new_text, 1)
        if destination.suffix == ".py":
            ast.parse(updated)
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{relative_path}",
                tofile=f"b/{relative_path}",
            )
        )
        violations = self.policy.validate_patch(diff)
        if violations:
            raise PermissionError(f"unsafe patch rejected: {', '.join(violations)}")

        temp = destination.with_suffix(destination.suffix + ".aiqa.tmp")
        temp.write_text(updated, encoding="utf-8")
        temp.replace(destination)
        return PatchResult(
            path=relative_path,
            old_sha256=actual_sha,
            new_sha256=self.sha256_text(updated),
            diff=diff,
        )

    def create_test(self, *, relative_path: str, content: str) -> PatchResult:
        """Create a new test file only after syntax/quality/policy checks."""
        from ..intelligence.quality_review import review_python_test_source

        path = Path(relative_path)
        decision = self.policy.authorize_path(path, write=True)
        if decision.decision != ToolDecision.ALLOW:
            raise PermissionError(f"{decision.rule_id}: {decision.reason}")
        destination = (self.workspace / path).resolve()
        if destination.exists():
            raise FileExistsError(destination)
        if destination.suffix == ".py":
            ast.parse(content)
            findings = review_python_test_source(content)
            blockers = [finding for finding in findings if finding.severity in {"HIGH", "CRITICAL"}]
            if blockers:
                raise PermissionError(
                    "generated test failed deterministic quality review: "
                    + ", ".join(f"{item.code}@{item.line}" for item in blockers)
                )
        synthetic_diff = "".join(f"+{line}" for line in content.splitlines(keepends=True))
        violations = self.policy.validate_patch(synthetic_diff)
        if violations:
            raise PermissionError(f"unsafe generated test rejected: {', '.join(violations)}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_suffix(destination.suffix + ".aiqa.tmp")
        temp.write_text(content, encoding="utf-8")
        temp.replace(destination)
        digest = self.sha256_text(content)
        return PatchResult(path=relative_path, old_sha256="ABSENT", new_sha256=digest, diff=synthetic_diff)
