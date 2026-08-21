from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


@dataclass(frozen=True)
class OwnershipRule:
    pattern: str
    owners: tuple[str, ...]
    line_number: int
    expression: re.Pattern[str]


@dataclass(frozen=True)
class OwnershipAssessment:
    source_path: str | None
    ownership_by_file: dict[str, tuple[str, ...]]
    unowned_files: tuple[str, ...]
    unsupported_patterns: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "source_path": self.source_path,
            "ownership_by_file": {
                path: list(owners) for path, owners in sorted(self.ownership_by_file.items())
            },
            "unowned_files": list(self.unowned_files),
            "unsupported_patterns": list(self.unsupported_patterns),
        }


class CodeownersResolver:
    """Bounded CODEOWNERS resolver with explicit unsupported-pattern reporting.

    GitHub CODEOWNERS uses a gitignore-like grammar, but not every gitignore
    feature is supported by GitHub itself. This parser implements the common
    root, directory, `*`, `**`, and `?` cases and refuses constructs it cannot
    model confidently instead of inventing ownership.
    """

    def __init__(
        self,
        rules: tuple[OwnershipRule, ...],
        *,
        source_path: str | None,
        unsupported_patterns: tuple[str, ...] = (),
    ) -> None:
        self.rules = rules
        self.source_path = source_path
        self.unsupported_patterns = unsupported_patterns

    @classmethod
    def from_workspace(cls, workspace: Path, *, max_bytes: int = 512_000) -> CodeownersResolver:
        root = workspace.expanduser().resolve()
        for relative in _CODEOWNERS_LOCATIONS:
            path = (root / relative).resolve()
            try:
                path.relative_to(root)
            except ValueError:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size > max_bytes:
                return cls((), source_path=relative, unsupported_patterns=("<file-too-large>",))
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                return cls((), source_path=relative, unsupported_patterns=("<unreadable>",))
            rules, unsupported = cls._parse(text)
            return cls(rules, source_path=relative, unsupported_patterns=unsupported)
        return cls((), source_path=None)

    def resolve(self, paths: list[str] | tuple[str, ...]) -> OwnershipAssessment:
        ownership: dict[str, tuple[str, ...]] = {}
        unowned: list[str] = []
        for raw in sorted({str(item).replace("\\", "/") for item in paths if str(item).strip()}):
            normalized = PurePosixPath(raw).as_posix().lstrip("/")
            matched: tuple[str, ...] | None = None
            for rule in self.rules:
                if rule.expression.fullmatch(normalized):
                    matched = rule.owners
            if matched:
                ownership[normalized] = matched
            else:
                unowned.append(normalized)
        return OwnershipAssessment(
            source_path=self.source_path,
            ownership_by_file=ownership,
            unowned_files=tuple(unowned),
            unsupported_patterns=self.unsupported_patterns,
        )

    @classmethod
    def _parse(cls, text: str) -> tuple[tuple[OwnershipRule, ...], tuple[str, ...]]:
        rules: list[OwnershipRule] = []
        unsupported: list[str] = []
        for line_number, raw_line in enumerate(text.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            fields = stripped.split()
            if len(fields) < 2:
                unsupported.append(f"line {line_number}: missing owner")
                continue
            pattern, owners = fields[0], tuple(fields[1:])
            if len(pattern) > 1024 or len(owners) > 100:
                unsupported.append(f"line {line_number}: pattern/owner list exceeds bounds")
                continue
            if pattern.startswith("!") or "[" in pattern or "]" in pattern:
                unsupported.append(f"line {line_number}: {pattern}")
                continue
            try:
                expression = cls._compile_pattern(pattern)
            except ValueError:
                unsupported.append(f"line {line_number}: {pattern}")
                continue
            rules.append(
                OwnershipRule(
                    pattern=pattern,
                    owners=owners,
                    line_number=line_number,
                    expression=expression,
                )
            )
        return tuple(rules), tuple(unsupported)

    @staticmethod
    def _compile_pattern(pattern: str) -> re.Pattern[str]:
        raw = pattern.strip().replace("\\", "/")
        if not raw or "\x00" in raw:
            raise ValueError("empty/invalid CODEOWNERS pattern")
        anchored = raw.startswith("/")
        raw = raw.lstrip("/")
        directory = raw.endswith("/")
        raw = raw.rstrip("/")
        if not raw:
            raise ValueError("empty CODEOWNERS pattern")

        pieces: list[str] = []
        index = 0
        while index < len(raw):
            char = raw[index]
            if char == "*":
                if index + 1 < len(raw) and raw[index + 1] == "*":
                    while index + 1 < len(raw) and raw[index + 1] == "*":
                        index += 1
                    if index + 1 < len(raw) and raw[index + 1] == "/":
                        index += 1
                        pieces.append("(?:.*/)?")
                    else:
                        pieces.append(".*")
                else:
                    pieces.append("[^/]*")
            elif char == "?":
                pieces.append("[^/]")
            else:
                pieces.append(re.escape(char))
            index += 1

        body = "".join(pieces)
        has_slash = "/" in raw
        prefix = "" if anchored or has_slash else "(?:.*/)?"
        suffix = "(?:/.*)?" if directory else ""
        return re.compile(f"{prefix}{body}{suffix}")
