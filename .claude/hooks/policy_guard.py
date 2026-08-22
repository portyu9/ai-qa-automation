#!/usr/bin/env python3
"""Control-plane Claude Code hook: reject obvious governance/destructive mutations."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

PROTECTED = (
    "CLAUDE.md",
    "LICENSE",
    "SECURITY.md",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/hooks/",
    ".claude/skills/",
    ".github/CODEOWNERS",
    ".github/workflows/",
    ".pre-commit-config.yaml",
    "pyproject.toml",
    "Dockerfile",
    "docs/SECURITY.md",
    "docs/THREAT_MODEL.md",
    "docs/PRODUCTION_READINESS.md",
    "docs/VERIFICATION_BOUNDARIES.md",
    "src/ai_qa_automation/policy.py",
    "src/ai_qa_automation/runtime/",
    "evals/",
)
DESTRUCTIVE = [
    re.compile(r"\bgit\s+push\b.*(?:--force|-f)"),
    re.compile(r"\bgit\s+reset\s+--hard\b"),
    re.compile(r"\bgit\s+clean\s+-[^\n]*f"),
    re.compile(r"\brm\s+-rf\s+/(?:\s|$)"),
]


def deny(reason: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )


def _evaluate(payload: dict[str, Any]) -> int:
    tool = str(payload.get("tool_name", ""))
    args = payload.get("tool_input") or {}
    if not isinstance(args, dict):
        raise TypeError("tool_input must be an object")

    command = str(args.get("command", ""))
    if tool == "Bash" and any(pattern.search(command) for pattern in DESTRUCTIVE):
        deny("SEC-GIT-001: destructive Git/filesystem command denied")
        return 0

    raw_path = args.get("file_path") or args.get("path")
    if raw_path and tool in {"Write", "Edit", "MultiEdit"}:
        try:
            relative = Path(str(raw_path)).resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            deny("SEC-FS-001: write outside control repository denied")
            return 0
        if any(relative == protected or relative.startswith(protected) for protected in PROTECTED):
            deny("SEC-GOV-001: governance file change requires reviewed engineering process")
            return 0
    return 0


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise TypeError("hook payload must be an object")
        return _evaluate(payload)
    except Exception as exc:
        # Claude Code treats ordinary non-zero hook exits as non-blocking. Policy
        # enforcement must therefore use exit 2 on parser/internal failures. Never
        # echo raw input or exception text because it may contain tool secrets.
        print(
            f"SEC-HOOK-001: policy guard failed closed ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
