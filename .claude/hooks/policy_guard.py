#!/usr/bin/env python3
"""Control-plane Claude Code hook: reject obvious governance/destructive mutations."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROTECTED = (
    "CLAUDE.md",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/hooks/",
    ".claude/skills/",
    ".github/workflows/",
    "src/ai_qa_automation/policy.py",
    "src/ai_qa_automation/runtime/runtime_hooks.py",
    "evals/thresholds.json",
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


def main() -> int:
    payload = json.load(sys.stdin)
    tool = str(payload.get("tool_name", ""))
    args = payload.get("tool_input") or {}
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
        if any(relative == p or relative.startswith(p) for p in PROTECTED):
            deny("SEC-GOV-001: governance file change requires reviewed engineering process")
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
