#!/usr/bin/env python3
"""Minimal post-tool audit hook; intentionally avoids logging raw tool output or secrets."""

from __future__ import annotations

import json
import sys


def main() -> int:
    payload = json.load(sys.stdin)
    tool = str(payload.get("tool_name", "unknown"))
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": f"Audit: {tool} completed; raw output was not persisted by this hook.",
                }
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
