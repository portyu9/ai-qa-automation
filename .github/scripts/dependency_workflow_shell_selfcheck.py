#!/usr/bin/env python3
"""Fail closed on Bash syntax errors in accepted-main dependency governance.

GitHub Actions validates workflow YAML but does not parse embedded Bash. The
trusted controller therefore must not defer a malformed shell branch to live
mutation admission, where a scheduled workflow can repeatedly fail or no-op.
This checker uses only the Python standard library and Bash's non-executing
syntax parser. It never evaluates workflow expressions or executes scripts.
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path

WORKFLOW = Path(".github/workflows/dependency-governance.yml")
LITERAL_RUN = re.compile(r"^(?P<space> *)run: \|[-+]?\s*$")


def literal_bash_blocks(source: str) -> list[tuple[int, str]]:
    lines = source.splitlines()
    blocks: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = LITERAL_RUN.fullmatch(line)
        if not match:
            continue
        indentation = len(match.group("space"))
        body: list[str] = []
        cursor = index + 1
        while cursor < len(lines):
            current = lines[cursor]
            if current.strip() and len(current) - len(current.lstrip(" ")) <= indentation:
                break
            body.append(current)
            cursor += 1
        if not any(part.strip() for part in body):
            raise ValueError(f"Empty literal shell block at YAML line {index + 1}")
        blocks.append((index + 1, textwrap.dedent("\n".join(body)) + "\n"))
    return blocks


def bash_syntax_error(script: str) -> str | None:
    result = subprocess.run(
        ["bash", "-n"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode:
        return result.stderr.strip() or f"bash -n exited {result.returncode}"
    return None


def verify(source: str) -> str:
    blocks = literal_bash_blocks(source)
    if len(blocks) < 8:
        raise ValueError("Expected governance literal Bash blocks are missing")
    for line, script in blocks:
        error = bash_syntax_error(script)
        if error:
            raise ValueError(f"Bash syntax invalid at governance YAML line {line}: {error}")

    admission = [
        script
        for _, script in blocks
        if "PREVIOUS_STATE" in script
        and "OWNER_SCHEDULE_WAKE" in script
        and "admitted=false" in script
    ]
    if len(admission) != 1:
        raise ValueError("Expected precisely one privileged mutation-admission Bash block")
    if "}; }; then" not in admission[0]:
        raise ValueError("Nested recovery admission requires both closed condition groups")

    # Regression: reproduce the November 24 production defect verbatim.
    broken = admission[0].replace("}; }; then", "}; then", 1)
    if broken == admission[0] or bash_syntax_error(broken) is None:
        raise ValueError("Missing nested recovery brace did not fail Bash syntax validation")

    # Regression: a harmless, correctly nested alternate path must parse.
    if bash_syntax_error(
        "if false; then\n  :\nelif true && { false || { true && true; }; }; then\n  :\nfi\n"
    ):
        raise ValueError("Valid nested recovery syntax was incorrectly rejected")
    return f"Validated {len(blocks)} governance Bash blocks and both recovery-brace fixtures"


def main() -> int:
    try:
        print(verify(WORKFLOW.read_text(encoding="utf-8")))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
