from __future__ import annotations

from pathlib import Path


def replace(path_s: str, old: str, new: str, *, count: int = 1) -> None:
    path = Path(path_s)
    text = path.read_text(encoding="utf-8")
    observed = text.count(old)
    if observed != count:
        raise SystemExit(
            f"refusing ambiguous repair in {path}: expected {count} occurrence(s), "
            f"found {observed}: {old!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


# The evaluator scripts are supported after project installation. ROOT remains the
# authority for repository-owned scenario/threshold paths; sys.path mutation is unnecessary.
for path in ("evals/runner.py", "evals/holdout_runner.py"):
    replace(path, "import sys\n", "")
    replace(path, 'sys.path.insert(0, str(ROOT / "src"))\n\n', "")

# Typer metadata belongs in Annotated rather than executable default expressions.
replace(
    "src/ai_qa_automation/cli.py",
    "from pathlib import Path\n",
    "from pathlib import Path\nfrom typing import Annotated\n",
)
replace(
    "src/ai_qa_automation/cli.py",
    '    run_dir: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),',
    '    run_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False, resolve_path=True)],',
    count=3,
)
replace(
    "src/ai_qa_automation/cli.py",
    '    output_format: str = typer.Option("json", "--format", help="json or dot"),',
    '    output_format: Annotated[str, typer.Option("--format", help="json or dot")] = "json",',
)
replace(
    "src/ai_qa_automation/cli.py",
    '    baseline: Path = typer.Option(\n        ..., "--baseline", exists=True, dir_okay=False, resolve_path=True\n    ),\n    current: Path = typer.Option(..., "--current", exists=True, dir_okay=False, resolve_path=True),',
    '    baseline: Annotated[\n        Path, typer.Option("--baseline", exists=True, dir_okay=False, resolve_path=True)\n    ],\n    current: Annotated[\n        Path, typer.Option("--current", exists=True, dir_okay=False, resolve_path=True)\n    ],',
)
replace(
    "src/ai_qa_automation/cli.py",
    '    objective: str = typer.Argument(..., help="Bounded QA objective"),\n    workspace: Path = typer.Option(\n        ..., "--workspace", exists=True, file_okay=False, resolve_path=True\n    ),\n    control_root: Path | None = typer.Option(\n        None, "--control-root", exists=True, file_okay=False, resolve_path=True\n    ),',
    '    objective: Annotated[str, typer.Argument(help="Bounded QA objective")],\n    workspace: Annotated[\n        Path, typer.Option("--workspace", exists=True, file_okay=False, resolve_path=True)\n    ],\n    control_root: Annotated[\n        Path | None, typer.Option("--control-root", exists=True, file_okay=False, resolve_path=True)\n    ] = None,',
)

# FastAPI query metadata also belongs in Annotated rather than a function-call default.
replace(
    "examples/reference_sut/app.py",
    "from typing import Literal\n",
    "from typing import Annotated, Literal\n",
)
replace(
    "examples/reference_sut/app.py",
    'def checkout(mode: Mode = Query(default="pass")) -> str:',
    'def checkout(mode: Annotated[Mode, Query()] = "pass") -> str:',
)

# Mutable registries are intentional class-level constants, not instance fields.
replace(
    "src/ai_qa_automation/intelligence/change_impact.py",
    "from pathlib import PurePosixPath\n",
    "from pathlib import PurePosixPath\nfrom typing import ClassVar\n",
)
for name in ("_CRITICAL", "_HIGH", "_MEDIUM"):
    replace(
        "src/ai_qa_automation/intelligence/change_impact.py",
        f"    {name} = {{",
        f"    {name}: ClassVar[dict[str, tuple[str, ...]]] = {{",
    )
replace(
    "src/ai_qa_automation/intelligence/contract_drift.py",
    "from typing import Any\n",
    "from typing import Any, ClassVar\n",
)
replace(
    "src/ai_qa_automation/intelligence/contract_drift.py",
    '    _METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}',
    '    _METHODS: ClassVar[set[str]] = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}',
)
replace(
    "src/ai_qa_automation/intelligence/repository_profile.py",
    "from pathlib import Path\n",
    "from pathlib import Path\nfrom typing import ClassVar\n",
)
replace(
    "src/ai_qa_automation/intelligence/repository_profile.py",
    "    _EXTENSIONS = {",
    "    _EXTENSIONS: ClassVar[dict[str, str]] = {",
)
replace(
    "src/ai_qa_automation/policy.py",
    "from typing import Any\n",
    "from typing import Any, ClassVar\n",
)
replace(
    "src/ai_qa_automation/policy.py",
    "    OFFICIAL_EXTERNAL_MCP = {",
    "    OFFICIAL_EXTERNAL_MCP: ClassVar[dict[str, str]] = {",
)
for name in (
    "_DANGEROUS_TOOL_NAMES",
    "_APPROVED_SKILLS",
    "_INTERNAL_QA_TOOLS",
    "_PROTECTED_RELATIVE_PATHS",
):
    replace(
        "src/ai_qa_automation/policy.py",
        f"    {name} = {{",
        f"    {name}: ClassVar[set[str]] = {{",
    )
replace(
    "src/ai_qa_automation/policy.py",
    "    _UNSAFE_PATCH_PATTERNS = {",
    "    _UNSAFE_PATCH_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {",
)
replace(
    "src/ai_qa_automation/tools/safe_patch.py",
    "from pathlib import Path\n",
    "from pathlib import Path\nfrom typing import ClassVar\n",
)
replace(
    "src/ai_qa_automation/tools/safe_patch.py",
    '    _SUPPORTED_SUFFIXES = {".py", ".js", ".ts"}',
    '    _SUPPORTED_SUFFIXES: ClassVar[set[str]] = {".py", ".js", ".ts"}',
)
replace(
    "src/ai_qa_automation/tools/test_execution.py",
    "from pathlib import Path\n",
    "from pathlib import Path\nfrom typing import ClassVar\n",
)
replace(
    "src/ai_qa_automation/tools/test_execution.py",
    "    _SAFE_FLAGS = {",
    "    _SAFE_FLAGS: ClassVar[set[str]] = {",
)
replace(
    "src/ai_qa_automation/tools/test_execution.py",
    '    _SAFE_VALUE_OPTIONS = {"-k", "-m", "--maxfail", "--tb"}',
    '    _SAFE_VALUE_OPTIONS: ClassVar[set[str]] = {"-k", "-m", "--maxfail", "--tb"}',
)
replace(
    "tests/integration/test_agent_sdk_contract.py",
    "from typing import Any\n",
    "from typing import Any, ClassVar\n",
)
replace(
    "tests/integration/test_agent_sdk_contract.py",
    "    last_kwargs: dict[str, Any] = {}",
    "    last_kwargs: ClassVar[dict[str, Any]] = {}",
)

# Path.replace has the same replacement semantics as os.replace for these Path operands.
replace("src/ai_qa_automation/evidence.py", "        os.replace(temp, path)", "        temp.replace(path)")
replace("src/ai_qa_automation/state.py", "            os.replace(temp, self.path)", "            temp.replace(self.path)")
replace(
    "src/ai_qa_automation/runtime/run_control.py",
    "        os.replace(temp, path)",
    "        temp.replace(path)",
    count=2,
)
replace(
    "src/ai_qa_automation/tools/safe_patch.py",
    "            os.replace(temp, destination)",
    "            temp.replace(destination)",
)

# Convert only OSError handlers that already discarded the exception without side effects.
replace(
    "src/ai_qa_automation/runtime/run_control.py",
    "from pathlib import Path\n",
    "from pathlib import Path\nfrom contextlib import suppress\n",
)
replace(
    "src/ai_qa_automation/runtime/run_control.py",
    "            if backup_path is not None:\n                try:\n                    backup_path.unlink(missing_ok=True)\n                except OSError:\n                    pass",
    "            if backup_path is not None:\n                with suppress(OSError):\n                    backup_path.unlink(missing_ok=True)",
)
replace(
    "src/ai_qa_automation/runtime/workspace_lease.py",
    "from contextlib import AbstractContextManager\n",
    "from contextlib import AbstractContextManager, suppress\n",
)
replace(
    "src/ai_qa_automation/runtime/workspace_lease.py",
    "            try:\n                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)\n            except OSError:\n                pass",
    "            with suppress(OSError):\n                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)",
)
replace(
    "src/ai_qa_automation/tools/execution_env.py",
    "from collections.abc import Mapping, Sequence\n",
    "from collections.abc import Mapping, Sequence\nfrom contextlib import suppress\n",
)
replace(
    "src/ai_qa_automation/tools/execution_env.py",
    "            try:\n                process.stdout.close()\n            except OSError:\n                pass\n            try:\n                process.stderr.close()\n            except OSError:\n                pass",
    "            with suppress(OSError):\n                process.stdout.close()\n            with suppress(OSError):\n                process.stderr.close()",
)

# Flatten nested conditions without changing branches, values, or error handling.
replace(
    "src/ai_qa_automation/tools/safe_patch.py",
    '                if ch == "\\\\":\n                    if i + 1 < len(chars):\n                        chars[i] = " "\n                        if chars[i + 1] != "\\n":\n                            chars[i + 1] = " "\n                        i += 2\n                        continue',
    '                if ch == "\\\\" and i + 1 < len(chars):\n                    chars[i] = " "\n                    if chars[i + 1] != "\\n":\n                        chars[i + 1] = " "\n                    i += 2\n                    continue',
)
replace(
    "src/ai_qa_automation/intelligence/quality_review.py",
    '        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):\n            if node.func.attr == "sleep":\n                findings.append(\n                    TestQualityFinding("QA001", "HIGH", "Arbitrary sleep detected", node.lineno)\n                )\n            if node.func.attr in {"skip", "xfail"}:\n                findings.append(\n                    TestQualityFinding(\n                        "QA002",\n                        "HIGH",\n                        "Skip/xfail requires explicit justification",\n                        node.lineno,\n                    )\n                )',
    '        if (\n            isinstance(node, ast.Call)\n            and isinstance(node.func, ast.Attribute)\n            and node.func.attr == "sleep"\n        ):\n            findings.append(\n                TestQualityFinding("QA001", "HIGH", "Arbitrary sleep detected", node.lineno)\n            )\n        if (\n            isinstance(node, ast.Call)\n            and isinstance(node.func, ast.Attribute)\n            and node.func.attr in {"skip", "xfail"}\n        ):\n            findings.append(\n                TestQualityFinding(\n                    "QA002",\n                    "HIGH",\n                    "Skip/xfail requires explicit justification",\n                    node.lineno,\n                )\n            )',
)

# Make pytest regex intent explicit: literal dots are escaped; existing wildcard intent remains.
regex_repairs: dict[str, list[tuple[str, str, int]]] = {
    "tests/unit/test_agent_terminal_status.py": [
        ('match="CLAUDE.md"', 'match=r"CLAUDE\\.md"', 1),
    ],
    "tests/unit/test_attestation.py": [
        ('match="state.json.*symlink"', 'match=r"state\\.json.*symlink"', 1),
        ('match="state.json"', 'match=r"state\\.json"', 1),
    ],
    "tests/unit/test_evidence_ownership.py": [
        ('match="control file.*symlink"', 'match=r"control file.*symlink"', 2),
    ],
    "tests/unit/test_journal_ownership.py": [
        ('match="journal path.*symlink"', 'match=r"journal path.*symlink"', 1),
    ],
    "tests/unit/test_k6_egress_contract.py": [
        ('match="existing .js file"', 'match=r"existing \\.js file"', 1),
    ],
    "tests/unit/test_lineage.py": [
        ('match="state.json"', 'match=r"state\\.json"', 1),
    ],
    "tests/unit/test_run_control_rollback_root.py": [
        ('match="rollback directory.*symlink"', 'match=r"rollback directory.*symlink"', 2),
    ],
    "tests/unit/test_workspace_lease_ownership.py": [
        ('match="lease directory.*symlink"', 'match=r"lease directory.*symlink"', 1),
        ('match="lease file.*symlink"', 'match=r"lease file.*symlink"', 1),
    ],
}
for path, repairs in regex_repairs.items():
    for old, new, count in repairs:
        replace(path, old, new, count=count)
