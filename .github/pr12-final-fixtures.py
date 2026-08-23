from __future__ import annotations

from pathlib import Path


def replace_exact(path_s: str, old: str, new: str, *, count: int = 1) -> None:
    path = Path(path_s)
    text = path.read_text(encoding="utf-8")
    observed = text.count(old)
    if observed != count:
        raise SystemExit(
            f"refusing ambiguous final repair in {path}: expected {count} occurrence(s), "
            f"found {observed}: {old!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


# ROOT is runtime data, not import setup. Keep it after every module import.
for path_s, last_import in (
    ("evals/runner.py", "from ai_qa_automation.tools.validation import ValidationGate\n"),
    ("evals/holdout_runner.py", "from ai_qa_automation.policy import PolicyEngine\n"),
):
    path = Path(path_s)
    text = path.read_text(encoding="utf-8")
    root_line = 'ROOT = Path(__file__).resolve().parents[1]\n'
    if text.count(root_line) != 1 or text.count(last_import) != 1:
        raise SystemExit(f"refusing ambiguous evaluator import repair in {path}")
    text = text.replace(root_line, "", 1)
    text = text.replace(last_import, last_import + "\n" + root_line, 1)
    path.write_text(text, encoding="utf-8")

replace_exact(
    "src/ai_qa_automation/intelligence/quality_review.py",
    "    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:\n"
    "        if isinstance(node.ops[0], (ast.Eq, ast.Is, ast.GtE, ast.LtE)):\n"
    "            return ast.dump(node.left, include_attributes=False) == ast.dump(\n"
    "                node.comparators[0], include_attributes=False\n"
    "            )",
    "    if (\n"
    "        isinstance(node, ast.Compare)\n"
    "        and len(node.ops) == 1\n"
    "        and len(node.comparators) == 1\n"
    "        and isinstance(node.ops[0], (ast.Eq, ast.Is, ast.GtE, ast.LtE))\n"
    "    ):\n"
    "        return ast.dump(node.left, include_attributes=False) == ast.dump(\n"
    "            node.comparators[0], include_attributes=False\n"
    "        )",
)
replace_exact(
    "tests/unit/test_telemetry.py",
    "    with pytest.raises(ValueError, match=\"runtime failure\"):\n"
    "        with telemetry.trace_span(\"failed-runtime\"):\n"
    "            raise ValueError(\"runtime failure\")",
    "    with (\n"
    "        pytest.raises(ValueError, match=\"runtime failure\"),\n"
    "        telemetry.trace_span(\"failed-runtime\"),\n"
    "    ):\n"
    "        raise ValueError(\"runtime failure\")",
)

# These exact lines are synthetic credential-shaped fixtures used to prove
# redaction/non-leakage. Inline allowlisting leaves every other repository line
# under detect-secrets rather than excluding test directories wholesale.
allowlist_repairs = {
    "tests/unit/test_doctor.py": [
        (
            '    secret = "test-only-secret-that-must-never-appear"',
            '    secret = "test-only-secret-that-must-never-appear"  # pragma: allowlist secret',
            1,
        ),
    ],
    "tests/unit/test_redaction.py": [
        (
            '        "AK" + "IA" + "1234567890ABCDEF",',
            '        "AK" + "IA" + "1234567890ABCDEF",  # pragma: allowlist secret',
            1,
        ),
        (
            '        "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456",',
            '        "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456",  # pragma: allowlist secret',
            1,
        ),
        (
            '        "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv",',
            '        "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv",  # pragma: allowlist secret',
            1,
        ),
        (
            '        "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz",',
            '        "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz",  # pragma: allowlist secret',
            1,
        ),
        (
            '        "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz1234567890",',
            '        "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz1234567890",  # pragma: allowlist secret',
            1,
        ),
        (
            '        "xox" + "b-" + "1234567890-abcdefghijklmnop",',
            '        "xox" + "b-" + "1234567890-abcdefghijklmnop",  # pragma: allowlist secret',
            1,
        ),
        (
            '    text = "https://automation-user:super-secret-password@example.test/api"',
            '    text = "https://automation-user:super-secret-password@example.test/api"  # pragma: allowlist secret',
            1,
        ),
        (
            '    secret = "unknown-format-secret-that-still-must-not-survive"',
            '    secret = "unknown-format-secret-that-still-must-not-survive"  # pragma: allowlist secret',
            1,
        ),
        (
            '        "nested": ["https://user:password@example.test"],',
            '        "nested": ["https://user:password@example.test"],  # pragma: allowlist secret',
            1,
        ),
    ],
    "tests/unit/test_runtime_hooks.py": [
        (
            '    secret = "sk-" + "ant-" + "this-must-never-enter-the-journal"',
            '    secret = "sk-" + "ant-" + "this-must-never-enter-the-journal"  # pragma: allowlist secret',
            1,
        ),
        (
            '    secret = "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv"',
            '    secret = "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv"  # pragma: allowlist secret',
            1,
        ),
    ],
}
for path_s, repairs in allowlist_repairs.items():
    for old, new, count in repairs:
        replace_exact(path_s, old, new, count=count)
