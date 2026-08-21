from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class TestQualityFinding:
    code: str
    severity: str
    message: str
    line: int


def review_python_test_source(source: str) -> list[TestQualityFinding]:
    """Cheap deterministic review before asking a model for semantic review."""
    findings: list[TestQualityFinding] = []
    tree = ast.parse(source)
    assert_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            assert_lines.add(node.lineno)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "sleep":
                findings.append(TestQualityFinding("QA001", "HIGH", "Arbitrary sleep detected", node.lineno))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"skip", "xfail"}:
                findings.append(TestQualityFinding("QA002", "HIGH", "Skip/xfail requires explicit justification", node.lineno))

    test_functions = [
        node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    ]
    for function in test_functions:
        lines = {node.lineno for node in ast.walk(function) if isinstance(node, ast.Assert)}
        calls_expect = any(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "expect"
            for node in ast.walk(function)
        )
        if not lines and not calls_expect:
            findings.append(TestQualityFinding("QA003", "CRITICAL", "Test has no observable assertion", function.lineno))
    return findings
