from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class TestQualityFinding:
    code: str
    severity: str
    message: str
    line: int


def _is_assertion_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in {"expect", "assert_that", "verify"}
    if isinstance(func, ast.Attribute):
        if func.attr.startswith("assert"):
            return True
        if func.attr == "raises" and isinstance(func.value, ast.Name) and func.value.id == "pytest":
            return True
        root = func.value
        while isinstance(root, (ast.Attribute, ast.Call)):
            if isinstance(root, ast.Call) and isinstance(root.func, ast.Name) and root.func.id == "expect":
                return True
            root = root.func.value if isinstance(root, ast.Call) and isinstance(root.func, ast.Attribute) else getattr(root, "value", None)
    return False


def _is_tautological_assert(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant) and node.value is True:
        return True
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        if isinstance(node.ops[0], (ast.Eq, ast.Is, ast.GtE, ast.LtE)):
            return ast.dump(node.left, include_attributes=False) == ast.dump(
                node.comparators[0], include_attributes=False
            )
    return False


def _has_observable_assertion(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call) and _is_assertion_call(node):
            return True
    return False


def review_python_test_source(source: str) -> list[TestQualityFinding]:
    """Run deterministic checks before semantic/model review."""
    findings: list[TestQualityFinding] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "sleep":
                findings.append(TestQualityFinding("QA001", "HIGH", "Arbitrary sleep detected", node.lineno))
            if node.func.attr in {"skip", "xfail"}:
                findings.append(
                    TestQualityFinding("QA002", "HIGH", "Skip/xfail requires explicit justification", node.lineno)
                )
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                broad = handler.type is None or (
                    isinstance(handler.type, ast.Name)
                    and handler.type.id in {"Exception", "BaseException"}
                )
                if broad and (not handler.body or all(isinstance(stmt, ast.Pass) for stmt in handler.body)):
                    findings.append(
                        TestQualityFinding(
                            "QA005",
                            "CRITICAL",
                            "Broad exception suppression detected",
                            handler.lineno,
                        )
                    )
        if isinstance(node, ast.Assert) and _is_tautological_assert(node.test):
            findings.append(
                TestQualityFinding("QA004", "CRITICAL", "Tautological assertion detected", node.lineno)
            )

    test_functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]
    for function in test_functions:
        if not _has_observable_assertion(function):
            findings.append(
                TestQualityFinding("QA003", "CRITICAL", "Test has no observable assertion", function.lineno)
            )
    return findings
