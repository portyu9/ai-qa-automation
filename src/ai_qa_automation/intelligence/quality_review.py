from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class TestQualityFinding:
    code: str
    severity: str
    message: str
    line: int


_ASSERTION_ROOTS = {"expect", "assert_that", "verify"}


def _is_assertion_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _ASSERTION_ROOTS
    if isinstance(func, ast.Attribute):
        if func.attr.startswith("assert"):
            return True
        if func.attr == "raises" and isinstance(func.value, ast.Name) and func.value.id == "pytest":
            return True
        root: ast.expr | None = func.value
        while isinstance(root, (ast.Attribute, ast.Call)):
            if (
                isinstance(root, ast.Call)
                and isinstance(root.func, ast.Name)
                and root.func.id in _ASSERTION_ROOTS
            ):
                return True
            if isinstance(root, ast.Call) and isinstance(root.func, ast.Attribute):
                root = root.func.value
            else:
                root = getattr(root, "value", None)
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


class _ObservableAssertionVisitor(ast.NodeVisitor):
    """Find assertions in one test body without borrowing evidence from nested scopes."""

    def __init__(self) -> None:
        self.found = False

    def visit_Assert(self, node: ast.Assert) -> None:  # noqa: N802 - ast visitor API
        self.found = True

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast visitor API
        if _is_assertion_call(node):
            self.found = True
            return
        self.generic_visit(node)

    # Nested scopes are separate executable units. An assertion inside an unused
    # local helper/class/lambda must not make the surrounding test observable.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        return


def _has_observable_assertion(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    visitor = _ObservableAssertionVisitor()
    for statement in function.body:
        visitor.visit(statement)
        if visitor.found:
            return True
    return False


def review_python_test_source(source: str) -> list[TestQualityFinding]:
    """Run deterministic checks before semantic/model review."""
    findings: list[TestQualityFinding] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "sleep":
                findings.append(
                    TestQualityFinding("QA001", "HIGH", "Arbitrary sleep detected", node.lineno)
                )
            if node.func.attr in {"skip", "xfail"}:
                findings.append(
                    TestQualityFinding(
                        "QA002",
                        "HIGH",
                        "Skip/xfail requires explicit justification",
                        node.lineno,
                    )
                )
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                broad = handler.type is None or (
                    isinstance(handler.type, ast.Name)
                    and handler.type.id in {"Exception", "BaseException"}
                )
                if broad and (
                    not handler.body or all(isinstance(stmt, ast.Pass) for stmt in handler.body)
                ):
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
                TestQualityFinding(
                    "QA004", "CRITICAL", "Tautological assertion detected", node.lineno
                )
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
                TestQualityFinding(
                    "QA003", "CRITICAL", "Test has no observable assertion", function.lineno
                )
            )
    return findings
