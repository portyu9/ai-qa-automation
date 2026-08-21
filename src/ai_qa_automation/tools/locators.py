from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class LocatorSpec:
    strategy: str
    value: str | None = None
    role: str | None = None
    name: str | None = None


_QUOTED = r"(?P<q>['\"])(?P<value>[^'\"\n]{1,500})(?P=q)"

_SIMPLE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "test_id",
        re.compile(rf"^(?:page\.)?(?:get_by_test_id|getByTestId)\(\s*{_QUOTED}\s*\)$"),
    ),
    (
        "label",
        re.compile(rf"^(?:page\.)?(?:get_by_label|getByLabel)\(\s*{_QUOTED}\s*\)$"),
    ),
    (
        "placeholder",
        re.compile(
            rf"^(?:page\.)?(?:get_by_placeholder|getByPlaceholder)\(\s*{_QUOTED}\s*\)$"
        ),
    ),
    (
        "exact_text",
        re.compile(
            rf"^(?:page\.)?(?:get_by_text|getByText)\(\s*{_QUOTED}(?:\s*,\s*(?:exact\s*=\s*True|\{{\s*exact\s*:\s*true\s*\}}))?\s*\)$"
        ),
    ),
    (
        "semantic_css",
        re.compile(rf"^(?:page\.)?locator\(\s*{_QUOTED}\s*\)$"),
    ),
)

_PY_ROLE = re.compile(
    r"^(?:page\.)?get_by_role\(\s*(?P<rq>['\"])(?P<role>[^'\"\n]{1,100})(?P=rq)\s*,\s*"
    r"name\s*=\s*(?P<nq>['\"])(?P<name>[^'\"\n]{1,500})(?P=nq)"
    r"(?:\s*,\s*exact\s*=\s*True)?\s*\)$"
)
_JS_ROLE = re.compile(
    r"^(?:page\.)?getByRole\(\s*(?P<rq>['\"])(?P<role>[^'\"\n]{1,100})(?P=rq)\s*,\s*\{\s*"
    r"name\s*:\s*(?P<nq>['\"])(?P<name>[^'\"\n]{1,500})(?P=nq)"
    r"(?:\s*,\s*exact\s*:\s*true)?\s*\}\s*\)$"
)


def parse_locator_expression(expression: str) -> LocatorSpec | None:
    """Parse a deliberately small, non-executable Playwright locator subset."""
    text = expression.strip()
    if not text or "\n" in text or len(text) > 1_000:
        return None
    for strategy, pattern in _SIMPLE_PATTERNS:
        match = pattern.fullmatch(text)
        if match:
            return LocatorSpec(strategy=strategy, value=match.group("value"))
    for pattern in (_PY_ROLE, _JS_ROLE):
        match = pattern.fullmatch(text)
        if match:
            return LocatorSpec(
                strategy="role_name",
                role=match.group("role"),
                name=match.group("name"),
            )
    return None
