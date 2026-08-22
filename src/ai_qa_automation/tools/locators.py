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
            rf"^(?:page\.)?(?:get_by_text|getByText)\(\s*{_QUOTED}\s*,\s*(?:exact\s*=\s*True|\{{\s*exact\s*:\s*true\s*\}})\s*\)$"
        ),
    ),
    (
        "text",
        re.compile(rf"^(?:page\.)?(?:get_by_text|getByText)\(\s*{_QUOTED}\s*\)$"),
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
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_TOKEN = re.compile(r"[a-z0-9]+")
_SEMANTIC_NOISE = {
    "data",
    "test",
    "testid",
    "id",
    "css",
    "locator",
    "get",
    "by",
    "exact",
}


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


def locator_semantic_tokens(spec: LocatorSpec) -> frozenset[str]:
    """Extract conservative lexical intent tokens from a supported locator."""

    raw_parts = [part for part in (spec.value, spec.role, spec.name) if part]
    rendered = " ".join(_CAMEL_BOUNDARY.sub(" ", part) for part in raw_parts).casefold()
    return frozenset(token for token in _TOKEN.findall(rendered) if token not in _SEMANTIC_NOISE)


def deterministic_locator_semantic_score(original: LocatorSpec, candidate: LocatorSpec) -> float:
    """Score lexical intent overlap without trusting a model-supplied confidence value.

    This score is intentionally conservative. A unique locator is not enough for
    autonomous repair: the replacement must also retain recognizable semantic
    intent from the original locator. Low-overlap changes remain available for
    human review rather than being promoted automatically.
    """

    original_tokens = locator_semantic_tokens(original)
    candidate_tokens = locator_semantic_tokens(candidate)
    if not original_tokens or not candidate_tokens:
        return 0.0
    intersection = original_tokens & candidate_tokens
    if not intersection:
        return 0.0
    containment = len(intersection) / min(len(original_tokens), len(candidate_tokens))
    jaccard = len(intersection) / len(original_tokens | candidate_tokens)
    score = (containment * 0.7) + (jaccard * 0.3)
    if original.strategy == candidate.strategy:
        score = min(1.0, score + 0.05)
    return round(score, 4)
