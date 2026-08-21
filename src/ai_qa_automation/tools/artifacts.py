from __future__ import annotations

from pathlib import Path

from ..evidence import EvidenceStore
from ..models import SanitizationStatus


def text_artifact(
    store: EvidenceStore,
    relative_path: str,
    text: str,
    *,
    originating_tool: str,
) -> tuple[str, str]:
    return store.register_artifact(
        relative_path=relative_path,
        content=text.encode("utf-8"),
        originating_tool=originating_tool,
        sanitization_status=SanitizationStatus.SANITIZED,
    )


def assert_inside(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError("path escapes artifact root")
    return resolved
