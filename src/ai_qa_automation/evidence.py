from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import EvidenceItem, SanitizationStatus
from .redaction import sanitize


class EvidenceStore:
    """Append-only evidence registry with content hashing and per-run manifests."""

    def __init__(self, root: Path, run_id: str) -> None:
        self.run_id = run_id
        self.run_root = (root / run_id).resolve()
        self.run_root.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, EvidenceItem] = {}

    @staticmethod
    def hash_bytes(content: bytes) -> str:
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    def add(self, item: EvidenceItem) -> EvidenceItem:
        if item.run_id != self.run_id:
            raise ValueError("evidence run_id does not match store")
        safe_payload = sanitize(item.model_dump(mode="json"))
        safe_item = EvidenceItem.model_validate(safe_payload)
        self._items[safe_item.id] = safe_item
        self._flush_manifest()
        return safe_item

    def register_artifact(
        self,
        *,
        relative_path: str,
        content: bytes,
        originating_tool: str,
    ) -> tuple[str, str]:
        destination = (self.run_root / relative_path).resolve()
        if self.run_root not in destination.parents and destination != self.run_root:
            raise ValueError("artifact path escapes run root")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        digest = self.hash_bytes(content)
        return str(destination), digest

    def get(self, evidence_id: str) -> EvidenceItem:
        return self._items[evidence_id]

    def all(self) -> list[EvidenceItem]:
        return list(self._items.values())

    def _flush_manifest(self) -> None:
        path = self.run_root / "evidence-manifest.json"
        data: dict[str, Any] = {
            "run_id": self.run_id,
            "evidence": [item.model_dump(mode="json") for item in self._items.values()],
            "sanitization_status": SanitizationStatus.SANITIZED,
        }
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
