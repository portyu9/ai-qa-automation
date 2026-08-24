from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.journal import RunJournal


@pytest.mark.parametrize("sequence", [True, 1.0])
def test_run_journal_rejects_hash_valid_non_integer_sequence_authority(
    tmp_path: Path,
    sequence: object,
) -> None:
    journal_path = tmp_path / "journal.jsonl"
    body = {
        "seq": sequence,
        "timestamp": "2026-08-24T00:00:00+00:00",
        "event": "coercive-sequence",
        "payload": {},
        "prev_hash": None,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    record_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    journal_path.write_text(
        json.dumps({**body, "record_hash": record_hash}, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="hash-chain verification"):
        RunJournal(journal_path)
