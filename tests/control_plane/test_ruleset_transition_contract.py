from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import ruleset_transition_contract as contract


def _live(state: dict[str, object]) -> dict[str, object]:
    return {
        "id": contract.EXPECTED_RULESET_ID,
        "name": contract.EXPECTED_RULESET_NAME,
        "target": "branch",
        "source_type": "Repository",
        "source": contract.EXPECTED_REPOSITORY,
        **json.loads(json.dumps(state)),
    }


def test_ruleset_transition_contract_binds_exact_live_predecessor_and_successor() -> None:
    reviewed = contract.load_contract()
    assert contract.classify_live(_live(reviewed["predecessor"]), reviewed) == "predecessor"
    assert contract.classify_live(_live(reviewed["successor"]), reviewed) == "successor"
    assert reviewed["successor"]["rules"][-1]["parameters"]["required_status_checks"] == [
        {
            "context": contract.EXPECTED_STATUS_CONTEXT,
            "integration_id": contract.EXPECTED_STATUS_INTEGRATION_ID,
        }
    ]


def test_ruleset_transition_live_rule_order_is_semantic_not_authority() -> None:
    reviewed = contract.load_contract()
    live = _live(reviewed["successor"])
    live["rules"].reverse()

    assert contract.classify_live(live, reviewed) == "successor"


def test_ruleset_transition_observable_plan_accepts_redacted_bypass_only_as_hint() -> None:
    reviewed = contract.load_contract()
    predecessor = _live(reviewed["predecessor"])
    predecessor.pop("bypass_actors")
    successor = _live(reviewed["successor"])
    successor["bypass_actors"] = None

    assert contract.classify_live_observable(predecessor, reviewed) == "predecessor"
    assert contract.classify_live_observable(successor, reviewed) == "successor"
    with pytest.raises(ValueError, match="not observable"):
        contract.classify_live(predecessor, reviewed)


def test_ruleset_transition_observable_plan_rejects_visible_bypass_actor() -> None:
    reviewed = contract.load_contract()
    live = _live(reviewed["predecessor"])
    live["bypass_actors"] = [
        {"actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"}
    ]

    with pytest.raises(ValueError, match="neither exact predecessor nor successor"):
        contract.classify_live_observable(live, reviewed)


def test_ruleset_transition_rejects_duplicate_live_rule_identity() -> None:
    reviewed = contract.load_contract()
    live = _live(reviewed["predecessor"])
    live["rules"][1] = json.loads(json.dumps(live["rules"][0]))

    with pytest.raises(ValueError, match="duplicate rule types"):
        contract.classify_live(live, reviewed)


def test_ruleset_transition_rejects_status_writer_identity_drift() -> None:
    reviewed = contract.load_contract()
    live = _live(reviewed["successor"])
    live["rules"][-1]["parameters"]["required_status_checks"][0]["integration_id"] = 15368
    with pytest.raises(ValueError, match="neither exact predecessor nor successor"):
        contract.classify_live(live, reviewed)


def test_ruleset_transition_rejects_bypass_actor_drift() -> None:
    reviewed = contract.load_contract()
    live = _live(reviewed["successor"])
    live["bypass_actors"] = [
        {"actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"}
    ]
    with pytest.raises(ValueError, match="neither exact predecessor nor successor"):
        contract.classify_live(live, reviewed)


def test_ruleset_transition_emit_put_is_exact_successor(tmp_path: Path) -> None:
    reviewed = contract.load_contract()
    output = tmp_path / "ruleset-put.json"
    contract.emit_put(reviewed, output)
    assert json.loads(output.read_text(encoding="utf-8")) == reviewed["successor"]


def test_ruleset_transition_receipt_accepts_ambiguous_write_only_after_successor_readback(
    tmp_path: Path,
) -> None:
    reviewed = contract.load_contract()
    output = tmp_path / "receipt.json"
    digest = contract.write_receipt(
        contract=reviewed,
        before=_live(reviewed["predecessor"]),
        after=_live(reviewed["successor"]),
        trusted_main_sha="a" * 40,
        run_id=123,
        run_attempt=1,
        write_exit_code=1,
        output=output,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert digest == payload["receiptDigest"]
    assert payload["receipt"]["outcome"] == "ambiguous-response-readback-applied"
    assert payload["receipt"]["writeExitCode"] == 1


def test_ruleset_transition_receipt_rejects_missing_successor_readback(
    tmp_path: Path,
) -> None:
    reviewed = contract.load_contract()
    with pytest.raises(ValueError, match="receipt after-state must be exact successor"):
        contract.write_receipt(
            contract=reviewed,
            before=_live(reviewed["predecessor"]),
            after=_live(reviewed["predecessor"]),
            trusted_main_sha="b" * 40,
            run_id=123,
            run_attempt=1,
            write_exit_code=1,
            output=tmp_path / "receipt.json",
        )


def test_ruleset_transition_strict_json_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"id":1,"id":2}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate object key"):
        contract.load_json(path)
