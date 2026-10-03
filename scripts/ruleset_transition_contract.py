from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TRANSITION_PATH = ROOT / ".github" / "rulesets" / "ruleset-transitions-v1.json"
DESIRED_PATH = ROOT / ".github" / "rulesets" / "repository-rulesets-v1.json"
DRIFT_WITNESS_PATH = ROOT / ".github" / "rulesets" / "ruleset-drift-witness-v1.json"

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_REPOSITORY_ID = 1341984495
EXPECTED_RULESET_ID = 21201916
EXPECTED_RULESET_NAME = "Protect Main"
EXPECTED_METHOD = "PUT"
EXPECTED_ENDPOINT = "repos/portyu9/ai-qa-automation/rulesets/21201916"
EXPECTED_STATUS_CONTEXT = "Trusted PR Gate"
EXPECTED_STATUS_INTEGRATION_ID = 4766700
EXPECTED_RULE_TYPES = (
    "deletion",
    "non_fast_forward",
    "pull_request",
    "required_status_checks",
)
MAX_JSON_BYTES = 256 * 1024
SHA256_RE_PREFIX = "sha256:"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode), f"{path.name} must be a regular non-symlink file")
    require(0 < info.st_size <= MAX_JSON_BYTES, f"{path.name} is outside bounded size")
    fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(fd)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_JSON_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_JSON_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    require(
        len(payload) == before.st_size and len(payload) <= MAX_JSON_BYTES,
        f"{path.name} changed or is oversized",
    )
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        f"{path.name} changed during ingestion",
    )
    try:
        return json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} is not strict UTF-8 JSON") from exc


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return SHA256_RE_PREFIX + hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_sha256(value: Any, *, label: str) -> str:
    require(isinstance(value, str), f"{label} must be a string")
    require(
        len(value) == 71
        and value.startswith(SHA256_RE_PREFIX)
        and all(ch in "0123456789abcdef" for ch in value[len(SHA256_RE_PREFIX) :]),
        f"{label} must be canonical sha256:<64 lowercase hex>",
    )
    return value


def require_positive_int(value: Any, *, label: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value > 0,
        f"{label} must be a positive integer",
    )
    return value


def require_exact_keys(value: Any, expected: set[str], *, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == expected, f"{label} fields are not exact")
    return value


def _validate_status_checks(
    rule: dict[str, Any], *, expected_entries: list[dict[str, Any]]
) -> None:
    require_exact_keys(rule, {"type", "parameters"}, label="required-status rule")
    require(rule["type"] == "required_status_checks", "required-status rule type drifted")
    params = require_exact_keys(
        rule["parameters"],
        {
            "strict_required_status_checks_policy",
            "do_not_enforce_on_create",
            "required_status_checks",
        },
        label="required-status parameters",
    )
    require(
        params["strict_required_status_checks_policy"] is True,
        "strict required-status policy must remain enabled",
    )
    require(
        params["do_not_enforce_on_create"] is False,
        "required statuses must remain enforced on create",
    )
    rows = params["required_status_checks"]
    require(isinstance(rows, list), "required status list must be an array")
    require(rows == expected_entries, "required status list differs from exact reviewed state")


def validate_state(
    state: Any, *, expected_entries: list[dict[str, Any]], label: str
) -> dict[str, Any]:
    state = require_exact_keys(
        state,
        {"name", "target", "enforcement", "bypass_actors", "conditions", "rules"},
        label=label,
    )
    require(state["name"] == EXPECTED_RULESET_NAME, f"{label} ruleset name drifted")
    require(state["target"] == "branch", f"{label} target must remain branch")
    require(state["enforcement"] == "active", f"{label} enforcement must remain active")
    require(state["bypass_actors"] == [], f"{label} bypass actors must remain empty")
    require(
        state["conditions"] == {"ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]}},
        f"{label} branch condition drifted",
    )
    rules = state["rules"]
    require(
        isinstance(rules, list) and len(rules) == 4,
        f"{label} must contain exactly four rules",
    )
    require(rules[0] == {"type": "deletion"}, f"{label} deletion rule drifted")
    require(
        rules[1] == {"type": "non_fast_forward"},
        f"{label} non-fast-forward rule drifted",
    )
    pr = require_exact_keys(rules[2], {"type", "parameters"}, label=f"{label} pull-request rule")
    require(pr["type"] == "pull_request", f"{label} pull-request rule type drifted")
    expected_pr = {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": False,
        "required_reviewers": [],
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_review_thread_resolution": True,
        "require_extra_approval_for_unattributed_changes": False,
        "allowed_merge_methods": ["merge"],
    }
    require(pr["parameters"] == expected_pr, f"{label} pull-request parameters drifted")
    _validate_status_checks(rules[3], expected_entries=expected_entries)
    return state


def load_contract() -> dict[str, Any]:
    raw = require_exact_keys(
        load_json(TRANSITION_PATH),
        {
            "schemaVersion",
            "repository",
            "repositoryId",
            "rulesetId",
            "rulesetName",
            "method",
            "endpoint",
            "predecessorDigest",
            "successorDigest",
            "predecessor",
            "successor",
            "transitionDigest",
        },
        label="ruleset transition contract",
    )
    require(
        raw["schemaVersion"] == 1 and not isinstance(raw["schemaVersion"], bool),
        "transition schemaVersion must be integer 1",
    )
    require(raw["repository"] == EXPECTED_REPOSITORY, "transition repository drifted")
    require_positive_int(raw["repositoryId"], label="transition repository id")
    require(
        raw["repositoryId"] == EXPECTED_REPOSITORY_ID,
        "transition repository id drifted",
    )
    require_positive_int(raw["rulesetId"], label="transition ruleset id")
    require(raw["rulesetId"] == EXPECTED_RULESET_ID, "transition ruleset id drifted")
    require(raw["rulesetName"] == EXPECTED_RULESET_NAME, "transition ruleset name drifted")
    require(raw["method"] == EXPECTED_METHOD, "transition method must remain PUT")
    require(raw["endpoint"] == EXPECTED_ENDPOINT, "transition endpoint drifted")
    predecessor = validate_state(raw["predecessor"], expected_entries=[], label="predecessor")
    successor = validate_state(
        raw["successor"],
        expected_entries=[
            {
                "context": EXPECTED_STATUS_CONTEXT,
                "integration_id": EXPECTED_STATUS_INTEGRATION_ID,
            }
        ],
        label="successor",
    )
    require_sha256(raw["predecessorDigest"], label="predecessor digest")
    require_sha256(raw["successorDigest"], label="successor digest")
    require_sha256(raw["transitionDigest"], label="transition digest")
    require(
        raw["predecessorDigest"] == digest(predecessor),
        "predecessor digest mismatch",
    )
    require(raw["successorDigest"] == digest(successor), "successor digest mismatch")
    without_transition_digest = dict(raw)
    without_transition_digest.pop("transitionDigest")
    require(
        raw["transitionDigest"] == digest(without_transition_digest),
        "transition digest mismatch",
    )

    desired = require_exact_keys(
        load_json(DESIRED_PATH),
        {
            "schemaVersion",
            "repository",
            "repositoryId",
            "rulesetId",
            "rulesetName",
            "desiredDigest",
            "desired",
        },
        label="desired ruleset contract",
    )
    require(
        desired["schemaVersion"] == 1 and not isinstance(desired["schemaVersion"], bool),
        "desired schemaVersion must be integer 1",
    )
    require(desired["repository"] == EXPECTED_REPOSITORY, "desired repository drifted")
    require(
        desired["repositoryId"] == EXPECTED_REPOSITORY_ID,
        "desired repository id drifted",
    )
    require(desired["rulesetId"] == EXPECTED_RULESET_ID, "desired ruleset id drifted")
    require(desired["rulesetName"] == EXPECTED_RULESET_NAME, "desired ruleset name drifted")
    validate_state(
        desired["desired"],
        expected_entries=[
            {
                "context": EXPECTED_STATUS_CONTEXT,
                "integration_id": EXPECTED_STATUS_INTEGRATION_ID,
            }
        ],
        label="desired",
    )
    require(
        desired["desired"] == successor,
        "desired ruleset differs from transition successor",
    )
    require(
        desired["desiredDigest"] == raw["successorDigest"],
        "desired digest differs from successor digest",
    )
    return raw


def _canonicalize_live_rules(rules: Any) -> list[dict[str, Any]]:
    require(
        isinstance(rules, list) and len(rules) == len(EXPECTED_RULE_TYPES),
        "live ruleset rule inventory changed",
    )
    by_type: dict[str, dict[str, Any]] = {}
    for rule in rules:
        require(isinstance(rule, dict), "live ruleset rule must be an object")
        rule_type = rule.get("type")
        require(
            isinstance(rule_type, str) and rule_type in EXPECTED_RULE_TYPES,
            "live ruleset rule type is outside the reviewed inventory",
        )
        require(rule_type not in by_type, "live ruleset contains duplicate rule types")
        by_type[rule_type] = rule
    require(
        set(by_type) == set(EXPECTED_RULE_TYPES),
        "live ruleset rule inventory changed",
    )

    canonical = [json.loads(json.dumps(by_type[rule_type])) for rule_type in EXPECTED_RULE_TYPES]
    status = canonical[-1]
    parameters = status.get("parameters")
    if isinstance(parameters, dict):
        checks = parameters.get("required_status_checks")
        if isinstance(checks, list):
            parameters["required_status_checks"] = sorted(
                checks,
                key=canonical_bytes,
            )
    return canonical


def _validate_live_identity(raw: Any) -> dict[str, Any]:
    require(isinstance(raw, dict), "live ruleset response must be an object")
    require_positive_int(raw.get("id"), label="live ruleset id")
    require(raw["id"] == EXPECTED_RULESET_ID, "live ruleset id drifted")
    require(raw.get("name") == EXPECTED_RULESET_NAME, "live ruleset name drifted")
    require(raw.get("target") == "branch", "live ruleset target drifted")
    require(raw.get("source_type") == "Repository", "live ruleset source type drifted")
    require(raw.get("source") == EXPECTED_REPOSITORY, "live ruleset source drifted")
    return raw


def normalize_live(raw: Any) -> dict[str, Any]:
    raw = _validate_live_identity(raw)
    require("bypass_actors" in raw, "live bypass actors are not observable")
    require(isinstance(raw["bypass_actors"], list), "live bypass actors must be an array")
    return {
        "name": raw.get("name"),
        "target": raw.get("target"),
        "enforcement": raw.get("enforcement"),
        "bypass_actors": raw["bypass_actors"],
        "conditions": raw.get("conditions"),
        "rules": _canonicalize_live_rules(raw.get("rules")),
    }


def classify_live(raw: Any, contract: dict[str, Any]) -> str:
    live = normalize_live(raw)
    observed = digest(live)
    if observed == contract["predecessorDigest"] and live == contract["predecessor"]:
        return "predecessor"
    if observed == contract["successorDigest"] and live == contract["successor"]:
        return "successor"
    raise ValueError(f"live ruleset is neither exact predecessor nor successor: {observed}")


def classify_live_observable(raw: Any, contract: dict[str, Any]) -> str:
    """Return only a non-authoritative state hint for read-only planning.

    GitHub may redact bypass_actors from a contents-read workflow token. A missing
    or null bypass list may therefore be projected to the reviewed empty value only
    to decide whether the separately credentialed administration job should run.
    That job must still perform classify_live() with its administration-scoped App
    token immediately before mutation; projected state never authorizes a PUT.
    """

    raw = _validate_live_identity(raw)
    bypass = raw.get("bypass_actors")
    if isinstance(bypass, list):
        return classify_live(raw, contract)
    require(
        "bypass_actors" not in raw or bypass is None,
        "live bypass actor observability shape is invalid",
    )
    projected = dict(raw)
    projected["bypass_actors"] = []
    return classify_live(projected, contract)


def validate_drift_witness(raw: Any, contract: dict[str, Any]) -> dict[str, Any]:
    witness = require_exact_keys(
        raw,
        {
            "schemaVersion",
            "repository",
            "repositoryId",
            "rulesetId",
            "rulesetName",
            "rulesetNodeId",
            "createdAt",
            "updatedAt",
            "successorDigest",
            "transitionDigest",
            "bypassActors",
            "requiredStatus",
            "certification",
        },
        label="ruleset drift witness",
    )
    require(witness["schemaVersion"] == 1, "ruleset drift witness schema version drifted")
    require(
        witness["repository"] == EXPECTED_REPOSITORY,
        "ruleset drift witness repository drifted",
    )
    require(
        witness["repositoryId"] == EXPECTED_REPOSITORY_ID,
        "ruleset drift witness repository id drifted",
    )
    require(witness["rulesetId"] == EXPECTED_RULESET_ID, "ruleset drift witness ruleset id drifted")
    require(
        witness["rulesetName"] == EXPECTED_RULESET_NAME,
        "ruleset drift witness ruleset name drifted",
    )
    require(
        isinstance(witness["rulesetNodeId"], str) and witness["rulesetNodeId"].startswith("RRS_"),
        "ruleset drift witness node id is malformed",
    )
    for key in ("createdAt", "updatedAt"):
        require(
            isinstance(witness[key], str)
            and "T" in witness[key]
            and (witness[key].endswith("Z") or "+00:00" in witness[key]),
            f"ruleset drift witness {key} is malformed",
        )
    require(
        witness["successorDigest"] == contract["successorDigest"],
        "ruleset drift witness successor digest drifted",
    )
    require(
        witness["transitionDigest"] == contract["transitionDigest"],
        "ruleset drift witness transition digest drifted",
    )
    require(witness["bypassActors"] == [], "ruleset drift witness bypass actors must be empty")
    require(
        witness["requiredStatus"]
        == {
            "context": EXPECTED_STATUS_CONTEXT,
            "integrationId": EXPECTED_STATUS_INTEGRATION_ID,
        },
        "ruleset drift witness required status drifted",
    )
    certification = require_exact_keys(
        witness["certification"],
        {
            "reconcilerRunId",
            "reconcilerArtifactId",
            "reconcilerArtifactDigest",
            "reconcilerReceiptDigest",
            "trustedMainSha",
        },
        label="ruleset drift witness certification",
    )
    require_positive_int(certification["reconcilerRunId"], label="witness reconciler run id")
    require_positive_int(
        certification["reconcilerArtifactId"],
        label="witness reconciler artifact id",
    )
    require_sha256(
        certification["reconcilerArtifactDigest"],
        label="witness reconciler artifact digest",
    )
    require_sha256(
        certification["reconcilerReceiptDigest"],
        label="witness reconciler receipt digest",
    )
    trusted_main_sha = certification["trustedMainSha"]
    require(
        isinstance(trusted_main_sha, str)
        and len(trusted_main_sha) == 40
        and all(ch in "0123456789abcdef" for ch in trusted_main_sha),
        "ruleset drift witness trusted main SHA is malformed",
    )
    return witness


def require_witnessed_successor(
    raw: Any,
    contract: dict[str, Any],
    witness: Any,
) -> str:
    witness = validate_drift_witness(witness, contract)
    raw = _validate_live_identity(raw)
    require(
        classify_live_observable(raw, contract) == "successor",
        "live observable ruleset is not the exact successor projection",
    )
    require(raw.get("node_id") == witness["rulesetNodeId"], "live ruleset node id drifted")
    require(raw.get("created_at") == witness["createdAt"], "live ruleset created_at drifted")
    require(
        raw.get("updated_at") == witness["updatedAt"],
        "live ruleset revision changed after exact full-state certification",
    )
    require(
        raw.get("current_user_can_bypass") == "never",
        "read-only sentinel unexpectedly has ruleset bypass authority",
    )
    return contract["successorDigest"]


def emit_put(contract: dict[str, Any], path: Path) -> None:
    require(path.is_absolute(), "PUT output path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(contract["successor"]) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        written = os.write(fd, payload)
        require(written == len(payload), "PUT payload write was incomplete")
        os.fsync(fd)
    finally:
        os.close(fd)


def write_receipt(
    *,
    contract: dict[str, Any],
    before: Any,
    after: Any,
    trusted_main_sha: str,
    run_id: int,
    run_attempt: int,
    write_exit_code: int,
    output: Path,
) -> str:
    require(
        isinstance(trusted_main_sha, str)
        and len(trusted_main_sha) == 40
        and all(ch in "0123456789abcdef" for ch in trusted_main_sha),
        "trusted main SHA is malformed",
    )
    require_positive_int(run_id, label="run id")
    require_positive_int(run_attempt, label="run attempt")
    require(
        isinstance(write_exit_code, int)
        and not isinstance(write_exit_code, bool)
        and 0 <= write_exit_code <= 255,
        "write exit code is malformed",
    )
    before_state = classify_live(before, contract)
    after_state = classify_live(after, contract)
    require(before_state == "predecessor", "receipt before-state must be exact predecessor")
    require(after_state == "successor", "receipt after-state must be exact successor")
    receipt = {
        "schemaVersion": 1,
        "repository": EXPECTED_REPOSITORY,
        "repositoryId": EXPECTED_REPOSITORY_ID,
        "rulesetId": EXPECTED_RULESET_ID,
        "rulesetName": EXPECTED_RULESET_NAME,
        "transitionDigest": contract["transitionDigest"],
        "predecessorDigest": contract["predecessorDigest"],
        "successorDigest": contract["successorDigest"],
        "trustedMainSha": trusted_main_sha,
        "runId": run_id,
        "runAttempt": run_attempt,
        "writeExitCode": write_exit_code,
        "outcome": ("applied" if write_exit_code == 0 else "ambiguous-response-readback-applied"),
    }
    receipt_digest = digest(receipt)
    wrapper = {"receipt": receipt, "receiptDigest": receipt_digest}
    require(output.is_absolute(), "receipt output path must be absolute")
    data = json.dumps(wrapper, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(output, flags, 0o600)
    try:
        require(os.write(fd, data) == len(data), "receipt write was incomplete")
        os.fsync(fd)
    finally:
        os.close(fd)
    return receipt_digest


def self_test() -> None:
    contract = load_contract()
    predecessor = {
        "id": EXPECTED_RULESET_ID,
        "name": EXPECTED_RULESET_NAME,
        "target": "branch",
        "source_type": "Repository",
        "source": EXPECTED_REPOSITORY,
        **json.loads(json.dumps(contract["predecessor"])),
    }
    successor = {
        "id": EXPECTED_RULESET_ID,
        "name": EXPECTED_RULESET_NAME,
        "target": "branch",
        "source_type": "Repository",
        "source": EXPECTED_REPOSITORY,
        **json.loads(json.dumps(contract["successor"])),
    }
    require(
        classify_live(predecessor, contract) == "predecessor",
        "predecessor fixture failed",
    )
    require(
        classify_live(successor, contract) == "successor",
        "successor fixture failed",
    )

    reordered = json.loads(json.dumps(successor))
    reordered["rules"].reverse()
    require(
        classify_live(reordered, contract) == "successor",
        "semantic live rule ordering was treated as authority",
    )

    redacted = json.loads(json.dumps(predecessor))
    redacted.pop("bypass_actors")
    require(
        classify_live_observable(redacted, contract) == "predecessor",
        "redacted predecessor planning hint failed",
    )
    redacted_successor = json.loads(json.dumps(successor))
    redacted_successor["bypass_actors"] = None
    require(
        classify_live_observable(redacted_successor, contract) == "successor",
        "redacted successor planning hint failed",
    )

    witness = validate_drift_witness(load_json(DRIFT_WITNESS_PATH), contract)
    witnessed = json.loads(json.dumps(successor))
    witnessed.update(
        {
            "node_id": witness["rulesetNodeId"],
            "created_at": witness["createdAt"],
            "updated_at": witness["updatedAt"],
            "current_user_can_bypass": "never",
        }
    )
    witnessed.pop("bypass_actors")
    require(
        require_witnessed_successor(witnessed, contract, witness) == contract["successorDigest"],
        "redacted witnessed successor failed",
    )
    drifted_witnessed = json.loads(json.dumps(witnessed))
    drifted_witnessed["updated_at"] = "2099-01-01T00:00:00Z"
    try:
        require_witnessed_successor(drifted_witnessed, contract, witness)
    except ValueError:
        pass
    else:
        raise ValueError("ruleset self-test accepted revision drift after certification")

    duplicated = json.loads(json.dumps(predecessor))
    duplicated["rules"][1] = json.loads(json.dumps(duplicated["rules"][0]))
    try:
        classify_live(duplicated, contract)
    except ValueError:
        pass
    else:
        raise ValueError("ruleset self-test accepted duplicate live rule identity")

    mutated = json.loads(json.dumps(successor))
    mutated["rules"][-1]["parameters"]["required_status_checks"][0]["integration_id"] = 15368
    try:
        classify_live(mutated, contract)
    except ValueError:
        pass
    else:
        raise ValueError("ruleset self-test accepted wrong status integration identity")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--transition-digest")

    classify = sub.add_parser("classify")
    classify.add_argument("--live", required=True, type=Path)

    classify_observable = sub.add_parser("classify-observable")
    classify_observable.add_argument("--live", required=True, type=Path)

    emit = sub.add_parser("emit-put")
    emit.add_argument("--output", required=True, type=Path)

    require_successor = sub.add_parser("require-successor")
    require_successor.add_argument("--live", required=True, type=Path)

    require_witnessed = sub.add_parser("require-witnessed-successor")
    require_witnessed.add_argument("--live", required=True, type=Path)
    require_witnessed.add_argument("--witness", required=True, type=Path)

    receipt = sub.add_parser("receipt")
    receipt.add_argument("--before", required=True, type=Path)
    receipt.add_argument("--after", required=True, type=Path)
    receipt.add_argument("--trusted-main-sha", required=True)
    receipt.add_argument("--run-id", required=True, type=int)
    receipt.add_argument("--run-attempt", required=True, type=int)
    receipt.add_argument("--write-exit-code", required=True, type=int)
    receipt.add_argument("--output", required=True, type=Path)

    sub.add_parser("self-test")
    args = parser.parse_args()

    try:
        contract = load_contract()
        if args.command == "validate":
            if args.transition_digest is not None:
                require(
                    args.transition_digest == contract["transitionDigest"],
                    "requested transition digest differs from reviewed contract",
                )
            print(contract["transitionDigest"])
        elif args.command == "classify":
            print(classify_live(load_json(args.live), contract))
        elif args.command == "classify-observable":
            print(classify_live_observable(load_json(args.live), contract))
        elif args.command == "emit-put":
            emit_put(contract, args.output.resolve())
        elif args.command == "require-successor":
            require(
                classify_live(load_json(args.live), contract) == "successor",
                "live ruleset is not exact desired successor",
            )
            print(contract["successorDigest"])
        elif args.command == "require-witnessed-successor":
            print(
                require_witnessed_successor(
                    load_json(args.live),
                    contract,
                    load_json(args.witness),
                )
            )
        elif args.command == "receipt":
            print(
                write_receipt(
                    contract=contract,
                    before=load_json(args.before),
                    after=load_json(args.after),
                    trusted_main_sha=args.trusted_main_sha,
                    run_id=args.run_id,
                    run_attempt=args.run_attempt,
                    write_exit_code=args.write_exit_code,
                    output=args.output.resolve(),
                )
            )
        elif args.command == "self-test":
            self_test()
            print("Ruleset transition contract self-test passed")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
