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

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_REPOSITORY_ID = 1341984495
EXPECTED_RULESET_ID = 21201916
EXPECTED_RULESET_NAME = "Protect Main"
EXPECTED_METHOD = "PUT"
EXPECTED_ENDPOINT = "repos/portyu9/ai-qa-automation/rulesets/21201916"
EXPECTED_STATUS_CONTEXT = "Trusted PR Gate"
EXPECTED_STATUS_INTEGRATION_ID = 4766700
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
        state["conditions"]
        == {"ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]}},
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
    pr = require_exact_keys(
        rules[2], {"type", "parameters"}, label=f"{label} pull-request rule"
    )
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
    predecessor = validate_state(
        raw["predecessor"], expected_entries=[], label="predecessor"
    )
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


def normalize_live(raw: Any) -> dict[str, Any]:
    require(isinstance(raw, dict), "live ruleset response must be an object")
    require_positive_int(raw.get("id"), label="live ruleset id")
    require(raw["id"] == EXPECTED_RULESET_ID, "live ruleset id drifted")
    require(raw.get("name") == EXPECTED_RULESET_NAME, "live ruleset name drifted")
    require(raw.get("target") == "branch", "live ruleset target drifted")
    require(raw.get("source_type") == "Repository", "live ruleset source type drifted")
    require(raw.get("source") == EXPECTED_REPOSITORY, "live ruleset source drifted")
    require("bypass_actors" in raw, "live bypass actors are not observable")
    return {
        "name": raw.get("name"),
        "target": raw.get("target"),
        "enforcement": raw.get("enforcement"),
        "bypass_actors": raw.get("bypass_actors"),
        "conditions": raw.get("conditions"),
        "rules": raw.get("rules"),
    }


def classify_live(raw: Any, contract: dict[str, Any]) -> str:
    live = normalize_live(raw)
    observed = digest(live)
    if observed == contract["predecessorDigest"] and live == contract["predecessor"]:
        return "predecessor"
    if observed == contract["successorDigest"] and live == contract["successor"]:
        return "successor"
    raise ValueError(
        f"live ruleset is neither exact predecessor nor successor: {observed}"
    )


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
        "outcome": (
            "applied"
            if write_exit_code == 0
            else "ambiguous-response-readback-applied"
        ),
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
    require(
        classify_live(
            {
                "id": EXPECTED_RULESET_ID,
                "name": EXPECTED_RULESET_NAME,
                "target": "branch",
                "source_type": "Repository",
                "source": EXPECTED_REPOSITORY,
                **contract["predecessor"],
            },
            contract,
        )
        == "predecessor",
        "predecessor fixture failed",
    )
    require(
        classify_live(
            {
                "id": EXPECTED_RULESET_ID,
                "name": EXPECTED_RULESET_NAME,
                "target": "branch",
                "source_type": "Repository",
                "source": EXPECTED_REPOSITORY,
                **contract["successor"],
            },
            contract,
        )
        == "successor",
        "successor fixture failed",
    )
    mutated = json.loads(json.dumps(contract["successor"]))
    mutated["rules"][-1]["parameters"]["required_status_checks"][0][
        "integration_id"
    ] = 15368
    try:
        classify_live(
            {
                "id": EXPECTED_RULESET_ID,
                "source_type": "Repository",
                "source": EXPECTED_REPOSITORY,
                **mutated,
            },
            contract,
        )
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

    emit = sub.add_parser("emit-put")
    emit.add_argument("--output", required=True, type=Path)

    require_successor = sub.add_parser("require-successor")
    require_successor.add_argument("--live", required=True, type=Path)

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
        elif args.command == "emit-put":
            emit_put(contract, args.output.resolve())
        elif args.command == "require-successor":
            require(
                classify_live(load_json(args.live), contract) == "successor",
                "live ruleset is not exact desired successor",
            )
            print(contract["successorDigest"])
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
