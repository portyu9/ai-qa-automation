from __future__ import annotations

import argparse
import importlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_DIR = ROOT / ".github" / "scripts"
EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
LANES = {"dependabot-actions", "dependency-promotion", "security-autoheal"}
MODES = {"full", "terminal"}


def _require_sha(value: str, label: str) -> str:
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{label} must be a canonical lowercase SHA-1")
    return value


def _load_controllers() -> tuple[Any, Any, Any]:
    directory = CONTROLLER_DIR.stat(follow_symlinks=False)
    if not stat.S_ISDIR(directory.st_mode) or CONTROLLER_DIR.is_symlink():
        raise RuntimeError("trusted controller directory must be a real directory")
    required = (
        "dependency_governance.py",
        "dependency_promotion.py",
        "dependency_lock_compiler.py",
        "security_autoheal.py",
        "trusted_qualification.py",
        "trusted_status.py",
    )
    for name in required:
        path = CONTROLLER_DIR / name
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise RuntimeError(f"trusted controller source must be a regular file: {name}")
    controller_path = str(CONTROLLER_DIR)
    if controller_path in sys.path:
        raise RuntimeError("trusted controller path unexpectedly exists in sys.path")
    sys.path.insert(0, controller_path)
    try:
        governance = importlib.import_module("dependency_governance")
        promotion = importlib.import_module("dependency_promotion")
        autoheal = importlib.import_module("security_autoheal")
    finally:
        if sys.path[0] != controller_path:
            raise RuntimeError("trusted controller import path order changed")
        sys.path.pop(0)
    return governance, promotion, autoheal


def _expected_subject(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "number": args.pr_number,
        "headSha": _require_sha(args.expected_head_sha, "expected head SHA"),
        "baseSha": _require_sha(args.expected_base_sha, "expected base SHA"),
        "mergeSha": _require_sha(args.expected_merge_sha, "expected merge SHA"),
    }


def _assert_exact(observed: dict[str, Any], expected: dict[str, Any], lane: str) -> None:
    if observed != expected:
        raise RuntimeError(
            f"{lane} trusted admission subject drifted: "
            + json.dumps({"expected": expected, "observed": observed}, sort_keys=True)
        )


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != EXPECTED_REPOSITORY:
        raise RuntimeError("trusted bot admission is bound to the expected repository")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required for trusted bot admission")
    if args.lane not in LANES or args.mode not in MODES:
        raise RuntimeError("trusted bot admission lane/mode is outside reviewed authority")

    governance, promotion, autoheal = _load_controllers()
    expected = _expected_subject(args)

    if args.lane == "dependabot-actions":
        api = governance.GitHubApi(token, repository)
        config = governance.load_config()
        pr = api.get(f"/pulls/{args.pr_number}")
        subject = governance.assess(api, pr, config, require_checks=False)
        merge_sha = governance.verify_merge_subject(
            api,
            args.pr_number,
            subject["headSha"],
            subject["baseSha"],
        )
        observed = {
            "number": subject["number"],
            "headSha": subject["headSha"],
            "baseSha": subject["baseSha"],
            "mergeSha": merge_sha,
        }
    elif args.lane == "dependency-promotion":
        api = governance.GitHubApi(token, repository)
        config = governance.load_config()
        if args.mode == "full":
            for name in ("PROMOTION_PYTHON311", "PROMOTION_PYTHON314"):
                executable = os.environ.get(name, "")
                if not executable or not Path(executable).is_absolute():
                    raise RuntimeError(f"{name} must be an absolute trusted interpreter path")
        pr = api.get(f"/pulls/{args.pr_number}")
        _, subject = promotion._validate_promotion(
            api,
            pr,
            config,
            validate_generated_bytes=args.mode == "full",
            require_checks=False,
        )
        merge_sha = governance.verify_merge_subject(
            api,
            args.pr_number,
            subject["headSha"],
            subject["baseSha"],
        )
        observed = {
            "number": subject["number"],
            "headSha": subject["headSha"],
            "baseSha": subject["baseSha"],
            "mergeSha": merge_sha,
        }
    else:
        api = autoheal.GitHubApi(token, repository)
        config = autoheal.load_config()
        pr = api.get(f"/pulls/{args.pr_number}")
        _, live = autoheal.assess_trusted_admission(
            api,
            pr,
            config,
            require_checks=False,
            verify_codeql=args.mode == "terminal",
        )
        merge_sha = governance.verify_merge_subject(
            api,
            args.pr_number,
            live["headSha"],
            live["baseSha"],
        )
        observed = {
            "number": args.pr_number,
            "headSha": live["headSha"],
            "baseSha": live["baseSha"],
            "mergeSha": merge_sha,
        }

    _assert_exact(observed, expected, args.lane)
    return {
        "result": "PASS",
        "lane": args.lane,
        "mode": args.mode,
        **observed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Trusted bot exact-subject admission")
    parser.add_argument("--lane", required=True, choices=sorted(LANES))
    parser.add_argument("--mode", required=True, choices=sorted(MODES))
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--expected-merge-sha", required=True)
    args = parser.parse_args()
    if args.pr_number < 1:
        raise ValueError("PR number must be positive")
    print(json.dumps(evaluate(args), sort_keys=True))


if __name__ == "__main__":
    main()
