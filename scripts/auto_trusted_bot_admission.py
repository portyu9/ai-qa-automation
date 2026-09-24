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
LANES = {
    "dependabot-actions",
    "dependency-promotion",
    "security-autoheal",
    "protected-security-remediation",
}
MODES = {"full", "terminal"}


def _require_sha(value: str, label: str) -> str:
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{label} must be a canonical lowercase SHA-1")
    return value


def _load_controller_modules(names: tuple[str, ...]) -> dict[str, Any]:
    directory = CONTROLLER_DIR.stat(follow_symlinks=False)
    if not stat.S_ISDIR(directory.st_mode) or CONTROLLER_DIR.is_symlink():
        raise RuntimeError("trusted controller directory must be a real directory")
    required = {
        "dependency_governance": "dependency_governance.py",
        "dependency_promotion": "dependency_promotion.py",
        "security_autoheal": "security_autoheal.py",
        "protected_security_remediation": "protected_security_remediation.py",
        "dependency_lock_compiler": "dependency_lock_compiler.py",
        "trusted_qualification": "trusted_qualification.py",
        "trusted_status": "trusted_status.py",
    }
    for module_name in names:
        file_name = required.get(module_name)
        if file_name is None:
            raise RuntimeError("trusted controller module request is outside reviewed authority")
        path = CONTROLLER_DIR / file_name
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise RuntimeError(f"trusted controller source must be a regular file: {file_name}")
    controller_path = str(CONTROLLER_DIR)
    if controller_path in sys.path:
        raise RuntimeError("trusted controller path unexpectedly exists in sys.path")
    sys.path.insert(0, controller_path)
    try:
        return {name: importlib.import_module(name) for name in names}
    finally:
        if sys.path[0] != controller_path:
            raise RuntimeError("trusted controller import path order changed")
        sys.path.pop(0)


def _load_controllers(lane: str) -> dict[str, Any]:
    if lane == "protected-security-remediation":
        return _load_controller_modules(
            ("dependency_governance", "protected_security_remediation")
        )
    return _load_controller_modules(
        ("dependency_governance", "dependency_promotion", "security_autoheal")
    )


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

    controllers = _load_controllers(args.lane)
    governance = controllers["dependency_governance"]
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
        promotion = controllers["dependency_promotion"]
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
    elif args.lane == "security-autoheal":
        autoheal = controllers["security_autoheal"]
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
    else:
        protected = controllers["protected_security_remediation"]
        author_login = os.environ.get("PROTECTED_REMEDIATION_BOT_LOGIN", "")
        raw_author_id = os.environ.get("PROTECTED_REMEDIATION_BOT_ID", "")
        if not raw_author_id.isdigit():
            raise RuntimeError("protected remediation author App user id is missing or malformed")
        api = protected.GitHubApi(token, repository)
        pr = api.get(f"/pulls/{args.pr_number}")
        live = protected.validate_generated_pr(
            api,
            pr,
            expected_bot_login=author_login,
            expected_bot_id=int(raw_author_id),
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
