from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_OWNER = "portyu9"
EXPECTED_WORKFLOW_NAMES = {
    "ci.yml",
    "manual-validation.yml",
    "release-candidate.yml",
    "trusted-pr-auto.yml",
}
MAX_WORKFLOW_BYTES = 256 * 1024
MAX_WORKFLOW_ENTRIES = 16
MAX_PREFLIGHT_BYTES = 64 * 1024

# GitHub Actions must not become an AWS authentication plane. This repository's AWS
# authority is intentionally external to Actions and is admitted by the Trusted PR Gate.
_FORBIDDEN_WORKFLOW_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub OIDC permission", re.compile(r"(?i)\bid-token\s*:")),
    (
        "GitHub OIDC request environment",
        re.compile(r"(?i)ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)"),
    ),
    ("AWS credential action", re.compile(r"(?i)\baws-actions/")),
    ("GitHub OIDC provider", re.compile(r"(?i)token\.actions\.githubusercontent\.com")),
    ("AWS web-identity assumption", re.compile(r"(?i)assumerolewithwebidentity")),
    ("AWS role-to-assume input", re.compile(r"(?i)role-to-assume")),
    ("AWS web identity token file", re.compile(r"(?i)aws_web_identity_token_file")),
    ("AWS access key", re.compile(r"(?i)aws_access_key_id")),
    ("AWS secret key", re.compile(r"(?i)aws_secret_access_key")),
    ("AWS session token", re.compile(r"(?i)aws_session_token")),
    ("AWS shared credentials file", re.compile(r"(?i)aws_shared_credentials_file")),
    ("AWS profile", re.compile(r"(?i)aws_(?:default_)?profile")),
    ("AWS credential file", re.compile(r"(?i)(?:~|\$HOME)/\.aws/credentials")),
    (
        "AWS credential process",
        re.compile(r"(?i)credential_process|credential_source|source_profile"),
    ),
    ("AWS configure command", re.compile(r"(?i)\baws\s+configure\b")),
    ("AWS STS command", re.compile(r"(?i)\baws\s+sts\b")),
    ("AWS-prefixed GitHub secret", re.compile(r"(?i)secrets\.AWS[_A-Z0-9]*")),
    ("indirect GitHub secret reference", re.compile(r"(?i)\bsecrets\s*\[")),
    ("inherited GitHub secrets", re.compile(r"(?i)\bsecrets\s*:\s*inherit\b")),
    ("pull_request_target trigger", re.compile(r"(?i)\bpull_request_target\b")),
)

_ALLOWED_SECRET_REFERENCES = {
    "manual-validation.yml": {"ANTHROPIC_API_KEY"},
    "trusted-pr-auto.yml": {"TRUSTED_GATE_APP_PRIVATE_KEY"},
}
_SECRET_REFERENCE_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

_REQUIRED_PREFLIGHT_FRAGMENTS = (
    f'EXPECTED_REPOSITORY = "{EXPECTED_REPOSITORY}"',
    f'EXPECTED_OWNER = "{EXPECTED_OWNER}"',
    "if repository != EXPECTED_REPOSITORY:",
    'if repository.get("full_name") != EXPECTED_REPOSITORY:',
    'if head_repository.get("full_name") != EXPECTED_REPOSITORY:',
    'raise ValueError("fork/external-head workflow runs are not auto-authorized")',
    'if actor.get("login") != EXPECTED_OWNER or triggering_actor.get("login") != EXPECTED_OWNER:',
    'and head_repo.get("full_name") == EXPECTED_REPOSITORY',
    'and base_repo.get("full_name") == EXPECTED_REPOSITORY',
)


def _read_regular_text(path: Path, *, max_bytes: int, label: str) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeError("fork/cloud authority verification requires O_NOFOLLOW")
    try:
        fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened as a regular non-symlink file") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError(f"{label} must be a bounded regular file")
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > max_bytes:
            raise ValueError(f"{label} exceeds the bounded ingestion limit")
        after = os.fstat(fd)
        before_sig = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_sig = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_sig != after_sig:
            raise ValueError(f"{label} changed during ingestion")
    finally:
        os.close(fd)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8 text") from exc


def _verify_workflow_text(name: str, text: str) -> dict[str, Any]:
    violations = [label for label, pattern in _FORBIDDEN_WORKFLOW_TOKENS if pattern.search(text)]
    if violations:
        raise ValueError(f"{name}: forbidden cloud/fork authority tokens: {', '.join(violations)}")

    secret_references = _SECRET_REFERENCE_RE.findall(text)
    observed_secrets = set(secret_references)
    allowed_secrets = _ALLOWED_SECRET_REFERENCES.get(name, set())
    if observed_secrets != allowed_secrets or len(secret_references) != len(allowed_secrets):
        raise ValueError(
            f"{name}: secret references differ from reviewed allowlist: "
            f"expected exactly {sorted(allowed_secrets)}, got {secret_references}"
        )

    return {
        "workflow": name,
        "aws_authentication": "forbidden",
        "pull_request_target": "forbidden",
        "secrets": sorted(observed_secrets),
    }


def _verify_trusted_preflight(text: str) -> dict[str, str]:
    missing = [fragment for fragment in _REQUIRED_PREFLIGHT_FRAGMENTS if fragment not in text]
    if missing:
        raise ValueError(
            "automatic trusted preflight lost canonical repository/fork isolation: "
            + "; ".join(missing)
        )
    return {
        "repository": EXPECTED_REPOSITORY,
        "owner": EXPECTED_OWNER,
        "fork_heads": "rejected",
        "external_actors": "rejected",
    }


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    workflow_dir = root / ".github" / "workflows"
    if workflow_dir.is_symlink() or not workflow_dir.is_dir():
        raise ValueError("workflow directory must be an owned regular directory")

    names: list[str] = []
    for entry in sorted(workflow_dir.iterdir(), key=lambda item: item.name):
        if entry.suffix not in {".yml", ".yaml"}:
            raise ValueError(f"unexpected non-workflow entry in workflow directory: {entry.name}")
        names.append(entry.name)
        if len(names) > MAX_WORKFLOW_ENTRIES:
            raise ValueError("workflow directory exceeds bounded entry limit")

    if set(names) != EXPECTED_WORKFLOW_NAMES:
        raise ValueError(
            "workflow set differs from reviewed cloud-authority contract: "
            f"expected {sorted(EXPECTED_WORKFLOW_NAMES)}, got {sorted(names)}"
        )

    workflows: list[dict[str, Any]] = []
    for name in names:
        text = _read_regular_text(
            workflow_dir / name,
            max_bytes=MAX_WORKFLOW_BYTES,
            label=f"workflow {name}",
        )
        workflows.append(_verify_workflow_text(name, text))

    preflight_text = _read_regular_text(
        root / "scripts" / "auto_trusted_preflight.py",
        max_bytes=MAX_PREFLIGHT_BYTES,
        label="automatic trusted preflight",
    )
    preflight = _verify_trusted_preflight(preflight_text)

    return {
        "schema_version": 1,
        "canonical_repository": EXPECTED_REPOSITORY,
        "github_actions_aws_authentication": "forbidden",
        "fork_cloud_authority": "denied",
        "workflow_count": len(workflows),
        "workflows": workflows,
        "trusted_preflight": preflight,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify fork isolation and absence of GitHub Actions AWS authority"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(json.dumps(verify_repository(args.root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
