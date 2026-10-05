#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any

from dependency_governance import (
    BOT_EMAIL,
    BOT_LOGIN,
    BOT_USER_ID,
    SIGNED_OFF_BY,
    TRUSTED_COMMITTER_EMAIL,
    TRUSTED_COMMITTER_LOGIN,
    TRUSTED_COMMITTER_NAME,
    GitHubApi,
    GovernanceError,
    PolicyBlock,
    changed_files,
    finalize_post_merge_evidence,
    load_config,
    require_current_control_revision,
    require_exact_automation_approval,
    require_green_checks,
    require_sha,
    validate_pr_identity,
)
from dependency_lock_compiler import LockCompileError, compile_locks, validate_frozen_locks
from dependency_trusted_gate import TRUSTED_PR_AUTO_WORKFLOW_ID, require_promotion_trusted_gate
from trusted_qualification import EXPECTED_REPOSITORY
from trusted_status import (
    EXPECTED_GATE_EVENTS,
    EXPECTED_GATE_WORKFLOW_NAME,
    EXPECTED_GATE_WORKFLOW_PATH,
    TARGET_URL_RE,
    TRUSTED_STATUS_BOT_ID,
    TRUSTED_STATUS_BOT_LOGIN,
    TRUSTED_STATUS_CONTEXT,
    TRUSTED_STATUS_DESCRIPTION,
    TrustedStatusError,
)

ROOT = Path(__file__).resolve().parents[2]
BRANCH_PREFIX = "automation/dependency-promotion-"
STAGING_BASE_PREFIX = "automation/dependency-promotion-base-"
PROMOTION_BRANCH_RE = re.compile(r"^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$")
STAGING_BASE_RE = re.compile(r"^automation/dependency-promotion-base-[1-9][0-9]*-[0-9a-f]{12}$")
PROMOTION_COMMIT_MESSAGE_RE = re.compile(
    r"^deps: promote Dependabot PR #[1-9][0-9]* with synchronized locks$"
)
MARKER_PREFIX = "<!-- aiqa-dependency-promotion:"
MARKER_SUFFIX = " -->"
GITHUB_ACTIONS_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_USER_ID = 41898282
GITHUB_ACTIONS_APP_ID = 15368
DEPENDABOT_LOGIN = "dependabot[bot]"
DEPENDABOT_USER_ID = 49699333
DEPENDABOT_ACTION_REF_RE = re.compile(
    r"^dependabot/github_actions/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$"
)
TRUSTED_GATE_LOGIN = "trusted-pr-gate[bot]"
PROMOTION_AUTHOR_TOKEN_ENV = "PROMOTION_AUTHOR_TOKEN"
PROMOTION_AUTHOR_LOGIN = "portyu9-security-remediator[bot]"
PROMOTION_AUTHOR_USER_ID = 333833782
PROMOTION_AUTHOR_LOGIN_ENV = "PROTECTED_REMEDIATION_BOT_LOGIN"
PROMOTION_AUTHOR_ID_ENV = "PROTECTED_REMEDIATION_BOT_ID"
QUALIFICATION_WAKE_CHECK = "Dependency Promotion Qualification Wake"
QUALIFICATION_WAKE_PREFIX = "aiqa-dependency-promotion-qualification-wake"
QUALIFICATION_WAKE_RE = re.compile(
    rf"^{QUALIFICATION_WAKE_PREFIX}:(?P<head>[0-9a-f]{{40}}):(?P<base>[0-9a-f]{{40}}):"
    r"(?P<stage>trusted-gate):(?P<run>[1-9][0-9]*):(?P<attempt>[1-9][0-9]*)$"
)


def _actions_check_details_url_is_canonical(
    details_url: Any,
    *,
    check_id: int,
    run_id: int,
) -> bool:
    if not isinstance(details_url, str):
        return False
    run_url = f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"
    if details_url == run_url:
        return True
    if re.fullmatch(re.escape(run_url) + r"/job/[1-9][0-9]*", details_url) is not None:
        return True
    return details_url == f"https://github.com/{EXPECTED_REPOSITORY}/runs/{check_id}"


DEPENDENCY_GOVERNANCE_WORKFLOW_NAME = "dependency-governance"
DEPENDENCY_GOVERNANCE_WORKFLOW_PATH = ".github/workflows/dependency-governance.yml"
DEPENDENCY_GOVERNANCE_EVENTS = {"workflow_run", "schedule"}
MAX_STATUS_EVENT_BYTES = 1024 * 1024
STATUS_EVENT_TERMINAL_ATTEMPTS = 20
STATUS_EVENT_POLL_SECONDS = 1.0
STATUS_EVENT_HISTORY_PAGES = 2
STATUS_EVENT_PENDING_STATES = frozenset(
    {"queued", "in_progress", "waiting", "pending", "requested"}
)
REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[A-Za-z0-9_,.-]+\])?(?P<specifier>[^;@\s]*)$"
)
PROMOTION_PATHS = {
    "README.md",
    "pyproject.toml",
    "requirements/build-py311.lock",
    "requirements/dev-py311.lock",
    "requirements/dev-py314.lock",
    "requirements/runtime-py311.lock",
    ".github/lock-authority.json",
}


class QualificationWakeRegistered(PolicyBlock):
    """A single exact-run qualification wake was durably published."""


def _read_status_event_payload() -> dict[str, Any]:
    raw_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not raw_path:
        raise GovernanceError("GITHUB_EVENT_PATH is required for trusted status synchronization")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise GovernanceError("trusted status synchronization requires O_NOFOLLOW")
    try:
        fd = os.open(Path(raw_path), os.O_RDONLY | nofollow)
    except OSError as exc:
        raise GovernanceError("trusted status event payload could not be opened safely") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_STATUS_EVENT_BYTES:
            raise GovernanceError("trusted status event payload is not one bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_STATUS_EVENT_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_STATUS_EVENT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if total > MAX_STATUS_EVENT_BYTES:
        raise GovernanceError("trusted status event payload exceeds bounded ingestion")
    before_signature = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_signature = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_signature != after_signature or total != before.st_size:
        raise GovernanceError("trusted status event payload changed during bounded read")
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceError("trusted status event payload is not canonical UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise GovernanceError("trusted status event payload must be one JSON object")
    return payload


def _require_exact_trusted_status_record(
    api: GitHubApi,
    payload: dict[str, Any],
    head_sha: str,
    target_url: str,
) -> None:
    status_id = payload.get("id")
    if isinstance(status_id, bool) or not isinstance(status_id, int) or status_id < 1:
        raise GovernanceError("trusted status event id is invalid")

    for page in range(1, STATUS_EVENT_HISTORY_PAGES + 1):
        rows = api.get(f"/commits/{head_sha}/statuses?per_page=100&page={page}")
        if not isinstance(rows, list) or len(rows) > 100:
            raise GovernanceError("trusted status history is not a bounded status list")
        matches = [
            row
            for row in rows
            if isinstance(row, dict)
            and not isinstance(row.get("id"), bool)
            and isinstance(row.get("id"), int)
            and row.get("id") == status_id
        ]
        if len(matches) > 1:
            raise GovernanceError("trusted status event id is duplicated in GitHub status history")
        if matches:
            status = matches[0]
            creator = status.get("creator")
            if (
                status.get("context") != TRUSTED_STATUS_CONTEXT
                or status.get("state") != "success"
                or status.get("description") != TRUSTED_STATUS_DESCRIPTION
                or status.get("target_url") != target_url
                or not isinstance(creator, dict)
                or creator.get("login") != TRUSTED_STATUS_BOT_LOGIN
                or creator.get("id") != TRUSTED_STATUS_BOT_ID
                or creator.get("type") != "Bot"
            ):
                raise GovernanceError(
                    "trusted status REST record is not exact dedicated-App gate evidence"
                )
            return
        if len(rows) < 100:
            break

    raise GovernanceError("trusted status event id is absent from bounded GitHub status history")


def await_trusted_status_event() -> dict[str, Any] | None:
    """Synchronize a trusted status wake to the exact completed validating workflow.

    This is a bounded read-only barrier. It executes before any recovery or repository
    mutation so an App status emitted near the end of the reporter job cannot race the
    workflow-run completion required by terminal merge authority.
    """

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != EXPECTED_REPOSITORY:
        raise GovernanceError("trusted status synchronization repository identity drifted")
    payload = _read_status_event_payload()
    event_repository = payload.get("repository")
    if (
        payload.get("context") != TRUSTED_STATUS_CONTEXT
        or payload.get("state") != "success"
        or not isinstance(event_repository, dict)
        or event_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise GovernanceError("status wake is not an exact Trusted PR Gate success event")

    head_sha = require_sha(payload.get("sha"), "trusted status event SHA")
    target_url = payload.get("target_url")
    if not isinstance(target_url, str):
        raise GovernanceError("trusted status event target URL is missing")
    match = TARGET_URL_RE.fullmatch(target_url)
    if match is None or match.group("head") != head_sha:
        raise GovernanceError("trusted status event target URL is not exact-subject-bound")
    run_id = int(match.group("run_id"))
    pr_number = int(match.group("pr"))
    base_sha = require_sha(match.group("base"), "trusted status event base SHA")
    token = os.environ.get("GITHUB_TOKEN", "")
    api = GitHubApi(token, repository)
    _require_exact_trusted_status_record(api, payload, head_sha, target_url)

    pr = api.get(f"/pulls/{pr_number}")
    pr_head = (pr or {}).get("head") if isinstance(pr, dict) else None
    pr_base = (pr or {}).get("base") if isinstance(pr, dict) else None
    branch = (pr_head or {}).get("ref") if isinstance(pr_head, dict) else None
    if (
        not isinstance(pr, dict)
        or pr.get("state") != "open"
        or pr.get("draft") is not False
        or not isinstance(branch, str)
        or require_sha((pr_head or {}).get("sha"), "trusted status PR head SHA") != head_sha
        or ((pr_head or {}).get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or require_sha((pr_base or {}).get("sha"), "trusted status PR base SHA") != base_sha
        or (pr_base or {}).get("ref") != "main"
        or ((pr_base or {}).get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
    ):
        raise GovernanceError("Trusted PR Gate status is not bound to an exact open same-repo PR")
    user = pr.get("user") or {}
    if PROMOTION_BRANCH_RE.fullmatch(branch) is not None:
        if not _promotion_actor_matches(user):
            raise GovernanceError(
                "Trusted PR Gate dependency promotion is not authored by the independent App"
            )
        lane = "dependency-promotion"
    elif DEPENDABOT_ACTION_REF_RE.fullmatch(branch) is not None:
        if (
            not isinstance(user, dict)
            or user.get("login") != DEPENDABOT_LOGIN
            or user.get("id") != DEPENDABOT_USER_ID
        ):
            raise GovernanceError(
                "Trusted PR Gate Dependabot Actions subject has unexpected actor identity"
            )
        lane = "dependabot-actions"
    else:
        if branch.startswith(BRANCH_PREFIX) or branch.startswith("dependabot/github_actions/"):
            raise GovernanceError(
                "Trusted PR Gate status claims a malformed dependency update namespace"
            )
        return None
    live = api.get("/branches/main")
    if (
        require_sha(
            ((live or {}).get("commit") or {}).get("sha"),
            "trusted status live main SHA",
        )
        != base_sha
    ):
        raise GovernanceError(
            "Trusted PR Gate dependency promotion is stale relative to current main"
        )

    for attempt in range(STATUS_EVENT_TERMINAL_ATTEMPTS):
        run = api.get(f"/actions/runs/{run_id}")
        run_repository = (run or {}).get("repository") if isinstance(run, dict) else None
        head_repository = (run or {}).get("head_repository") if isinstance(run, dict) else None
        if (
            not isinstance(run, dict)
            or run.get("id") != run_id
            or run.get("workflow_id") != TRUSTED_PR_AUTO_WORKFLOW_ID
            or run.get("name") != EXPECTED_GATE_WORKFLOW_NAME
            or run.get("path") != EXPECTED_GATE_WORKFLOW_PATH
            or run.get("event") not in EXPECTED_GATE_EVENTS
            or run.get("run_attempt") != 1
            or run.get("head_branch") != "main"
            or require_sha(run.get("head_sha"), "trusted status workflow head SHA") != base_sha
            or not isinstance(run_repository, dict)
            or run_repository.get("full_name") != EXPECTED_REPOSITORY
            or not isinstance(head_repository, dict)
            or head_repository.get("full_name") != EXPECTED_REPOSITORY
        ):
            raise GovernanceError("status wake target is not the exact reviewed trusted workflow")

        state = run.get("status")
        if state == "completed":
            if run.get("conclusion") != "success":
                raise GovernanceError("trusted status workflow completed without success")
            return {
                "runId": run_id,
                "prNumber": pr_number,
                "baseSha": base_sha,
                "headSha": head_sha,
                "event": str(run.get("event")),
                "lane": lane,
            }
        if state not in STATUS_EVENT_PENDING_STATES:
            raise GovernanceError("trusted status workflow has an unsupported nonterminal state")
        if attempt + 1 == STATUS_EVENT_TERMINAL_ATTEMPTS:
            raise GovernanceError("trusted status workflow did not become terminal within bound")
        time.sleep(STATUS_EVENT_POLL_SECONDS)

    raise GovernanceError("trusted status workflow synchronization exhausted unexpectedly")


def _promotion_author_identity() -> tuple[str, int]:
    login = os.environ.get(PROMOTION_AUTHOR_LOGIN_ENV, "")
    raw_id = os.environ.get(PROMOTION_AUTHOR_ID_ENV, "")
    if bool(login) != bool(raw_id):
        raise GovernanceError("independent promotion author App identity is partially configured")
    if (login or raw_id) and (
        login != PROMOTION_AUTHOR_LOGIN
        or not raw_id.isdigit()
        or int(raw_id) != PROMOTION_AUTHOR_USER_ID
    ):
        raise GovernanceError(
            "independent promotion author App identity drifted from trusted policy"
        )
    return PROMOTION_AUTHOR_LOGIN, PROMOTION_AUTHOR_USER_ID


def _legacy_promotion_actor_matches(user: Any) -> bool:
    return isinstance(user, dict) and (
        user.get("login") == GITHUB_ACTIONS_LOGIN and user.get("id") == GITHUB_ACTIONS_USER_ID
    )


def _promotion_actor_matches(user: Any) -> bool:
    if not isinstance(user, dict):
        return False
    identity = _promotion_author_identity()
    return user.get("login") == identity[0] and user.get("id") == identity[1]


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _requirement_identity(raw: Any, *, context: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 512:
        raise PolicyBlock(f"{context} dependency must be a bounded non-empty string")
    if any(token in raw for token in (";", "@", "://", "\\", "../", "./")):
        raise PolicyBlock(f"{context} dependency introduces URL/path/marker authority")
    match = REQUIREMENT.fullmatch(raw)
    if match is None or not match.group("specifier"):
        raise PolicyBlock(f"{context} dependency uses unsupported or unconstrained syntax: {raw!r}")
    extras = match.group("extras") or ""
    return _canonical_name(match.group("name")) + extras.lower()


def _normalized_semantics(document: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    normalized = copy.deepcopy(document)
    versions: dict[str, str] = {}
    project = normalized.get("project")
    build = normalized.get("build-system")
    if not isinstance(project, dict) or not isinstance(build, dict):
        raise PolicyBlock("pyproject.toml must retain project and build-system tables")

    def normalize_list(container: dict[str, Any], key: str, context: str) -> None:
        values = container.get(key)
        if not isinstance(values, list) or not values:
            raise PolicyBlock(f"{context} dependency list is missing or empty")
        identities: list[str] = []
        for value in values:
            identity = _requirement_identity(value, context=context)
            if identity in versions:
                raise PolicyBlock(
                    f"duplicate dependency identity across reviewed groups: {identity}"
                )
            versions[identity] = str(value)
            identities.append(identity)
        container[key] = identities

    normalize_list(project, "dependencies", "runtime")
    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or not optional:
        raise PolicyBlock("optional dependency groups are missing")
    optional_specs: dict[str, str] = {}
    for group in sorted(optional):
        values = optional[group]
        if not isinstance(group, str) or not group or not isinstance(values, list) or not values:
            raise PolicyBlock("optional dependency groups are malformed")
        identities: list[str] = []
        for value in values:
            identity = _requirement_identity(value, context=f"optional:{group}")
            scoped = f"optional:{group}:{identity}"
            if scoped in versions:
                raise PolicyBlock(f"duplicate dependency identity in optional group: {identity}")
            rendered = str(value)
            prior = optional_specs.get(identity)
            if prior is not None and prior != rendered:
                raise PolicyBlock(
                    f"duplicate optional dependency specs disagree across groups: {identity}"
                )
            optional_specs[identity] = rendered
            versions[scoped] = rendered
            identities.append(identity)
        optional[group] = identities

    requires = build.get("requires")
    if not isinstance(requires, list) or not requires:
        raise PolicyBlock("build-system.requires is missing")
    build_identities: list[str] = []
    for value in requires:
        identity = _requirement_identity(value, context="build-system")
        scoped = f"build:{identity}"
        versions[scoped] = str(value)
        build_identities.append(identity)
    build["requires"] = build_identities
    return normalized, versions


def validate_pyproject_transition(base_raw: bytes, head_raw: bytes) -> None:
    if base_raw == head_raw:
        raise PolicyBlock("Dependabot pyproject.toml bytes did not change")
    try:
        base = tomllib.loads(base_raw.decode("utf-8"))
        head = tomllib.loads(head_raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyBlock("Dependabot pyproject.toml is not canonical UTF-8 TOML") from exc
    base_semantics, base_versions = _normalized_semantics(base)
    head_semantics, head_versions = _normalized_semantics(head)
    if base_semantics != head_semantics:
        raise PolicyBlock(
            "pip update changes non-version pyproject semantics or dependency identities"
        )
    if set(base_versions) != set(head_versions):
        raise PolicyBlock("pip update adds, removes, or renames a dependency identity")
    changed = [name for name in base_versions if base_versions[name] != head_versions[name]]
    if not changed:
        raise PolicyBlock("pip update does not change any reviewed dependency specifier")


SDK_REQUIREMENT_PREFIX = "claude-agent-sdk=="
SDK_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")


def _sdk_version(pyproject_raw: bytes) -> str:
    try:
        document = tomllib.loads(pyproject_raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyBlock(
            "SDK documentation synchronization requires canonical UTF-8 TOML"
        ) from exc
    dependencies = (document.get("project") or {}).get("dependencies")
    if not isinstance(dependencies, list):
        raise PolicyBlock("SDK documentation synchronization requires project dependencies")
    matches: list[str] = []
    for dependency in dependencies:
        if isinstance(dependency, str) and dependency.startswith(SDK_REQUIREMENT_PREFIX):
            version = dependency[len(SDK_REQUIREMENT_PREFIX) :]
            if SDK_VERSION_RE.fullmatch(version) is None:
                raise PolicyBlock("claude-agent-sdk promotion version is malformed")
            matches.append(version)
    if len(matches) != 1:
        raise PolicyBlock("promotion requires exactly one exact claude-agent-sdk dependency pin")
    return matches[0]


def _synchronize_readme_sdk_claim(
    readme_raw: bytes,
    base_pyproject_raw: bytes,
    head_pyproject_raw: bytes,
) -> bytes:
    base_version = _sdk_version(base_pyproject_raw)
    head_version = _sdk_version(head_pyproject_raw)
    if base_version == head_version:
        return readme_raw
    try:
        text = readme_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyBlock("README.md is not canonical UTF-8") from exc
    replacements = (
        (
            f"Claude%20Agent%20SDK-{base_version}-",
            f"Claude%20Agent%20SDK-{head_version}-",
            "README Claude Agent SDK badge",
        ),
        (
            f"`claude-agent-sdk=={base_version}`",
            f"`claude-agent-sdk=={head_version}`",
            "README exact SDK runtime claim",
        ),
    )
    for old, new, label in replacements:
        if text.count(old) != 1 or text.count(new) != 0:
            raise PolicyBlock(f"{label} is missing, duplicated, or already drifted")
        text = text.replace(old, new, 1)
    return text.encode("utf-8")


def _decode_contents_base64(content: str, path: str) -> bytes:
    compact = content.replace("\r", "").replace("\n", "")
    if not compact:
        raise PolicyBlock(f"repository content base64 is invalid: {path}")
    try:
        return base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PolicyBlock(f"repository content base64 is invalid: {path}") from exc


def _contents_bytes(api: GitHubApi, path: str, ref: str) -> bytes:
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    payload = api.get(f"/contents/{encoded_path}?ref={urllib.parse.quote(ref, safe='')}")
    if not isinstance(payload, dict) or payload.get("type") != "file":
        raise PolicyBlock(f"repository content is not one regular file: {path}")
    content = payload.get("content")
    encoding = payload.get("encoding")
    if not isinstance(content, str) or encoding != "base64":
        raise PolicyBlock(f"repository content encoding is invalid: {path}")
    raw = _decode_contents_base64(content, path)
    if len(raw) > 2 * 1024 * 1024:
        raise PolicyBlock(f"repository content exceeds promotion ingestion bound: {path}")
    return raw


def _validate_dependabot_provenance(api: GitHubApi, number: int) -> None:
    commits = api.list_all(f"/pulls/{number}/commits", max_pages=2)
    if len(commits) != 1:
        raise PolicyBlock(
            f"pip promotion requires exactly one Dependabot commit, found {len(commits)}"
        )
    row = commits[0]
    author = row.get("author") or {}
    committer = row.get("committer") or {}
    commit = row.get("commit") or {}
    raw_author = commit.get("author") or {}
    raw_committer = commit.get("committer") or {}
    verification = commit.get("verification") or {}
    message = commit.get("message")
    if author.get("login") != BOT_LOGIN or author.get("id") != BOT_USER_ID:
        raise PolicyBlock("pip promotion commit author is not exact Dependabot identity")
    if raw_author.get("email") != BOT_EMAIL:
        raise PolicyBlock("pip promotion commit author email is not canonical Dependabot")
    if committer.get("login") != TRUSTED_COMMITTER_LOGIN:
        raise PolicyBlock("pip promotion commit committer is not GitHub web-flow")
    if (
        raw_committer.get("name") != TRUSTED_COMMITTER_NAME
        or raw_committer.get("email") != TRUSTED_COMMITTER_EMAIL
    ):
        raise PolicyBlock("pip promotion committer metadata is not canonical GitHub metadata")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise PolicyBlock("pip promotion Dependabot commit signature is not verified-valid")
    if not isinstance(message, str) or SIGNED_OFF_BY not in message:
        raise PolicyBlock("pip promotion Dependabot Signed-off-by provenance is missing")


def _promotion_base(
    source_base_sha: str,
    live_main_sha: str,
    source_base_raw: bytes,
    live_main_raw: bytes,
) -> str:
    if source_base_sha != live_main_sha and source_base_raw != live_main_raw:
        raise PolicyBlock(
            "stale Dependabot source overlaps current pyproject.toml; wait for native rebase"
        )
    return live_main_sha


def source_subject(api: GitHubApi, pr: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    head_sha, source_base_sha, number = validate_pr_identity(
        api, pr, config, require_current_base=False
    )
    _validate_dependabot_provenance(api, number)
    files = changed_files(api, number, config)
    if (
        len(files) != 1
        or files[0].get("filename") != "pyproject.toml"
        or files[0].get("status") != "modified"
    ):
        raise PolicyBlock("pip promotion source must modify only existing pyproject.toml")
    source_base_raw = _contents_bytes(api, "pyproject.toml", source_base_sha)
    head_raw = _contents_bytes(api, "pyproject.toml", head_sha)
    validate_pyproject_transition(source_base_raw, head_raw)

    live = api.get(f"/branches/{urllib.parse.quote(config['baseBranch'], safe='')}")
    live_main_sha = require_sha(((live or {}).get("commit") or {}).get("sha"), "live main SHA")
    live_main_raw = _contents_bytes(api, "pyproject.toml", live_main_sha)
    promotion_base_sha = _promotion_base(
        source_base_sha,
        live_main_sha,
        source_base_raw,
        live_main_raw,
    )
    live_readme_raw = _contents_bytes(api, "README.md", promotion_base_sha)

    fingerprint = hashlib.sha256(
        b"\0".join(
            (
                str(number).encode(),
                source_base_sha.encode(),
                head_sha.encode(),
                promotion_base_sha.encode(),
                hashlib.sha256(head_raw).hexdigest().encode(),
                hashlib.sha256(live_readme_raw).hexdigest().encode(),
            )
        )
    ).hexdigest()
    return {
        "number": number,
        "headSha": head_sha,
        "sourceBaseSha": source_base_sha,
        "baseSha": promotion_base_sha,
        "basePyproject": live_main_raw,
        "pyproject": head_raw,
        "readme": live_readme_raw,
        "fingerprint": fingerprint,
    }


def _branch_name(source: dict[str, Any]) -> str:
    return f"{BRANCH_PREFIX}{source['number']}-{source['fingerprint'][:12]}"


def _staging_base_name(source_number: int, fingerprint: str) -> str:
    if source_number < 1 or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise GovernanceError("promotion staging-base identity is malformed")
    return f"{STAGING_BASE_PREFIX}{source_number}-{fingerprint[:12]}"


def _owned_generated_promotion_commit(
    payload: Any,
    head_sha: str,
    *,
    allow_legacy_cleanup: bool = False,
) -> bool:
    if not isinstance(payload, dict) or payload.get("sha") != head_sha:
        return False
    author = payload.get("author") or {}
    commit = payload.get("commit") or {}
    message = commit.get("message")
    actor_matches = _promotion_actor_matches(author) or (
        allow_legacy_cleanup and _legacy_promotion_actor_matches(author)
    )
    return (
        actor_matches
        and isinstance(message, str)
        and PROMOTION_COMMIT_MESSAGE_RE.fullmatch(message) is not None
    )


def _require_ref_unclaimed_by_open_pr(
    api: GitHubApi,
    branch: str,
    *,
    role: str,
) -> None:
    """Re-prove an exact generated ref is not in use immediately before deletion."""

    if role not in {"head", "base"}:
        raise GovernanceError("promotion cleanup claim role is invalid")
    rows = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    for row in rows:
        if row.get("state") != "open":
            continue
        for claim_role in ("head", "base"):
            subject = row.get(claim_role) or {}
            repository = subject.get("repo") or {}
            if subject.get("ref") == branch and repository.get("full_name") == EXPECTED_REPOSITORY:
                raise PolicyBlock(
                    f"dependency promotion {claim_role} ref became claimed by an open PR "
                    "before cleanup"
                )


def _prune_orphan_promotion_refs(api: GitHubApi, config: dict[str, Any]) -> int:
    open_prs = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    open_heads = {
        str((row.get("head") or {}).get("ref"))
        for row in open_prs
        if isinstance((row.get("head") or {}).get("ref"), str)
        and PROMOTION_BRANCH_RE.fullmatch(str((row.get("head") or {}).get("ref"))) is not None
        and ((row.get("head") or {}).get("repo") or {}).get("full_name") == EXPECTED_REPOSITORY
    }
    open_staged_bases = {
        str((row.get("base") or {}).get("ref"))
        for row in open_prs
        if isinstance((row.get("head") or {}).get("ref"), str)
        and isinstance((row.get("base") or {}).get("ref"), str)
        and PROMOTION_BRANCH_RE.fullmatch(str((row.get("head") or {}).get("ref"))) is not None
        and STAGING_BASE_RE.fullmatch(str((row.get("base") or {}).get("ref"))) is not None
        and ((row.get("head") or {}).get("repo") or {}).get("full_name") == EXPECTED_REPOSITORY
        and ((row.get("base") or {}).get("repo") or {}).get("full_name") == EXPECTED_REPOSITORY
        and str((row.get("head") or {}).get("ref")).removeprefix(BRANCH_PREFIX)
        == str((row.get("base") or {}).get("ref")).removeprefix(STAGING_BASE_PREFIX)
    }
    prefix = f"refs/heads/{BRANCH_PREFIX}"
    refs = api.list_all(f"/git/matching-refs/heads/{BRANCH_PREFIX}", max_pages=4)

    def cleanup_priority(row: dict[str, Any]) -> int:
        ref = row.get("ref")
        if not isinstance(ref, str) or not ref.startswith(prefix):
            return 1
        branch = ref.removeprefix("refs/heads/")
        return 0 if STAGING_BASE_RE.fullmatch(branch) is not None else 1

    pruned = 0
    for row in sorted(refs, key=cleanup_priority):
        ref = row.get("ref")
        if not isinstance(ref, str) or not ref.startswith(prefix):
            raise GovernanceError("GitHub returned a ref outside dependency promotion namespace")
        branch = ref.removeprefix("refs/heads/")
        obj = row.get("object") or {}
        if obj.get("type") != "commit":
            raise PolicyBlock("orphan dependency promotion ref does not point to a commit")
        ref_sha = require_sha(obj.get("sha"), "orphan dependency promotion SHA")

        if STAGING_BASE_RE.fullmatch(branch) is not None:
            if branch in open_staged_bases:
                continue
            suffix = branch.removeprefix(STAGING_BASE_PREFIX)
            generated_branch = f"{BRANCH_PREFIX}{suffix}"
            if PROMOTION_BRANCH_RE.fullmatch(generated_branch) is None:
                raise PolicyBlock("orphan promotion staging-base counterpart is malformed")
            encoded_generated = urllib.parse.quote(generated_branch, safe="")
            generated_ref = api.get(f"/git/ref/heads/{encoded_generated}")
            generated_sha = require_sha(
                ((generated_ref or {}).get("object") or {}).get("sha"),
                "orphan staging-base generated counterpart SHA",
            )
            generated_commit = api.get(f"/commits/{generated_sha}")
            parents = (generated_commit or {}).get("parents")
            if (
                not _owned_generated_promotion_commit(
                    generated_commit,
                    generated_sha,
                    allow_legacy_cleanup=True,
                )
                or not isinstance(parents, list)
                or len(parents) != 1
                or require_sha(
                    (parents[0] or {}).get("sha"),
                    "orphan staging-base counterpart parent SHA",
                )
                != ref_sha
            ):
                raise PolicyBlock(
                    "orphan promotion staging-base lacks exact generated counterpart provenance"
                )
            require_current_control_revision(api, config)
            _delete_exact_ref(
                api,
                branch,
                ref_sha,
                label="orphan promotion staging-base ref",
                claim_role="base",
            )
            pruned += 1
            print(
                json.dumps(
                    {
                        "branch": branch,
                        "baseSha": ref_sha,
                        "decision": "orphan-staging-base-pruned",
                    },
                    sort_keys=True,
                )
            )
            continue

        if PROMOTION_BRANCH_RE.fullmatch(branch) is None:
            raise PolicyBlock("dependency promotion namespace contains an unreviewed branch")
        if branch in open_heads:
            continue
        commit = api.get(f"/commits/{ref_sha}")
        if not _owned_generated_promotion_commit(
            commit,
            ref_sha,
            allow_legacy_cleanup=True,
        ):
            raise PolicyBlock("orphan dependency promotion ref lacks reviewed cleanup provenance")
        require_current_control_revision(api, config)
        _delete_exact_ref(
            api,
            branch,
            ref_sha,
            label="orphan generated promotion ref",
            claim_role="head",
        )
        try:
            encoded_branch = urllib.parse.quote(branch, safe="")
            api.get(f"/git/ref/heads/{encoded_branch}")
        except GovernanceError as exc:
            if "HTTP 404" not in str(exc):
                raise
        else:
            raise GovernanceError("orphan dependency promotion ref still exists after deletion")
        pruned += 1
        print(
            json.dumps(
                {"branch": branch, "headSha": ref_sha, "decision": "orphan-ref-pruned"},
                sort_keys=True,
            )
        )
    return pruned


def _marker(metadata: dict[str, Any]) -> str:
    return (
        MARKER_PREFIX + json.dumps(metadata, separators=(",", ":"), sort_keys=True) + MARKER_SUFFIX
    )


def _parse_marker(body: Any) -> dict[str, Any] | None:
    if not isinstance(body, str):
        return None
    for line in body.splitlines():
        if line.startswith(MARKER_PREFIX) and line.endswith(MARKER_SUFFIX):
            try:
                value = json.loads(line[len(MARKER_PREFIX) : -len(MARKER_SUFFIX)])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _compile(source: dict[str, Any]) -> dict[str, bytes]:
    python311 = os.environ.get("PROMOTION_PYTHON311", "")
    python314 = os.environ.get("PROMOTION_PYTHON314", "")
    if not python311 or not python314:
        raise GovernanceError("PROMOTION_PYTHON311 and PROMOTION_PYTHON314 are required")
    with tempfile.TemporaryDirectory(prefix="aiqa-promotion-") as temporary:
        root = Path(temporary) / "root"
        output = Path(temporary) / "locks"
        (root / "requirements").mkdir(parents=True)
        (root / "pyproject.toml").write_bytes(source["pyproject"])
        shutil.copy2(
            ROOT / "requirements" / "base-image.lock", root / "requirements" / "base-image.lock"
        )
        compile_locks(root, python311, python314, output)
        result = {"pyproject.toml": source["pyproject"]}
        synchronized_readme = _synchronize_readme_sdk_claim(
            source["readme"], source["basePyproject"], source["pyproject"]
        )
        if synchronized_readme != source["readme"]:
            result["README.md"] = synchronized_readme
        for name in (
            "build-py311.lock",
            "dev-py311.lock",
            "dev-py314.lock",
            "runtime-py311.lock",
        ):
            result[f"requirements/{name}"] = (output / name).read_bytes()
        result[".github/lock-authority.json"] = (output / "lock-authority.json").read_bytes()
        return result


def _git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()


def _promotion_commit_matches(payload: Any, *, tree_sha: str, base_sha: str, message: str) -> bool:
    if not isinstance(payload, dict):
        return False
    parents = payload.get("parents")
    return (
        ((payload.get("tree") or {}).get("sha") == tree_sha)
        and isinstance(parents, list)
        and len(parents) == 1
        and isinstance(parents[0], dict)
        and parents[0].get("sha") == base_sha
        and payload.get("message") == message
    )


def _existing_promotion_head(
    api: GitHubApi,
    branch: str,
    *,
    tree_sha: str,
    base_sha: str,
    message: str,
) -> str | None:
    encoded = urllib.parse.quote(branch, safe="")
    try:
        existing = api.get(f"/git/ref/heads/{encoded}")
    except GovernanceError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    head_sha = require_sha(
        ((existing or {}).get("object") or {}).get("sha"),
        "existing promotion branch SHA",
    )
    commit = api.get(f"/git/commits/{head_sha}")
    if not _promotion_commit_matches(
        commit,
        tree_sha=tree_sha,
        base_sha=base_sha,
        message=message,
    ) or not _owned_generated_promotion_commit(api.get(f"/commits/{head_sha}"), head_sha):
        raise PolicyBlock(
            "existing dependency promotion branch does not match the exact independent-App subject"
        )
    return head_sha


def _create_promotion_commit(
    api: GitHubApi,
    source: dict[str, Any],
    branch: str,
    config: dict[str, Any],
) -> tuple[str, dict[str, bytes]]:
    _promotion_author_identity()
    generated = _compile(source)
    base_commit = api.get(f"/git/commits/{source['baseSha']}")
    base_tree = require_sha(
        ((base_commit or {}).get("tree") or {}).get("sha"), "promotion base tree SHA"
    )
    tree_rows = []
    for path, raw in sorted(generated.items()):
        blob = api.post(
            "/git/blobs", {"content": base64.b64encode(raw).decode(), "encoding": "base64"}
        )
        blob_sha = require_sha((blob or {}).get("sha"), f"generated blob SHA for {path}")
        if blob_sha != _git_blob_sha1(raw):
            raise GovernanceError(f"GitHub blob identity mismatch for generated path {path}")
        tree_rows.append({"path": path, "mode": "100644", "type": "blob", "sha": blob_sha})
    tree = api.post("/git/trees", {"base_tree": base_tree, "tree": tree_rows})
    tree_sha = require_sha((tree or {}).get("sha"), "promotion tree SHA")
    message = f"deps: promote Dependabot PR #{source['number']} with synchronized locks"
    existing_head = _existing_promotion_head(
        api,
        branch,
        tree_sha=tree_sha,
        base_sha=source["baseSha"],
        message=message,
    )
    if existing_head is not None:
        return existing_head, generated
    commit = api.post(
        "/git/commits",
        {
            "message": message,
            "tree": tree_sha,
            "parents": [source["baseSha"]],
        },
    )
    head_sha = require_sha((commit or {}).get("sha"), "promotion commit SHA")
    require_current_control_revision(api, config)
    created = api.post("/git/refs", {"ref": f"refs/heads/{branch}", "sha": head_sha})
    if (created or {}).get("ref") != f"refs/heads/{branch}":
        raise GovernanceError("GitHub did not acknowledge dependency promotion branch creation")
    observed = api.get(f"/commits/{head_sha}")
    if not _owned_generated_promotion_commit(observed, head_sha):
        raise GovernanceError(
            "new dependency promotion commit is not authored by the exact independent App"
        )
    try:
        require_current_control_revision(api, config)
    except (GovernanceError, PolicyBlock):
        _delete_exact_generated_branch(api, branch, head_sha)
        raise
    return head_sha, generated


def _delete_exact_ref(
    api: GitHubApi,
    branch: str,
    expected_sha: str,
    *,
    label: str,
    claim_role: str,
) -> None:
    encoded = urllib.parse.quote(branch, safe="")

    def require_exact_ref(*, phase: str) -> None:
        ref = api.get(f"/git/ref/heads/{encoded}")
        obj = (ref or {}).get("object") or {}
        if (ref or {}).get("ref") != f"refs/heads/{branch}" or obj.get("type") != "commit":
            raise PolicyBlock(f"{label} identity changed {phase}")
        observed = require_sha(
            obj.get("sha"),
            f"{label} SHA {phase}",
        )
        if observed != expected_sha:
            raise PolicyBlock(f"{label} changed {phase}")

    require_exact_ref(phase="before exact cleanup")
    _require_ref_unclaimed_by_open_pr(api, branch, role=claim_role)
    require_exact_ref(phase="at terminal cleanup boundary")
    api.request("DELETE", f"/git/refs/heads/{encoded}")


def _delete_exact_generated_branch(api: GitHubApi, branch: str, head_sha: str) -> None:
    _delete_exact_ref(
        api,
        branch,
        head_sha,
        label="generated promotion branch",
        claim_role="head",
    )


def _cleanup_merged_promotion_branch(
    api: GitHubApi,
    promotion: dict[str, Any],
    merge_evidence: dict[str, Any],
    config: dict[str, Any],
) -> None:
    number = promotion.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise GovernanceError("merged promotion cleanup PR number is invalid")
    head_sha = require_sha(promotion.get("headSha"), "merged promotion cleanup head SHA")
    base_sha = require_sha(promotion.get("baseSha"), "merged promotion cleanup base SHA")
    merge_sha = require_sha(merge_evidence.get("mergeSha"), "merged promotion cleanup merge SHA")

    live = api.get(f"/pulls/{number}")
    live_head = (live or {}).get("head") or {}
    branch = live_head.get("ref")
    if not isinstance(branch, str) or PROMOTION_BRANCH_RE.fullmatch(branch) is None:
        raise GovernanceError("merged promotion cleanup branch is invalid")
    live_base = (live or {}).get("base") or {}
    live_user = (live or {}).get("user") or {}
    merge_hint = live.get("merge_commit_sha") if isinstance(live, dict) else None
    if (
        isinstance(merge_hint, str)
        and re.fullmatch(r"[0-9a-f]{40}", merge_hint) is not None
        and merge_hint != merge_sha
    ):
        raise PolicyBlock("merged promotion canonical merge hint conflicts with proven merge")
    if (
        not isinstance(live, dict)
        or live.get("number") != number
        or live.get("state") != "closed"
        or live.get("merged") is not True
        or not _promotion_actor_matches(live_user)
        or live_head.get("ref") != branch
        or require_sha(live_head.get("sha"), "merged promotion live head SHA") != head_sha
        or (live_head.get("repo") or {}).get("full_name") != config["repository"]
        or live_base.get("ref") != config["baseBranch"]
        or require_sha(live_base.get("sha"), "merged promotion live base SHA") != base_sha
        or (live_base.get("repo") or {}).get("full_name") != config["repository"]
    ):
        raise PolicyBlock("merged promotion identity drifted before exact branch cleanup")

    commit = api.get(f"/commits/{head_sha}")
    if not _owned_generated_promotion_commit(commit, head_sha):
        raise PolicyBlock("merged promotion head lacks exact independent-App ownership")

    live_main = require_sha(
        ((api.get("/branches/main") or {}).get("commit") or {}).get("sha"),
        "merged promotion cleanup current-main SHA",
    )
    if live_main != merge_sha:
        raise PolicyBlock("main advanced before merged promotion branch cleanup")

    _delete_exact_generated_branch(api, branch, head_sha)
    encoded_branch = urllib.parse.quote(branch, safe="")
    try:
        api.get(f"/git/ref/heads/{encoded_branch}")
    except GovernanceError as exc:
        if "HTTP 404" not in str(exc):
            raise
    else:
        raise GovernanceError("merged promotion branch still exists after exact cleanup")


def _ensure_staging_base_ref(
    api: GitHubApi,
    source: dict[str, Any],
    config: dict[str, Any],
) -> str:
    """Create or re-prove the exact non-main base used to suppress unsafe PR-open wakes."""

    if config.get("baseBranch") != "main":
        raise GovernanceError("dependency promotion staging requires the reviewed main base")
    source_number = source.get("number")
    fingerprint = source.get("fingerprint")
    if (
        isinstance(source_number, bool)
        or not isinstance(source_number, int)
        or source_number < 1
        or not isinstance(fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
    ):
        raise GovernanceError("promotion staging-base source identity is malformed")
    base_sha = require_sha(source.get("baseSha"), "promotion staging-base source SHA")
    branch = _staging_base_name(source_number, fingerprint)
    encoded = urllib.parse.quote(branch, safe="")
    created_new = False

    try:
        existing = api.get(f"/git/ref/heads/{encoded}")
    except GovernanceError as exc:
        if "HTTP 404" not in str(exc):
            raise
        require_current_control_revision(api, config)
        created = api.post(
            "/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        created_obj = (created or {}).get("object") or {}
        if (created or {}).get("ref") != f"refs/heads/{branch}" or created_obj.get(
            "type"
        ) != "commit":
            raise GovernanceError(
                "GitHub did not acknowledge exact promotion staging-base creation"
            ) from None
        observed = require_sha(
            created_obj.get("sha"),
            "created promotion staging-base SHA",
        )
        created_new = True
    else:
        existing_obj = (existing or {}).get("object") or {}
        if (existing or {}).get("ref") != f"refs/heads/{branch}" or existing_obj.get(
            "type"
        ) != "commit":
            raise PolicyBlock("existing promotion staging-base ref identity drifted")
        observed = require_sha(
            existing_obj.get("sha"),
            "existing promotion staging-base SHA",
        )

    if observed != base_sha:
        raise PolicyBlock("promotion staging-base ref does not equal exact current main")

    if created_new:
        try:
            require_current_control_revision(api, config)
        except (GovernanceError, PolicyBlock):
            _delete_exact_ref(
                api,
                branch,
                base_sha,
                label="promotion staging-base ref",
                claim_role="base",
            )
            raise
    return branch


def _promotion_body(metadata: dict[str, Any]) -> str:
    return "\n".join(
        (
            _marker(metadata),
            "Generated exact-subject Python dependency promotion.",
            "",
            "The source Dependabot branch is never mutated by governance. This subject carries the",
            "exact signed Dependabot pyproject.toml plus deterministic wheel-only hash locks and must",
            "pass the full locked CI, CodeQL, frozen-lock replay proof, and Trusted PR Gate before merge.",
        )
    )


def _validate_promotion_pr_identity(
    pr: dict[str, Any],
    *,
    number: int,
    branch: str,
    head_sha: str,
    base_ref: str,
    base_sha: str,
    repository: str,
) -> None:
    if pr.get("number") != number or pr.get("state") != "open" or pr.get("draft") is not False:
        raise GovernanceError("promotion PR lifecycle drifted from the exact generated subject")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        not _promotion_actor_matches(pr.get("user") or {})
        or (head.get("repo") or {}).get("full_name") != repository
        or (base.get("repo") or {}).get("full_name") != repository
        or head.get("ref") != branch
        or require_sha(head.get("sha"), "promotion PR head SHA") != head_sha
        or base.get("ref") != base_ref
        or require_sha(base.get("sha"), "promotion PR base SHA") != base_sha
    ):
        raise GovernanceError("promotion PR identity drifted from the exact generated subject")


def _validate_promotion_pr_cleanup_identity(
    pr: dict[str, Any],
    *,
    number: int,
    branch: str,
    head_sha: str,
    base_ref: str,
    repository: str,
) -> None:
    """Prove rollback ownership while allowing the target branch SHA to advance."""

    if pr.get("number") != number or pr.get("state") != "open" or pr.get("draft") is not False:
        raise GovernanceError("promotion PR cleanup lifecycle drifted from the created subject")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    require_sha(base.get("sha"), "promotion PR cleanup base SHA")
    if (
        not _promotion_actor_matches(pr.get("user") or {})
        or (head.get("repo") or {}).get("full_name") != repository
        or (base.get("repo") or {}).get("full_name") != repository
        or head.get("ref") != branch
        or require_sha(head.get("sha"), "promotion PR cleanup head SHA") != head_sha
        or base.get("ref") != base_ref
    ):
        raise GovernanceError("promotion PR cleanup identity drifted from the created subject")


def _create_promotion_pr(
    api: GitHubApi,
    source: dict[str, Any],
    branch: str,
    head_sha: str,
    config: dict[str, Any],
) -> int:
    """Create through an exact non-main base, then retarget without a subscribed PR event."""

    _promotion_author_identity()
    metadata = {
        "version": 1,
        "sourcePr": source["number"],
        "sourceHead": source["headSha"],
        "sourceBase": source["sourceBaseSha"],
        "base": source["baseSha"],
        "head": head_sha,
        "fingerprint": source["fingerprint"],
    }
    body = _promotion_body(metadata)
    base_sha = require_sha(source.get("baseSha"), "promotion PR base SHA")
    staging_base = _ensure_staging_base_ref(api, source, config)
    target_base = str(config["baseBranch"])
    try:
        require_current_control_revision(api, config)
    except (GovernanceError, PolicyBlock):
        try:
            _delete_exact_ref(
                api,
                staging_base,
                base_sha,
                label="promotion staging-base ref",
                claim_role="base",
            )
            _delete_exact_generated_branch(api, branch, head_sha)
        except (GovernanceError, PolicyBlock) as cleanup_exc:
            raise GovernanceError(
                "stale control before promotion PR creation could not be fully rolled back; "
                "retaining remaining exact refs for recovery"
            ) from cleanup_exc
        raise

    try:
        pr = api.post(
            "/pulls",
            {
                "title": f"deps: promote Dependabot PR #{source['number']}",
                "head": branch,
                "base": staging_base,
                "body": body,
                "draft": False,
            },
        )
    except GovernanceError as exc:
        # POST is non-replay-safe: a transport failure can occur after GitHub accepted the PR.
        # Without a returned PR number there is no exact subject we can safely close, and deleting
        # either ref could invalidate an actually-created PR before it becomes observable.
        raise GovernanceError(
            "promotion PR creation failed ambiguously after submission; retaining exact staging "
            "and generated refs for recovery"
        ) from exc

    number = (pr or {}).get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise GovernanceError(
            "GitHub promotion PR creation response is ambiguous; retaining exact staging "
            "and generated refs for recovery"
        )

    try:
        _validate_promotion_pr_identity(
            pr,
            number=number,
            branch=branch,
            head_sha=head_sha,
            base_ref=staging_base,
            base_sha=base_sha,
            repository=os.environ.get("GITHUB_REPOSITORY", ""),
        )
        require_current_control_revision(api, config)
        retargeted = api.request("PATCH", f"/pulls/{number}", {"base": target_base})
        if not isinstance(retargeted, dict):
            raise GovernanceError("GitHub returned a malformed promotion retarget response")
        _validate_promotion_pr_identity(
            retargeted,
            number=number,
            branch=branch,
            head_sha=head_sha,
            base_ref=target_base,
            base_sha=base_sha,
            repository=os.environ.get("GITHUB_REPOSITORY", ""),
        )
        require_current_control_revision(api, config)
    except (GovernanceError, PolicyBlock) as exc:
        before_close = api.get(f"/pulls/{number}")
        before_base = (before_close or {}).get("base") or {}
        cleanup_base_ref = before_base.get("ref")
        if cleanup_base_ref not in {staging_base, target_base}:
            raise GovernanceError(
                "malformed promotion PR base drifted outside rollback authority; "
                "retaining exact refs"
            ) from exc
        try:
            _validate_promotion_pr_cleanup_identity(
                before_close,
                number=number,
                branch=branch,
                head_sha=head_sha,
                base_ref=str(cleanup_base_ref),
                repository=os.environ.get("GITHUB_REPOSITORY", ""),
            )
        except (GovernanceError, PolicyBlock) as cleanup_exc:
            raise GovernanceError(
                "malformed promotion PR could not be proven exact for cleanup; retaining exact refs"
            ) from cleanup_exc
        if (
            before_close.get("title") != f"deps: promote Dependabot PR #{source['number']}"
            or before_close.get("body") != body
        ):
            raise GovernanceError(
                "malformed promotion PR metadata drifted before cleanup; retaining exact refs"
            ) from exc
        closed = api.request("PATCH", f"/pulls/{number}", {"state": "closed"})
        if (
            not isinstance(closed, dict)
            or closed.get("number") != number
            or closed.get("state") != "closed"
        ):
            raise GovernanceError(
                "malformed promotion PR could not be durably closed; retaining exact refs"
            ) from exc
        _delete_exact_ref(
            api,
            staging_base,
            base_sha,
            label="promotion staging-base ref",
            claim_role="base",
        )
        _delete_exact_generated_branch(api, branch, head_sha)
        raise

    _delete_exact_ref(
        api,
        staging_base,
        base_sha,
        label="promotion staging-base ref",
        claim_role="base",
    )
    return number


def _normalize_staged_promotion(
    api: GitHubApi,
    pr: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    if pr.get("state") != "open" or pr.get("draft") is not False:
        raise PolicyBlock("staged promotion is no longer open and non-draft")
    base = pr.get("base") or {}
    if base.get("ref") == config["baseBranch"]:
        return pr
    metadata = _parse_marker(pr.get("body"))
    if metadata is None or metadata.get("version") != 1:
        raise PolicyBlock("staged promotion lacks exact promotion marker")
    source_number = metadata.get("sourcePr")
    fingerprint = metadata.get("fingerprint")
    if not isinstance(source_number, int) or not isinstance(fingerprint, str):
        raise PolicyBlock("staged promotion marker identity is malformed")
    expected_base = _staging_base_name(source_number, fingerprint)
    if base.get("ref") != expected_base or STAGING_BASE_RE.fullmatch(expected_base) is None:
        raise PolicyBlock("promotion targets an unreviewed non-main base")
    user = pr.get("user") or {}
    head = pr.get("head") or {}
    if (
        not _promotion_actor_matches(user)
        or (head.get("repo") or {}).get("full_name") != config["repository"]
        or (base.get("repo") or {}).get("full_name") != config["repository"]
        or head.get("ref")
        != _branch_name(
            {
                "number": source_number,
                "fingerprint": fingerprint,
            }
        )
        or require_sha(head.get("sha"), "staged promotion head SHA") != metadata.get("head")
        or require_sha(base.get("sha"), "staged promotion base SHA") != metadata.get("base")
    ):
        raise PolicyBlock("staged promotion identity drifted before retarget")
    live = api.get(f"/branches/{urllib.parse.quote(config['baseBranch'], safe='')}")
    live_sha = require_sha(((live or {}).get("commit") or {}).get("sha"), "live main SHA")
    if live_sha != metadata.get("base"):
        raise PolicyBlock("promotion is stale relative to current main")
    encoded = urllib.parse.quote(expected_base, safe="")
    staging_ref = api.get(f"/git/ref/heads/{encoded}")
    if (
        require_sha(
            ((staging_ref or {}).get("object") or {}).get("sha"),
            "staged promotion ref SHA",
        )
        != live_sha
    ):
        raise PolicyBlock("promotion staging-base ref drifted before retarget")
    number = pr.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise PolicyBlock("staged promotion PR number is invalid")
    require_current_control_revision(api, config)
    try:
        retargeted = api.request("PATCH", f"/pulls/{number}", {"base": config["baseBranch"]})
    except GovernanceError as retarget_error:
        converged = api.get(f"/pulls/{number}")
        rebound = dict(converged) if isinstance(converged, dict) else {}
        rebound["state"] = "open"
        try:
            _validate_promotion_pr_identity(
                rebound,
                number=number,
                branch=str(head.get("ref")),
                head_sha=str(metadata["head"]),
                base_ref=expected_base,
                base_sha=live_sha,
                repository=config["repository"],
            )
        except (GovernanceError, PolicyBlock) as validation_error:
            raise retarget_error from validation_error
        if (
            not isinstance(converged, dict)
            or converged.get("state") != "closed"
            or converged.get("title") != pr.get("title")
            or converged.get("body") != pr.get("body")
        ):
            raise retarget_error
        raise PolicyBlock(
            "staged promotion closed before retarget; reconciliation already converged"
        ) from retarget_error
    if not isinstance(retargeted, dict):
        raise GovernanceError("GitHub returned a malformed staged promotion retarget response")
    _validate_promotion_pr_identity(
        retargeted,
        number=number,
        branch=str(head.get("ref")),
        head_sha=str(metadata["head"]),
        base_ref=config["baseBranch"],
        base_sha=live_sha,
        repository=config["repository"],
    )
    require_current_control_revision(api, config)
    _delete_exact_ref(
        api,
        expected_base,
        live_sha,
        label="promotion staging-base ref",
        claim_role="base",
    )
    return retargeted


def _publish_status_sync_outputs(
    github_output: Path | None,
    result: dict[str, Any] | None,
) -> None:
    if github_output is None or result is None:
        return
    expected = os.environ.get("GITHUB_OUTPUT")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or not expected
        or Path(expected) != github_output
    ):
        raise GovernanceError(
            "status synchronization output is not the exact GitHub Actions output file"
        )
    pr_number = result.get("prNumber")
    lane = result.get("lane")
    if (
        isinstance(pr_number, bool)
        or not isinstance(pr_number, int)
        or pr_number < 1
        or lane not in {"dependency-promotion", "dependabot-actions"}
    ):
        raise GovernanceError("status synchronization output identity is malformed")
    payload = f"pr_number={pr_number}\nlane={lane}\n".encode()
    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(github_output, flags)
    except OSError as exc:
        raise GovernanceError(
            f"unable to open exact GitHub Actions status synchronization output: {exc}"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise GovernanceError(
                "GitHub Actions status synchronization output is not an owned regular file"
            )
        if os.write(descriptor, payload) != len(payload):
            raise GovernanceError(
                "GitHub Actions status synchronization output write was incomplete"
            )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_merge_signal(github_output: Path | None) -> None:
    if github_output is None:
        return
    expected = os.environ.get("GITHUB_OUTPUT")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or not expected
        or Path(expected) != github_output
    ):
        raise GovernanceError("merge signal output is not the exact GitHub Actions output file")
    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(github_output, flags)
    except OSError as exc:
        raise GovernanceError(f"unable to open exact GitHub Actions merge output: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise GovernanceError("GitHub Actions merge output is not an owned regular file")
        payload = b"merged=true\n"
        if os.write(descriptor, payload) != len(payload):
            raise GovernanceError("GitHub Actions merge output write was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _promotion_pulls(api: GitHubApi) -> list[dict[str, Any]]:
    rows = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    return [
        row
        for row in rows
        if (
            _promotion_actor_matches(row.get("user") or {})
            or _legacy_promotion_actor_matches(row.get("user") or {})
        )
        and isinstance(((row.get("head") or {}).get("ref")), str)
        and str((row.get("head") or {}).get("ref")).startswith(BRANCH_PREFIX)
        and _parse_marker(row.get("body")) is not None
    ]


def _require_green(api: GitHubApi, head_sha: str, config: dict[str, Any]) -> None:
    require_green_checks(api, head_sha, config)


def _validate_generated_bytes(api: GitHubApi, source: dict[str, Any], head_sha: str) -> None:
    python311 = os.environ.get("PROMOTION_PYTHON311", "")
    python314 = os.environ.get("PROMOTION_PYTHON314", "")
    if not python311 or not python314:
        raise GovernanceError("PROMOTION_PYTHON311 and PROMOTION_PYTHON314 are required")
    observed = {path: _contents_bytes(api, path, head_sha) for path in PROMOTION_PATHS}
    if observed["pyproject.toml"] != source["pyproject"]:
        raise PolicyBlock("promotion pyproject.toml differs from exact Dependabot source")
    expected_readme = _synchronize_readme_sdk_claim(
        source["readme"], source["basePyproject"], source["pyproject"]
    )
    if observed["README.md"] != expected_readme:
        raise PolicyBlock("promotion README.md differs from exact synchronized SDK claim")
    with tempfile.TemporaryDirectory(prefix="aiqa-promotion-replay-") as temporary:
        root = Path(temporary) / "root"
        bundle = Path(temporary) / "bundle"
        (root / "requirements").mkdir(parents=True)
        bundle.mkdir()
        (root / "pyproject.toml").write_bytes(observed["pyproject.toml"])
        shutil.copy2(
            ROOT / "requirements" / "base-image.lock", root / "requirements" / "base-image.lock"
        )
        for name in (
            "build-py311.lock",
            "dev-py311.lock",
            "dev-py314.lock",
            "runtime-py311.lock",
        ):
            (bundle / name).write_bytes(observed[f"requirements/{name}"])
        (bundle / "lock-authority.json").write_bytes(observed[".github/lock-authority.json"])
        try:
            validate_frozen_locks(root, python311, python314, bundle)
        except LockCompileError as exc:
            raise PolicyBlock(f"promotion frozen lock replay failed: {exc}") from exc


def _require_promotion_lifecycle(
    pr: dict[str, Any],
    metadata: dict[str, Any],
    *,
    base_sha: str,
    live_sha: str,
) -> None:
    if pr.get("state") != "open" or pr.get("draft") is not False:
        raise PolicyBlock("promotion PR is not open and non-draft")
    if base_sha != live_sha or metadata.get("base") != live_sha:
        raise PolicyBlock("promotion is stale relative to current main")
    if pr.get("mergeable") is not True:
        raise PolicyBlock("promotion PR is not definitively mergeable")


def _validate_promotion_changed_paths(files: list[dict[str, Any]]) -> set[str]:
    """Require an exact ordinary-modification file set for generated promotions."""

    if not files:
        raise PolicyBlock("promotion has no changed files")
    paths: set[str] = set()
    for row in files:
        path = row.get("filename")
        if not isinstance(path, str) or path not in PROMOTION_PATHS:
            raise PolicyBlock(f"promotion changed path is outside generated authority: {path!r}")
        if path in paths:
            raise PolicyBlock(f"promotion changed-file list is ambiguous for path: {path}")
        if row.get("status") != "modified" or row.get("previous_filename") is not None:
            raise PolicyBlock(
                "promotion generated paths must be ordinary modified files without rename provenance"
            )
        paths.add(path)
    if "pyproject.toml" not in paths or ".github/lock-authority.json" not in paths:
        raise PolicyBlock(
            f"promotion changed-path set is outside generated authority: {sorted(paths)}"
        )
    return paths


def _validate_promotion(
    api: GitHubApi,
    pr: dict[str, Any],
    config: dict[str, Any],
    *,
    validate_generated_bytes: bool = True,
    require_checks: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = _parse_marker(pr.get("body"))
    if metadata is None or metadata.get("version") != 1:
        raise PolicyBlock("promotion PR lacks exact promotion marker")
    if not _promotion_actor_matches(pr.get("user") or {}):
        raise PolicyBlock("promotion PR is not authored by the independent promotion App")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (head.get("repo") or {}).get("full_name") != config["repository"] or (
        base.get("repo") or {}
    ).get("full_name") != config["repository"]:
        raise PolicyBlock("promotion PR is not repository-owned")
    if base.get("ref") != config["baseBranch"]:
        raise PolicyBlock("promotion PR no longer targets main")
    head_sha = require_sha(head.get("sha"), "promotion head SHA")
    base_sha = require_sha(base.get("sha"), "promotion base SHA")
    live = api.get(f"/branches/{urllib.parse.quote(config['baseBranch'], safe='')}")
    live_sha = require_sha(((live or {}).get("commit") or {}).get("sha"), "live main SHA")
    _require_promotion_lifecycle(
        pr,
        metadata,
        base_sha=base_sha,
        live_sha=live_sha,
    )
    if metadata.get("head") != head_sha:
        raise PolicyBlock("promotion head changed after generation")
    source_number = metadata.get("sourcePr")
    if not isinstance(source_number, int) or source_number < 1:
        raise PolicyBlock("promotion source PR number is invalid")
    source = source_subject(api, api.get(f"/pulls/{source_number}"), config)
    if (
        source["headSha"] != metadata.get("sourceHead")
        or source["sourceBaseSha"] != metadata.get("sourceBase")
        or source["fingerprint"] != metadata.get("fingerprint")
    ):
        raise PolicyBlock("source Dependabot PR changed after promotion generation")
    commit = api.get(f"/commits/{head_sha}")
    if not _owned_generated_promotion_commit(commit, head_sha):
        raise PolicyBlock("promotion head lacks exact independent-App ownership")
    parents = (commit or {}).get("parents")
    if (
        not isinstance(parents, list)
        or len(parents) != 1
        or require_sha((parents[0] or {}).get("sha"), "promotion parent SHA") != live_sha
    ):
        raise PolicyBlock("promotion commit is not directly parented to exact current main")
    files = api.list_all(f"/pulls/{pr['number']}/files", max_pages=2)
    _validate_promotion_changed_paths(files)
    if validate_generated_bytes:
        _validate_generated_bytes(api, source, head_sha)
    if require_checks:
        _require_green(api, head_sha, config)
    return source, {"number": pr["number"], "headSha": head_sha, "baseSha": base_sha}


def _qualification_wake_stage(
    api: GitHubApi,
    promotion: dict[str, Any],
) -> str | None:
    head_sha = require_sha(promotion.get("headSha"), "promotion qualification head SHA")
    base_sha = require_sha(promotion.get("baseSha"), "promotion qualification base SHA")
    rows = api.list_all(
        f"/commits/{head_sha}/check-runs?filter=all",
        max_pages=2,
    )
    matches: list[tuple[int, str]] = []
    for row in rows:
        if row.get("name") != QUALIFICATION_WAKE_CHECK:
            continue
        external_id = row.get("external_id")
        if not isinstance(external_id, str):
            raise GovernanceError("promotion qualification wake has no external identity")
        match = QUALIFICATION_WAKE_RE.fullmatch(external_id)
        if match is None:
            raise GovernanceError("promotion qualification wake external identity is malformed")
        if match.group("head") != head_sha or match.group("base") != base_sha:
            raise GovernanceError("promotion qualification wake subject drifted")
        app = row.get("app") or {}
        if (
            row.get("head_sha") != head_sha
            or row.get("status") != "completed"
            or row.get("conclusion") != "neutral"
            or app.get("id") != GITHUB_ACTIONS_APP_ID
            or app.get("slug") != "github-actions"
        ):
            raise GovernanceError("promotion qualification wake check provenance is invalid")
        run_id = int(match.group("run"))
        run_attempt = int(match.group("attempt"))
        check_id = row.get("id")
        if not isinstance(check_id, int) or isinstance(check_id, bool) or check_id < 1:
            raise GovernanceError("promotion qualification wake check id is invalid")
        if not _actions_check_details_url_is_canonical(
            row.get("details_url"),
            check_id=check_id,
            run_id=run_id,
        ):
            raise GovernanceError("promotion qualification wake details URL is not canonical")
        run = api.get(f"/actions/runs/{run_id}")
        repository = (run or {}).get("repository") or {}
        head_repository = (run or {}).get("head_repository") or {}
        if (
            (run or {}).get("id") != run_id
            or (run or {}).get("run_attempt") != run_attempt
            or (run or {}).get("name") != DEPENDENCY_GOVERNANCE_WORKFLOW_NAME
            or (run or {}).get("path") != DEPENDENCY_GOVERNANCE_WORKFLOW_PATH
            or (run or {}).get("event") not in DEPENDENCY_GOVERNANCE_EVENTS
            or (run or {}).get("head_branch") != "main"
            or (run or {}).get("head_sha") != base_sha
            or (run or {}).get("status") != "completed"
            or (run or {}).get("conclusion") != "success"
            or repository.get("full_name") != EXPECTED_REPOSITORY
            or head_repository.get("full_name") != EXPECTED_REPOSITORY
        ):
            raise GovernanceError("promotion qualification wake workflow provenance is invalid")
        matches.append((check_id, match.group("stage")))
    return max(matches)[1] if matches else None


def _publish_qualification_wake(
    api: GitHubApi,
    promotion: dict[str, Any],
    *,
    stage: str,
) -> None:
    if stage != "trusted-gate":
        raise GovernanceError("promotion qualification wake stage is outside reviewed authority")
    head_sha = require_sha(promotion.get("headSha"), "promotion qualification head SHA")
    base_sha = require_sha(promotion.get("baseSha"), "promotion qualification base SHA")
    raw_run_id = os.environ.get("GITHUB_RUN_ID", "")
    raw_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not raw_run_id.isdigit() or not raw_attempt.isdigit():
        raise GovernanceError("workflow run identity is required for qualification wake evidence")
    run_id = int(raw_run_id)
    run_attempt = int(raw_attempt)
    if run_id < 1 or run_attempt < 1:
        raise GovernanceError("workflow run identity for qualification wake must be positive")
    external_id = (
        f"{QUALIFICATION_WAKE_PREFIX}:{head_sha}:{base_sha}:{stage}:{run_id}:{run_attempt}"
    )
    details_url = f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"
    response = api.post(
        "/check-runs",
        {
            "name": QUALIFICATION_WAKE_CHECK,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "neutral",
            "details_url": details_url,
            "external_id": external_id,
            "output": {
                "title": "Trusted-main automatic gate qualification wake registered",
                "summary": (
                    "Wake evidence only; this check is not validation authority and cannot "
                    "satisfy Required PR Gate, CodeQL, or Trusted PR Gate."
                ),
            },
        },
    )
    app = (response or {}).get("app") or {}
    if (
        not isinstance(response, dict)
        or response.get("name") != QUALIFICATION_WAKE_CHECK
        or response.get("head_sha") != head_sha
        or response.get("status") != "completed"
        or response.get("conclusion") != "neutral"
        or response.get("external_id") != external_id
        or app.get("id") != GITHUB_ACTIONS_APP_ID
        or app.get("slug") != "github-actions"
    ):
        raise GovernanceError("GitHub did not acknowledge exact promotion qualification wake")
    response_id = response.get("id")
    if (
        not isinstance(response_id, int)
        or isinstance(response_id, bool)
        or response_id < 1
        or not _actions_check_details_url_is_canonical(
            response.get("details_url"),
            check_id=response_id,
            run_id=run_id,
        )
    ):
        raise GovernanceError("GitHub returned a non-canonical promotion wake details URL")


def _exact_terminal_trusted_gate_state(
    api: GitHubApi,
    promotion: dict[str, Any],
) -> str | None:
    head_sha = require_sha(promotion.get("headSha"), "promotion trusted gate head SHA")
    base_sha = require_sha(promotion.get("baseSha"), "promotion trusted gate base SHA")
    number = promotion.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise GovernanceError("promotion trusted gate PR number is invalid")
    merge_ref = api.get(f"/git/ref/pull/{number}/merge")
    if (
        not isinstance(merge_ref, dict)
        or merge_ref.get("ref") != f"refs/pull/{number}/merge"
        or ((merge_ref.get("object") or {}).get("type")) != "commit"
    ):
        raise PolicyBlock("promotion trusted gate merge ref is unavailable")
    merge_sha = require_sha(
        (merge_ref.get("object") or {}).get("sha"),
        "promotion trusted gate merge SHA",
    )
    matches: list[dict[str, Any]] = []
    for row in api.list_all(f"/commits/{head_sha}/statuses", max_pages=4):
        if row.get("context") != TRUSTED_STATUS_CONTEXT:
            continue
        creator = row.get("creator") or {}
        if (
            creator.get("login") != TRUSTED_STATUS_BOT_LOGIN
            or creator.get("id") != TRUSTED_STATUS_BOT_ID
            or creator.get("type") != "Bot"
        ):
            continue
        target_url = row.get("target_url")
        match = TARGET_URL_RE.fullmatch(target_url) if isinstance(target_url, str) else None
        if (
            match is None
            or int(match.group("pr")) != number
            or match.group("base") != base_sha
            or match.group("head") != head_sha
            or match.group("merge") != merge_sha
        ):
            continue
        status_id = row.get("id")
        if isinstance(status_id, bool) or not isinstance(status_id, int) or status_id < 1:
            raise GovernanceError("exact Trusted PR Gate status id is invalid")
        matches.append(row)
    if not matches:
        return None
    latest = max(matches, key=lambda row: int(row["id"]))
    state = latest.get("state")
    if state not in {"pending", "success", "failure", "error"}:
        raise GovernanceError("exact Trusted PR Gate status state is invalid")
    return str(state)


def _advance_promotion_qualification(
    api: GitHubApi,
    promotion: dict[str, Any],
    branch: str,
    config: dict[str, Any],
) -> None:
    if PROMOTION_BRANCH_RE.fullmatch(branch) is None:
        raise PolicyBlock("promotion qualification branch is outside reviewed authority")
    terminal_state = _exact_terminal_trusted_gate_state(api, promotion)
    if terminal_state is not None:
        raise PolicyBlock(
            "automatic Trusted PR Gate already has exact-subject state "
            f"{terminal_state}; refusing duplicate qualification wake"
        )
    wake_stage = _qualification_wake_stage(api, promotion)
    if wake_stage is not None:
        raise PolicyBlock("automatic Trusted PR Gate qualification wake is registered and pending")
    require_current_control_revision(api, config)
    _publish_qualification_wake(api, promotion, stage="trusted-gate")
    raise QualificationWakeRegistered("automatic Trusted PR Gate qualification wake registered")


def _publish_and_merge(
    api: GitHubApi, promotion: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    fresh_before_merge = api.get(f"/pulls/{promotion['number']}")
    _, rebound_before_merge = _validate_promotion(
        api, fresh_before_merge, config, require_checks=False
    )
    if rebound_before_merge != promotion:
        raise PolicyBlock("promotion changed before guarded merge")
    branch = str((fresh_before_merge.get("head") or {}).get("ref") or "")
    try:
        gate_evidence = require_promotion_trusted_gate(
            api,
            promotion["number"],
            promotion["headSha"],
            promotion["baseSha"],
        )
    except TrustedStatusError as exc:
        _advance_promotion_qualification(api, promotion, branch, config)
        raise GovernanceError("promotion qualification wake returned unexpectedly") from exc
    require_exact_automation_approval(
        api,
        number=promotion["number"],
        head_sha=promotion["headSha"],
        base_sha=promotion["baseSha"],
        gate_evidence=gate_evidence,
    )
    terminal_pr = api.get(f"/pulls/{promotion['number']}")
    _, terminal_promotion = _validate_promotion(api, terminal_pr, config, require_checks=False)
    if terminal_promotion != promotion:
        raise PolicyBlock("promotion changed after automation approval")
    try:
        terminal_gate_evidence = require_promotion_trusted_gate(
            api,
            promotion["number"],
            promotion["headSha"],
            promotion["baseSha"],
        )
    except TrustedStatusError as exc:
        raise PolicyBlock("Trusted PR Gate changed after automation approval") from exc
    if terminal_gate_evidence != gate_evidence:
        raise PolicyBlock("Trusted PR Gate evidence changed after automation approval")
    require_current_control_revision(api, config)
    require_exact_automation_approval(
        api,
        number=promotion["number"],
        head_sha=promotion["headSha"],
        base_sha=promotion["baseSha"],
        gate_evidence=terminal_gate_evidence,
    )
    result = api.put(
        f"/pulls/{promotion['number']}/merge",
        {"sha": promotion["headSha"], "merge_method": config["mergeMethod"]},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        raise GovernanceError(
            f"GitHub declined dependency promotion merge: {(result or {}).get('message')}"
        )
    merge_evidence = finalize_post_merge_evidence(api, result, promotion, config)
    _cleanup_merged_promotion_branch(api, promotion, merge_evidence, config)
    return merge_evidence


def _close_stale(
    api: GitHubApi,
    number: int,
    branch: str,
    head_sha: str,
    config: dict[str, Any],
) -> None:
    if PROMOTION_BRANCH_RE.fullmatch(branch) is None:
        raise PolicyBlock("stale promotion branch is outside reviewed authority")
    fresh = api.get(f"/pulls/{number}")
    fresh_head = (fresh or {}).get("head") or {}
    fresh_base = (fresh or {}).get("base") or {}
    metadata = _parse_marker((fresh or {}).get("body"))
    if (
        (fresh or {}).get("state") != "open"
        or (fresh or {}).get("draft") is not False
        or not _promotion_actor_matches((fresh or {}).get("user") or {})
        or (fresh_head.get("repo") or {}).get("full_name") != config["repository"]
        or (fresh_base.get("repo") or {}).get("full_name") != config["repository"]
        or fresh_head.get("ref") != branch
        or require_sha(fresh_head.get("sha"), "stale promotion live head SHA") != head_sha
        or metadata is None
        or metadata.get("version") != 1
        or metadata.get("head") != head_sha
    ):
        raise PolicyBlock("stale promotion changed before exact cleanup")

    staging_base: str | None = None
    if fresh_base.get("ref") != config["baseBranch"]:
        source_number = metadata.get("sourcePr")
        fingerprint = metadata.get("fingerprint")
        if not isinstance(source_number, int) or not isinstance(fingerprint, str):
            raise PolicyBlock("stale staged promotion marker identity is malformed")
        staging_base = _staging_base_name(source_number, fingerprint)
        if fresh_base.get("ref") != staging_base or require_sha(
            fresh_base.get("sha"), "stale promotion staging-base SHA"
        ) != require_sha(metadata.get("base"), "stale promotion marker base SHA"):
            raise PolicyBlock("stale promotion staging-base identity drifted before cleanup")

    commit = api.get(f"/commits/{head_sha}")
    if not _owned_generated_promotion_commit(commit, head_sha):
        raise PolicyBlock("stale promotion head lacks exact independent-App ownership")
    require_current_control_revision(api, config)
    closed = api.request("PATCH", f"/pulls/{number}", {"state": "closed"})
    if not isinstance(closed, dict) or closed.get("state") != "closed":
        raise GovernanceError("GitHub did not acknowledge stale promotion closure")
    if staging_base is not None:
        require_current_control_revision(api, config)
        _delete_exact_ref(
            api,
            staging_base,
            require_sha(metadata.get("base"), "stale promotion marker base SHA"),
            label="stale promotion staging-base ref",
            claim_role="base",
        )
    require_current_control_revision(api, config)
    _delete_exact_generated_branch(api, branch, head_sha)


def _remaining_exact_legacy_head_claims(
    api: GitHubApi,
    *,
    branch: str,
    head_sha: str,
    source_number: int,
    fingerprint: str,
) -> list[int]:
    """Identify only exact legacy duplicate PRs still claiming a generated head."""

    rows = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    remaining: list[int] = []
    for row in rows:
        head = row.get("head") or {}
        repository = head.get("repo") or {}
        if head.get("ref") != branch or repository.get("full_name") != EXPECTED_REPOSITORY:
            continue
        metadata = _parse_marker(row.get("body"))
        number = row.get("number")
        if (
            not _legacy_promotion_actor_matches(row.get("user") or {})
            or row.get("state") != "open"
            or row.get("draft") is not False
            or isinstance(number, bool)
            or not isinstance(number, int)
            or number < 1
            or require_sha(head.get("sha"), "remaining legacy promotion head SHA") != head_sha
            or metadata is None
            or metadata.get("version") != 1
            or metadata.get("sourcePr") != source_number
            or metadata.get("fingerprint") != fingerprint
            or metadata.get("head") != head_sha
            or row.get("title") != f"deps: promote Dependabot PR #{source_number}"
        ):
            raise PolicyBlock(
                "generated promotion branch is claimed by a non-exact legacy subject during cleanup"
            )
        remaining.append(number)
    return sorted(remaining)


def _retire_legacy_promotion(
    api: GitHubApi,
    number: int,
    branch: str,
    head_sha: str,
    config: dict[str, Any],
) -> None:
    """Remove one exact pre-App promotion without granting it merge authority."""

    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
        or PROMOTION_BRANCH_RE.fullmatch(branch) is None
    ):
        raise PolicyBlock("legacy promotion cleanup identity is malformed")
    fresh = api.get(f"/pulls/{number}")
    head = (fresh or {}).get("head") or {}
    base = (fresh or {}).get("base") or {}
    metadata = _parse_marker((fresh or {}).get("body"))
    if (
        not isinstance(fresh, dict)
        or fresh.get("number") != number
        or fresh.get("state") != "open"
        or fresh.get("draft") is not False
        or not _legacy_promotion_actor_matches(fresh.get("user") or {})
        or (head.get("repo") or {}).get("full_name") != config["repository"]
        or (base.get("repo") or {}).get("full_name") != config["repository"]
        or head.get("ref") != branch
        or require_sha(head.get("sha"), "legacy promotion head SHA") != head_sha
        or metadata is None
        or metadata.get("version") != 1
        or metadata.get("head") != head_sha
    ):
        raise PolicyBlock("legacy promotion changed before exact retirement")

    initial_base_sha = require_sha(base.get("sha"), "legacy promotion initial base SHA")
    source_number = metadata.get("sourcePr")
    fingerprint = metadata.get("fingerprint")
    if (
        isinstance(source_number, bool)
        or not isinstance(source_number, int)
        or source_number < 1
        or not isinstance(fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        or branch != _branch_name({"number": source_number, "fingerprint": fingerprint})
        or fresh.get("title") != f"deps: promote Dependabot PR #{source_number}"
    ):
        raise PolicyBlock("legacy promotion marker does not bind the exact reserved subject")

    marker_base = require_sha(metadata.get("base"), "legacy promotion marker base SHA")
    require_sha(metadata.get("sourceHead"), "legacy promotion source head SHA")
    require_sha(metadata.get("sourceBase"), "legacy promotion source base SHA")
    staging_base: str | None = None
    if base.get("ref") == config["baseBranch"]:
        pass
    else:
        staging_base = _staging_base_name(source_number, fingerprint)
        if base.get("ref") != staging_base or initial_base_sha != marker_base:
            raise PolicyBlock("legacy promotion base is outside exact migration authority")

    commit = api.get(f"/commits/{head_sha}")
    author = (commit or {}).get("author") or {}
    details = (commit or {}).get("commit") or {}
    parents = (commit or {}).get("parents")
    if (
        not isinstance(commit, dict)
        or commit.get("sha") != head_sha
        or not _legacy_promotion_actor_matches(author)
        or details.get("message")
        != f"deps: promote Dependabot PR #{source_number} with synchronized locks"
        or not isinstance(parents, list)
        or len(parents) != 1
        or require_sha((parents[0] or {}).get("sha"), "legacy promotion parent SHA") != marker_base
    ):
        raise PolicyBlock("legacy promotion commit provenance is outside migration authority")

    files = api.list_all(f"/pulls/{number}/files", max_pages=2)
    paths = {str(row.get("filename")) for row in files if isinstance(row.get("filename"), str)}
    if (
        not paths
        or not paths <= PROMOTION_PATHS
        or "pyproject.toml" not in paths
        or ".github/lock-authority.json" not in paths
    ):
        raise PolicyBlock("legacy promotion changed-path set is outside migration authority")

    before_close = api.get(f"/pulls/{number}")
    before_head = (before_close or {}).get("head") or {}
    before_base = (before_close or {}).get("base") or {}
    before_base_sha = require_sha(before_base.get("sha"), "legacy promotion pre-close base SHA")
    if (
        not isinstance(before_close, dict)
        or before_close.get("number") != number
        or before_close.get("state") != "open"
        or before_close.get("draft") is not False
        or not _legacy_promotion_actor_matches(before_close.get("user") or {})
        or before_close.get("title") != fresh.get("title")
        or before_close.get("body") != fresh.get("body")
        or before_head.get("ref") != branch
        or require_sha(before_head.get("sha"), "legacy promotion pre-close head SHA") != head_sha
        or (before_head.get("repo") or {}).get("full_name") != config["repository"]
        or before_base.get("ref") != base.get("ref")
        or before_base_sha != initial_base_sha
        or (before_base.get("repo") or {}).get("full_name") != config["repository"]
    ):
        raise PolicyBlock("legacy promotion changed during retirement revalidation")

    require_current_control_revision(api, config)
    closed = api.request("PATCH", f"/pulls/{number}", {"state": "closed"})
    if (
        not isinstance(closed, dict)
        or closed.get("number") != number
        or closed.get("state") != "closed"
    ):
        raise GovernanceError("GitHub did not acknowledge legacy promotion retirement")
    if staging_base is not None:
        require_current_control_revision(api, config)
        _delete_exact_ref(
            api,
            staging_base,
            marker_base,
            label="legacy promotion staging-base ref",
            claim_role="base",
        )
    remaining_claims = _remaining_exact_legacy_head_claims(
        api,
        branch=branch,
        head_sha=head_sha,
        source_number=source_number,
        fingerprint=fingerprint,
    )
    if remaining_claims:
        return
    require_current_control_revision(api, config)
    _delete_exact_generated_branch(api, branch, head_sha)


def reconcile_status_target(
    config: dict[str, Any],
    *,
    target_pr_number: int,
    allow_merge: bool,
    github_output: Path | None = None,
) -> int:
    """Merge only the exact promotion admitted by the trusted status synchronization job."""

    if config.get("pipMode") != "promotion":
        raise GovernanceError("dependency promotion requires pipMode=promotion")
    if (
        isinstance(target_pr_number, bool)
        or not isinstance(target_pr_number, int)
        or target_pr_number < 1
    ):
        raise GovernanceError("status-target promotion PR number is invalid")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != config["repository"]:
        raise GovernanceError("workflow repository does not match dependency promotion config")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    require_current_control_revision(api, config)
    live_pr = api.get(f"/pulls/{target_pr_number}")
    _, promotion = _validate_promotion(api, live_pr, config, require_checks=False)
    if promotion["number"] != target_pr_number:
        raise GovernanceError("status-target promotion identity drifted during revalidation")
    print(
        json.dumps(
            {"pr": target_pr_number, "decision": "status-target-promotion-qualified"},
            sort_keys=True,
        )
    )
    if not allow_merge or not config["automergeEnabled"]:
        return 0
    fresh_before_merge = api.get(f"/pulls/{target_pr_number}")
    _, rebound_before_merge = _validate_promotion(
        api,
        fresh_before_merge,
        config,
        require_checks=False,
    )
    if rebound_before_merge != promotion:
        raise PolicyBlock("status-target promotion changed before guarded merge")
    try:
        gate_evidence = require_promotion_trusted_gate(
            api,
            promotion["number"],
            promotion["headSha"],
            promotion["baseSha"],
        )
    except TrustedStatusError as exc:
        raise PolicyBlock(
            "status-target Trusted PR Gate is no longer exact-subject admissible"
        ) from exc
    require_exact_automation_approval(
        api,
        number=promotion["number"],
        head_sha=promotion["headSha"],
        base_sha=promotion["baseSha"],
        gate_evidence=gate_evidence,
    )
    terminal_pr = api.get(f"/pulls/{target_pr_number}")
    _, terminal_promotion = _validate_promotion(
        api,
        terminal_pr,
        config,
        require_checks=False,
    )
    if terminal_promotion != promotion:
        raise PolicyBlock("status-target promotion changed after automation approval")
    try:
        terminal_gate_evidence = require_promotion_trusted_gate(
            api,
            promotion["number"],
            promotion["headSha"],
            promotion["baseSha"],
        )
    except TrustedStatusError as exc:
        raise PolicyBlock(
            "status-target Trusted PR Gate changed after automation approval"
        ) from exc
    if terminal_gate_evidence != gate_evidence:
        raise PolicyBlock(
            "status-target Trusted PR Gate evidence changed after automation approval"
        )
    require_current_control_revision(api, config)
    require_exact_automation_approval(
        api,
        number=promotion["number"],
        head_sha=promotion["headSha"],
        base_sha=promotion["baseSha"],
        gate_evidence=terminal_gate_evidence,
    )
    result = api.put(
        f"/pulls/{target_pr_number}/merge",
        {"sha": promotion["headSha"], "merge_method": config["mergeMethod"]},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        raise GovernanceError(
            f"GitHub declined status-target dependency promotion merge: "
            f"{(result or {}).get('message')}"
        )
    merge_evidence = finalize_post_merge_evidence(api, result, promotion, config)
    _cleanup_merged_promotion_branch(api, promotion, merge_evidence, config)
    print(
        json.dumps(
            {
                "pr": target_pr_number,
                "decision": "status-target-promotion-merged",
                **merge_evidence,
            },
            sort_keys=True,
        )
    )
    _publish_merge_signal(github_output)
    return 0


def reconcile(
    config: dict[str, Any],
    *,
    allow_merge: bool,
    github_output: Path | None = None,
) -> int:
    if config.get("pipMode") != "promotion":
        raise GovernanceError("dependency promotion requires pipMode=promotion")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != config["repository"]:
        raise GovernanceError("workflow repository does not match dependency promotion config")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    require_current_control_revision(api, config)
    _prune_orphan_promotion_refs(api, config)

    active_sources: set[int] = set()
    for summary in _promotion_pulls(api):
        number = summary.get("number")
        branch = str((summary.get("head") or {}).get("ref") or "")
        metadata = _parse_marker(summary.get("body")) or {}
        source_number = metadata.get("sourcePr")
        if isinstance(source_number, int):
            active_sources.add(source_number)
        if _legacy_promotion_actor_matches(summary.get("user") or {}):
            legacy_head_sha = require_sha(
                metadata.get("head"),
                "legacy promotion marker head SHA",
            )
            require_current_control_revision(api, config)
            _retire_legacy_promotion(
                api,
                number,
                branch,
                legacy_head_sha,
                config,
            )
            if isinstance(source_number, int):
                active_sources.discard(source_number)
            print(
                json.dumps(
                    {"pr": number, "decision": "legacy-promotion-retired"},
                    sort_keys=True,
                )
            )
            continue
        try:
            require_current_control_revision(api, config)
            live_pr = _normalize_staged_promotion(
                api,
                api.get(f"/pulls/{number}"),
                config,
            )
            _, promotion = _validate_promotion(api, live_pr, config, require_checks=False)
            print(json.dumps({"pr": number, "decision": "promotion-qualified"}, sort_keys=True))
            if allow_merge and config["automergeEnabled"]:
                require_current_control_revision(api, config)
                merge_evidence = _publish_and_merge(api, promotion, config)
                print(
                    json.dumps(
                        {"pr": number, "decision": "promotion-merged", **merge_evidence},
                        sort_keys=True,
                    )
                )
                _publish_merge_signal(github_output)
                return 0
        except QualificationWakeRegistered as exc:
            print(
                json.dumps(
                    {"pr": number, "decision": "promotion-waiting", "reason": str(exc)},
                    sort_keys=True,
                )
            )
            return 0
        except PolicyBlock as exc:
            reason = str(exc)
            print(
                json.dumps(
                    {"pr": number, "decision": "promotion-waiting", "reason": reason},
                    sort_keys=True,
                )
            )
            if (
                "stale relative to current main" in reason
                or "source Dependabot PR changed" in reason
            ):
                stale_head_sha = require_sha(
                    metadata.get("head"),
                    "stale promotion marker head SHA",
                )
                require_current_control_revision(api, config)
                _close_stale(api, int(number), branch, stale_head_sha, config)
                if isinstance(source_number, int):
                    active_sources.discard(source_number)

    created = 0
    for summary in api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4):
        if (summary.get("user") or {}).get("login") != BOT_LOGIN or (summary.get("user") or {}).get(
            "id"
        ) != BOT_USER_ID:
            continue
        number = summary.get("number")
        if not isinstance(number, int) or number in active_sources:
            continue
        try:
            source = source_subject(api, api.get(f"/pulls/{number}"), config)
            branch = _branch_name(source)
            author_token = os.environ.get(PROMOTION_AUTHOR_TOKEN_ENV, "")
            if not author_token:
                raise GovernanceError(
                    "independent promotion author App token is required for new promotion creation"
                )
            _promotion_author_identity()
            author_api = GitHubApi(author_token, repository)
            require_current_control_revision(api, config)
            head_sha, _ = _create_promotion_commit(author_api, source, branch, config)
            require_current_control_revision(api, config)
            promotion_number = _create_promotion_pr(author_api, source, branch, head_sha, config)
            created_pr = api.get(f"/pulls/{promotion_number}")
            if not _promotion_actor_matches(
                (created_pr or {}).get("user") or {},
            ):
                raise GovernanceError(
                    "created promotion PR is not authored by the exact independent App"
                )
            live_created_pr = _normalize_staged_promotion(api, created_pr, config)
            _, created_promotion = _validate_promotion(
                api,
                live_created_pr,
                config,
                require_checks=False,
            )
            active_sources.add(number)
            created += 1
            print(
                json.dumps(
                    {
                        "sourcePr": number,
                        "promotionPr": promotion_number,
                        "decision": "promotion-created",
                    },
                    sort_keys=True,
                )
            )
            try:
                _advance_promotion_qualification(
                    api,
                    created_promotion,
                    branch,
                    config,
                )
            except QualificationWakeRegistered as exc:
                print(
                    json.dumps(
                        {
                            "pr": promotion_number,
                            "decision": "promotion-waiting",
                            "reason": str(exc),
                        },
                        sort_keys=True,
                    )
                )
                return created
            raise GovernanceError("new promotion qualification wake returned unexpectedly")
        except PolicyBlock as exc:
            print(
                json.dumps(
                    {"pr": number, "decision": "not-pip-promotion", "reason": str(exc)},
                    sort_keys=True,
                )
            )
    return created


def selftest() -> None:
    base_raw = b"""[build-system]
requires = ["hatchling==1.32.0"]
build-backend = "hatchling.build"

[project]
name = "ai-qa-automation"
dependencies = ["httpx>=0.28,<1"]

[project.optional-dependencies]
browser = ["playwright>=1.51,<2"]
dev = ["mypy>=1.14,<2", "playwright>=1.51,<2"]
"""
    head_raw = b"""[build-system]
requires = ["hatchling==1.33.0"]
build-backend = "hatchling.build"

[project]
name = "ai-qa-automation"
dependencies = ["httpx>=0.29,<1"]

[project.optional-dependencies]
browser = ["playwright>=1.52,<2"]
dev = ["mypy>=2,<3", "playwright>=1.52,<2"]
"""
    validate_pyproject_transition(base_raw, head_raw)

    owned_commit = {
        "sha": "d" * 40,
        "author": {"login": PROMOTION_AUTHOR_LOGIN, "id": PROMOTION_AUTHOR_USER_ID},
        "commit": {"message": "deps: promote Dependabot PR #170 with synchronized locks"},
    }
    if not _owned_generated_promotion_commit(owned_commit, "d" * 40):
        raise GovernanceError("canonical generated promotion App ownership was rejected")
    legacy_commit = {
        **owned_commit,
        "author": {"login": GITHUB_ACTIONS_LOGIN, "id": GITHUB_ACTIONS_USER_ID},
    }
    if _owned_generated_promotion_commit(legacy_commit, "d" * 40):
        raise GovernanceError("legacy GitHub Actions promotion retained merge authority")
    if not _owned_generated_promotion_commit(
        legacy_commit,
        "d" * 40,
        allow_legacy_cleanup=True,
    ):
        raise GovernanceError("legacy GitHub Actions promotion lost bounded cleanup recognition")
    for drifted in (
        {**owned_commit, "sha": "e" * 40},
        {**owned_commit, "author": {"login": "portyu9", "id": 35150859}},
        {**owned_commit, "commit": {"message": "deps: unrelated maintenance"}},
    ):
        if _owned_generated_promotion_commit(drifted, "d" * 40):
            raise GovernanceError("non-canonical generated promotion ownership was accepted")

    exact_commit = {
        "tree": {"sha": "c" * 40},
        "parents": [{"sha": "b" * 40}],
        "message": "deps: promote Dependabot PR #170 with synchronized locks",
    }
    if not _promotion_commit_matches(
        exact_commit,
        tree_sha="c" * 40,
        base_sha="b" * 40,
        message="deps: promote Dependabot PR #170 with synchronized locks",
    ):
        raise GovernanceError("exact reusable promotion commit did not match")
    for drifted in (
        {**exact_commit, "tree": {"sha": "d" * 40}},
        {**exact_commit, "parents": [{"sha": "a" * 40}]},
        {**exact_commit, "message": "unexpected promotion commit"},
    ):
        if _promotion_commit_matches(
            drifted,
            tree_sha="c" * 40,
            base_sha="b" * 40,
            message="deps: promote Dependabot PR #170 with synchronized locks",
        ):
            raise GovernanceError("drifted reusable promotion commit did not fail closed")

    encoded_base = base64.b64encode(base_raw).decode("ascii")
    wrapped_base = "\n".join(
        encoded_base[index : index + 60] for index in range(0, len(encoded_base), 60)
    )
    if _decode_contents_base64(wrapped_base, "pyproject.toml") != base_raw:
        raise GovernanceError("wrapped GitHub Contents base64 did not round-trip")
    for malformed in (encoded_base + "%", "Y Q==", "", "\r\n"):
        try:
            _decode_contents_base64(malformed, "pyproject.toml")
        except PolicyBlock:
            pass
        else:
            raise GovernanceError("malformed GitHub Contents base64 did not fail closed")

    if _promotion_base("a" * 40, "b" * 40, base_raw, base_raw) != "b" * 40:
        raise GovernanceError(
            "stale source with unchanged dependency authority was not rebased safely"
        )
    try:
        _promotion_base("a" * 40, "b" * 40, base_raw, base_raw + b"\n# changed\n")
    except PolicyBlock:
        pass
    else:
        raise GovernanceError("stale source with changed dependency authority did not fail closed")

    stale_lifecycle = {"state": "open", "draft": False, "mergeable": False}
    try:
        _require_promotion_lifecycle(
            stale_lifecycle,
            {"base": "a" * 40},
            base_sha="a" * 40,
            live_sha="c" * 40,
        )
    except PolicyBlock as exc:
        if str(exc) != "promotion is stale relative to current main":
            raise GovernanceError("stale promotion lifecycle ordering changed") from exc
    else:
        raise GovernanceError("stale promotion did not fail as stale")

    try:
        _require_promotion_lifecycle(
            stale_lifecycle,
            {"base": "c" * 40},
            base_sha="c" * 40,
            live_sha="c" * 40,
        )
    except PolicyBlock as exc:
        if str(exc) != "promotion PR is not definitively mergeable":
            raise GovernanceError("promotion mergeability guard changed semantics") from exc
    else:
        raise GovernanceError("current non-mergeable promotion did not fail closed")

    added_identity = head_raw.replace(
        b'dependencies = ["httpx>=0.29,<1"]',
        b'dependencies = ["httpx>=0.29,<1", "requests>=2,<3"]',
    )
    try:
        validate_pyproject_transition(base_raw, added_identity)
    except PolicyBlock:
        pass
    else:
        raise GovernanceError("promotion self-test accepted dependency identity addition")

    semantic_change = head_raw.replace(
        b'name = "ai-qa-automation"', b'name = "ai-qa-automation-renamed"'
    )
    try:
        validate_pyproject_transition(base_raw, semantic_change)
    except PolicyBlock:
        pass
    else:
        raise GovernanceError("promotion self-test accepted unrelated pyproject mutation")

    for bad in (
        b"httpx @ https://example.invalid/httpx.whl",
        b'httpx>=0.29,<1; python_version > "3.11"',
        b"httpx @ ../local-wheel.whl",
    ):
        candidate = head_raw.replace(b"httpx>=0.29,<1", bad)
        try:
            validate_pyproject_transition(base_raw, candidate)
        except PolicyBlock:
            pass
        else:
            raise GovernanceError(
                f"promotion self-test accepted external dependency authority: {bad!r}"
            )

    wake_re = QUALIFICATION_WAKE_RE.fullmatch(
        f"{QUALIFICATION_WAKE_PREFIX}:{'a' * 40}:{'b' * 40}:trusted-gate:123:1"
    )
    if wake_re is None or wake_re.group("stage") != "trusted-gate":
        raise GovernanceError("qualification wake identity parser rejected canonical evidence")
    for malformed in (
        f"{QUALIFICATION_WAKE_PREFIX}:{'a' * 39}:{'b' * 40}:trusted-gate:123:1",
        f"{QUALIFICATION_WAKE_PREFIX}:{'a' * 40}:{'b' * 40}:other:123:1",
        f"{QUALIFICATION_WAKE_PREFIX}:{'a' * 40}:{'b' * 40}:trusted-gate:0:1",
    ):
        if QUALIFICATION_WAKE_RE.fullmatch(malformed) is not None:
            raise GovernanceError("qualification wake identity parser accepted malformed evidence")

    print("dependency-promotion self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic Python dependency promotion")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--await-trusted-status-event", action="store_true")
    parser.add_argument("--target-promotion-pr", type=int)
    parser.add_argument("--allow-merge", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    if args.github_output is not None and not (
        args.await_trusted_status_event or (args.reconcile and args.allow_merge)
    ):
        parser.error(
            "--github-output requires --await-trusted-status-event or --reconcile --allow-merge"
        )
    if args.await_trusted_status_event and (
        args.self_test or args.reconcile or args.allow_merge or args.target_promotion_pr is not None
    ):
        parser.error("--await-trusted-status-event must run as a standalone read-only barrier")
    if args.target_promotion_pr is not None and (not args.reconcile or not args.allow_merge):
        parser.error("--target-promotion-pr requires --reconcile --allow-merge")
    if args.self_test:
        selftest()
    if args.await_trusted_status_event:
        status_result = await_trusted_status_event()
        _publish_status_sync_outputs(args.github_output, status_result)
        if status_result is None:
            print(json.dumps({"decision": "trusted-status-not-governed-dependency"}))
    if args.reconcile:
        if args.target_promotion_pr is not None:
            reconcile_status_target(
                load_config(),
                target_pr_number=args.target_promotion_pr,
                allow_merge=args.allow_merge,
                github_output=args.github_output,
            )
        else:
            reconcile(
                load_config(),
                allow_merge=args.allow_merge,
                github_output=args.github_output,
            )
    if not args.self_test and not args.reconcile and not args.await_trusted_status_event:
        parser.error("choose --self-test, --await-trusted-status-event, or --reconcile")


if __name__ == "__main__":
    main()
