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
import tomllib
import urllib.parse
from datetime import UTC, datetime, timedelta
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
    dispatch_exact_ci,
    dispatch_exact_codeql,
    finalize_post_merge_evidence,
    load_config,
    require_green_checks,
    require_sha,
    validate_pr_identity,
)
from dependency_lock_compiler import LockCompileError, compile_locks, validate_frozen_locks
from dependency_trusted_gate import require_qualified_trusted_gate
from trusted_qualification import qualification_states
from trusted_status import TrustedStatusError

ROOT = Path(__file__).resolve().parents[2]
BRANCH_PREFIX = "automation/dependency-promotion-"
STAGING_BASE_PREFIX = "automation/dependency-promotion-base-"
PROMOTION_BRANCH_RE = re.compile(r"^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$")
STAGING_BASE_RE = re.compile(r"^automation/dependency-promotion-base-[1-9][0-9]*-[0-9a-f]{12}$")
QUALIFICATION_RETRY_AFTER = timedelta(minutes=45)
MAX_QUALIFICATION_ATTEMPTS = 2
PROMOTION_COMMIT_MESSAGE_RE = re.compile(
    r"^deps: promote Dependabot PR #[1-9][0-9]* with synchronized locks$"
)
MARKER_PREFIX = "<!-- aiqa-dependency-promotion:"
MARKER_SUFFIX = " -->"
GITHUB_ACTIONS_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_USER_ID = 41898282
REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[A-Za-z0-9_,.-]+\])?(?P<specifier>[^;@\s]*)$"
)
PROMOTION_PATHS = {
    "pyproject.toml",
    "requirements/build-py311.lock",
    "requirements/dev-py311.lock",
    "requirements/dev-py314.lock",
    "requirements/runtime-py311.lock",
    ".github/lock-authority.json",
}
REQUIRED_CHECKS = ("Required PR Gate", "CodeQL")


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


def _decode_contents_base64(content: str, path: str) -> bytes:
    compact = "".join(content.split())
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

    fingerprint = hashlib.sha256(
        b"\0".join(
            (
                str(number).encode(),
                source_base_sha.encode(),
                head_sha.encode(),
                promotion_base_sha.encode(),
                hashlib.sha256(head_raw).hexdigest().encode(),
            )
        )
    ).hexdigest()
    return {
        "number": number,
        "headSha": head_sha,
        "sourceBaseSha": source_base_sha,
        "baseSha": promotion_base_sha,
        "pyproject": head_raw,
        "fingerprint": fingerprint,
    }


def _branch_name(source: dict[str, Any]) -> str:
    return f"{BRANCH_PREFIX}{source['number']}-{source['fingerprint'][:12]}"


def _staging_base_name(source_number: int, fingerprint: str) -> str:
    if source_number < 1 or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise GovernanceError("promotion staging-base identity is malformed")
    return f"{STAGING_BASE_PREFIX}{source_number}-{fingerprint[:12]}"


def _owned_generated_promotion_commit(payload: Any, head_sha: str) -> bool:
    if not isinstance(payload, dict) or payload.get("sha") != head_sha:
        return False
    author = payload.get("author") or {}
    commit = payload.get("commit") or {}
    message = commit.get("message")
    return (
        author.get("login") == GITHUB_ACTIONS_LOGIN
        and author.get("id") == GITHUB_ACTIONS_USER_ID
        and isinstance(message, str)
        and PROMOTION_COMMIT_MESSAGE_RE.fullmatch(message) is not None
    )


def _prune_orphan_promotion_refs(api: GitHubApi) -> int:
    open_prs = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    open_heads = {
        str((row.get("head") or {}).get("ref"))
        for row in open_prs
        if isinstance((row.get("head") or {}).get("ref"), str)
    }
    open_bases = {
        str((row.get("base") or {}).get("ref"))
        for row in open_prs
        if isinstance((row.get("base") or {}).get("ref"), str)
    }
    prefix = f"refs/heads/{BRANCH_PREFIX}"
    refs = api.list_all(f"/git/matching-refs/heads/{BRANCH_PREFIX}", max_pages=4)
    pruned = 0
    for row in refs:
        ref = row.get("ref")
        if not isinstance(ref, str) or not ref.startswith(prefix):
            raise GovernanceError("GitHub returned a ref outside dependency promotion namespace")
        branch = ref.removeprefix("refs/heads/")
        obj = row.get("object") or {}
        if obj.get("type") != "commit":
            raise PolicyBlock("orphan dependency promotion ref does not point to a commit")
        ref_sha = require_sha(obj.get("sha"), "orphan dependency promotion SHA")

        if STAGING_BASE_RE.fullmatch(branch) is not None:
            if branch in open_bases:
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
                not _owned_generated_promotion_commit(generated_commit, generated_sha)
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
            _delete_exact_ref(
                api,
                branch,
                ref_sha,
                label="orphan promotion staging-base ref",
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
        if not _owned_generated_promotion_commit(commit, ref_sha):
            raise PolicyBlock(
                "orphan dependency promotion ref lacks exact GitHub Actions ownership"
            )
        _delete_exact_ref(
            api,
            branch,
            ref_sha,
            label="orphan generated promotion ref",
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
    ):
        raise PolicyBlock(
            "existing dependency promotion branch does not match the exact generated subject"
        )
    return head_sha


def _create_promotion_commit(
    api: GitHubApi, source: dict[str, Any], branch: str
) -> tuple[str, dict[str, bytes]]:
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
    created = api.post("/git/refs", {"ref": f"refs/heads/{branch}", "sha": head_sha})
    if (created or {}).get("ref") != f"refs/heads/{branch}":
        raise GovernanceError("GitHub did not acknowledge dependency promotion branch creation")
    return head_sha, generated


def _github_actions_pr_creation_denied(exc: Exception) -> bool:
    detail = str(exc)
    return (
        "HTTP 403" in detail
        and "GitHub Actions is not permitted to create or approve pull requests" in detail
    )


def _delete_exact_ref(
    api: GitHubApi,
    branch: str,
    expected_sha: str,
    *,
    label: str,
) -> None:
    encoded = urllib.parse.quote(branch, safe="")
    ref = api.get(f"/git/ref/heads/{encoded}")
    obj = (ref or {}).get("object") or {}
    if (ref or {}).get("ref") != f"refs/heads/{branch}" or obj.get("type") != "commit":
        raise PolicyBlock(f"{label} identity changed before exact cleanup")
    observed = require_sha(
        obj.get("sha"),
        f"{label} SHA before cleanup",
    )
    if observed != expected_sha:
        raise PolicyBlock(f"{label} changed before exact cleanup")
    api.request("DELETE", f"/git/refs/heads/{encoded}")


def _delete_exact_generated_branch(api: GitHubApi, branch: str, head_sha: str) -> None:
    _delete_exact_ref(
        api,
        branch,
        head_sha,
        label="generated promotion branch",
    )


def _ensure_staging_base_ref(api: GitHubApi, source: dict[str, Any]) -> str:
    branch = _staging_base_name(int(source["number"]), str(source["fingerprint"]))
    encoded = urllib.parse.quote(branch, safe="")
    try:
        existing = api.get(f"/git/ref/heads/{encoded}")
    except GovernanceError as exc:
        if "HTTP 404" not in str(exc):
            raise
        created = api.post(
            "/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": source["baseSha"]},
        )
        created_obj = (created or {}).get("object") or {}
        if (created or {}).get("ref") != f"refs/heads/{branch}" or created_obj.get(
            "type"
        ) != "commit":
            raise GovernanceError(
                "GitHub did not acknowledge exact promotion staging-base creation"
            )
        observed = require_sha(
            created_obj.get("sha"),
            "created promotion staging-base SHA",
        )
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
    if observed != source["baseSha"]:
        raise PolicyBlock("promotion staging-base ref does not equal exact current main")
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


def _validate_staged_or_main_pr(
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
        raise GovernanceError("promotion PR lifecycle changed during staged-base transition")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        (head.get("repo") or {}).get("full_name") != repository
        or (base.get("repo") or {}).get("full_name") != repository
        or head.get("ref") != branch
        or require_sha(head.get("sha"), "promotion PR head SHA") != head_sha
        or base.get("ref") != base_ref
        or require_sha(base.get("sha"), "promotion PR base SHA") != base_sha
    ):
        raise GovernanceError("promotion PR identity changed during staged-base transition")


def _create_promotion_pr(api: GitHubApi, source: dict[str, Any], branch: str, head_sha: str) -> int:
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
    staging_base = _ensure_staging_base_ref(api, source)
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
        _delete_exact_ref(
            api,
            staging_base,
            source["baseSha"],
            label="promotion staging-base ref",
        )
        if not _github_actions_pr_creation_denied(exc):
            raise
        _delete_exact_generated_branch(api, branch, head_sha)
        raise GovernanceError(
            "repository Actions policy blocks generated pull-request creation; "
            "enable 'Allow GitHub Actions to create and approve pull requests'"
        ) from exc
    number = (pr or {}).get("number")
    if not isinstance(number, int) or number < 1:
        raise GovernanceError("GitHub did not acknowledge dependency promotion PR creation")
    _validate_staged_or_main_pr(
        pr,
        number=number,
        branch=branch,
        head_sha=head_sha,
        base_ref=staging_base,
        base_sha=source["baseSha"],
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
    )
    retargeted = api.request("PATCH", f"/pulls/{number}", {"base": "main"})
    if not isinstance(retargeted, dict):
        raise GovernanceError("GitHub returned a malformed promotion retarget response")
    _validate_staged_or_main_pr(
        retargeted,
        number=number,
        branch=branch,
        head_sha=head_sha,
        base_ref="main",
        base_sha=source["baseSha"],
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
    )
    _delete_exact_ref(
        api,
        staging_base,
        source["baseSha"],
        label="promotion staging-base ref",
    )
    return number


def _normalize_staged_promotion(
    api: GitHubApi,
    pr: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
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
        user.get("login") != GITHUB_ACTIONS_LOGIN
        or user.get("id") != GITHUB_ACTIONS_USER_ID
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
    if not isinstance(number, int) or number < 1:
        raise PolicyBlock("staged promotion PR number is invalid")
    retargeted = api.request("PATCH", f"/pulls/{number}", {"base": config["baseBranch"]})
    if not isinstance(retargeted, dict):
        raise GovernanceError("GitHub returned a malformed staged promotion retarget response")
    _validate_staged_or_main_pr(
        retargeted,
        number=number,
        branch=str(head.get("ref")),
        head_sha=str(metadata["head"]),
        base_ref=config["baseBranch"],
        base_sha=live_sha,
        repository=config["repository"],
    )
    _delete_exact_ref(
        api,
        expected_base,
        live_sha,
        label="promotion staging-base ref",
    )
    return retargeted


def _qualification_request_age(metadata: dict[str, Any]) -> timedelta | None:
    request = metadata.get("qualificationRequest")
    if not isinstance(request, dict):
        return None
    raw = request.get("requestedAt")
    if not isinstance(raw, str):
        raise PolicyBlock("promotion qualification request timestamp is malformed")
    try:
        requested = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise PolicyBlock("promotion qualification request timestamp is malformed") from exc
    if requested.tzinfo is None:
        raise PolicyBlock("promotion qualification request timestamp is not timezone-aware")
    now = datetime.now(UTC)
    requested_utc = requested.astimezone(UTC)
    if requested_utc > now:
        raise PolicyBlock("promotion qualification request timestamp is in the future")
    return now - requested_utc


def _request_exact_qualification(
    api: GitHubApi,
    pr: dict[str, Any],
    head_sha: str,
    base_sha: str,
) -> bool:
    metadata = _parse_marker(pr.get("body"))
    if metadata is None:
        raise PolicyBlock("promotion PR lacks exact promotion marker")
    states = qualification_states(
        api,
        head_sha,
        base_sha,
        required=REQUIRED_CHECKS,
    )
    if all(
        states[name] is not None and states[name].get("conclusion") == "success"
        for name in REQUIRED_CHECKS
    ):
        return True

    terminal_failures = [
        f"{name}={states[name].get('conclusion')}"
        for name in REQUIRED_CHECKS
        if states[name] is not None and states[name].get("conclusion") != "success"
    ]
    if terminal_failures:
        raise PolicyBlock(
            "promotion exact-subject qualification is not green: " + ", ".join(terminal_failures)
        )

    request = metadata.get("qualificationRequest")
    attempt = 0
    if request is not None:
        if not isinstance(request, dict):
            raise PolicyBlock("promotion qualification request metadata is malformed")
        raw_attempt = request.get("attempt")
        if isinstance(raw_attempt, bool) or not isinstance(raw_attempt, int) or raw_attempt < 1:
            raise PolicyBlock("promotion qualification request attempt is malformed")
        attempt = raw_attempt
        age = _qualification_request_age(metadata)
        if age is None or age < QUALIFICATION_RETRY_AFTER:
            return False
        if attempt >= MAX_QUALIFICATION_ATTEMPTS:
            raise PolicyBlock("promotion exact-subject qualification retry budget is exhausted")

    missing = [name for name in REQUIRED_CHECKS if states[name] is None]
    if not missing:
        raise GovernanceError("promotion qualification state is internally inconsistent")

    persisted_metadata = copy.deepcopy(metadata)
    persisted_metadata["qualificationRequest"] = {
        "attempt": attempt + 1,
        "requestedAt": datetime.now(UTC).isoformat(),
    }
    number = pr.get("number")
    if not isinstance(number, int) or number < 1:
        raise GovernanceError("promotion PR number is invalid during qualification request")
    updated = api.request(
        "PATCH",
        f"/pulls/{number}",
        {"body": _promotion_body(persisted_metadata)},
    )
    if not isinstance(updated, dict):
        raise GovernanceError("GitHub returned malformed promotion qualification metadata update")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    _validate_staged_or_main_pr(
        updated,
        number=number,
        branch=str(head.get("ref") or ""),
        head_sha=head_sha,
        base_ref=str(base.get("ref") or ""),
        base_sha=base_sha,
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
    )
    if _parse_marker(updated.get("body")) != persisted_metadata:
        raise GovernanceError("promotion qualification request metadata did not persist exactly")

    head_ref = str(head.get("ref") or "")
    for name in missing:
        if name == "Required PR Gate":
            dispatch_exact_ci(api, head_ref, head_sha)
        elif name == "CodeQL":
            dispatch_exact_codeql(api, head_ref, head_sha)
        else:
            raise GovernanceError(f"unsupported promotion qualification check: {name}")
    return False


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
        if (row.get("user") or {}).get("login") == GITHUB_ACTIONS_LOGIN
        and (row.get("user") or {}).get("id") == GITHUB_ACTIONS_USER_ID
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
    if (pr.get("user") or {}).get("login") != GITHUB_ACTIONS_LOGIN or (pr.get("user") or {}).get(
        "id"
    ) != GITHUB_ACTIONS_USER_ID:
        raise PolicyBlock("promotion PR is not authored by canonical GitHub Actions")
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
        raise PolicyBlock("promotion head lacks exact GitHub Actions ownership")
    parents = (commit or {}).get("parents")
    if (
        not isinstance(parents, list)
        or len(parents) != 1
        or require_sha((parents[0] or {}).get("sha"), "promotion parent SHA") != live_sha
    ):
        raise PolicyBlock("promotion commit is not directly parented to exact current main")
    files = api.list_all(f"/pulls/{pr['number']}/files", max_pages=2)
    paths = {str(row.get("filename")) for row in files if isinstance(row.get("filename"), str)}
    if (
        not paths
        or not paths <= PROMOTION_PATHS
        or "pyproject.toml" not in paths
        or ".github/lock-authority.json" not in paths
    ):
        raise PolicyBlock(
            f"promotion changed-path set is outside generated authority: {sorted(paths)}"
        )
    if validate_generated_bytes:
        _validate_generated_bytes(api, source, head_sha)
    if require_checks:
        _require_green(api, head_sha, config)
    return source, {"number": pr["number"], "headSha": head_sha, "baseSha": base_sha}


def _publish_and_merge(
    api: GitHubApi, promotion: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    fresh_before_merge = api.get(f"/pulls/{promotion['number']}")
    _, rebound_before_merge = _validate_promotion(
        api, fresh_before_merge, config, require_checks=True
    )
    if rebound_before_merge != promotion:
        raise PolicyBlock("promotion changed before guarded merge")
    try:
        require_qualified_trusted_gate(
            api,
            promotion["number"],
            promotion["headSha"],
            promotion["baseSha"],
        )
    except TrustedStatusError as exc:
        raise PolicyBlock("automatic Trusted PR Gate is not yet exact-qualified") from exc
    result = api.put(
        f"/pulls/{promotion['number']}/merge",
        {"sha": promotion["headSha"], "merge_method": config["mergeMethod"]},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        raise GovernanceError(
            f"GitHub declined dependency promotion merge: {(result or {}).get('message')}"
        )
    return finalize_post_merge_evidence(api, result, promotion, config)


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
        or ((fresh or {}).get("user") or {}).get("login") != GITHUB_ACTIONS_LOGIN
        or ((fresh or {}).get("user") or {}).get("id") != GITHUB_ACTIONS_USER_ID
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
        raise PolicyBlock("stale promotion head lacks exact GitHub Actions ownership")
    closed = api.request("PATCH", f"/pulls/{number}", {"state": "closed"})
    if not isinstance(closed, dict) or closed.get("state") != "closed":
        raise GovernanceError("GitHub did not acknowledge stale promotion closure")
    if staging_base is not None:
        _delete_exact_ref(
            api,
            staging_base,
            require_sha(metadata.get("base"), "stale promotion marker base SHA"),
            label="stale promotion staging-base ref",
        )
    _delete_exact_generated_branch(api, branch, head_sha)


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
    _prune_orphan_promotion_refs(api)

    active_sources: set[int] = set()
    for summary in _promotion_pulls(api):
        number = summary.get("number")
        branch = str((summary.get("head") or {}).get("ref") or "")
        metadata = _parse_marker(summary.get("body")) or {}
        source_number = metadata.get("sourcePr")
        if isinstance(source_number, int):
            active_sources.add(source_number)
        try:
            live_pr = _normalize_staged_promotion(
                api,
                api.get(f"/pulls/{number}"),
                config,
            )
            _, promotion = _validate_promotion(api, live_pr, config, require_checks=False)
            if not _request_exact_qualification(
                api,
                live_pr,
                promotion["headSha"],
                promotion["baseSha"],
            ):
                print(
                    json.dumps(
                        {
                            "pr": number,
                            "decision": "promotion-waiting",
                            "reason": "trusted-main exact-subject qualification is pending",
                        },
                        sort_keys=True,
                    )
                )
                continue
            _, promotion = _validate_promotion(
                api, api.get(f"/pulls/{number}"), config, require_checks=True
            )
            print(json.dumps({"pr": number, "decision": "promotion-qualified"}, sort_keys=True))
            if allow_merge and config["automergeEnabled"]:
                merge_evidence = _publish_and_merge(api, promotion, config)
                print(
                    json.dumps(
                        {"pr": number, "decision": "promotion-merged", **merge_evidence},
                        sort_keys=True,
                    )
                )
                _publish_merge_signal(github_output)
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
            head_sha, _ = _create_promotion_commit(api, source, branch)
            promotion_number = _create_promotion_pr(api, source, branch, head_sha)
            created_pr = api.get(f"/pulls/{promotion_number}")
            if _request_exact_qualification(
                api,
                created_pr,
                head_sha,
                source["baseSha"],
            ):
                raise GovernanceError(
                    "new promotion unexpectedly had pre-existing exact-subject qualification"
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
        "author": {"login": GITHUB_ACTIONS_LOGIN, "id": GITHUB_ACTIONS_USER_ID},
        "commit": {"message": "deps: promote Dependabot PR #170 with synchronized locks"},
    }
    if not _owned_generated_promotion_commit(owned_commit, "d" * 40):
        raise GovernanceError("canonical generated promotion commit ownership was rejected")
    for drifted in (
        {**owned_commit, "sha": "e" * 40},
        {**owned_commit, "author": {"login": "portyu9", "id": 35150859}},
        {**owned_commit, "commit": {"message": "deps: unrelated maintenance"}},
    ):
        if _owned_generated_promotion_commit(drifted, "d" * 40):
            raise GovernanceError("non-canonical generated promotion ownership was accepted")

    denied = GovernanceError(
        "GitHub API POST /pulls failed HTTP 403: "
        '{"message":"GitHub Actions is not permitted to create or approve pull requests."}'
    )
    if not _github_actions_pr_creation_denied(denied):
        raise GovernanceError("GitHub Actions PR creation denial was not classified")
    if _github_actions_pr_creation_denied(GovernanceError("HTTP 403: unrelated policy")):
        raise GovernanceError("unrelated HTTP 403 was misclassified as PR creation denial")

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
    try:
        _decode_contents_base64(encoded_base + "%", "pyproject.toml")
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

    print("dependency-promotion self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic Python dependency promotion")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--allow-merge", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    if args.github_output is not None and (not args.reconcile or not args.allow_merge):
        parser.error("--github-output requires --reconcile --allow-merge")
    if args.self_test:
        selftest()
    if args.reconcile:
        reconcile(
            load_config(),
            allow_merge=args.allow_merge,
            github_output=args.github_output,
        )
    if not args.self_test and not args.reconcile:
        parser.error("choose --self-test or --reconcile")


if __name__ == "__main__":
    main()
