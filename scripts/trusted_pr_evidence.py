from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

if __package__:
    from scripts.trusted_pr_control import (
        FULL_SHA_RE,
        GitHubApi,
        PullRequestSubject,
        _mapping,
        _require_positive_int,
        _require_sha,
        resolve_current_subject,
    )
else:
    from trusted_pr_control import (
        FULL_SHA_RE,
        GitHubApi,
        PullRequestSubject,
        _mapping,
        _require_positive_int,
        _require_sha,
        resolve_current_subject,
    )

EXPECTED_BASE_REF = "main"
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_WORKFLOW_EVENT = "pull_request"
EXPECTED_REQUIRED_JOB = "Required PR Gate"
EXPECTED_REQUIRED_STEP = "Require every automatic gate to succeed"
EXPECTED_SUPPLY_CHAIN_JOB = "Supply Chain / Wheel + SBOM + Container"
EXPECTED_SUPPLY_CHAIN_ARTIFACT = "supply-chain-evidence"
EXPECTED_BUILD_MANIFEST = "build-manifest.json"
EXPECTED_CI_CONTRACT_STEP = "Verify CI authority contract"
EXPECTED_SUBJECT_BINDING = (
    "CI_SUBJECT_SHA: ${{ github.event_name == 'repository_dispatch' "
    "&& github.event.client_payload.expected_merge_sha || github.sha }}"
)
MAX_WORKFLOW_RUNS = 20
MAX_JOBS = 100
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_ENTRIES = 32
MAX_ARTIFACT_UNCOMPRESSED_BYTES = 8 * 1024 * 1024
MAX_BUILD_MANIFEST_BYTES = 256 * 1024
PROTECTED_PATHS = (
    ".github",
    ".claude",
    ".dockerignore",
    ".mcp.json",
    ".pre-commit-config.yaml",
    "CLAUDE.md",
    "Dockerfile",
    "evals",
    "examples",
    "pyproject.toml",
    "requirements",
    "scripts",
    "tests",
    "src/ai_qa_automation/__init__.py",
    "src/ai_qa_automation/io_safety.py",
    "src/ai_qa_automation/tools/__init__.py",
    "src/ai_qa_automation/tools/execution_env.py",
)
PROTECTED_PATH_SET = frozenset(PROTECTED_PATHS)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del request, fp, code, msg, headers, newurl
        return None


def _require_authorization_context() -> None:
    if os.environ.get("GITHUB_EVENT_NAME") != "repository_dispatch":
        raise PermissionError("trusted evidence admission requires repository_dispatch")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise PermissionError("trusted evidence admission requires refs/heads/main")
    actor = os.environ.get("GITHUB_ACTOR", "")
    owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
    if not owner or actor != owner:
        raise PermissionError("trusted evidence admission requires the repository owner")


def _parse_manifest(raw: str) -> list[dict[str, str]]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("protected_manifest must be valid JSON") from exc
    if not isinstance(parsed, list):
        raise ValueError("protected_manifest must be a JSON array")
    if len(parsed) > len(PROTECTED_PATHS):
        raise ValueError("protected_manifest exceeds the bounded protected-path set")

    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in parsed:
        if not isinstance(item, dict) or set(item) != {"path", "base_oid", "subject_oid"}:
            raise ValueError(
                "protected_manifest entries must contain exactly path/base_oid/subject_oid"
            )
        path = item["path"]
        base_oid = item["base_oid"]
        subject_oid = item["subject_oid"]
        if not isinstance(path, str) or path not in PROTECTED_PATH_SET or path in seen:
            raise ValueError("protected_manifest contains an unknown or duplicate path")
        for label, oid in (("base_oid", base_oid), ("subject_oid", subject_oid)):
            if oid != "MISSING" and (
                not isinstance(oid, str) or FULL_SHA_RE.fullmatch(oid) is None
            ):
                raise ValueError(
                    f"protected_manifest {label} must be a full Git object ID or MISSING"
                )
        seen.add(path)
        normalized.append(
            {
                "path": path,
                "base_oid": base_oid,
                "subject_oid": subject_oid,
            }
        )
    normalized.sort(key=lambda item: item["path"])
    return normalized


def _tree_entries(api: GitHubApi, commit_sha: str) -> dict[str, str]:
    commit = api.fetch_git_commit(commit_sha)
    tree = _mapping(commit.get("tree"), label="commit tree")
    tree_sha = _require_sha(tree.get("sha"), label="commit tree SHA")
    payload = api.get_json(f"/repos/{api.repository}/git/trees/{tree_sha}?recursive=1")
    if payload.get("truncated") is True:
        raise RuntimeError("Git tree response was truncated")
    entries = payload.get("tree")
    if not isinstance(entries, list):
        raise RuntimeError("Git tree response must contain a tree array")

    result: dict[str, str] = {}
    for entry in entries:
        item = _mapping(entry, label="Git tree entry")
        path = item.get("path")
        if not isinstance(path, str):
            raise RuntimeError("Git tree entry path must be a string")
        if path in PROTECTED_PATH_SET:
            result[path] = _require_sha(item.get("sha"), label=f"Git object ID for {path}")
    return result


def _verify_protected_manifest(
    api: GitHubApi,
    expected: PullRequestSubject,
    raw_manifest: str,
) -> list[dict[str, str]]:
    authorized = _parse_manifest(raw_manifest)
    base_entries = _tree_entries(api, expected.base_sha)
    subject_entries = _tree_entries(api, expected.merge_sha)

    observed: list[dict[str, str]] = []
    for path in PROTECTED_PATHS:
        base_oid = base_entries.get(path, "MISSING")
        subject_oid = subject_entries.get(path, "MISSING")
        if base_oid != subject_oid:
            observed.append(
                {
                    "path": path,
                    "base_oid": base_oid,
                    "subject_oid": subject_oid,
                }
            )
    observed.sort(key=lambda item: item["path"])
    if observed != authorized:
        raise ValueError(
            "protected_manifest does not exactly authorize the observed protected-path changes"
        )
    return observed


def _pull_request_head_ref(payload: Mapping[str, Any], expected: PullRequestSubject) -> str:
    if payload.get("state") != "open" or payload.get("number") != expected.number:
        raise ValueError("pull request must remain open with the expected number")
    head = _mapping(payload.get("head"), label="pull-request head")
    base = _mapping(payload.get("base"), label="pull-request base")
    if head.get("sha") != expected.head_sha or base.get("sha") != expected.base_sha:
        raise ValueError("pull-request head/base identity changed after authorization")
    if base.get("ref") != EXPECTED_BASE_REF:
        raise ValueError(f"pull request must target {EXPECTED_BASE_REF!r}")
    head_repo = _mapping(head.get("repo"), label="pull-request head repository")
    if head_repo.get("full_name") != os.environ.get("GITHUB_REPOSITORY"):
        raise ValueError("trusted evidence admission requires a same-repository pull request")
    head_ref = head.get("ref")
    if not isinstance(head_ref, str) or not head_ref or len(head_ref) > 255:
        raise ValueError("pull-request head ref is invalid")
    return head_ref


def _run_matches(
    run: Mapping[str, Any],
    *,
    expected: PullRequestSubject,
    head_ref: str,
) -> bool:
    if (
        run.get("event") != EXPECTED_WORKFLOW_EVENT
        or run.get("path") != EXPECTED_WORKFLOW_PATH
        or run.get("head_sha") != expected.head_sha
        or run.get("head_branch") != head_ref
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        return False
    pull_requests = run.get("pull_requests")
    if not isinstance(pull_requests, list) or len(pull_requests) != 1:
        return False
    pr = _mapping(pull_requests[0], label="workflow-run pull request")
    if pr.get("number") != expected.number:
        return False
    head = _mapping(pr.get("head"), label="workflow-run pull-request head")
    base = _mapping(pr.get("base"), label="workflow-run pull-request base")
    return (
        head.get("sha") == expected.head_sha
        and head.get("ref") == head_ref
        and base.get("sha") == expected.base_sha
        and base.get("ref") == EXPECTED_BASE_REF
    )


def _step_succeeded(job: Mapping[str, Any], step_name: str) -> bool:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    matches = [
        _mapping(step, label="workflow job step")
        for step in steps
        if isinstance(step, dict) and step.get("name") == step_name
    ]
    return len(matches) == 1 and matches[0].get("conclusion") == "success"


def _verify_jobs(api: GitHubApi, run_id: int) -> dict[str, Any]:
    payload = api.get_json(
        f"/repos/{api.repository}/actions/runs/{run_id}/jobs?per_page={MAX_JOBS}&filter=latest"
    )
    total = payload.get("total_count")
    jobs = payload.get("jobs")
    if not isinstance(total, int) or total < 1 or total > MAX_JOBS:
        raise ValueError("workflow run job count is outside the bounded admission range")
    if not isinstance(jobs, list) or len(jobs) != total:
        raise ValueError("workflow run jobs were not retrieved completely")

    by_name: dict[str, Mapping[str, Any]] = {}
    for raw_job in jobs:
        job = _mapping(raw_job, label="workflow job")
        name = job.get("name")
        if not isinstance(name, str) or not name or name in by_name:
            raise ValueError("workflow run contains an invalid or duplicate job name")
        by_name[name] = job

    for required in (
        EXPECTED_SUPPLY_CHAIN_JOB,
        "Security Gates",
        "Playwright Reference SUT",
        "34-Case Deterministic Control Evaluation",
        EXPECTED_REQUIRED_JOB,
    ):
        job = by_name.get(required)
        if job is None or job.get("conclusion") != "success":
            raise ValueError(f"required evidence job did not succeed: {required}")

    quality_jobs = [job for name, job in by_name.items() if name.startswith("Quality / Python ")]
    if len(quality_jobs) != 2 or any(job.get("conclusion") != "success" for job in quality_jobs):
        raise ValueError("exactly two successful Python quality lanes are required")

    supply_chain = by_name[EXPECTED_SUPPLY_CHAIN_JOB]
    if not _step_succeeded(supply_chain, EXPECTED_CI_CONTRACT_STEP):
        raise ValueError("ordinary CI did not successfully verify the exact CI authority contract")
    required_gate = by_name[EXPECTED_REQUIRED_JOB]
    if not _step_succeeded(required_gate, EXPECTED_REQUIRED_STEP):
        raise ValueError("ordinary CI Required PR Gate did not deterministically aggregate success")

    return {
        "required_jobs": sorted(
            (
                EXPECTED_SUPPLY_CHAIN_JOB,
                "Security Gates",
                "Playwright Reference SUT",
                "34-Case Deterministic Control Evaluation",
                EXPECTED_REQUIRED_JOB,
            )
        ),
        "quality_jobs": sorted(str(job["name"]) for job in quality_jobs),
    }


def _verify_candidate_workflow_binding(api: GitHubApi, merge_sha: str) -> None:
    payload = api.get_json(
        f"/repos/{api.repository}/contents/{EXPECTED_WORKFLOW_PATH}?ref={merge_sha}"
    )
    if payload.get("encoding") != "base64":
        raise ValueError("candidate workflow content must be returned as base64")
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        raise ValueError("candidate workflow content is missing")
    try:
        text = base64.b64decode(encoded, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("candidate workflow content is not valid UTF-8") from exc
    if EXPECTED_SUBJECT_BINDING not in text:
        raise ValueError("candidate pull_request workflow is not bound to github.sha")
    if "\n  pull_request:\n" not in text:
        raise ValueError("candidate workflow no longer has the reviewed pull_request trigger")
    if f"\n    name: {EXPECTED_REQUIRED_JOB}\n" not in text:
        raise ValueError("candidate workflow no longer contains the deterministic Required PR Gate")


def _select_evidence_run(
    api: GitHubApi,
    *,
    expected: PullRequestSubject,
    head_ref: str,
) -> Mapping[str, Any]:
    branch = urllib.parse.quote(head_ref, safe="")
    payload = api.get_json(
        f"/repos/{api.repository}/actions/workflows/ci.yml/runs"
        f"?event={EXPECTED_WORKFLOW_EVENT}&branch={branch}&per_page={MAX_WORKFLOW_RUNS}"
    )
    total = payload.get("total_count")
    runs = payload.get("workflow_runs")
    if not isinstance(total, int) or total < 1:
        raise ValueError("no pull-request CI runs exist for the expected head branch")
    if not isinstance(runs, list) or len(runs) > MAX_WORKFLOW_RUNS:
        raise ValueError("workflow run listing is malformed or exceeds the bounded page")
    matches = [
        _mapping(run, label="workflow run")
        for run in runs
        if isinstance(run, dict) and _run_matches(run, expected=expected, head_ref=head_ref)
    ]
    if not matches:
        raise ValueError(
            "no successful exact-head pull-request CI run matches the authorized subject"
        )
    matches.sort(
        key=lambda run: (
            _require_positive_int(run.get("run_attempt"), label="workflow run attempt"),
            _require_positive_int(run.get("id"), label="workflow run ID"),
        ),
        reverse=True,
    )
    return matches[0]


def _artifact_digest(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError("supply-chain artifact must provide a SHA-256 digest")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("supply-chain artifact SHA-256 digest is malformed")
    return digest


def _artifact_redirect_url(*, repository: str, token: str, artifact_id: int) -> str:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "yp-ai-qa-trusted-pr-evidence",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=15):
            raise RuntimeError("artifact download unexpectedly bypassed the reviewed redirect")
    except urllib.error.HTTPError as exc:
        if exc.code not in {302, 303, 307, 308}:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub artifact redirect request failed with HTTP {exc.code}: {detail}"
            ) from exc
        location = exc.headers.get("Location")
        exc.close()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub artifact redirect transport failure: {exc}") from exc

    if not isinstance(location, str) or not location:
        raise RuntimeError("GitHub artifact redirect did not provide a location")
    parsed = urllib.parse.urlsplit(location)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.hostname == "api.github.com"
    ):
        raise RuntimeError("GitHub artifact redirect target is not an isolated HTTPS storage URL")
    return location


def _download_artifact_archive(
    *,
    repository: str,
    token: str,
    artifact_id: int,
    expected_size: int,
    expected_digest: str,
) -> bytes:
    if expected_size < 1 or expected_size > MAX_ARTIFACT_BYTES:
        raise ValueError("supply-chain artifact size is outside the bounded admission range")
    location = _artifact_redirect_url(
        repository=repository,
        token=token,
        artifact_id=artifact_id,
    )
    request = urllib.request.Request(
        location,
        method="GET",
        headers={"User-Agent": "yp-ai-qa-trusted-pr-evidence"},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=15) as response:
            data = response.read(MAX_ARTIFACT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(
            f"artifact storage download failed with HTTP {exc.code}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"artifact storage transport failure: {exc}") from exc

    if len(data) > MAX_ARTIFACT_BYTES or len(data) != expected_size:
        raise ValueError("downloaded supply-chain artifact size does not match trusted metadata")
    observed_digest = hashlib.sha256(data).hexdigest()
    if observed_digest != expected_digest:
        raise ValueError("downloaded supply-chain artifact digest does not match trusted metadata")
    return data


def _verify_build_manifest_archive(archive: bytes, expected_merge_sha: str) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            infos = bundle.infolist()
            if not infos or len(infos) > MAX_ARTIFACT_ENTRIES:
                raise ValueError("supply-chain artifact entry count is outside the bounded range")
            names: set[str] = set()
            total_uncompressed = 0
            manifest_info: zipfile.ZipInfo | None = None
            for info in infos:
                name = info.filename
                path = PurePosixPath(name)
                mode = info.external_attr >> 16
                if (
                    not name
                    or "\\" in name
                    or "\x00" in name
                    or path.is_absolute()
                    or ".." in path.parts
                    or name in names
                    or info.is_dir()
                    or (mode and stat.S_ISLNK(mode))
                    or info.flag_bits & 0x1
                ):
                    raise ValueError("supply-chain artifact contains an unsafe or duplicate entry")
                names.add(name)
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ARTIFACT_UNCOMPRESSED_BYTES:
                    raise ValueError("supply-chain artifact exceeds the uncompressed size bound")
                if name == EXPECTED_BUILD_MANIFEST:
                    manifest_info = info
            if manifest_info is None:
                raise ValueError("supply-chain artifact is missing build-manifest.json")
            if manifest_info.file_size < 1 or manifest_info.file_size > MAX_BUILD_MANIFEST_BYTES:
                raise ValueError("build-manifest.json size is outside the bounded admission range")
            manifest_bytes = bundle.read(manifest_info)
    except zipfile.BadZipFile as exc:
        raise ValueError("supply-chain artifact is not a valid ZIP archive") from exc

    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("build-manifest.json must be valid UTF-8 JSON") from exc
    payload = _mapping(manifest, label="build manifest")
    if (
        payload.get("schema_version") != 1
        or payload.get("kind") != "unsigned_reproducible_build_manifest"
    ):
        raise ValueError("build manifest schema or kind is not the reviewed evidence format")
    source = _mapping(payload.get("source"), label="build manifest source")
    if source.get("commit_sha") != expected_merge_sha:
        raise ValueError("build manifest is not bound to the authorized prospective merge SHA")
    if source.get("tracked_worktree_clean") is not True:
        raise ValueError("build manifest source worktree was not recorded as clean")
    return _require_sha(source.get("tree_sha"), label="build manifest source tree SHA")


def _verify_supply_chain_artifact(
    api: GitHubApi,
    *,
    token: str,
    run_id: int,
    expected: PullRequestSubject,
    head_ref: str,
) -> dict[str, Any]:
    artifact_name = urllib.parse.quote(EXPECTED_SUPPLY_CHAIN_ARTIFACT, safe="")
    payload = api.get_json(
        f"/repos/{api.repository}/actions/runs/{run_id}/artifacts?per_page=20&name={artifact_name}"
    )
    total = payload.get("total_count")
    artifacts = payload.get("artifacts")
    if total != 1 or not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ValueError("exactly one supply-chain evidence artifact is required")
    artifact = _mapping(artifacts[0], label="supply-chain artifact")
    if (
        artifact.get("name") != EXPECTED_SUPPLY_CHAIN_ARTIFACT
        or artifact.get("expired") is not False
    ):
        raise ValueError("supply-chain evidence artifact is missing, expired, or misnamed")
    artifact_id = _require_positive_int(artifact.get("id"), label="supply-chain artifact ID")
    size = _require_positive_int(artifact.get("size_in_bytes"), label="supply-chain artifact size")
    digest = _artifact_digest(artifact.get("digest"))
    expected_download_url = (
        f"https://api.github.com/repos/{api.repository}/actions/artifacts/{artifact_id}/zip"
    )
    if artifact.get("archive_download_url") != expected_download_url:
        raise ValueError("supply-chain artifact download URL is not canonical")
    workflow_run = _mapping(
        artifact.get("workflow_run"), label="supply-chain artifact workflow run"
    )
    if (
        workflow_run.get("id") != run_id
        or workflow_run.get("head_sha") != expected.head_sha
        or workflow_run.get("head_branch") != head_ref
    ):
        raise ValueError("supply-chain artifact is not bound to the selected pull-request run")

    archive = _download_artifact_archive(
        repository=api.repository,
        token=token,
        artifact_id=artifact_id,
        expected_size=size,
        expected_digest=digest,
    )
    tree_sha = _verify_build_manifest_archive(archive, expected.merge_sha)
    return {
        "artifact_id": artifact_id,
        "artifact_sha256": digest,
        "build_manifest_source_commit": expected.merge_sha,
        "build_manifest_source_tree": tree_sha,
    }


def verify_trusted_evidence(
    *,
    repository: str,
    token: str,
    expected: PullRequestSubject,
    protected_manifest_json: str,
) -> dict[str, Any]:
    _require_authorization_context()
    api = GitHubApi(repository=repository, token=token)

    resolve_current_subject(api, expected)
    current_pr = api.fetch_pull_request(expected.number)
    head_ref = _pull_request_head_ref(current_pr, expected)
    protected_changes = _verify_protected_manifest(api, expected, protected_manifest_json)
    _verify_candidate_workflow_binding(api, expected.merge_sha)

    run = _select_evidence_run(api, expected=expected, head_ref=head_ref)
    run_id = _require_positive_int(run.get("id"), label="workflow run ID")
    job_summary = _verify_jobs(api, run_id)
    artifact_summary = _verify_supply_chain_artifact(
        api,
        token=token,
        run_id=run_id,
        expected=expected,
        head_ref=head_ref,
    )

    # Re-resolve immediately after evidence admission so a head/base/merge change cannot
    # reuse a previously matching run as authorization for a different prospective merge.
    resolve_current_subject(api, expected)

    target_url = run.get("html_url")
    expected_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    if target_url != expected_url:
        raise ValueError("workflow evidence target URL is not canonical")

    return {
        "result": "SUCCESS",
        "subject": {
            "pr_number": expected.number,
            "head_sha": expected.head_sha,
            "base_sha": expected.base_sha,
            "merge_sha": expected.merge_sha,
        },
        "protected_changes": protected_changes,
        "evidence_run_id": run_id,
        "evidence_target_url": expected_url,
        "jobs": job_summary,
        "supply_chain_artifact": artifact_summary,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorize exact successful pull-request CI evidence for trusted reporting"
    )
    parser.add_argument("--pr-number", required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--expected-merge-sha", required=True)
    parser.add_argument("--protected-manifest-json", required=True)
    parser.add_argument("--github-output")
    return parser


def main() -> None:
    args = _parser().parse_args()
    expected = PullRequestSubject(
        number=_require_positive_int(args.pr_number, label="pull-request number"),
        head_sha=_require_sha(args.expected_head_sha, label="expected head SHA"),
        base_sha=_require_sha(args.expected_base_sha, label="expected base SHA"),
        merge_sha=_require_sha(args.expected_merge_sha, label="expected merge SHA"),
    )
    result = verify_trusted_evidence(
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        token=os.environ.get("GITHUB_TOKEN", ""),
        expected=expected,
        protected_manifest_json=args.protected_manifest_json,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.github_output:
        output = Path(args.github_output)
        if output.is_symlink():
            raise ValueError("GITHUB_OUTPUT must not be a symlink")
        with output.open("a", encoding="utf-8") as handle:
            handle.write(f"evidence_run_id={result['evidence_run_id']}\n")
            handle.write(f"evidence_target_url={result['evidence_target_url']}\n")


if __name__ == "__main__":
    main()
