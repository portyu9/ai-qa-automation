from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .core import (
    EXPECTED_DEFAULT_BRANCH,
    EXPECTED_OWNER,
    EXPECTED_REPOSITORY,
    EXPECTED_REPOSITORY_ID,
    EXPECTED_STATUS_CONTEXT,
    EXPECTED_WORKFLOW_ID,
    EXPECTED_WORKFLOW_NAME,
    EXPECTED_WORKFLOW_PATH,
    MAX_API_BYTES,
    PROTECTED_PATHS,
    Subject,
    derive_protected_changes,
    require_dict,
    require_list,
    require_positive_int,
    require_sha,
    require_str,
    strict_json_loads,
)

API_URL = "https://api.github.com"
API_VERSION = "2026-03-10"
USER_AGENT = "yp-trusted-pr-gate-external/1"
MAX_TOKEN_RESPONSE_BYTES = 512 * 1024
MAX_PULL_REQUEST_CANDIDATES = 100
MAX_PRIVATE_KEY_BYTES = 64 * 1024


class GitHubTransportError(RuntimeError):
    pass


class GitHubProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class Token:
    value: str
    expires_at_epoch: int


class AppTokenProvider:
    def __init__(
        self,
        *,
        app_id: str,
        installation_id: int,
        repository: str,
        private_key_pem: str,
        openssl_bin: str = "/usr/bin/openssl",
    ) -> None:
        self._app_id = require_str(app_id, label="GitHub App id", max_len=64)
        self._installation_id = require_positive_int(
            installation_id,
            label="GitHub App installation id",
        )
        if repository != EXPECTED_REPOSITORY:
            raise ValueError("token provider repository is not the reviewed repository")
        try:
            private_key_bytes = private_key_pem.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("GitHub App private key must be ASCII PEM") from exc
        if (
            not private_key_bytes
            or len(private_key_bytes) > MAX_PRIVATE_KEY_BYTES
            or b"\x00" in private_key_bytes
            or b"BEGIN" not in private_key_bytes
            or b"PRIVATE KEY" not in private_key_bytes
        ):
            raise ValueError("GitHub App private key is malformed or outside bounds")
        self._repository = repository
        self._private_key_pem = private_key_bytes
        self._openssl = self._resolve_openssl(openssl_bin)
        self._cached: Token | None = None

    @staticmethod
    def _resolve_openssl(path: str) -> str:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError("openssl path must be absolute")
        resolved = candidate.resolve(strict=True)
        st = resolved.stat()
        if not stat.S_ISREG(st.st_mode) or not os.access(resolved, os.X_OK):
            raise ValueError("openssl path must be an executable regular file")
        return str(resolved)

    @staticmethod
    def _inherited_fd_path(fd: int) -> str:
        if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
            raise ValueError("inherited descriptor must be a non-negative integer")
        for root in ("/proc/self/fd", "/dev/fd"):
            candidate = f"{root}/{fd}"
            try:
                descriptor_stat = Path(candidate).stat()
            except OSError:
                continue
            if stat.S_ISREG(descriptor_stat.st_mode):
                return candidate
        raise GitHubProtocolError("anonymous inherited key descriptor is not addressable")

    def installation_token(self) -> str:
        now = int(time.time())
        if self._cached is not None and self._cached.expires_at_epoch - 120 > now:
            return self._cached.value
        app_jwt = self._mint_app_jwt(now=now)
        installation = _request_json(
            method="GET",
            path=f"/repos/{self._repository}/installation",
            bearer=app_jwt,
            max_bytes=MAX_TOKEN_RESPONSE_BYTES,
        )
        observed_installation_id = require_positive_int(
            installation.get("id"),
            label="repository installation id",
        )
        if observed_installation_id != self._installation_id:
            raise GitHubProtocolError(
                "repository installation id differs from configured installation"
            )
        repo_name = self._repository.split("/", 1)[1]
        body = json.dumps(
            {
                "repositories": [repo_name],
                "permissions": {
                    "actions": "read",
                    "contents": "read",
                    "pull_requests": "read",
                    "statuses": "write",
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload = _request_json(
            method="POST",
            path=f"/app/installations/{self._installation_id}/access_tokens",
            bearer=app_jwt,
            body=body,
            max_bytes=MAX_TOKEN_RESPONSE_BYTES,
        )
        token = require_str(payload.get("token"), label="installation token", max_len=4096)
        expires_at = require_str(
            payload.get("expires_at"),
            label="installation token expiry",
            max_len=64,
        )
        try:
            expiry_epoch = int(
                datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
            )
        except (TypeError, ValueError) as exc:
            raise GitHubProtocolError("installation token expiry is malformed") from exc
        self._cached = Token(token, expiry_epoch)
        return token

    def _mint_app_jwt(self, *, now: int) -> str:
        header = _b64url(
            json.dumps(
                {"alg": "RS256", "typ": "JWT"},
                separators=(",", ":"),
            ).encode()
        )
        payload = _b64url(
            json.dumps(
                {"iat": now - 60, "exp": now + 540, "iss": self._app_id},
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        unsigned = f"{header}.{payload}".encode("ascii")
        proc: subprocess.CompletedProcess[bytes] | None = None
        try:
            # TemporaryFile is anonymous/unlinked on the supported POSIX deployment model. Passing
            # its inherited descriptor through a runtime-proven descriptor namespace avoids ever
            # creating a named private-key file that could survive abrupt process termination.
            with tempfile.TemporaryFile(mode="w+b") as key_file:
                key_fd = key_file.fileno()
                os.fchmod(key_fd, 0o600)
                key_file.write(self._private_key_pem)
                key_file.flush()
                key_file.seek(0)
                key_path = self._inherited_fd_path(key_fd)
                proc = subprocess.run(
                    [self._openssl, "dgst", "-sha256", "-sign", key_path],
                    input=unsigned,
                    capture_output=True,
                    check=False,
                    timeout=5,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    pass_fds=(key_fd,),
                )
        except subprocess.TimeoutExpired as exc:
            raise GitHubTransportError("openssl signing timed out") from exc
        except OSError as exc:
            raise GitHubProtocolError("openssl signing could not be started safely") from exc
        if (
            proc is None
            or proc.returncode != 0
            or not proc.stdout
            or len(proc.stdout) > 4096
            or proc.stderr != b""
        ):
            raise GitHubProtocolError("openssl could not sign GitHub App JWT")
        return f"{unsigned.decode('ascii')}.{_b64url(proc.stdout)}"


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_github_contents_base64_utf8(encoded: str) -> str:
    error = "candidate workflow content is not canonical base64 UTF-8"
    try:
        rendered = encoded.encode("ascii")
    except UnicodeEncodeError as exc:
        raise GitHubProtocolError(error) from exc

    lines = rendered.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if not lines or any(not line for line in lines):
        raise GitHubProtocolError(error)
    compact = b"".join(lines)
    try:
        decoded = base64.b64decode(compact, validate=True)
    except ValueError as exc:
        raise GitHubProtocolError(error) from exc
    if base64.b64encode(decoded) != compact:
        raise GitHubProtocolError(error)
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitHubProtocolError(error) from exc


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


def _direct_no_redirect_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _request_bytes(
    *,
    method: str,
    path: str,
    bearer: str,
    body: bytes | None = None,
    max_bytes: int = MAX_API_BYTES,
    accept: str = "application/vnd.github+json",
) -> bytes:
    if not path.startswith("/") or ".." in path or "\\" in path:
        raise ValueError("GitHub API path is not canonical")
    if not bearer:
        raise ValueError("GitHub bearer token is required")
    request = urllib.request.Request(
        API_URL + path,
        method=method,
        data=body,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Accept": accept,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with _direct_no_redirect_opener().open(request, timeout=20) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    observed_length = int(content_length)
                except ValueError as exc:
                    raise GitHubProtocolError(
                        "GitHub response Content-Length is malformed"
                    ) from exc
                if observed_length > max_bytes:
                    raise GitHubProtocolError("GitHub response exceeds configured bound")
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise GitHubProtocolError("GitHub response exceeds configured bound")
            return payload
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096)
        if exc.code in {408, 429, 500, 502, 503, 504}:
            raise GitHubTransportError(
                f"GitHub API transient HTTP {exc.code} for {path}: {detail[:200]!r}"
            ) from exc
        raise GitHubProtocolError(
            f"GitHub API non-retryable HTTP {exc.code} for {path}: {detail[:200]!r}"
        ) from exc
    except urllib.error.URLError as exc:
        raise GitHubTransportError(f"GitHub API transport failure for {path}") from exc


def _request_json(
    *,
    method: str,
    path: str,
    bearer: str,
    body: bytes | None = None,
    max_bytes: int = MAX_API_BYTES,
) -> dict[str, Any]:
    payload = _request_bytes(
        method=method,
        path=path,
        bearer=bearer,
        body=body,
        max_bytes=max_bytes,
    )
    parsed = strict_json_loads(payload, max_bytes=max_bytes, label="GitHub API JSON")
    return require_dict(parsed, label="GitHub API response")


class GitHubClient:
    def __init__(self, *, token_provider: AppTokenProvider, installation_id: int) -> None:
        self._token_provider = token_provider
        self.installation_id = require_positive_int(
            installation_id,
            label="configured GitHub App installation id",
        )
        self.repository = EXPECTED_REPOSITORY
        self.repository_id = EXPECTED_REPOSITORY_ID

    def get_json(self, path: str) -> dict[str, Any]:
        return _request_json(
            method="GET",
            path=path,
            bearer=self._token_provider.installation_token(),
        )

    def resolve_subject(self, *, run_id: int, event_head_sha: str) -> Subject:
        run = self.get_json(f"/repos/{self.repository}/actions/runs/{run_id}")
        self._validate_run(run, run_id=run_id, event_head_sha=event_head_sha)
        head_sha = require_sha(run.get("head_sha"), label="workflow run head SHA")
        token = self._token_provider.installation_token()
        raw = _request_bytes(
            method="GET",
            path=(
                f"/repos/{self.repository}/commits/{head_sha}/pulls"
                f"?per_page={MAX_PULL_REQUEST_CANDIDATES}"
            ),
            bearer=token,
        )
        pull_rows = require_list(
            strict_json_loads(
                raw,
                max_bytes=MAX_API_BYTES,
                label="commit pull requests",
            ),
            label="commit pull requests",
        )
        if len(pull_rows) >= MAX_PULL_REQUEST_CANDIDATES:
            raise GitHubProtocolError("commit pull-request resolution reached the pagination bound")
        matching: list[dict[str, Any]] = []
        for value in pull_rows:
            pr = require_dict(value, label="pull request candidate")
            head = require_dict(pr.get("head"), label="pull request candidate head")
            base = require_dict(pr.get("base"), label="pull request candidate base")
            head_repo = require_dict(
                head.get("repo"),
                label="pull request candidate head repository",
            )
            base_repo = require_dict(
                base.get("repo"),
                label="pull request candidate base repository",
            )
            if (
                pr.get("state") == "open"
                and pr.get("draft") is False
                and head.get("sha") == head_sha
                and head_repo.get("full_name") == self.repository
                and base.get("ref") == EXPECTED_DEFAULT_BRANCH
                and base_repo.get("full_name") == self.repository
            ):
                matching.append(pr)
        if len(matching) != 1:
            raise GitHubProtocolError(
                "workflow head does not resolve to exactly one eligible pull request"
            )
        pr_number = require_positive_int(
            matching[0].get("number"),
            label="pull request number",
        )
        main_ref = self.get_json(
            f"/repos/{self.repository}/git/ref/heads/{EXPECTED_DEFAULT_BRANCH}"
        )
        main_sha = self._ref_sha(
            main_ref,
            expected_ref=f"refs/heads/{EXPECTED_DEFAULT_BRANCH}",
            label="main ref",
        )
        pr = self.get_json(f"/repos/{self.repository}/pulls/{pr_number}")
        head = require_dict(pr.get("head"), label="live pull request head")
        base = require_dict(pr.get("base"), label="live pull request base")
        if pr.get("state") != "open" or pr.get("draft") is not False:
            raise GitHubProtocolError("pull request is no longer open and non-draft")
        if head.get("sha") != head_sha:
            raise GitHubProtocolError("pull request head drifted")
        head_repo = require_dict(
            head.get("repo"),
            label="live pull request head repository",
        )
        base_repo = require_dict(
            base.get("repo"),
            label="live pull request base repository",
        )
        if (
            head_repo.get("full_name") != self.repository
            or base_repo.get("full_name") != self.repository
        ):
            raise GitHubProtocolError("fork/cross-repository pull request is not eligible")
        if base.get("ref") != EXPECTED_DEFAULT_BRANCH:
            raise GitHubProtocolError("pull request no longer targets main")
        base_sha = require_sha(base.get("sha"), label="pull request base SHA")
        if base_sha != main_sha:
            raise GitHubProtocolError("pull request base is stale relative to main")
        head_ref = require_str(
            head.get("ref"),
            label="pull request head ref",
            max_len=255,
        )
        merge_ref = self.get_json(f"/repos/{self.repository}/git/ref/pull/{pr_number}/merge")
        merge_sha = self._ref_sha(
            merge_ref,
            expected_ref=f"refs/pull/{pr_number}/merge",
            label="merge ref",
        )
        merge_commit = self.get_json(f"/repos/{self.repository}/git/commits/{merge_sha}")
        parents = require_list(
            merge_commit.get("parents"),
            label="prospective merge parents",
        )
        if len(parents) != 2:
            raise GitHubProtocolError("prospective merge does not have exactly two parents")
        parent_shas = [
            require_sha(
                require_dict(item, label="merge parent").get("sha"),
                label="merge parent SHA",
            )
            for item in parents
        ]
        if parent_shas != [base_sha, head_sha]:
            raise GitHubProtocolError("prospective merge parent order differs from base/head")
        merge_tree = require_dict(
            merge_commit.get("tree"),
            label="prospective merge tree",
        )
        merge_tree_sha = require_sha(
            merge_tree.get("sha"),
            label="prospective merge tree SHA",
        )
        base_tree_index = self._tree_index(base_sha)
        merge_tree_index = self._tree_index(merge_sha)
        return Subject(
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            merge_sha=merge_sha,
            merge_tree_sha=merge_tree_sha,
            head_ref=head_ref,
            protected_changes=derive_protected_changes(
                base_tree_index,
                merge_tree_index,
            ),
        )

    def verify_run_evidence(
        self,
        *,
        run_id: int,
        subject: Subject,
    ) -> dict[str, Any]:
        run = self.get_json(f"/repos/{self.repository}/actions/runs/{run_id}")
        self._validate_run(run, run_id=run_id, event_head_sha=subject.head_sha)
        if run.get("head_branch") != subject.head_ref:
            raise GitHubProtocolError("workflow run branch differs from live pull request head ref")
        raw_jobs = _request_bytes(
            method="GET",
            path=(
                f"/repos/{self.repository}/actions/runs/{run_id}/jobs?per_page=100&filter=latest"
            ),
            bearer=self._token_provider.installation_token(),
        )
        from .core import (
            verify_build_manifest_archive,
            verify_candidate_workflow,
            verify_jobs,
        )

        jobs = verify_jobs(
            strict_json_loads(
                raw_jobs,
                max_bytes=MAX_API_BYTES,
                label="workflow jobs",
            )
        )
        workflow_path = urllib.parse.quote(EXPECTED_WORKFLOW_PATH, safe="/")
        workflow_payload = self.get_json(
            f"/repos/{self.repository}/contents/{workflow_path}?ref={subject.merge_sha}"
        )
        if workflow_payload.get("encoding") != "base64":
            raise GitHubProtocolError("candidate workflow content encoding is not base64")
        encoded = require_str(
            workflow_payload.get("content"),
            label="candidate workflow content",
            max_len=1024 * 1024,
        )
        workflow_text = _decode_github_contents_base64_utf8(encoded)
        verify_candidate_workflow(workflow_text)
        artifact_meta = self._artifact_metadata(run_id=run_id, subject=subject)
        archive = self._download_artifact(
            artifact_id=artifact_meta["artifact_id"],
            expected_size=artifact_meta["size"],
            expected_digest=artifact_meta["digest"],
        )
        manifest = verify_build_manifest_archive(
            archive,
            expected_merge_sha=subject.merge_sha,
            expected_tree_sha=subject.merge_tree_sha,
        )
        return {
            "run_id": run_id,
            "target_url": (f"https://github.com/{self.repository}/actions/runs/{run_id}"),
            "jobs": jobs,
            "artifact": {
                "artifact_id": artifact_meta["artifact_id"],
                "sha256": artifact_meta["digest"],
                "build_manifest": manifest,
            },
        }

    def publish_success(
        self,
        *,
        subject: Subject,
        target_url: str,
    ) -> dict[str, Any]:
        body = json.dumps(
            {
                "state": "success",
                "target_url": target_url,
                "description": ("Independent exact-subject protected maintenance admission passed"),
                "context": EXPECTED_STATUS_CONTEXT,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return _request_json(
            method="POST",
            path=f"/repos/{self.repository}/statuses/{subject.head_sha}",
            bearer=self._token_provider.installation_token(),
            body=body,
        )

    def latest_matching_success(
        self,
        *,
        subject: Subject,
        target_url: str,
        expected_creator_login: str,
    ) -> bool:
        token = self._token_provider.installation_token()
        raw = _request_bytes(
            method="GET",
            path=(f"/repos/{self.repository}/commits/{subject.head_sha}/statuses?per_page=100"),
            bearer=token,
        )
        rows = require_list(
            strict_json_loads(
                raw,
                max_bytes=MAX_API_BYTES,
                label="commit statuses",
            ),
            label="commit statuses",
        )
        for value in rows:
            status = require_dict(value, label="commit status")
            if status.get("context") != EXPECTED_STATUS_CONTEXT:
                continue
            creator = require_dict(
                status.get("creator"),
                label="commit status creator",
            )
            return (
                status.get("state") == "success"
                and status.get("target_url") == target_url
                and creator.get("login") == expected_creator_login
            )
        return False

    def _validate_run(
        self,
        run: dict[str, Any],
        *,
        run_id: int,
        event_head_sha: str,
    ) -> None:
        if require_positive_int(run.get("id"), label="workflow run id") != run_id:
            raise GitHubProtocolError("workflow run id drifted")
        workflow_id = require_positive_int(run.get("workflow_id"), label="workflow id")
        if workflow_id != EXPECTED_WORKFLOW_ID:
            raise GitHubProtocolError("workflow id is not reviewed")
        if run.get("name") != EXPECTED_WORKFLOW_NAME or run.get("path") != EXPECTED_WORKFLOW_PATH:
            raise GitHubProtocolError("workflow name/path is not reviewed")
        if (
            run.get("event") != "pull_request"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
        ):
            raise GitHubProtocolError("workflow run is not a completed successful pull_request run")
        repo = require_dict(
            run.get("repository"),
            label="workflow run repository",
        )
        head_repo = require_dict(
            run.get("head_repository"),
            label="workflow run head repository",
        )
        if repo.get("full_name") != self.repository or repo.get("id") != self.repository_id:
            raise GitHubProtocolError("workflow repository identity mismatch")
        if head_repo.get("full_name") != self.repository:
            raise GitHubProtocolError("fork workflow run is not eligible")
        actor = require_dict(run.get("actor"), label="workflow run actor")
        triggering_actor = require_dict(
            run.get("triggering_actor"),
            label="workflow triggering actor",
        )
        if actor.get("login") != EXPECTED_OWNER or triggering_actor.get("login") != EXPECTED_OWNER:
            raise GitHubProtocolError("workflow run was not initiated by the repository owner")
        head_sha = require_sha(run.get("head_sha"), label="workflow run head SHA")
        if head_sha != event_head_sha:
            raise GitHubProtocolError("webhook head SHA differs from live workflow run")

    @staticmethod
    def _ref_sha(
        payload: dict[str, Any],
        *,
        expected_ref: str,
        label: str,
    ) -> str:
        if payload.get("ref") != expected_ref:
            raise GitHubProtocolError(f"{label} identity mismatch")
        obj = require_dict(payload.get("object"), label=f"{label} object")
        if obj.get("type") != "commit":
            raise GitHubProtocolError(f"{label} does not point to a commit")
        return require_sha(obj.get("sha"), label=f"{label} SHA")

    def _tree_index(self, commit_sha: str) -> dict[str, str]:
        commit = self.get_json(f"/repos/{self.repository}/git/commits/{commit_sha}")
        tree = require_dict(commit.get("tree"), label="commit tree")
        tree_sha = require_sha(tree.get("sha"), label="commit tree SHA")
        payload = self.get_json(f"/repos/{self.repository}/git/trees/{tree_sha}?recursive=1")
        if payload.get("truncated") is not False:
            raise GitHubProtocolError("Git tree response is truncated or ambiguous")
        rows = require_list(payload.get("tree"), label="Git tree entries")
        result: dict[str, str] = {}
        for raw in rows:
            entry = require_dict(raw, label="Git tree entry")
            path = entry.get("path")
            if isinstance(path, str) and path in PROTECTED_PATHS:
                if path in result:
                    raise GitHubProtocolError("Git tree contains duplicate protected path")
                result[path] = require_sha(
                    entry.get("sha"),
                    label=f"Git object id for {path}",
                )
        return result

    def _artifact_metadata(
        self,
        *,
        run_id: int,
        subject: Subject,
    ) -> dict[str, Any]:
        token = self._token_provider.installation_token()
        name = urllib.parse.quote("supply-chain-evidence", safe="")
        payload = _request_json(
            method="GET",
            path=(
                f"/repos/{self.repository}/actions/runs/{run_id}/artifacts?per_page=20&name={name}"
            ),
            bearer=token,
        )
        artifacts = require_list(
            payload.get("artifacts"),
            label="workflow artifacts",
        )
        if payload.get("total_count") != 1 or len(artifacts) != 1:
            raise GitHubProtocolError("exactly one supply-chain evidence artifact is required")
        artifact = require_dict(artifacts[0], label="supply-chain artifact")
        if artifact.get("name") != "supply-chain-evidence" or artifact.get("expired") is not False:
            raise GitHubProtocolError("supply-chain artifact is missing/expired/misnamed")
        artifact_id = require_positive_int(artifact.get("id"), label="artifact id")
        size = require_positive_int(
            artifact.get("size_in_bytes"),
            label="artifact size",
        )
        digest_value = require_str(
            artifact.get("digest"),
            label="artifact digest",
            max_len=80,
        )
        if not digest_value.startswith("sha256:"):
            raise GitHubProtocolError("artifact digest is not SHA-256")
        digest = digest_value.removeprefix("sha256:")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise GitHubProtocolError("artifact SHA-256 digest is malformed")
        expected_download_url = (
            f"https://api.github.com/repos/{self.repository}/actions/artifacts/{artifact_id}/zip"
        )
        if artifact.get("archive_download_url") != expected_download_url:
            raise GitHubProtocolError("supply-chain artifact download URL is not canonical")
        workflow_run = require_dict(
            artifact.get("workflow_run"),
            label="artifact workflow run",
        )
        if (
            workflow_run.get("id") != run_id
            or workflow_run.get("head_sha") != subject.head_sha
            or workflow_run.get("head_branch") != subject.head_ref
        ):
            raise GitHubProtocolError("artifact is not bound to the selected workflow run")
        return {
            "artifact_id": artifact_id,
            "size": size,
            "digest": digest,
        }

    def _download_artifact(
        self,
        *,
        artifact_id: int,
        expected_size: int,
        expected_digest: str,
    ) -> bytes:
        from .core import MAX_ARTIFACT_BYTES

        if expected_size < 1 or expected_size > MAX_ARTIFACT_BYTES:
            raise GitHubProtocolError("artifact size is outside admission bounds")
        token = self._token_provider.installation_token()
        request = urllib.request.Request(
            (f"{API_URL}/repos/{self.repository}/actions/artifacts/{artifact_id}/zip"),
            method="GET",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": USER_AGENT,
            },
        )
        opener = _direct_no_redirect_opener()
        try:
            with opener.open(request, timeout=15):
                raise GitHubProtocolError("artifact endpoint unexpectedly bypassed redirect")
        except urllib.error.HTTPError as exc:
            if exc.code not in {302, 303, 307, 308}:
                detail = exc.read(4096)
                raise GitHubTransportError(
                    f"artifact redirect failed with HTTP {exc.code}: {detail[:200]!r}"
                ) from exc
            location = exc.headers.get("Location")
            exc.close()
        except urllib.error.URLError as exc:
            raise GitHubTransportError("artifact redirect transport failure") from exc
        if not isinstance(location, str) or not location:
            raise GitHubProtocolError("artifact redirect location is missing")
        parsed = urllib.parse.urlsplit(location)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.hostname == "api.github.com"
        ):
            raise GitHubProtocolError("artifact redirect target is not isolated HTTPS storage")
        storage_request = urllib.request.Request(
            location,
            headers={"User-Agent": USER_AGENT},
            method="GET",
        )
        try:
            with opener.open(storage_request, timeout=15) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        observed_length = int(content_length)
                    except ValueError as exc:
                        raise GitHubProtocolError(
                            "artifact storage Content-Length is malformed"
                        ) from exc
                    if observed_length != expected_size:
                        raise GitHubProtocolError(
                            "artifact storage Content-Length differs from metadata"
                        )
                data = response.read(MAX_ARTIFACT_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise GitHubTransportError(
                f"artifact storage download failed with HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise GitHubTransportError("artifact storage download failed") from exc
        if len(data) != expected_size or len(data) > MAX_ARTIFACT_BYTES:
            raise GitHubProtocolError("downloaded artifact size differs from metadata")
        if hashlib.sha256(data).hexdigest() != expected_digest:
            raise GitHubProtocolError("downloaded artifact digest differs from metadata")
        return data
