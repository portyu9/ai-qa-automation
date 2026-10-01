from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_promotion.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_promotion_lock_replay_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


promotion = _load()
qualification = sys.modules["trusted_qualification"]
governance = sys.modules["dependency_governance"]
HEAD = "a" * 40
LOCK_NAMES = (
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py314.lock",
    "runtime-py311.lock",
)


def _readme(version: str) -> bytes:
    return (
        f"[![Claude Agent SDK](https://img.shields.io/badge/Claude%20Agent%20SDK-{version}-purple)]\n"
        f"Runtime: `claude-agent-sdk=={version}`\n"
    ).encode()


def _sdk_pyproject(version: str) -> bytes:
    return (
        f'[project]\nname = "ai-qa-automation"\ndependencies = ["claude-agent-sdk=={version}"]\n'
    ).encode()


def _observed(pyproject: bytes, *, readme: bytes | None = None) -> dict[str, bytes]:
    result = {
        "README.md": readme if readme is not None else _readme("0.2.159"),
        "pyproject.toml": pyproject,
        ".github/lock-authority.json": b"authority\n",
    }
    for name in LOCK_NAMES:
        result[f"requirements/{name}"] = f"{name}\n".encode()
    return result


def test_generated_validation_replays_exact_observed_lock_without_recompiling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base_pyproject = _sdk_pyproject("0.2.136")
    pyproject = _sdk_pyproject("0.2.159")
    base_readme = _readme("0.2.136")
    observed = _observed(pyproject, readme=_readme("0.2.159"))
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base-image.lock").write_text("image@sha256:" + "1" * 64 + "\n")
    monkeypatch.setattr(promotion, "ROOT", tmp_path)
    monkeypatch.setenv("PROMOTION_PYTHON311", "/python311")
    monkeypatch.setenv("PROMOTION_PYTHON314", "/python314")
    monkeypatch.setattr(
        promotion,
        "_contents_bytes",
        lambda api, path, ref: observed[path],
    )
    monkeypatch.setattr(
        promotion,
        "_compile",
        lambda source: (_ for _ in ()).throw(AssertionError("live re-resolution is forbidden")),
    )
    captured: dict[str, Any] = {}

    def fake_validate(root: Path, python311: str, python314: str, bundle: Path) -> dict[str, Any]:
        captured["python311"] = python311
        captured["python314"] = python314
        captured["pyproject"] = (root / "pyproject.toml").read_bytes()
        captured["base_image"] = (root / "requirements" / "base-image.lock").read_bytes()
        captured["authority"] = (bundle / "lock-authority.json").read_bytes()
        captured["locks"] = {name: (bundle / name).read_bytes() for name in LOCK_NAMES}
        return {"schemaVersion": 1}

    monkeypatch.setattr(promotion, "validate_frozen_locks", fake_validate)
    promotion._validate_generated_bytes(
        object(),
        {"basePyproject": base_pyproject, "pyproject": pyproject, "readme": base_readme},
        HEAD,
    )

    assert captured["python311"] == "/python311"
    assert captured["python314"] == "/python314"
    assert captured["pyproject"] == pyproject
    assert captured["authority"] == observed[".github/lock-authority.json"]
    assert captured["locks"] == {name: observed[f"requirements/{name}"] for name in LOCK_NAMES}


def test_generated_validation_rejects_pyproject_drift_before_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = _observed(b"different\n")
    monkeypatch.setenv("PROMOTION_PYTHON311", "/python311")
    monkeypatch.setenv("PROMOTION_PYTHON314", "/python314")
    monkeypatch.setattr(promotion, "_contents_bytes", lambda api, path, ref: observed[path])
    called = False

    def fake_validate(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(promotion, "validate_frozen_locks", fake_validate)
    with pytest.raises(promotion.PolicyBlock, match="differs from exact Dependabot source"):
        promotion._validate_generated_bytes(object(), {"pyproject": b"expected\n"}, HEAD)
    assert called is False


def test_generated_validation_translates_frozen_replay_failure_to_policy_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base_pyproject = _sdk_pyproject("0.2.136")
    pyproject = _sdk_pyproject("0.2.159")
    base_readme = _readme("0.2.136")
    observed = _observed(pyproject, readme=_readme("0.2.159"))
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base-image.lock").write_text("base\n")
    monkeypatch.setattr(promotion, "ROOT", tmp_path)
    monkeypatch.setenv("PROMOTION_PYTHON311", "/python311")
    monkeypatch.setenv("PROMOTION_PYTHON314", "/python314")
    monkeypatch.setattr(promotion, "_contents_bytes", lambda api, path, ref: observed[path])

    def fail(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise promotion.LockCompileError("exact artifact disappeared")

    monkeypatch.setattr(promotion, "validate_frozen_locks", fail)
    with pytest.raises(promotion.PolicyBlock, match="promotion frozen lock replay failed"):
        promotion._validate_generated_bytes(
            object(),
            {"basePyproject": base_pyproject, "pyproject": pyproject, "readme": base_readme},
            HEAD,
        )


BASE = "b" * 40
FINGERPRINT = "c" * 64
BRANCH = "automation/dependency-promotion-171-" + FINGERPRINT[:12]
STAGING = "automation/dependency-promotion-base-171-" + FINGERPRINT[:12]
AUTHOR_LOGIN = "portyu9-security-remediator[bot]"
AUTHOR_ID = 333833782


def _stale_source_pyproject(*, hatchling: str = "1.32.0") -> bytes:
    return f"""[build-system]
requires = ["hatchling=={hatchling}"]
build-backend = "hatchling.build"

[project]
name = "ai-qa-automation"
dependencies = ["httpx>=0.28,<1"]

[project.optional-dependencies]
dev = ["ruff>=0.16,<1"]
""".encode()


def test_source_subject_rebases_stale_dependabot_when_live_pyproject_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_base = "d" * 40
    source_head = "e" * 40
    live_main = "f" * 40
    base_raw = _stale_source_pyproject()
    head_raw = _stale_source_pyproject(hatchling="1.32.4")
    readme_raw = b"exact live README\n"
    reads: list[tuple[str, str]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/branches/main"
            return {"commit": {"sha": live_main}}

    def validate_identity(
        api: Any,
        pr: dict[str, Any],
        config: dict[str, Any],
        require_current_base: bool,
    ) -> tuple[str, str, int]:
        assert isinstance(api, Api)
        assert pr == {"number": 179}
        assert config == {"baseBranch": "main"}
        assert require_current_base is False
        return source_head, source_base, 179

    def validate_provenance(api: Any, number: int) -> None:
        assert isinstance(api, Api)
        assert number == 179

    def source_files(
        api: Any,
        number: int,
        config: dict[str, Any],
    ) -> list[dict[str, str]]:
        assert isinstance(api, Api)
        assert number == 179
        assert config == {"baseBranch": "main"}
        return [{"filename": "pyproject.toml", "status": "modified"}]

    monkeypatch.setattr(promotion, "validate_pr_identity", validate_identity)
    monkeypatch.setattr(
        promotion,
        "_validate_dependabot_provenance",
        validate_provenance,
    )
    monkeypatch.setattr(promotion, "changed_files", source_files)

    def contents(api: Any, path: str, ref: str) -> bytes:
        assert api.__class__ is Api
        reads.append((path, ref))
        if path == "README.md":
            assert ref == live_main
            return readme_raw
        assert path == "pyproject.toml"
        return {
            source_base: base_raw,
            source_head: head_raw,
            live_main: base_raw,
        }[ref]

    monkeypatch.setattr(promotion, "_contents_bytes", contents)

    observed = promotion.source_subject(Api(), {"number": 179}, {"baseBranch": "main"})

    assert observed["number"] == 179
    assert observed["headSha"] == source_head
    assert observed["sourceBaseSha"] == source_base
    assert observed["baseSha"] == live_main
    assert observed["basePyproject"] == base_raw
    assert observed["pyproject"] == head_raw
    assert observed["readme"] == readme_raw
    assert reads == [
        ("pyproject.toml", source_base),
        ("pyproject.toml", source_head),
        ("pyproject.toml", live_main),
        ("README.md", live_main),
    ]


def test_source_subject_rejects_stale_dependabot_evidence_when_live_pyproject_drifted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_base = "d" * 40
    source_head = "e" * 40
    live_main = "f" * 40
    base_raw = _stale_source_pyproject()
    head_raw = _stale_source_pyproject(hatchling="1.32.4")
    live_raw = base_raw + b"\n# concurrent main drift\n"

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/branches/main"
            return {"commit": {"sha": live_main}}

    def validate_identity(
        api: Any,
        pr: dict[str, Any],
        config: dict[str, Any],
        require_current_base: bool,
    ) -> tuple[str, str, int]:
        assert isinstance(api, Api)
        assert pr == {"number": 179}
        assert config == {"baseBranch": "main"}
        assert require_current_base is False
        return source_head, source_base, 179

    def validate_provenance(api: Any, number: int) -> None:
        assert isinstance(api, Api)
        assert number == 179

    def source_files(
        api: Any,
        number: int,
        config: dict[str, Any],
    ) -> list[dict[str, str]]:
        assert isinstance(api, Api)
        assert number == 179
        assert config == {"baseBranch": "main"}
        return [{"filename": "pyproject.toml", "status": "modified"}]

    monkeypatch.setattr(promotion, "validate_pr_identity", validate_identity)
    monkeypatch.setattr(
        promotion,
        "_validate_dependabot_provenance",
        validate_provenance,
    )
    monkeypatch.setattr(promotion, "changed_files", source_files)
    monkeypatch.setattr(
        promotion,
        "_contents_bytes",
        lambda api, path, ref: {
            source_base: base_raw,
            source_head: head_raw,
            live_main: live_raw,
        }[ref],
    )

    with pytest.raises(
        promotion.PolicyBlock,
        match=r"stale Dependabot source overlaps current pyproject\.toml; wait for native rebase",
    ):
        promotion.source_subject(Api(), {"number": 179}, {"baseBranch": "main"})


def test_current_control_revision_guard_is_exact_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Api:
        def __init__(self, live_sha: str) -> None:
            self.live_sha = live_sha

        def get(self, path: str) -> dict[str, Any]:
            assert path == "/branches/main"
            return {"commit": {"sha": self.live_sha}}

    config = {"baseBranch": "main"}
    monkeypatch.setenv(governance.GOVERNANCE_CONTROL_SHA_ENV, BASE)
    assert governance.require_current_control_revision(Api(BASE), config) == BASE

    with pytest.raises(governance.GovernanceError, match="stale relative to current main"):
        governance.require_current_control_revision(Api(HEAD), config)

    monkeypatch.delenv(governance.GOVERNANCE_CONTROL_SHA_ENV)
    with pytest.raises(governance.GovernanceError, match="must be an exact 40-character SHA"):
        governance.require_current_control_revision(Api(BASE), config)


def _promotion_metadata() -> dict[str, Any]:
    return {
        "version": 1,
        "sourcePr": 171,
        "sourceHead": "d" * 40,
        "sourceBase": "e" * 40,
        "base": BASE,
        "head": HEAD,
        "fingerprint": FINGERPRINT,
    }


def _promotion_pr(
    *,
    base_ref: str = "main",
    body: str | None = None,
    author_login: str = AUTHOR_LOGIN,
    author_id: int = AUTHOR_ID,
) -> dict[str, Any]:
    return {
        "number": 901,
        "title": "deps: promote Dependabot PR #171",
        "state": "open",
        "draft": False,
        "user": {
            "login": author_login,
            "id": author_id,
        },
        "head": {
            "ref": BRANCH,
            "sha": HEAD,
            "repo": {"full_name": "portyu9/ai-qa-automation"},
        },
        "base": {
            "ref": base_ref,
            "sha": BASE,
            "repo": {"full_name": "portyu9/ai-qa-automation"},
        },
        "body": body or promotion._promotion_body(_promotion_metadata()),
    }


def test_sdk_readme_synchronization_updates_only_exact_reviewed_tokens() -> None:
    base = _sdk_pyproject("0.2.136")
    head = _sdk_pyproject("0.2.159")
    readme = _readme("0.2.136")

    assert promotion._synchronize_readme_sdk_claim(readme, base, head) == _readme("0.2.159")
    assert promotion._synchronize_readme_sdk_claim(readme, base, base) == readme


def test_sdk_readme_synchronization_rejects_missing_or_duplicate_authority() -> None:
    base = _sdk_pyproject("0.2.136")
    head = _sdk_pyproject("0.2.159")
    readme = _readme("0.2.136")

    with pytest.raises(
        promotion.PolicyBlock, match="badge is missing, duplicated, or already drifted"
    ):
        promotion._synchronize_readme_sdk_claim(readme + readme, base, head)

    with pytest.raises(
        promotion.PolicyBlock, match="runtime claim is missing, duplicated, or already drifted"
    ):
        promotion._synchronize_readme_sdk_claim(
            readme.replace(b"`claude-agent-sdk==0.2.136`", b"SDK"),
            base,
            head,
        )


def test_promotion_changed_paths_accept_only_unique_modified_generated_files() -> None:
    files = [
        {"filename": "README.md", "status": "modified"},
        {"filename": "pyproject.toml", "status": "modified"},
        {"filename": ".github/lock-authority.json", "status": "modified"},
    ]

    assert promotion._validate_promotion_changed_paths(files) == {
        "README.md",
        "pyproject.toml",
        ".github/lock-authority.json",
    }


@pytest.mark.parametrize(
    ("files", "message"),
    (
        (
            [
                {
                    "filename": "pyproject.toml",
                    "status": "renamed",
                    "previous_filename": ".github/workflows/ci.yml",
                },
                {"filename": ".github/lock-authority.json", "status": "modified"},
            ],
            "ordinary modified files without rename provenance",
        ),
        (
            [
                {"filename": "pyproject.toml", "status": "removed"},
                {"filename": ".github/lock-authority.json", "status": "modified"},
            ],
            "ordinary modified files without rename provenance",
        ),
        (
            [
                {"filename": None, "status": "modified"},
                {"filename": "pyproject.toml", "status": "modified"},
                {"filename": ".github/lock-authority.json", "status": "modified"},
            ],
            "outside generated authority",
        ),
        (
            [
                {"filename": "pyproject.toml", "status": "modified"},
                {"filename": "pyproject.toml", "status": "modified"},
                {"filename": ".github/lock-authority.json", "status": "modified"},
            ],
            "ambiguous for path",
        ),
    ),
)
def test_promotion_changed_paths_reject_rename_delete_malformed_and_duplicate_rows(
    files: list[dict[str, Any]],
    message: str,
) -> None:
    with pytest.raises(promotion.PolicyBlock, match=message):
        promotion._validate_promotion_changed_paths(files)


def test_create_promotion_pr_uses_non_main_staging_base_then_exact_retarget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_calls = 0
    events: list[tuple[str, str]] = []
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        assert config["baseBranch"] == "main"
        control_calls += 1
        return BASE

    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)

    class Api:
        def __init__(self) -> None:
            self.staging_exists = False
            self.pr_base = STAGING

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}":
                if not self.staging_exists:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            raise AssertionError(path)

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            if path == "/git/refs":
                assert payload == {"ref": f"refs/heads/{STAGING}", "sha": BASE}
                self.staging_exists = True
                events.append(("create-ref", STAGING))
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == "/pulls":
                assert payload["head"] == BRANCH
                assert payload["base"] == STAGING
                assert payload["draft"] is False
                events.append(("create-pr", STAGING))
                return _promotion_pr(
                    base_ref=STAGING,
                    body=str(payload["body"]),
                    author_login=AUTHOR_LOGIN,
                    author_id=AUTHOR_ID,
                )
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            return [
                _promotion_pr(
                    base_ref=self.pr_base,
                    author_login=AUTHOR_LOGIN,
                    author_id=AUTHOR_ID,
                )
            ]

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            if (method, path) == ("PATCH", "/pulls/901"):
                assert payload == {"base": "main"}
                self.pr_base = "main"
                events.append(("retarget", "main"))
                return _promotion_pr(
                    author_login=AUTHOR_LOGIN,
                    author_id=AUTHOR_ID,
                )
            if (method, path) == (
                "DELETE",
                f"/git/refs/heads/{STAGING.replace('/', '%2F')}",
            ):
                assert payload is None
                self.staging_exists = False
                events.append(("delete-ref", STAGING))
                return None
            raise AssertionError((method, path, payload))

    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }
    assert (
        promotion._create_promotion_pr(Api(), source, BRANCH, HEAD, {"baseBranch": "main"}) == 901
    )
    assert control_calls == 5
    assert events == [
        ("create-ref", STAGING),
        ("create-pr", STAGING),
        ("retarget", "main"),
        ("delete-ref", STAGING),
    ]


def test_existing_exact_staging_base_is_reused_without_ref_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_calls = 0

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}"
            return {
                "ref": f"refs/heads/{STAGING}",
                "object": {"type": "commit", "sha": BASE},
            }

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            raise AssertionError("exact existing staging ref must be reused")

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        control_calls += 1
        return BASE

    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)
    source = {
        "number": 171,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }

    assert promotion._ensure_staging_base_ref(Api(), source, {"baseBranch": "main"}) == STAGING
    assert control_calls == 0


def test_drifted_existing_staging_base_blocks_before_pr_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutations: list[str] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}"
            return {
                "ref": f"refs/heads/{STAGING}",
                "object": {"type": "commit", "sha": "9" * 40},
            }

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            mutations.append(path)
            raise AssertionError("drifted staging ref must block before mutation")

    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }

    with pytest.raises(
        promotion.PolicyBlock,
        match="staging-base ref does not equal exact current main",
    ):
        promotion._create_promotion_pr(Api(), source, BRANCH, HEAD, {"baseBranch": "main"})

    assert mutations == []


def test_transport_failure_after_promotion_pr_submission_retains_exact_refs_for_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    requests: list[tuple[str, str]] = []

    class Api:
        def __init__(self) -> None:
            self.staging_exists = False

        def get(self, path: str) -> dict[str, Any]:
            assert path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}"
            if not self.staging_exists:
                raise promotion.GovernanceError("HTTP 404")
            return {
                "ref": f"refs/heads/{STAGING}",
                "object": {"type": "commit", "sha": BASE},
            }

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            if path == "/git/refs":
                self.staging_exists = True
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls"
            assert payload["base"] == STAGING
            raise promotion.GovernanceError(
                "GitHub API POST /pulls transport failure: connection reset"
            )

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            requests.append((method, path))
            raise AssertionError("ambiguous PR submission must not trigger cleanup mutation")

    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }
    api = Api()
    with pytest.raises(
        promotion.GovernanceError,
        match="failed ambiguously after submission; retaining exact staging and generated refs",
    ):
        promotion._create_promotion_pr(api, source, BRANCH, HEAD, {"baseBranch": "main"})

    assert api.staging_exists is True
    assert requests == []


def test_ambiguous_promotion_pr_create_retains_staging_and_branch_for_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    requests: list[tuple[str, str]] = []

    class Api:
        def __init__(self) -> None:
            self.staging_exists = False

        def get(self, path: str) -> dict[str, Any]:
            assert path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}"
            if not self.staging_exists:
                raise promotion.GovernanceError("HTTP 404")
            return {
                "ref": f"refs/heads/{STAGING}",
                "object": {"type": "commit", "sha": BASE},
            }

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            if path == "/git/refs":
                self.staging_exists = True
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls"
            assert payload["base"] == STAGING
            return {}

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            requests.append((method, path))
            raise AssertionError("ambiguous PR response must retain exact refs")

    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }
    api = Api()
    with pytest.raises(
        promotion.GovernanceError,
        match="ambiguous; retaining exact staging and generated refs",
    ):
        promotion._create_promotion_pr(api, source, BRANCH, HEAD, {"baseBranch": "main"})

    assert api.staging_exists is True
    assert requests == []


def test_failed_malformed_pr_closure_retains_staging_and_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    created_body = ""

    class Api:
        def __init__(self) -> None:
            self.staging_exists = False

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}":
                if not self.staging_exists:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls/901"
            return _promotion_pr(
                base_ref=STAGING,
                body=created_body,
                author_login=AUTHOR_LOGIN,
                author_id=AUTHOR_ID,
            )

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal created_body
            if path == "/git/refs":
                self.staging_exists = True
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls"
            created_body = str(payload["body"])
            pr = _promotion_pr(
                base_ref=STAGING,
                body=created_body,
                author_login=AUTHOR_LOGIN,
                author_id=AUTHOR_ID,
            )
            pr["head"]["sha"] = "9" * 40
            return pr

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            assert (method, path) == ("PATCH", "/pulls/901")
            assert payload == {"state": "closed"}
            return {"number": 901, "state": "open"}

    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }
    api = Api()
    with pytest.raises(
        promotion.GovernanceError,
        match="could not be durably closed; retaining exact refs",
    ):
        promotion._create_promotion_pr(api, source, BRANCH, HEAD, {"baseBranch": "main"})

    assert api.staging_exists is True


def test_malformed_new_promotion_pr_is_closed_and_exact_refs_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    deleted: list[str] = []
    closed: list[int] = []
    created_body = ""

    class Api:
        def __init__(self) -> None:
            self.staging_exists = False
            self.open = True

        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/901":
                return _promotion_pr(
                    base_ref=STAGING,
                    body=created_body,
                    author_login=AUTHOR_LOGIN,
                    author_id=AUTHOR_ID,
                )
            if path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}":
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == f"/git/ref/heads/{BRANCH.replace('/', '%2F')}":
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            raise AssertionError(path)

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal created_body
            if path == "/git/refs":
                self.staging_exists = True
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls"
            created_body = str(payload["body"])
            pr = _promotion_pr(
                base_ref=STAGING,
                body=created_body,
                author_login=AUTHOR_LOGIN,
                author_id=AUTHOR_ID,
            )
            pr["head"]["sha"] = "9" * 40
            return pr

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            return [] if not self.open else [_promotion_pr(base_ref=STAGING)]

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            if (method, path) == ("PATCH", "/pulls/901"):
                assert payload == {"state": "closed"}
                self.open = False
                closed.append(901)
                return {"number": 901, "state": "closed"}
            if method == "DELETE":
                deleted.append(path)
                if path == f"/git/refs/heads/{STAGING.replace('/', '%2F')}":
                    self.staging_exists = False
                return None
            raise AssertionError((method, path, payload))

    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }
    with pytest.raises(promotion.GovernanceError, match="identity drifted"):
        promotion._create_promotion_pr(Api(), source, BRANCH, HEAD, {"baseBranch": "main"})

    assert closed == [901]
    assert deleted == [
        f"/git/refs/heads/{STAGING.replace('/', '%2F')}",
        f"/git/refs/heads/{BRANCH.replace('/', '%2F')}",
    ]


def test_malformed_new_promotion_pr_drift_retains_exact_refs_without_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    requests: list[tuple[str, str]] = []

    class Api:
        def __init__(self) -> None:
            self.staging_exists = False

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}":
                if not self.staging_exists:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls/901"
            pr = _promotion_pr(
                base_ref=STAGING,
                author_login=AUTHOR_LOGIN,
                author_id=AUTHOR_ID,
            )
            pr["head"]["sha"] = "8" * 40
            return pr

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            if path == "/git/refs":
                self.staging_exists = True
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls"
            pr = _promotion_pr(
                base_ref=STAGING,
                body=str(payload["body"]),
                author_login=AUTHOR_LOGIN,
                author_id=AUTHOR_ID,
            )
            pr["head"]["sha"] = "9" * 40
            return pr

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            requests.append((method, path))
            raise AssertionError("unproven PR must not be mutated")

    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }
    api = Api()
    with pytest.raises(
        promotion.GovernanceError,
        match="could not be proven exact for cleanup; retaining exact refs",
    ):
        promotion._create_promotion_pr(api, source, BRANCH, HEAD, {"baseBranch": "main"})

    assert api.staging_exists is True
    assert requests == []


def test_new_promotion_author_must_be_independent_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, raising=False)
    monkeypatch.delenv(promotion.PROMOTION_AUTHOR_ID_ENV, raising=False)
    assert promotion._promotion_author_identity() == (AUTHOR_LOGIN, AUTHOR_ID)

    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, "attacker-app[bot]")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    with pytest.raises(promotion.GovernanceError, match="drifted from trusted policy"):
        promotion._promotion_author_identity()

    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    assert promotion._promotion_actor_matches({"login": AUTHOR_LOGIN, "id": AUTHOR_ID})
    legacy = {
        "login": promotion.GITHUB_ACTIONS_LOGIN,
        "id": promotion.GITHUB_ACTIONS_USER_ID,
    }
    assert not promotion._promotion_actor_matches(legacy)
    assert promotion._legacy_promotion_actor_matches(legacy)


def test_new_promotion_commit_requires_independent_app_author(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    generated = {"pyproject.toml": b"exact generated bytes\n"}
    base_tree = "f" * 40
    tree_sha = "1" * 40

    class Api:
        def __init__(self, author_login: str, author_id: int) -> None:
            self.author_login = author_login
            self.author_id = author_id

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/commits/{BASE}":
                return {"sha": BASE, "tree": {"sha": base_tree}}
            if path == f"/git/ref/heads/{BRANCH.replace('/', '%2F')}":
                raise promotion.GovernanceError("GitHub API GET failed HTTP 404")
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {"login": self.author_login, "id": self.author_id},
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                }
            raise AssertionError(path)

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            if path == "/git/blobs":
                raw = base64.b64decode(payload["content"], validate=True)
                return {"sha": promotion._git_blob_sha1(raw)}
            if path == "/git/trees":
                assert payload["base_tree"] == base_tree
                return {"sha": tree_sha}
            if path == "/git/commits":
                assert payload == {
                    "message": "deps: promote Dependabot PR #171 with synchronized locks",
                    "tree": tree_sha,
                    "parents": [BASE],
                }
                return {"sha": HEAD}
            if path == "/git/refs":
                assert payload == {"ref": f"refs/heads/{BRANCH}", "sha": HEAD}
                return {"ref": f"refs/heads/{BRANCH}", "object": {"type": "commit", "sha": HEAD}}
            raise AssertionError(path)

    source = {"number": 171, "baseSha": BASE}
    monkeypatch.setattr(promotion, "_compile", lambda source_arg: generated)

    assert promotion._create_promotion_commit(
        Api(AUTHOR_LOGIN, AUTHOR_ID),
        source,
        BRANCH,
        {"baseBranch": "main"},
    ) == (HEAD, generated)

    with pytest.raises(
        promotion.GovernanceError,
        match="not authored by the exact independent App",
    ):
        promotion._create_promotion_commit(
            Api(promotion.GITHUB_ACTIONS_LOGIN, promotion.GITHUB_ACTIONS_USER_ID),
            source,
            BRANCH,
            {"baseBranch": "main"},
        )


@pytest.mark.parametrize(
    "control_error",
    [promotion.GovernanceError, promotion.PolicyBlock],
)
def test_new_promotion_branch_is_rolled_back_if_control_moves_after_creation(
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[Exception],
) -> None:
    generated = {"pyproject.toml": b"exact generated bytes\n"}
    base_tree = "f" * 40
    tree_sha = "1" * 40
    control_calls = 0
    branch_created = False
    deleted: list[str] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/commits/{BASE}":
                return {"sha": BASE, "tree": {"sha": base_tree}}
            if path == f"/git/ref/heads/{BRANCH.replace('/', '%2F')}":
                if not branch_created:
                    raise promotion.GovernanceError("GitHub API GET failed HTTP 404")
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {"login": AUTHOR_LOGIN, "id": AUTHOR_ID},
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                }
            raise AssertionError(path)

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal branch_created
            if path == "/git/blobs":
                raw = base64.b64decode(payload["content"], validate=True)
                return {"sha": promotion._git_blob_sha1(raw)}
            if path == "/git/trees":
                assert payload["base_tree"] == base_tree
                return {"sha": tree_sha}
            if path == "/git/commits":
                return {"sha": HEAD}
            if path == "/git/refs":
                branch_created = True
                return {"ref": f"refs/heads/{BRANCH}", "object": {"type": "commit", "sha": HEAD}}
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path.startswith("/pulls?")
            return []

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> None:
            nonlocal branch_created
            assert method == "DELETE"
            assert path == f"/git/refs/heads/{BRANCH.replace('/', '%2F')}"
            assert payload is None
            branch_created = False
            deleted.append(path)

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        control_calls += 1
        if control_calls == 2:
            raise control_error("control moved after branch creation")
        return BASE

    monkeypatch.setattr(promotion, "_compile", lambda source: generated)
    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)

    with pytest.raises(
        control_error,
        match="control moved after branch creation",
    ):
        promotion._create_promotion_commit(
            Api(),
            {"number": 171, "baseSha": BASE},
            BRANCH,
            {"baseBranch": "main"},
        )

    assert control_calls == 2
    assert not branch_created
    assert deleted == [f"/git/refs/heads/{BRANCH.replace('/', '%2F')}"]


def test_new_promotion_pr_control_move_before_staging_create_has_no_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutations: list[tuple[str, str]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}"
            raise promotion.GovernanceError("HTTP 404")

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            mutations.append(("POST", path))
            raise AssertionError("stale control must stop before staging ref creation")

    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: (_ for _ in ()).throw(
            promotion.GovernanceError("control moved before staging creation")
        ),
    )
    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }

    with pytest.raises(promotion.GovernanceError, match="control moved before staging creation"):
        promotion._create_promotion_pr(Api(), source, BRANCH, HEAD, {"baseBranch": "main"})

    assert mutations == []


def test_pre_pr_control_move_rolls_back_exact_staging_and_generated_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_calls = 0
    staging_exists = False
    generated_exists = True
    deleted: list[str] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}":
                if not staging_exists:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == f"/git/ref/heads/{BRANCH.replace('/', '%2F')}":
                assert generated_exists
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            raise AssertionError(path)

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal staging_exists
            assert path == "/git/refs"
            assert payload == {"ref": f"refs/heads/{STAGING}", "sha": BASE}
            staging_exists = True
            return {
                "ref": f"refs/heads/{STAGING}",
                "object": {"type": "commit", "sha": BASE},
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            return []

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> None:
            nonlocal staging_exists, generated_exists
            assert method == "DELETE"
            assert payload is None
            if path == f"/git/refs/heads/{STAGING.replace('/', '%2F')}":
                staging_exists = False
            elif path == f"/git/refs/heads/{BRANCH.replace('/', '%2F')}":
                generated_exists = False
            else:
                raise AssertionError(path)
            deleted.append(path)

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        control_calls += 1
        if control_calls == 3:
            raise promotion.GovernanceError("control moved at pre-PR boundary")
        return BASE

    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)
    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }

    with pytest.raises(promotion.GovernanceError, match="control moved at pre-PR boundary"):
        promotion._create_promotion_pr(Api(), source, BRANCH, HEAD, {"baseBranch": "main"})

    assert control_calls == 3
    assert staging_exists is False
    assert generated_exists is False
    assert deleted == [
        f"/git/refs/heads/{STAGING.replace('/', '%2F')}",
        f"/git/refs/heads/{BRANCH.replace('/', '%2F')}",
    ]


@pytest.mark.parametrize(
    "control_error",
    [promotion.GovernanceError, promotion.PolicyBlock],
)
def test_new_staging_ref_is_rolled_back_if_control_moves_after_creation(
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[Exception],
) -> None:
    control_calls = 0
    staging_exists = False
    deleted: list[str] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}"
            if not staging_exists:
                raise promotion.GovernanceError("HTTP 404")
            return {
                "ref": f"refs/heads/{STAGING}",
                "object": {"type": "commit", "sha": BASE},
            }

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal staging_exists
            assert path == "/git/refs"
            assert payload == {"ref": f"refs/heads/{STAGING}", "sha": BASE}
            staging_exists = True
            return {
                "ref": f"refs/heads/{STAGING}",
                "object": {"type": "commit", "sha": BASE},
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            return []

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> None:
            nonlocal staging_exists
            assert method == "DELETE"
            assert path == f"/git/refs/heads/{STAGING.replace('/', '%2F')}"
            assert payload is None
            staging_exists = False
            deleted.append(path)

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        control_calls += 1
        if control_calls == 2:
            raise control_error("control moved after staging creation")
        return BASE

    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)
    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }

    with pytest.raises(control_error, match="control moved after staging creation"):
        promotion._create_promotion_pr(Api(), source, BRANCH, HEAD, {"baseBranch": "main"})

    assert control_calls == 2
    assert staging_exists is False
    assert deleted == [f"/git/refs/heads/{STAGING.replace('/', '%2F')}"]


def test_new_promotion_pr_is_rolled_back_if_control_moves_after_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_calls = 0
    staging_exists = False
    pr_open = False
    body = ""
    requests: list[tuple[str, str]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{STAGING.replace('/', '%2F')}":
                if not staging_exists:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == "/pulls/901":
                return _promotion_pr(
                    base_ref=STAGING,
                    body=body,
                    author_login=AUTHOR_LOGIN,
                    author_id=AUTHOR_ID,
                )
            if path == f"/git/ref/heads/{BRANCH.replace('/', '%2F')}":
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            raise AssertionError(path)

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal staging_exists, pr_open, body
            if path == "/git/refs":
                staging_exists = True
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            assert path == "/pulls"
            assert payload["base"] == STAGING
            body = str(payload["body"])
            pr_open = True
            return _promotion_pr(
                base_ref=STAGING,
                body=body,
                author_login=AUTHOR_LOGIN,
                author_id=AUTHOR_ID,
            )

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            if not pr_open:
                return []
            return [
                _promotion_pr(
                    base_ref=STAGING,
                    body=body,
                    author_login=AUTHOR_LOGIN,
                    author_id=AUTHOR_ID,
                )
            ]

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            nonlocal staging_exists, pr_open
            requests.append((method, path))
            if (method, path) == ("PATCH", "/pulls/901"):
                assert payload == {"state": "closed"}
                pr_open = False
                return {"number": 901, "state": "closed"}
            if method == "DELETE":
                assert payload is None
                if path == f"/git/refs/heads/{STAGING.replace('/', '%2F')}":
                    staging_exists = False
                return None
            raise AssertionError((method, path, payload))

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        control_calls += 1
        if control_calls == 4:
            raise promotion.GovernanceError("control moved after PR creation")
        return BASE

    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)
    source = {
        "number": 171,
        "headSha": "d" * 40,
        "sourceBaseSha": "e" * 40,
        "baseSha": BASE,
        "fingerprint": FINGERPRINT,
    }

    with pytest.raises(promotion.GovernanceError, match="control moved after PR creation"):
        promotion._create_promotion_pr(Api(), source, BRANCH, HEAD, {"baseBranch": "main"})

    assert control_calls == 4
    assert pr_open is False
    assert staging_exists is False
    assert requests == [
        ("PATCH", "/pulls/901"),
        ("DELETE", f"/git/refs/heads/{STAGING.replace('/', '%2F')}"),
        ("DELETE", f"/git/refs/heads/{BRANCH.replace('/', '%2F')}"),
    ]


def test_legacy_promotion_is_cleanup_only_and_cannot_validate() -> None:
    legacy = _promotion_pr(
        author_login=promotion.GITHUB_ACTIONS_LOGIN,
        author_id=promotion.GITHUB_ACTIONS_USER_ID,
    )
    with pytest.raises(
        promotion.PolicyBlock,
        match="not authored by the independent promotion App",
    ):
        promotion._validate_promotion(
            object(),
            legacy,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
            validate_generated_bytes=False,
            require_checks=False,
        )


def test_exact_legacy_promotion_can_only_be_retired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = BRANCH.replace("/", "%2F")
    legacy = _promotion_pr(
        author_login=promotion.GITHUB_ACTIONS_LOGIN,
        author_id=promotion.GITHUB_ACTIONS_USER_ID,
    )
    mutations: list[tuple[str, str, dict[str, Any] | None]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/901":
                return legacy
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            if path == f"/git/ref/heads/{encoded}":
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            if path.startswith("/pulls?"):
                return []
            assert path == "/pulls/901/files"
            assert max_pages == 2
            return [
                {"filename": "pyproject.toml"},
                {"filename": ".github/lock-authority.json"},
            ]

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            mutations.append((method, path, payload))
            if (method, path) == ("PATCH", "/pulls/901"):
                assert payload == {"state": "closed"}
                return {"number": 901, "state": "closed"}
            if (method, path) == ("DELETE", f"/git/refs/heads/{encoded}"):
                assert payload is None
                return None
            raise AssertionError((method, path, payload))

    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    promotion._retire_legacy_promotion(
        Api(),
        901,
        BRANCH,
        HEAD,
        {
            "repository": promotion.EXPECTED_REPOSITORY,
            "baseBranch": "main",
        },
    )

    assert mutations == [
        ("PATCH", "/pulls/901", {"state": "closed"}),
        ("DELETE", f"/git/refs/heads/{encoded}", None),
    ]


def test_legacy_retirement_rechecks_subject_before_mutation() -> None:
    legacy = _promotion_pr(
        author_login=promotion.GITHUB_ACTIONS_LOGIN,
        author_id=promotion.GITHUB_ACTIONS_USER_ID,
    )
    pull_reads = 0

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            nonlocal pull_reads
            if path == "/pulls/901":
                pull_reads += 1
                observed = deepcopy(legacy)
                if pull_reads == 2:
                    observed["head"]["sha"] = "9" * 40
                return observed
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls/901/files"
            return [
                {"filename": "pyproject.toml"},
                {"filename": ".github/lock-authority.json"},
            ]

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("drifted legacy subject must fail before mutation")

    with pytest.raises(
        promotion.PolicyBlock,
        match="changed during retirement revalidation",
    ):
        promotion._retire_legacy_promotion(
            Api(),
            901,
            BRANCH,
            HEAD,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )
    assert pull_reads == 2


def test_legacy_retirement_rechecks_base_sha_before_mutation() -> None:
    legacy = _promotion_pr(
        author_login=promotion.GITHUB_ACTIONS_LOGIN,
        author_id=promotion.GITHUB_ACTIONS_USER_ID,
    )
    pull_reads = 0

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            nonlocal pull_reads
            if path == "/pulls/901":
                pull_reads += 1
                observed = deepcopy(legacy)
                if pull_reads == 2:
                    observed["base"]["sha"] = "8" * 40
                return observed
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls/901/files"
            return [
                {"filename": "pyproject.toml"},
                {"filename": ".github/lock-authority.json"},
            ]

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("base-drifted legacy subject must fail before mutation")

    with pytest.raises(
        promotion.PolicyBlock,
        match="changed during retirement revalidation",
    ):
        promotion._retire_legacy_promotion(
            Api(),
            901,
            BRANCH,
            HEAD,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )
    assert pull_reads == 2


def test_independent_app_promotion_cannot_enter_legacy_retirement() -> None:
    app_pr = _promotion_pr()

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/pulls/901"
            return app_pr

        def list_all(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            raise AssertionError("App promotion must fail before file enumeration")

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("App promotion must never be mutated by legacy retirement")

    with pytest.raises(
        promotion.PolicyBlock,
        match="changed before exact retirement",
    ):
        promotion._retire_legacy_promotion(
            Api(),
            901,
            BRANCH,
            HEAD,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )


def test_staged_promotion_rejects_already_closed_subject_before_retarget() -> None:
    staged = _promotion_pr(base_ref=STAGING)
    staged["state"] = "closed"

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            raise AssertionError(f"closed staged promotion must not read {path}")

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("closed staged promotion must not mutate")

    with pytest.raises(
        promotion.PolicyBlock,
        match="staged promotion is no longer open and non-draft",
    ):
        promotion._normalize_staged_promotion(
            Api(),
            staged,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )


def test_staged_promotion_close_race_converges_without_second_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged = _promotion_pr(base_ref=STAGING)
    closed = deepcopy(staged)
    closed["state"] = "closed"
    encoded_staging = STAGING.replace("/", "%2F")
    requests: list[tuple[str, str]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == f"/git/ref/heads/{encoded_staging}":
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == "/pulls/901":
                return closed
            raise AssertionError(path)

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            requests.append((method, path))
            assert payload == {"base": "main"}
            raise promotion.GovernanceError("retarget lost race with duplicate cleanup")

    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )

    with pytest.raises(
        promotion.PolicyBlock,
        match="staged promotion closed before retarget; reconciliation already converged",
    ):
        promotion._normalize_staged_promotion(
            Api(),
            staged,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )

    assert requests == [("PATCH", "/pulls/901")]


def test_staged_promotion_retarget_failure_is_not_swallowed_when_subject_remains_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged = _promotion_pr(base_ref=STAGING)
    encoded_staging = STAGING.replace("/", "%2F")
    requests: list[tuple[str, str]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == f"/git/ref/heads/{encoded_staging}":
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == "/pulls/901":
                return staged
            raise AssertionError(path)

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            requests.append((method, path))
            assert payload == {"base": "main"}
            raise promotion.GovernanceError("retarget API unavailable")

    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )

    with pytest.raises(promotion.GovernanceError, match="retarget API unavailable"):
        promotion._normalize_staged_promotion(
            Api(),
            staged,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )

    assert requests == [("PATCH", "/pulls/901")]


def test_staged_promotion_control_move_blocks_retarget_before_patch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged = _promotion_pr(base_ref=STAGING)
    encoded_staging = STAGING.replace("/", "%2F")

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == f"/git/ref/heads/{encoded_staging}":
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            raise AssertionError(path)

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("stale control must block retarget mutation")

    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: (_ for _ in ()).throw(
            promotion.GovernanceError("control revision moved")
        ),
    )

    with pytest.raises(promotion.GovernanceError, match="control revision moved"):
        promotion._normalize_staged_promotion(
            Api(),
            staged,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )


def test_staged_promotion_control_move_after_patch_blocks_ref_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged = _promotion_pr(base_ref=STAGING)
    encoded_staging = STAGING.replace("/", "%2F")
    control_calls = 0
    requests: list[tuple[str, str]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == f"/git/ref/heads/{encoded_staging}":
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            raise AssertionError(path)

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            requests.append((method, path))
            assert (method, path) == ("PATCH", "/pulls/901")
            assert payload == {"base": "main"}
            return _promotion_pr()

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        control_calls += 1
        if control_calls == 2:
            raise promotion.GovernanceError("control revision moved after retarget")
        return BASE

    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)

    with pytest.raises(
        promotion.GovernanceError,
        match="control revision moved after retarget",
    ):
        promotion._normalize_staged_promotion(
            Api(),
            staged,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )

    assert control_calls == 2
    assert requests == [("PATCH", "/pulls/901")]


def test_stale_promotion_control_move_blocks_close_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _promotion_pr()

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/901":
                return live
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {"login": AUTHOR_LOGIN, "id": AUTHOR_ID},
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                }
            raise AssertionError(path)

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("stale control must block close mutation")

    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: (_ for _ in ()).throw(
            promotion.GovernanceError("control revision moved")
        ),
    )

    with pytest.raises(promotion.GovernanceError, match="control revision moved"):
        promotion._close_stale(
            Api(),
            901,
            BRANCH,
            HEAD,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )


def test_legacy_retirement_control_move_after_close_blocks_ref_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = _promotion_pr(
        author_login=promotion.GITHUB_ACTIONS_LOGIN,
        author_id=promotion.GITHUB_ACTIONS_USER_ID,
    )
    control_calls = 0
    requests: list[tuple[str, str]] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/901":
                return legacy
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            if path == "/pulls/901/files":
                return [
                    {"filename": "pyproject.toml"},
                    {"filename": ".github/lock-authority.json"},
                ]
            if path == "/pulls?state=open&sort=created&direction=asc":
                return []
            raise AssertionError(path)

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            requests.append((method, path))
            assert (method, path) == ("PATCH", "/pulls/901")
            assert payload == {"state": "closed"}
            return {"number": 901, "state": "closed"}

    def require_control(api: Any, config: dict[str, Any]) -> str:
        nonlocal control_calls
        control_calls += 1
        if control_calls == 2:
            raise promotion.GovernanceError("control revision moved after close")
        return BASE

    monkeypatch.setattr(promotion, "require_current_control_revision", require_control)

    with pytest.raises(
        promotion.GovernanceError,
        match="control revision moved after close",
    ):
        promotion._retire_legacy_promotion(
            Api(),
            901,
            BRANCH,
            HEAD,
            {
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
            },
        )

    assert control_calls == 2
    assert requests == [("PATCH", "/pulls/901")]


def test_reconcile_retires_legacy_before_any_qualification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = _promotion_pr(
        author_login=promotion.GITHUB_ACTIONS_LOGIN,
        author_id=promotion.GITHUB_ACTIONS_USER_ID,
    )
    retired: list[tuple[int, str, str]] = []

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            return []

    api = Api()
    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "migration-test-token")
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(promotion, "require_current_control_revision", lambda api_arg, config: BASE)
    monkeypatch.setattr(
        promotion,
        "_prune_orphan_promotion_refs",
        lambda api_arg, config_arg: 0,
    )
    monkeypatch.setattr(promotion, "_promotion_pulls", lambda api_arg: [legacy])
    monkeypatch.setattr(
        promotion,
        "_retire_legacy_promotion",
        lambda api_arg, number, branch, head_sha, config: retired.append(
            (number, branch, head_sha)
        ),
    )
    monkeypatch.setattr(
        promotion,
        "_normalize_staged_promotion",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("legacy promotion must never enter qualification")
        ),
    )

    assert (
        promotion.reconcile(
            {
                "pipMode": "promotion",
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
                "automergeEnabled": True,
            },
            allow_merge=True,
        )
        == 0
    )
    assert retired == [(901, BRANCH, HEAD)]


def test_reconcile_retires_legacy_then_recreates_same_stale_source_under_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = _promotion_pr(
        author_login=promotion.GITHUB_ACTIONS_LOGIN,
        author_id=promotion.GITHUB_ACTIONS_USER_ID,
    )
    source_pr = {
        "number": 171,
        "user": {"login": promotion.BOT_LOGIN, "id": promotion.BOT_USER_ID},
    }
    events: list[str] = []

    class ControllerApi:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/171":
                return source_pr
            if path == "/pulls/902":
                return {"user": {"login": AUTHOR_LOGIN, "id": AUTHOR_ID}}
            raise AssertionError(f"unexpected controller API path: {path}")

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 4
            return [source_pr]

    controller_api = ControllerApi()
    author_api = object()

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "controller-token")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_TOKEN_ENV, "author-token")
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    monkeypatch.setattr(
        promotion,
        "GitHubApi",
        lambda token, repository: controller_api if token == "controller-token" else author_api,
    )
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api_arg, config: BASE,
    )
    monkeypatch.setattr(
        promotion,
        "_prune_orphan_promotion_refs",
        lambda api_arg, config_arg: 0,
    )
    monkeypatch.setattr(promotion, "_promotion_pulls", lambda api_arg: [legacy])

    def retire_legacy(
        api_arg: Any,
        number: int,
        branch_name: str,
        head_sha: str,
        config: dict[str, Any],
    ) -> None:
        assert api_arg is controller_api
        assert number == 901
        assert branch_name == BRANCH
        assert head_sha == HEAD
        events.append("legacy-retired")

    monkeypatch.setattr(promotion, "_retire_legacy_promotion", retire_legacy)

    def stale_source(
        api_arg: Any,
        pr_record: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        assert api_arg is controller_api
        assert pr_record is source_pr
        assert events == ["legacy-retired"]
        events.append("source-reconsidered")
        return {
            "number": 171,
            "headSha": "d" * 40,
            "sourceBaseSha": "e" * 40,
            "baseSha": BASE,
            "fingerprint": FINGERPRINT,
        }

    monkeypatch.setattr(promotion, "source_subject", stale_source)

    def create_commit(
        api_arg: Any,
        source: dict[str, Any],
        branch_name: str,
        config: dict[str, Any],
    ) -> tuple[str, str]:
        assert api_arg is author_api
        assert source["number"] == 171
        assert source["sourceBaseSha"] != source["baseSha"]
        assert branch_name == BRANCH
        assert config["baseBranch"] == "main"
        events.append("app-commit-created")
        return "9" * 40, "8" * 40

    monkeypatch.setattr(promotion, "_create_promotion_commit", create_commit)

    def create_pr(
        api_arg: Any,
        source: dict[str, Any],
        branch_name: str,
        head_sha: str,
        config: dict[str, Any],
    ) -> int:
        assert api_arg is author_api
        assert source["number"] == 171
        assert branch_name == BRANCH
        assert head_sha == "9" * 40
        assert config["baseBranch"] == "main"
        events.append("app-pr-created")
        return 902

    monkeypatch.setattr(promotion, "_create_promotion_pr", create_pr)

    created_promotion = {
        "number": 902,
        "headSha": "9" * 40,
        "baseSha": BASE,
    }

    def normalize_created(
        api_arg: Any,
        pr_record: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        assert api_arg is controller_api
        assert pr_record == {"user": {"login": AUTHOR_LOGIN, "id": AUTHOR_ID}}
        assert config["baseBranch"] == "main"
        events.append("created-pr-normalized")
        return created_promotion

    monkeypatch.setattr(promotion, "_normalize_staged_promotion", normalize_created)

    def validate_created(
        api_arg: Any,
        pr_record: dict[str, Any],
        config: dict[str, Any],
        *,
        require_checks: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        assert api_arg is controller_api
        assert pr_record is created_promotion
        assert config["baseBranch"] == "main"
        assert require_checks is False
        events.append("created-pr-validated")
        return {}, created_promotion

    monkeypatch.setattr(promotion, "_validate_promotion", validate_created)

    def qualify_created(
        api_arg: Any,
        promotion_record: dict[str, Any],
        branch_name: str,
        config: dict[str, Any],
    ) -> None:
        assert api_arg is controller_api
        assert promotion_record is created_promotion
        assert branch_name == BRANCH
        assert config["baseBranch"] == "main"
        events.append("qualification-wake-registered")
        raise promotion.QualificationWakeRegistered(
            "automatic Trusted PR Gate qualification wake registered"
        )

    monkeypatch.setattr(promotion, "_advance_promotion_qualification", qualify_created)

    assert (
        promotion.reconcile(
            {
                "pipMode": "promotion",
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
                "automergeEnabled": True,
            },
            allow_merge=True,
        )
        == 1
    )
    assert events == [
        "legacy-retired",
        "source-reconsidered",
        "app-commit-created",
        "app-pr-created",
        "created-pr-normalized",
        "created-pr-validated",
        "qualification-wake-registered",
    ]


def test_reconcile_serializes_one_qualification_wake_per_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _promotion_pr()
    second = deepcopy(first)
    second["number"] = 902
    promotions = {901: first, 902: second}
    qualification_attempts: list[int] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            prefix = "/pulls/"
            assert path.startswith(prefix)
            return promotions[int(path.removeprefix(prefix))]

        def list_all(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            raise AssertionError(
                "reconciliation must stop before source discovery after one qualification wake"
            )

    api = Api()
    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "serialization-test-token")
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(promotion, "require_current_control_revision", lambda api_arg, config: BASE)
    monkeypatch.setattr(
        promotion,
        "_prune_orphan_promotion_refs",
        lambda api_arg, config_arg: 0,
    )
    monkeypatch.setattr(promotion, "_promotion_pulls", lambda api_arg: [first, second])
    monkeypatch.setattr(
        promotion,
        "_normalize_staged_promotion",
        lambda api_arg, pr, config: pr,
    )
    monkeypatch.setattr(
        promotion,
        "_validate_promotion",
        lambda api_arg, pr, config, require_checks=False: (
            {},
            {"number": pr["number"]},
        ),
    )

    def register_one_wake(
        api_arg: Any, promotion_record: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        qualification_attempts.append(int(promotion_record["number"]))
        raise promotion.QualificationWakeRegistered(
            "automatic Trusted PR Gate qualification wake registered"
        )

    monkeypatch.setattr(promotion, "_publish_and_merge", register_one_wake)

    assert (
        promotion.reconcile(
            {
                "pipMode": "promotion",
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
                "automergeEnabled": True,
            },
            allow_merge=True,
        )
        == 0
    )
    assert qualification_attempts == [901]


def test_status_event_payload_reader_is_bounded_regular_and_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_path = tmp_path / "event.json"
    payload_path.write_text(json.dumps({"context": "Trusted PR Gate"}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(payload_path))
    if not getattr(os, "O_NOFOLLOW", 0):
        with pytest.raises(promotion.GovernanceError, match="requires O_NOFOLLOW"):
            promotion._read_status_event_payload()
        return
    assert promotion._read_status_event_payload() == {"context": "Trusted PR Gate"}

    payload_path.write_bytes(b"x" * (promotion.MAX_STATUS_EVENT_BYTES + 1))
    with pytest.raises(promotion.GovernanceError, match="bounded regular file"):
        promotion._read_status_event_payload()

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "event-link.json"
    link.symlink_to(target)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(link))
    with pytest.raises(promotion.GovernanceError, match="opened safely"):
        promotion._read_status_event_payload()


TRUSTED_STATUS_ID = 712345
TRUSTED_STATUS_HISTORY_PATH = f"/commits/{HEAD}/statuses?per_page=100&page=1"


def _trusted_status_event(*, status_id: int = TRUSTED_STATUS_ID) -> dict[str, Any]:
    run_id = 812345
    return {
        "id": status_id,
        "context": promotion.TRUSTED_STATUS_CONTEXT,
        "state": "success",
        "sha": HEAD,
        "target_url": (
            f"https://github.com/{promotion.EXPECTED_REPOSITORY}/actions/runs/{run_id}"
            f"?pr=901&base={BASE}&head={HEAD}&merge={'3' * 40}"
        ),
        "sender": {
            "login": promotion.TRUSTED_STATUS_BOT_LOGIN,
            "id": promotion.TRUSTED_STATUS_BOT_ID,
        },
        "repository": {"full_name": promotion.EXPECTED_REPOSITORY},
    }


def _trusted_status_record(
    *,
    creator_id: int | None = None,
    creator_type: str = "Bot",
    context: str | None = None,
    description: str | None = None,
    state: str = "success",
    target_url: str | None = None,
    status_id: int = TRUSTED_STATUS_ID,
) -> dict[str, Any]:
    event = _trusted_status_event(status_id=status_id)
    return {
        "id": status_id,
        "context": promotion.TRUSTED_STATUS_CONTEXT if context is None else context,
        "state": state,
        "description": (
            promotion.TRUSTED_STATUS_DESCRIPTION if description is None else description
        ),
        "target_url": event["target_url"] if target_url is None else target_url,
        "creator": {
            "login": promotion.TRUSTED_STATUS_BOT_LOGIN,
            "id": promotion.TRUSTED_STATUS_BOT_ID if creator_id is None else creator_id,
            "type": creator_type,
        },
    }


def _trusted_status_promotion_pr(*, branch: str = BRANCH) -> dict[str, Any]:
    return {
        "number": 901,
        "state": "open",
        "draft": False,
        "user": {
            "login": AUTHOR_LOGIN,
            "id": AUTHOR_ID,
        },
        "head": {
            "ref": branch,
            "sha": HEAD,
            "repo": {"full_name": promotion.EXPECTED_REPOSITORY},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": promotion.EXPECTED_REPOSITORY},
        },
    }


def _trusted_status_run(*, status: str, conclusion: str | None) -> dict[str, Any]:
    return {
        "id": 812345,
        "workflow_id": promotion.TRUSTED_PR_AUTO_WORKFLOW_ID,
        "name": promotion.EXPECTED_GATE_WORKFLOW_NAME,
        "path": promotion.EXPECTED_GATE_WORKFLOW_PATH,
        "event": "workflow_run",
        "run_attempt": 1,
        "head_branch": "main",
        "head_sha": BASE,
        "status": status,
        "conclusion": conclusion,
        "repository": {"full_name": promotion.EXPECTED_REPOSITORY},
        "head_repository": {"full_name": promotion.EXPECTED_REPOSITORY},
    }


def test_trusted_status_event_waits_read_only_for_exact_run_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs = [
        _trusted_status_run(status="in_progress", conclusion=None),
        _trusted_status_run(status="completed", conclusion="success"),
    ]
    calls: list[str] = []
    sleeps: list[float] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return [_trusted_status_record()]
            if path == "/pulls/901":
                return _trusted_status_promotion_pr()
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == "/actions/runs/812345":
                return runs.pop(0)
            raise AssertionError(path)

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())
    monkeypatch.setattr(promotion.time, "sleep", sleeps.append)

    result = promotion.await_trusted_status_event()

    assert result == {
        "runId": 812345,
        "prNumber": 901,
        "baseSha": BASE,
        "headSha": HEAD,
        "event": "workflow_run",
        "lane": "dependency-promotion",
    }
    assert calls == [
        TRUSTED_STATUS_HISTORY_PATH,
        "/pulls/901",
        "/branches/main",
        "/actions/runs/812345",
        "/actions/runs/812345",
    ]
    assert sleeps == [promotion.STATUS_EVENT_POLL_SECONDS]


def test_trusted_status_event_authenticates_creator_from_exact_rest_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            assert path == TRUSTED_STATUS_HISTORY_PATH
            return [
                _trusted_status_record(
                    creator_id=promotion.TRUSTED_STATUS_BOT_ID + 1,
                )
            ]

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(
        promotion.GovernanceError,
        match="REST record is not exact dedicated-App gate evidence",
    ):
        promotion.await_trusted_status_event()

    assert calls == [TRUSTED_STATUS_HISTORY_PATH]


def test_trusted_status_event_requires_real_webhook_status_id_before_api_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _trusted_status_event()
    payload.pop("id")

    class Api:
        def get(self, path: str) -> Any:
            raise AssertionError("malformed status id must fail before GitHub API read")

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", lambda: payload)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(promotion.GovernanceError, match="trusted status event id is invalid"):
        promotion.await_trusted_status_event()


def test_trusted_status_event_rejects_rest_target_drift_before_subject_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            assert path == TRUSTED_STATUS_HISTORY_PATH
            return [_trusted_status_record(target_url="https://example.invalid/drift")]

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(
        promotion.GovernanceError,
        match="REST record is not exact dedicated-App gate evidence",
    ):
        promotion.await_trusted_status_event()

    assert calls == [TRUSTED_STATUS_HISTORY_PATH]


@pytest.mark.parametrize(
    "record",
    [
        _trusted_status_record(description="drifted"),
        _trusted_status_record(creator_type="User"),
        _trusted_status_record(context="spoofed"),
        _trusted_status_record(state="pending"),
    ],
)
def test_trusted_status_event_rejects_noncanonical_rest_record(
    record: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Api:
        def get(self, path: str) -> Any:
            assert path == TRUSTED_STATUS_HISTORY_PATH
            return [record]

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(
        promotion.GovernanceError,
        match="REST record is not exact dedicated-App gate evidence",
    ):
        promotion.await_trusted_status_event()


def test_trusted_status_rest_binding_searches_only_bounded_newest_pages() -> None:
    payload = _trusted_status_event()
    page_one = [{"id": 800000 + index} for index in range(100)]
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return page_one
            if path == f"/commits/{HEAD}/statuses?per_page=100&page=2":
                return [_trusted_status_record()]
            raise AssertionError(path)

    promotion._require_exact_trusted_status_record(
        Api(),
        payload,
        HEAD,
        str(payload["target_url"]),
    )

    assert calls == [
        TRUSTED_STATUS_HISTORY_PATH,
        f"/commits/{HEAD}/statuses?per_page=100&page=2",
    ]


def test_trusted_status_rest_binding_rejects_oversized_page() -> None:
    payload = _trusted_status_event()

    class Api:
        def get(self, path: str) -> Any:
            assert path == TRUSTED_STATUS_HISTORY_PATH
            return [{"id": 800000 + index} for index in range(101)]

    with pytest.raises(promotion.GovernanceError, match="not a bounded status list"):
        promotion._require_exact_trusted_status_record(
            Api(),
            payload,
            HEAD,
            str(payload["target_url"]),
        )


@pytest.mark.parametrize("invalid_id", [0, -1, True, "712345"])
def test_trusted_status_event_rejects_malformed_status_ids_before_api_read(
    invalid_id: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _trusted_status_event()
    payload["id"] = invalid_id

    class Api:
        def get(self, path: str) -> Any:
            raise AssertionError("malformed status id must fail before GitHub API read")

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", lambda: payload)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(promotion.GovernanceError, match="trusted status event id is invalid"):
        promotion.await_trusted_status_event()


def test_trusted_status_event_rejects_legacy_promotion_before_run_polling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return [_trusted_status_record()]
            if path == "/pulls/901":
                pr = _trusted_status_promotion_pr()
                pr["user"] = {
                    "login": promotion.GITHUB_ACTIONS_LOGIN,
                    "id": promotion.GITHUB_ACTIONS_USER_ID,
                }
                return pr
            raise AssertionError(path)

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(
        promotion.GovernanceError,
        match="not authored by the independent App",
    ):
        promotion.await_trusted_status_event()
    assert calls == [TRUSTED_STATUS_HISTORY_PATH, "/pulls/901"]


def test_trusted_status_event_skips_non_promotion_lane_before_run_polling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return [_trusted_status_record()]
            if path == "/pulls/901":
                return _trusted_status_promotion_pr(
                    branch="automation/codeql-autoheal-17-deadbeefcafe"
                )
            raise AssertionError(path)

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    assert promotion.await_trusted_status_event() is None
    assert calls == [TRUSTED_STATUS_HISTORY_PATH, "/pulls/901"]


def test_trusted_status_event_accepts_exact_dependabot_actions_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return [_trusted_status_record()]
            if path == "/pulls/901":
                pr = _trusted_status_promotion_pr(
                    branch="dependabot/github_actions/actions/checkout-7"
                )
                pr["user"] = {
                    "login": promotion.DEPENDABOT_LOGIN,
                    "id": promotion.DEPENDABOT_USER_ID,
                }
                return pr
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == "/actions/runs/812345":
                return _trusted_status_run(status="completed", conclusion="success")
            raise AssertionError(path)

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    assert promotion.await_trusted_status_event() == {
        "runId": 812345,
        "prNumber": 901,
        "baseSha": BASE,
        "headSha": HEAD,
        "event": "workflow_run",
        "lane": "dependabot-actions",
    }
    assert calls == [
        TRUSTED_STATUS_HISTORY_PATH,
        "/pulls/901",
        "/branches/main",
        "/actions/runs/812345",
    ]


def test_trusted_status_event_rejects_dependabot_actions_wrong_actor_before_run_polling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> Any:
            calls.append(path)
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return [_trusted_status_record()]
            if path == "/pulls/901":
                return _trusted_status_promotion_pr(
                    branch="dependabot/github_actions/actions/checkout-7"
                )
            raise AssertionError(path)

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(
        promotion.GovernanceError,
        match="Dependabot Actions subject has unexpected actor identity",
    ):
        promotion.await_trusted_status_event()

    assert calls == [TRUSTED_STATUS_HISTORY_PATH, "/pulls/901"]


def test_trusted_status_event_rejects_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Api:
        def get(self, path: str) -> Any:
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return [_trusted_status_record()]
            if path == "/pulls/901":
                return _trusted_status_promotion_pr()
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == "/actions/runs/812345":
                return _trusted_status_run(status="completed", conclusion="failure")
            raise AssertionError(path)

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(
        promotion.GovernanceError,
        match="completed without success",
    ):
        promotion.await_trusted_status_event()


def test_trusted_status_event_timeout_is_bounded_and_non_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    class Api:
        def get(self, path: str) -> Any:
            if path == TRUSTED_STATUS_HISTORY_PATH:
                return [_trusted_status_record()]
            if path == "/pulls/901":
                return _trusted_status_promotion_pr()
            if path == "/branches/main":
                return {"commit": {"sha": BASE}}
            if path == "/actions/runs/812345":
                return _trusted_status_run(status="in_progress", conclusion=None)
            raise AssertionError(path)

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-only-test-token")
    monkeypatch.setattr(promotion, "_read_status_event_payload", _trusted_status_event)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())
    monkeypatch.setattr(promotion, "STATUS_EVENT_TERMINAL_ATTEMPTS", 2)
    monkeypatch.setattr(promotion.time, "sleep", sleeps.append)

    with pytest.raises(
        promotion.GovernanceError,
        match="did not become terminal within bound",
    ):
        promotion.await_trusted_status_event()

    assert sleeps == [promotion.STATUS_EVENT_POLL_SECONDS]


def test_status_sync_outputs_are_exact_owned_github_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    promotion._publish_status_sync_outputs(
        output,
        {
            "prNumber": 901,
            "runId": 812345,
            "headSha": HEAD,
            "baseSha": BASE,
            "lane": "dependency-promotion",
        },
    )

    assert output.read_text(encoding="utf-8") == ("pr_number=901\nlane=dependency-promotion\n")


def test_status_target_reconcile_mutates_only_exact_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, Any]] = []
    live_pr = {"number": 901}
    subject = {"number": 901, "headSha": HEAD, "baseSha": BASE}

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            calls.append(("GET", path, None))
            assert path == "/pulls/901"
            return live_pr

        def put(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            calls.append(("PUT", path, payload))
            assert path == "/pulls/901/merge"
            assert payload == {"sha": HEAD, "merge_method": "merge"}
            return {"merged": True, "sha": "9" * 40}

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("status-target merge must not use generic mutation request")

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("post-merge evidence is stubbed; no other mutation is admissible")

        def list_all(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("status-target merge must not enumerate unrelated PRs or refs")

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "status-target-test-token")
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())
    control_revision_calls: list[str] = []
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: control_revision_calls.append(config["repository"]) or BASE,
    )
    monkeypatch.setattr(
        promotion,
        "_validate_promotion",
        lambda api, pr, config, require_checks=False: ({}, subject),
    )
    gate_calls: list[tuple[int, str, str]] = []
    gate_evidence = {
        "statusId": 7001,
        "runId": 8001,
        "runAttempt": 1,
        "mergeSha": "8" * 40,
    }
    monkeypatch.setattr(
        promotion,
        "require_promotion_trusted_gate",
        lambda api, number, head, base: gate_calls.append((number, head, base)) or gate_evidence,
    )
    approval_calls: list[tuple[int, str, str, dict[str, Any]]] = []
    monkeypatch.setattr(
        promotion,
        "require_exact_automation_approval",
        lambda api, *, number, head_sha, base_sha, gate_evidence: (
            approval_calls.append((number, head_sha, base_sha, gate_evidence))
            or {"reviewId": 9001, "reviewer": "portyu9", "headSha": head_sha}
        ),
    )
    monkeypatch.setattr(
        promotion,
        "finalize_post_merge_evidence",
        lambda api, result, observed, config: {"mergeSha": result["sha"]},
    )

    assert (
        promotion.reconcile_status_target(
            {
                "pipMode": "promotion",
                "repository": promotion.EXPECTED_REPOSITORY,
                "automergeEnabled": True,
                "mergeMethod": "merge",
            },
            target_pr_number=901,
            allow_merge=True,
        )
        == 0
    )
    assert calls == [
        ("GET", "/pulls/901", None),
        ("GET", "/pulls/901", None),
        ("GET", "/pulls/901", None),
        ("PUT", "/pulls/901/merge", {"sha": HEAD, "merge_method": "merge"}),
    ]
    assert gate_calls == [
        (901, HEAD, BASE),
        (901, HEAD, BASE),
    ]
    assert approval_calls == [(901, HEAD, BASE, gate_evidence)]
    assert control_revision_calls == [
        promotion.EXPECTED_REPOSITORY,
        promotion.EXPECTED_REPOSITORY,
    ]


def test_status_target_gate_loss_fails_without_qualification_wake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live_pr = {"number": 901}
    subject = {"number": 901, "headSha": HEAD, "baseSha": BASE}

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/pulls/901"
            return live_pr

        def put(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("gate loss must fail before merge")

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "status-target-test-token")
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )
    monkeypatch.setattr(
        promotion,
        "_validate_promotion",
        lambda api, pr, config, require_checks=False: ({}, subject),
    )
    monkeypatch.setattr(
        promotion,
        "require_promotion_trusted_gate",
        lambda *args, **kwargs: (_ for _ in ()).throw(promotion.TrustedStatusError("gate drift")),
    )
    monkeypatch.setattr(
        promotion,
        "_advance_promotion_qualification",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("status-target path must never publish a qualification wake")
        ),
    )

    with pytest.raises(
        promotion.PolicyBlock,
        match="no longer exact-subject admissible",
    ):
        promotion.reconcile_status_target(
            {
                "pipMode": "promotion",
                "repository": promotion.EXPECTED_REPOSITORY,
                "automergeEnabled": True,
                "mergeMethod": "merge",
            },
            target_pr_number=901,
            allow_merge=True,
        )


def test_status_target_stale_control_revision_fails_before_target_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            calls.append(path)
            if path == "/branches/main":
                return {"commit": {"sha": HEAD}}
            raise AssertionError("stale status-target control must fail before reading the PR")

        def put(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("stale status-target control must fail before merge")

    monkeypatch.setenv("GITHUB_REPOSITORY", promotion.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "status-target-test-token")
    monkeypatch.setenv(governance.GOVERNANCE_CONTROL_SHA_ENV, BASE)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: Api())

    with pytest.raises(
        promotion.GovernanceError,
        match="trusted governance control revision is stale relative to current main",
    ):
        promotion.reconcile_status_target(
            {
                "pipMode": "promotion",
                "repository": promotion.EXPECTED_REPOSITORY,
                "baseBranch": "main",
                "automergeEnabled": True,
                "mergeMethod": "merge",
            },
            target_pr_number=901,
            allow_merge=True,
        )

    assert calls == ["/branches/main"]


def test_trusted_qualification_rejects_duplicate_exact_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == f"/commits/{HEAD}/check-runs?filter=latest"
            assert max_pages == 4
            return [
                {"id": 11, "name": "Required PR Gate"},
                {"id": 12, "name": "Required PR Gate"},
            ]

    def fake_candidate(
        api: Any,
        row: dict[str, Any],
        *,
        name: str,
        head_sha: str,
        base_sha: str,
    ) -> dict[str, Any]:
        del api, name, head_sha, base_sha
        return {
            "check_id": row["id"],
            "run_id": row["id"],
            "run_attempt": 1,
            "conclusion": "success",
            "details_url": f"https://example.invalid/{row['id']}",
        }

    monkeypatch.setattr(qualification, "_check_candidate", fake_candidate)
    with pytest.raises(qualification.TrustedQualificationError, match="ambiguous"):
        qualification.qualification_states(
            Api(),
            HEAD,
            BASE,
            required=("Required PR Gate",),
        )


@pytest.mark.parametrize(
    ("claim_role", "claim_key", "observed_role"),
    [
        ("head", "head", "head"),
        ("head", "base", "base"),
        ("base", "head", "head"),
        ("base", "base", "base"),
    ],
)
def test_exact_ref_delete_blocks_new_open_pr_claim_at_final_boundary(
    claim_role: str,
    claim_key: str,
    observed_role: str,
) -> None:
    encoded = BRANCH.replace("/", "%2F")

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert path == f"/git/ref/heads/{encoded}"
            return {
                "ref": f"refs/heads/{BRANCH}",
                "object": {"type": "commit", "sha": HEAD},
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path.startswith("/pulls?")
            return [
                {
                    "state": "open",
                    claim_key: {
                        "ref": BRANCH,
                        "repo": {"full_name": promotion.EXPECTED_REPOSITORY},
                    },
                }
            ]

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("newly claimed exact ref must not be deleted")

    with pytest.raises(
        promotion.PolicyBlock,
        match=f"{observed_role} ref became claimed by an open PR before cleanup",
    ):
        promotion._delete_exact_ref(
            Api(),
            BRANCH,
            HEAD,
            label="test exact ref",
            claim_role=claim_role,
        )


def test_exact_ref_delete_rejects_ref_drift_after_claim_scan() -> None:
    encoded = BRANCH.replace("/", "%2F")
    drifted_head = "d" * 40
    reads = 0

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            nonlocal reads
            assert path == f"/git/ref/heads/{encoded}"
            reads += 1
            return {
                "ref": f"refs/heads/{BRANCH}",
                "object": {
                    "type": "commit",
                    "sha": HEAD if reads == 1 else drifted_head,
                },
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path.startswith("/pulls?")
            return []

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("terminally drifted ref must not be deleted")

    with pytest.raises(
        promotion.PolicyBlock,
        match="changed at terminal cleanup boundary",
    ):
        promotion._delete_exact_ref(
            Api(),
            BRANCH,
            HEAD,
            label="test exact ref",
            claim_role="head",
        )
    assert reads == 2


def test_orphan_staging_base_prune_requires_generated_parent_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_branch = BRANCH
    encoded_generated = generated_branch.replace("/", "%2F")
    encoded_staging = STAGING.replace("/", "%2F")
    deleted: list[str] = []
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            if path.startswith("/pulls?"):
                return []
            if path == f"/git/matching-refs/heads/{promotion.BRANCH_PREFIX}":
                return [
                    {
                        "ref": f"refs/heads/{generated_branch}",
                        "object": {"type": "commit", "sha": HEAD},
                    },
                    {
                        "ref": f"refs/heads/{STAGING}",
                        "object": {"type": "commit", "sha": BASE},
                    },
                ]
            raise AssertionError(path)

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{encoded_staging}":
                if f"/git/refs/heads/{encoded_staging}" in deleted:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == f"/git/ref/heads/{encoded_generated}":
                if f"/git/refs/heads/{encoded_generated}" in deleted:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{generated_branch}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            raise promotion.GovernanceError("HTTP 404")

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> None:
            assert method == "DELETE"
            assert payload is None
            deleted.append(path)
            return None

    assert promotion._prune_orphan_promotion_refs(Api(), {"baseBranch": "main"}) == 2
    assert deleted == [
        f"/git/refs/heads/{encoded_staging}",
        f"/git/refs/heads/{encoded_generated}",
    ]


def test_fork_open_pr_cannot_pin_promotion_or_staging_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded_generated = BRANCH.replace("/", "%2F")
    encoded_staging = STAGING.replace("/", "%2F")
    deleted: list[str] = []
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api, config: BASE,
    )

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            if path.startswith("/pulls?"):
                return [
                    {
                        "user": {
                            "login": promotion.GITHUB_ACTIONS_LOGIN,
                            "id": promotion.GITHUB_ACTIONS_USER_ID,
                        },
                        "head": {
                            "ref": BRANCH,
                            "repo": {"full_name": "attacker/fork"},
                        },
                        "base": {
                            "ref": STAGING,
                            "repo": {"full_name": promotion.EXPECTED_REPOSITORY},
                        },
                    }
                ]
            if path == f"/git/matching-refs/heads/{promotion.BRANCH_PREFIX}":
                return [
                    {
                        "ref": f"refs/heads/{BRANCH}",
                        "object": {"type": "commit", "sha": HEAD},
                    },
                    {
                        "ref": f"refs/heads/{STAGING}",
                        "object": {"type": "commit", "sha": BASE},
                    },
                ]
            raise AssertionError(path)

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{encoded_staging}":
                if f"/git/refs/heads/{encoded_staging}" in deleted:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == f"/git/ref/heads/{encoded_generated}":
                if f"/git/refs/heads/{encoded_generated}" in deleted:
                    raise promotion.GovernanceError("HTTP 404")
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            raise promotion.GovernanceError("HTTP 404")

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> None:
            assert method == "DELETE"
            assert payload is None
            deleted.append(path)

    assert promotion._prune_orphan_promotion_refs(Api(), {"baseBranch": "main"}) == 2
    assert deleted == [
        f"/git/refs/heads/{encoded_staging}",
        f"/git/refs/heads/{encoded_generated}",
    ]


def test_orphan_generated_ref_prune_rechecks_open_pr_claim_before_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api_arg, config: BASE,
    )
    encoded_branch = BRANCH.replace("/", "%2F")
    pulls_calls = 0

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            nonlocal pulls_calls
            if path.startswith("/pulls?"):
                pulls_calls += 1
                if pulls_calls == 1:
                    return []
                return [
                    {
                        "state": "open",
                        "head": {
                            "ref": BRANCH,
                            "repo": {"full_name": promotion.EXPECTED_REPOSITORY},
                        },
                    }
                ]
            if path == f"/git/matching-refs/heads/{promotion.BRANCH_PREFIX}":
                return [
                    {
                        "ref": f"refs/heads/{BRANCH}",
                        "object": {"type": "commit", "sha": HEAD},
                    }
                ]
            raise AssertionError(path)

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{encoded_branch}":
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                }
            raise AssertionError(path)

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("newly claimed generated ref must not be deleted")

    with pytest.raises(promotion.PolicyBlock, match="head ref became claimed by an open PR"):
        promotion._prune_orphan_promotion_refs(Api(), {"baseBranch": "main"})
    assert pulls_calls == 2


def test_orphan_staging_ref_prune_rechecks_open_pr_claim_before_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "require_current_control_revision",
        lambda api_arg, config: BASE,
    )
    encoded_generated = BRANCH.replace("/", "%2F")
    encoded_staging = STAGING.replace("/", "%2F")
    pulls_calls = 0

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            nonlocal pulls_calls
            if path.startswith("/pulls?"):
                pulls_calls += 1
                if pulls_calls == 1:
                    return []
                return [
                    {
                        "state": "open",
                        "base": {
                            "ref": STAGING,
                            "repo": {"full_name": promotion.EXPECTED_REPOSITORY},
                        },
                    }
                ]
            if path == f"/git/matching-refs/heads/{promotion.BRANCH_PREFIX}":
                return [
                    {
                        "ref": f"refs/heads/{STAGING}",
                        "object": {"type": "commit", "sha": BASE},
                    }
                ]
            raise AssertionError(path)

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{encoded_generated}":
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            if path == f"/git/ref/heads/{encoded_staging}":
                return {
                    "ref": f"refs/heads/{STAGING}",
                    "object": {"type": "commit", "sha": BASE},
                }
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            raise AssertionError(path)

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("newly claimed staging ref must not be deleted")

    with pytest.raises(promotion.PolicyBlock, match="base ref became claimed by an open PR"):
        promotion._prune_orphan_promotion_refs(Api(), {"baseBranch": "main"})
    assert pulls_calls == 2


def test_orphan_generated_ref_prune_rechecks_control_before_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_checks: list[dict[str, Any]] = []

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            if path.startswith("/pulls?"):
                return []
            if path == f"/git/matching-refs/heads/{promotion.BRANCH_PREFIX}":
                return [
                    {
                        "ref": f"refs/heads/{BRANCH}",
                        "object": {"type": "commit", "sha": HEAD},
                    }
                ]
            raise AssertionError(path)

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                }
            raise AssertionError(path)

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("stale control revision must stop before orphan ref deletion")

    config = {"baseBranch": "main"}

    def stale_control(api: Any, observed_config: dict[str, Any]) -> str:
        assert observed_config is config
        control_checks.append(observed_config)
        raise promotion.GovernanceError(
            "trusted governance control revision is stale relative to current main"
        )

    monkeypatch.setattr(promotion, "require_current_control_revision", stale_control)

    with pytest.raises(
        promotion.GovernanceError,
        match="trusted governance control revision is stale relative to current main",
    ):
        promotion._prune_orphan_promotion_refs(Api(), config)

    assert control_checks == [config]


def test_orphan_staging_ref_prune_rechecks_control_before_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded_generated = BRANCH.replace("/", "%2F")
    control_checks: list[dict[str, Any]] = []

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            if path.startswith("/pulls?"):
                return []
            if path == f"/git/matching-refs/heads/{promotion.BRANCH_PREFIX}":
                return [
                    {
                        "ref": f"refs/heads/{STAGING}",
                        "object": {"type": "commit", "sha": BASE},
                    }
                ]
            raise AssertionError(path)

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{encoded_generated}":
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": BASE}],
                }
            raise AssertionError(path)

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("stale control revision must stop before staging ref deletion")

    config = {"baseBranch": "main"}

    def stale_control(api: Any, observed_config: dict[str, Any]) -> str:
        assert observed_config is config
        control_checks.append(observed_config)
        raise promotion.GovernanceError(
            "trusted governance control revision is stale relative to current main"
        )

    monkeypatch.setattr(promotion, "require_current_control_revision", stale_control)

    with pytest.raises(
        promotion.GovernanceError,
        match="trusted governance control revision is stale relative to current main",
    ):
        promotion._prune_orphan_promotion_refs(Api(), config)

    assert control_checks == [config]


def test_orphan_staging_base_prune_rejects_parent_mismatch() -> None:
    encoded_generated = BRANCH.replace("/", "%2F")

    class Api:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            if path.startswith("/pulls?"):
                return []
            if path == f"/git/matching-refs/heads/{promotion.BRANCH_PREFIX}":
                return [
                    {
                        "ref": f"refs/heads/{STAGING}",
                        "object": {"type": "commit", "sha": BASE},
                    }
                ]
            raise AssertionError(path)

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/ref/heads/{encoded_generated}":
                return {
                    "ref": f"refs/heads/{BRANCH}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {
                        "login": promotion.GITHUB_ACTIONS_LOGIN,
                        "id": promotion.GITHUB_ACTIONS_USER_ID,
                    },
                    "commit": {
                        "message": "deps: promote Dependabot PR #171 with synchronized locks"
                    },
                    "parents": [{"sha": "f" * 40}],
                }
            raise AssertionError(path)

        def request(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("unproven staging ref must not be deleted")

    with pytest.raises(
        promotion.PolicyBlock,
        match="lacks exact generated counterpart provenance",
    ):
        promotion._prune_orphan_promotion_refs(Api(), {"baseBranch": "main"})
