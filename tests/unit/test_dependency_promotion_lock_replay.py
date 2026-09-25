from __future__ import annotations

import importlib.util
import sys
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
HEAD = "a" * 40
LOCK_NAMES = (
    "build-py311.lock",
    "dev-py311.lock",
    "dev-py314.lock",
    "runtime-py311.lock",
)


def _observed(pyproject: bytes) -> dict[str, bytes]:
    result = {"pyproject.toml": pyproject, ".github/lock-authority.json": b"authority\n"}
    for name in LOCK_NAMES:
        result[f"requirements/{name}"] = f"{name}\n".encode()
    return result


def test_generated_validation_replays_exact_observed_lock_without_recompiling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pyproject = b"[project]\nname='ai-qa-automation'\n"
    observed = _observed(pyproject)
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
    promotion._validate_generated_bytes(object(), {"pyproject": pyproject}, HEAD)

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
    pyproject = b"[project]\nname='ai-qa-automation'\n"
    observed = _observed(pyproject)
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
        promotion._validate_generated_bytes(object(), {"pyproject": pyproject}, HEAD)


BASE = "b" * 40
FINGERPRINT = "c" * 64
BRANCH = "automation/dependency-promotion-171-" + FINGERPRINT[:12]
STAGING = "automation/dependency-promotion-base-171-" + FINGERPRINT[:12]


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


def _promotion_pr(*, base_ref: str = "main", body: str | None = None) -> dict[str, Any]:
    return {
        "number": 901,
        "state": "open",
        "draft": False,
        "user": {
            "login": promotion.GITHUB_ACTIONS_LOGIN,
            "id": promotion.GITHUB_ACTIONS_USER_ID,
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


def test_create_promotion_pr_uses_non_main_staging_base_then_exact_retarget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str]] = []
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")

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
                events.append(("create-pr", STAGING))
                return _promotion_pr(base_ref=STAGING, body=str(payload["body"]))
            raise AssertionError(path)

        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            if (method, path) == ("PATCH", "/pulls/901"):
                assert payload == {"base": "main"}
                events.append(("retarget", "main"))
                return _promotion_pr()
            if (method, path) == ("DELETE", f"/git/refs/heads/{STAGING.replace('/', '%2F')}"):
                assert payload is None
                assert self.staging_exists is True
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
    assert promotion._create_promotion_pr(Api(), source, BRANCH, HEAD) == 901
    assert events == [
        ("create-ref", STAGING),
        ("create-pr", STAGING),
        ("retarget", "main"),
        ("delete-ref", STAGING),
    ]


def test_exact_qualification_persists_intent_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str, str]] = []
    updates: list[dict[str, Any]] = []

    class Api:
        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            assert (method, path) == ("PATCH", "/pulls/901")
            assert payload is not None and isinstance(payload.get("body"), str)
            updates.append(payload)
            events.append(("persist", path, HEAD))
            return _promotion_pr(body=str(payload["body"]))

    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setattr(
        promotion,
        "qualification_states",
        lambda api, head, base, required: {
            "Required PR Gate": None,
            "CodeQL": None,
        },
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_ci",
        lambda api, ref, sha: events.append(("ci", ref, sha)),
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_codeql",
        lambda api, ref, sha: events.append(("codeql", ref, sha)),
    )

    pr = _promotion_pr()
    assert promotion._request_exact_qualification(Api(), pr, HEAD, BASE) is False
    assert events == [
        ("persist", "/pulls/901", HEAD),
        ("ci", BRANCH, HEAD),
        ("codeql", BRANCH, HEAD),
    ]
    persisted = promotion._parse_marker(str(updates[0]["body"]))
    assert persisted is not None
    assert persisted["qualificationRequest"]["attempt"] == 1
    assert isinstance(persisted["qualificationRequest"]["requestedAt"], str)


def test_exact_qualification_reuses_green_exact_checks_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        promotion,
        "qualification_states",
        lambda api, head, base, required: {
            "Required PR Gate": {"conclusion": "success"},
            "CodeQL": {"conclusion": "success"},
        },
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_ci",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected CI dispatch")),
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_codeql",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected CodeQL dispatch")),
    )
    assert promotion._request_exact_qualification(object(), _promotion_pr(), HEAD, BASE) is True


def test_qualification_request_rejects_future_timestamp() -> None:
    metadata = _promotion_metadata()
    metadata["qualificationRequest"] = {
        "attempt": 1,
        "requestedAt": "2999-01-01T00:00:00+00:00",
    }
    with pytest.raises(promotion.PolicyBlock, match="timestamp is in the future"):
        promotion._qualification_request_age(metadata)


def test_qualification_persistence_failure_dispatches_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Api:
        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            del method, path, payload
            raise promotion.GovernanceError("simulated persistence failure")

    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setattr(
        promotion,
        "qualification_states",
        lambda api, head, base, required: {
            "Required PR Gate": None,
            "CodeQL": None,
        },
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_ci",
        lambda *args, **kwargs: calls.append("ci"),
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_codeql",
        lambda *args, **kwargs: calls.append("codeql"),
    )

    with pytest.raises(promotion.GovernanceError, match="simulated persistence failure"):
        promotion._request_exact_qualification(Api(), _promotion_pr(), HEAD, BASE)
    assert calls == []


def test_terminal_qualification_failure_is_non_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        promotion,
        "qualification_states",
        lambda api, head, base, required: {
            "Required PR Gate": {"conclusion": "failure"},
            "CodeQL": None,
        },
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_ci",
        lambda *args, **kwargs: calls.append("ci"),
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_codeql",
        lambda *args, **kwargs: calls.append("codeql"),
    )

    with pytest.raises(promotion.PolicyBlock, match="qualification is not green"):
        promotion._request_exact_qualification(object(), _promotion_pr(), HEAD, BASE)
    assert calls == []


def test_pending_qualification_intent_prevents_immediate_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = _promotion_metadata()
    metadata["qualificationRequest"] = {
        "attempt": 1,
        "requestedAt": promotion.datetime.now(promotion.UTC).isoformat(),
    }
    monkeypatch.setattr(
        promotion,
        "qualification_states",
        lambda api, head, base, required: {
            "Required PR Gate": None,
            "CodeQL": None,
        },
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_ci",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected CI replay")),
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_codeql",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected CodeQL replay")),
    )
    assert (
        promotion._request_exact_qualification(
            object(),
            _promotion_pr(body=promotion._promotion_body(metadata)),
            HEAD,
            BASE,
        )
        is False
    )


def test_expired_partial_qualification_dispatches_only_missing_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = _promotion_metadata()
    metadata["qualificationRequest"] = {
        "attempt": 1,
        "requestedAt": "2000-01-01T00:00:00+00:00",
    }
    events: list[str] = []
    updates: list[dict[str, Any]] = []

    class Api:
        def request(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            assert (method, path) == ("PATCH", "/pulls/901")
            assert payload is not None and isinstance(payload.get("body"), str)
            updates.append(payload)
            events.append("persist")
            return _promotion_pr(body=str(payload["body"]))

    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setattr(
        promotion,
        "qualification_states",
        lambda api, head, base, required: {
            "Required PR Gate": {"conclusion": "success"},
            "CodeQL": None,
        },
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_ci",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected CI dispatch")),
    )
    monkeypatch.setattr(
        promotion,
        "dispatch_exact_codeql",
        lambda *args, **kwargs: events.append("codeql"),
    )

    assert (
        promotion._request_exact_qualification(
            Api(),
            _promotion_pr(body=promotion._promotion_body(metadata)),
            HEAD,
            BASE,
        )
        is False
    )
    assert events == ["persist", "codeql"]
    persisted = promotion._parse_marker(str(updates[0]["body"]))
    assert persisted is not None
    assert persisted["qualificationRequest"]["attempt"] == 2


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


def test_orphan_staging_base_prune_requires_generated_parent_provenance() -> None:
    generated_branch = BRANCH
    encoded_generated = generated_branch.replace("/", "%2F")
    encoded_staging = STAGING.replace("/", "%2F")
    deleted: list[str] = []

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

    assert promotion._prune_orphan_promotion_refs(Api()) == 2
    assert deleted == [
        f"/git/refs/heads/{encoded_staging}",
        f"/git/refs/heads/{encoded_generated}",
    ]


def test_fork_open_pr_cannot_pin_promotion_or_staging_refs() -> None:
    encoded_generated = BRANCH.replace("/", "%2F")
    encoded_staging = STAGING.replace("/", "%2F")
    deleted: list[str] = []

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

    assert promotion._prune_orphan_promotion_refs(Api()) == 2
    assert deleted == [
        f"/git/refs/heads/{encoded_staging}",
        f"/git/refs/heads/{encoded_generated}",
    ]


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
        promotion._prune_orphan_promotion_refs(Api())
