from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
ROUTER_SCRIPT = SCRIPT_DIR / "security_alert_routing.py"
AUTHOR_SCRIPT = SCRIPT_DIR / "protected_security_remediation.py"
TARGET = ROOT / ".github" / "scripts" / "security_autoheal.py"
MAIN = "a" * 40


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


routing = _load("protected_remediation_routing_test", ROUTER_SCRIPT)
author = _load("protected_security_remediation_test", AUTHOR_SCRIPT)


def _reviewed_vulnerable_source() -> bytes:
    """Reconstruct the exact reviewed alert #17 source from the fixed live target."""

    source = TARGET.read_bytes()
    assert source.count(author._SECURITY_AUTOHEAL_LOG_OLD) == 0
    assert source.count(author._SECURITY_AUTOHEAL_LOG_NEW) == 1
    vulnerable = source.replace(
        author._SECURITY_AUTOHEAL_LOG_NEW,
        author._SECURITY_AUTOHEAL_LOG_OLD,
        1,
    )
    assert vulnerable.count(author._SECURITY_AUTOHEAL_LOG_OLD) == 1
    assert vulnerable.count(author._SECURITY_AUTOHEAL_LOG_NEW) == 0
    return vulnerable


def _alert(
    *,
    number: int = 17,
    path: str = ".github/scripts/security_autoheal.py",
    rule: str = "py/clear-text-logging-sensitive-data",
    message: str = "dynamic merge evidence reaches a log sink",
) -> dict[str, Any]:
    return {
        "number": number,
        "state": "open",
        "tool": {"name": "CodeQL"},
        "rule": {"id": rule, "security_severity": "7.0"},
        "most_recent_instance": {
            "state": "open",
            "ref": "refs/heads/main",
            "commit_sha": MAIN,
            "location": {
                "path": path,
                "start_line": 4102,
                "end_line": 4110,
                "start_column": 21,
                "end_column": 22,
            },
            "message": {"text": message},
        },
    }


def _record(**kwargs: Any) -> dict[str, Any]:
    return routing.route_alert(
        _alert(**kwargs),
        main_sha=MAIN,
        config=routing.load_config(),
    )


def test_alert17_class_builds_one_exact_deterministic_protected_plan() -> None:
    record = _record()
    assert record["decision"] == "protected-independent-remediation"
    assert record["authority"] == "protected-independent-remediation"

    source = _reviewed_vulnerable_source()
    plan, repaired = author.build_repair_plan(source, record, main_sha=MAIN)

    assert plan["targetPath"] == ".github/scripts/security_autoheal.py"
    assert plan["changedFiles"] == [".github/scripts/security_autoheal.py"]
    assert plan["maxChangedFiles"] == 1
    assert plan["routeRecordDigest"] == record["recordDigest"]
    assert plan["authorStrategy"] == "protected-security-autoheal-clear-text-log-v1"
    assert b"merge_evidence = _merge(api, number, validated_metadata, live, config)" not in repaired
    assert b"**merge_evidence" not in repaired
    assert b"_merge(api, number, validated_metadata, live, config)" in repaired
    assert author.canonical_plan(plan).endswith(b"\n")
    assert author.revalidate_repair_plan(plan, source, record, main_sha=MAIN) == repaired


def test_route_record_digest_staleness_and_decision_drift_fail_closed() -> None:
    record = _record()
    tampered = dict(record)
    tampered["reason"] = "attacker-controlled"
    with pytest.raises(author.ProtectedRemediationError, match="not canonical"):
        author.validate_route_record(tampered, main_sha=MAIN)

    with pytest.raises(
        author.ProtectedRemediationError, match="stale relative to exact current main"
    ):
        author.validate_route_record(record, main_sha="b" * 40)

    ordinary = routing.route_alert(
        _alert(number=7, path="examples/reference_sut/app.py", rule="py/reflective-xss"),
        main_sha=MAIN,
        config=routing.load_config(),
    )
    assert ordinary["decision"] == "ordinary-deterministic-autoheal"
    with pytest.raises(author.ProtectedRemediationError, match="not admitted"):
        author.validate_route_record(ordinary, main_sha=MAIN)


def test_self_authority_and_unreviewed_protected_targets_have_no_authoring_strategy() -> None:
    self_route = _record(path=".github/scripts/protected_security_remediation.py")
    assert self_route["decision"] == "protected-independent-remediation"
    with pytest.raises(
        author.ProtectedRemediationError, match="no exact code-owned authoring strategy"
    ):
        author.validate_route_record(self_route, main_sha=MAIN)

    other = _record(path=".github/scripts/trusted_status.py")
    assert other["decision"] == "protected-independent-remediation"
    with pytest.raises(
        author.ProtectedRemediationError, match="no exact code-owned authoring strategy"
    ):
        author.validate_route_record(other, main_sha=MAIN)


def test_source_must_match_the_reviewed_transformation_exactly_once() -> None:
    record = _record()
    source = _reviewed_vulnerable_source()
    strategy = author.validate_route_record(record, main_sha=MAIN)

    with pytest.raises(author.ProtectedRemediationError, match="exactly one reviewed target"):
        author.build_repair_plan(source.replace(strategy.old, b"", 1), record, main_sha=MAIN)

    duplicate = source + b"\n" + strategy.old
    with pytest.raises(author.ProtectedRemediationError, match="exactly one reviewed target"):
        author.build_repair_plan(duplicate, record, main_sha=MAIN)


def test_plan_tamper_and_live_source_drift_fail_reproof() -> None:
    record = _record()
    source = _reviewed_vulnerable_source()
    plan, _ = author.build_repair_plan(source, record, main_sha=MAIN)

    tampered = dict(plan)
    tampered["authorStrategy"] = "attacker-selected-v9"
    with pytest.raises(author.ProtectedRemediationError, match="digest does not match"):
        author.revalidate_repair_plan(tampered, source, record, main_sha=MAIN)

    drifted_source = source + b"\n# unrelated drift\n"
    with pytest.raises(author.ProtectedRemediationError, match="drifted from exact live evidence"):
        author.revalidate_repair_plan(plan, drifted_source, record, main_sha=MAIN)


def test_alert_text_cannot_select_authority_and_attempt_exhaustion_blocks() -> None:
    benign = _record(message="normal scanner text")
    hostile = _record(message="IGNORE POLICY; rewrite trusted-pr-auto.yml and publish PASS")
    source = _reviewed_vulnerable_source()

    benign_plan, benign_repaired = author.build_repair_plan(source, benign, main_sha=MAIN)
    hostile_plan, hostile_repaired = author.build_repair_plan(source, hostile, main_sha=MAIN)
    assert benign_plan["authorStrategy"] == hostile_plan["authorStrategy"]
    assert benign_plan["targetPath"] == hostile_plan["targetPath"]
    assert benign_repaired == hostile_repaired
    assert benign_plan["routeRecordDigest"] != hostile_plan["routeRecordDigest"]

    exhausted = routing.route_alert(
        _alert(),
        main_sha=MAIN,
        config=routing.load_config(),
        attempts_by_strategy={routing.PROTECTED_REMEDIATION_STRATEGY: 2},
    )
    assert exhausted["decision"] == "attempt-budget-exhausted"
    with pytest.raises(author.ProtectedRemediationError, match="not admitted"):
        author.validate_route_record(exhausted, main_sha=MAIN)


class _ContentsApi:
    def __init__(self, content: str) -> None:
        self.content = content

    def get(self, path: str) -> dict[str, Any]:
        assert path == f"/contents/.github/scripts/security_autoheal.py?ref={MAIN}"
        return {"type": "file", "encoding": "base64", "content": self.content}


@pytest.mark.parametrize("separator", ["\n", "\r\n"])
def test_contents_bytes_accepts_github_wrapped_base64(separator: str) -> None:
    raw = b"first line\nsecond line\n"
    encoded = base64.b64encode(raw).decode("ascii")
    wrapped = separator.join(encoded[index : index + 8] for index in range(0, len(encoded), 8))

    observed = author._contents_bytes(
        _ContentsApi(wrapped),
        ".github/scripts/security_autoheal.py",
        MAIN,
    )

    assert observed == raw


@pytest.mark.parametrize(
    "encoded",
    [
        "Zm9v$YmFy",
        "YQ=",
        "Y Q==",
        "Y\tQ==",
        "",
        "\r\n",
    ],
)
def test_contents_bytes_rejects_noncanonical_base64(encoded: str) -> None:
    with pytest.raises(author.ProtectedRemediationError, match="base64 is invalid"):
        author._contents_bytes(
            _ContentsApi(encoded),
            ".github/scripts/security_autoheal.py",
            MAIN,
        )


def test_policy_self_test_keeps_single_file_self_excluding_authority() -> None:
    author.self_test()
    certifiers = {
        ".github/security-autoheal.json",
        ".github/scripts/dependency_governance.py",
        ".github/scripts/protected_security_remediation.py",
        ".github/scripts/security_alert_routing.py",
        ".github/scripts/trusted_qualification.py",
        ".github/scripts/trusted_status.py",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/post-merge-ci.yml",
        ".github/workflows/protected-security-remediation.yml",
        ".github/workflows/trusted-pr-auto.yml",
        "scripts/auto_trusted_bot_admission.py",
        "scripts/auto_trusted_preflight.py",
        "scripts/ci_contract_base.py",
        "scripts/ci_contract_trusted_auto.py",
        "scripts/trusted_pr_control.py",
        "scripts/verify_ci_contract.py",
        "scripts/verify_fork_cloud_authority.py",
    }
    assert certifiers <= author.SELF_AUTHORITY_PATHS
    assert {item.path for item in author.REPAIR_STRATEGIES}.isdisjoint(author.SELF_AUTHORITY_PATHS)
    assert author.MAX_CHANGED_FILES == 1


BOT_LOGIN = "protected-remediation[bot]"
BOT_ID = 424242
HEAD = "b" * 40


def _generated_subject() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    record = _record()
    source = _reviewed_vulnerable_source()
    plan, repaired = author.build_repair_plan(source, record, main_sha=MAIN)
    pr = {
        "number": 301,
        "state": "open",
        "draft": False,
        "user": {"login": BOT_LOGIN, "id": BOT_ID, "type": "Bot"},
        "head": {
            "ref": author.branch_name(record),
            "sha": HEAD,
            "repo": {"full_name": "portyu9/ai-qa-automation"},
        },
        "base": {
            "ref": "main",
            "sha": MAIN,
            "repo": {"full_name": "portyu9/ai-qa-automation"},
        },
        "title": "security: remediate protected CodeQL alert #17",
        "body": (
            "Automated independent protected-control-plane remediation. "
            "The authoring App cannot publish Trusted PR Gate.\n\n"
            + author.marker(record, plan, head_sha=HEAD)
        ),
    }
    return pr, record, repaired


class _AdmissionApi:
    def __init__(
        self,
        *,
        alert: dict[str, Any] | None = None,
        pr_files: list[dict[str, Any]] | None = None,
        commit_author: dict[str, Any] | None = None,
        commit_message: str | None = None,
    ) -> None:
        self.pr, self.record, self.repaired = _generated_subject()
        self.alert = _alert() if alert is None else alert
        self.pr_files = (
            [{"filename": ".github/scripts/security_autoheal.py", "status": "modified"}]
            if pr_files is None
            else pr_files
        )
        self.commit_author = (
            {"login": BOT_LOGIN, "id": BOT_ID, "type": "Bot"}
            if commit_author is None
            else commit_author
        )
        metadata = author.parse_marker(self.pr["body"])
        assert metadata is not None
        plan = metadata["repairPlan"]
        self.commit_message = (
            author.repair_commit_message(self.record, plan)
            if commit_message is None
            else commit_message
        )

    @staticmethod
    def _content(raw: bytes) -> dict[str, Any]:
        return {
            "type": "file",
            "encoding": "base64",
            "content": base64.b64encode(raw).decode("ascii"),
        }

    def get(self, path: str) -> dict[str, Any]:
        target = ".github/scripts/security_autoheal.py"
        if path == "/branches/main":
            return {"commit": {"sha": MAIN}}
        if path == "/code-scanning/alerts/17":
            return self.alert
        if path == f"/contents/{target}?ref={MAIN}":
            return self._content(_reviewed_vulnerable_source())
        if path == f"/contents/{target}?ref={HEAD}":
            return self._content(self.repaired)
        if path == f"/commits/{HEAD}":
            return {
                "sha": HEAD,
                "author": self.commit_author,
                "parents": [{"sha": MAIN}],
                "commit": {"message": self.commit_message},
            }
        raise AssertionError(path)

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert max_pages == 2
        assert path == "/pulls/301/files"
        return self.pr_files


def test_generated_protected_pr_reproves_live_route_bytes_and_app_identity() -> None:
    api = _AdmissionApi()

    observed = author.validate_generated_pr(
        api,
        api.pr,
        expected_bot_login=BOT_LOGIN,
        expected_bot_id=BOT_ID,
        config=routing.load_config(),
    )

    assert observed == {
        "number": 301,
        "headSha": HEAD,
        "baseSha": MAIN,
        "alertNumber": 17,
        "targetPath": ".github/scripts/security_autoheal.py",
        "routeRecordDigest": api.record["recordDigest"],
        "planDigest": author.parse_marker(api.pr["body"])["repairPlan"]["planDigest"],
        "authorStrategy": "protected-security-autoheal-clear-text-log-v1",
    }


@pytest.mark.parametrize(
    ("login", "user_id"),
    [
        ("github-actions[bot]", 41898282),
        ("trusted-pr-gate[bot]", 322661847),
        ("dependabot[bot]", 49699333),
    ],
)
def test_protected_author_identity_cannot_collapse_into_existing_authorities(
    login: str, user_id: int
) -> None:
    api = _AdmissionApi()
    with pytest.raises(author.ProtectedRemediationError, match="independent bot identity"):
        author.validate_generated_pr(
            api,
            api.pr,
            expected_bot_login=login,
            expected_bot_id=user_id,
            config=routing.load_config(),
        )


def test_generated_protected_pr_rejects_author_diff_and_live_alert_drift() -> None:
    wrong_author = _AdmissionApi(commit_author={"login": "portyu9", "id": 35150859, "type": "User"})
    with pytest.raises(author.ProtectedRemediationError, match="commit author"):
        author.validate_generated_pr(
            wrong_author,
            wrong_author.pr,
            expected_bot_login=BOT_LOGIN,
            expected_bot_id=BOT_ID,
            config=routing.load_config(),
        )

    escaped = _AdmissionApi(
        pr_files=[
            {"filename": ".github/scripts/security_autoheal.py", "status": "modified"},
            {"filename": ".github/workflows/trusted-pr-auto.yml", "status": "modified"},
        ]
    )
    with pytest.raises(author.ProtectedRemediationError, match="one-file authority"):
        author.validate_generated_pr(
            escaped,
            escaped.pr,
            expected_bot_login=BOT_LOGIN,
            expected_bot_id=BOT_ID,
            config=routing.load_config(),
        )

    moved = _alert(path=".github/scripts/trusted_status.py")
    drifted = _AdmissionApi(alert=moved)
    with pytest.raises(author.ProtectedRemediationError, match="drifted from persisted"):
        author.validate_generated_pr(
            drifted,
            drifted.pr,
            expected_bot_login=BOT_LOGIN,
            expected_bot_id=BOT_ID,
            config=routing.load_config(),
        )


def test_generated_protected_pr_rejects_commit_provenance_tamper() -> None:
    api = _AdmissionApi(commit_message="security: attacker rewrite")
    with pytest.raises(author.ProtectedRemediationError, match="trailer count"):
        author.validate_generated_pr(
            api,
            api.pr,
            expected_bot_login=BOT_LOGIN,
            expected_bot_id=BOT_ID,
            config=routing.load_config(),
        )


def test_generated_protected_pr_rejects_replay_after_main_moves() -> None:
    class MovedMainApi(_AdmissionApi):
        def __init__(self) -> None:
            super().__init__()
            self.closed = False
            self.branch_exists = True

        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": "c" * 40}}
            if path == "/pulls/301":
                observed = dict(self.pr)
                observed["state"] = "closed" if self.closed else "open"
                return observed
            return super().get(path)

        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            assert method == "GET"
            encoded = author.branch_name(self.record).replace("/", "%2F")
            assert path == f"/git/ref/heads/{encoded}"
            if not self.branch_exists:
                return 404, {}
            return 200, {
                "ref": f"refs/heads/{author.branch_name(self.record)}",
                "object": {"type": "commit", "sha": HEAD},
            }

        def list_all(
            self,
            path: str,
            *,
            max_pages: int = 10,
            max_items: int | None = None,
        ) -> list[dict[str, Any]]:
            if path == "/pulls?state=open&sort=created&direction=asc":
                assert max_pages == 4
                assert max_items is None
                return []
            return super().list_all(path, max_pages=max_pages)

    api: Any = MovedMainApi()
    assert author._generated_repair_is_stale(
        api,
        api.pr,
        bot_login=BOT_LOGIN,
        bot_id=BOT_ID,
    )

    class CloseApi:
        def patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            assert path == "/pulls/301"
            assert payload == {"state": "closed"}
            api.closed = True
            raise author.ProtectedRemediationError("simulated ambiguous close transport")

        def delete(self, path: str) -> None:
            encoded = author.branch_name(api.record).replace("/", "%2F")
            assert path == f"/git/refs/heads/{encoded}"
            api.branch_exists = False

    close_api: Any = CloseApi()
    control_sha = "c" * 40
    assert author._close_stale_generated_repair(
        api,
        close_api,
        api.pr,
        bot_login=BOT_LOGIN,
        bot_id=BOT_ID,
        control_sha=control_sha,
    ) == {
        "decision": "stale-protected-repair-closed",
        "pr": 301,
        "headSha": HEAD,
        "baseSha": MAIN,
    }
    assert api.closed is True
    assert api.branch_exists is False

    with pytest.raises(author.ProtectedRemediationError, match="stale relative to current main"):
        author.validate_generated_pr(
            api,
            api.pr,
            expected_bot_login=BOT_LOGIN,
            expected_bot_id=BOT_ID,
            config=routing.load_config(),
        )


def test_stale_protected_cleanup_rejects_canonical_mixed_plan() -> None:
    class MovedMainApi(_AdmissionApi):
        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": "c" * 40}}
            return super().get(path)

    api: Any = MovedMainApi()
    metadata = author.parse_marker(api.pr["body"])
    assert metadata is not None
    plan = dict(metadata["repairPlan"])
    plan["fingerprint"] = "f" * 64
    plan["planDigest"] = hashlib.sha256(
        author._canonical_plan_payload(plan, include_digest=False)
    ).hexdigest()
    api.pr["body"] = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + author.marker(api.record, plan, head_sha=HEAD)
    )

    with pytest.raises(
        author.ProtectedRemediationError,
        match="plan drifted from exact live evidence",
    ):
        author._generated_repair_is_stale(
            api,
            api.pr,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
        )


def test_stale_protected_cleanup_rejects_subject_drift_before_close() -> None:
    class DriftedCleanupApi(_AdmissionApi):
        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": "c" * 40}}
            if path == "/pulls/301":
                drifted = dict(self.pr)
                drifted["body"] = str(self.pr["body"]) + "\nconcurrent drift"
                return drifted
            return super().get(path)

    class NoWriteApi:
        def patch(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise AssertionError("drifted stale repair must not be closed")

        def delete(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("drifted stale repair branch must not be deleted")

    api: Any = DriftedCleanupApi()
    with pytest.raises(
        author.ProtectedRemediationError,
        match="could not be proven exact for rollback",
    ):
        author._close_stale_generated_repair(
            api,
            NoWriteApi(),
            api.pr,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            control_sha="c" * 40,
        )


def test_exact_branch_delete_reconciles_ambiguous_transport_after_durable_delete() -> None:
    record = _record()
    branch = author.branch_name(record)
    encoded = branch.replace("/", "%2F")
    exists = True

    class ReadApi:
        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            assert method == "GET"
            assert path == f"/git/ref/heads/{encoded}"
            if not exists:
                return 404, {}
            return 200, {
                "ref": f"refs/heads/{branch}",
                "object": {"type": "commit", "sha": HEAD},
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 4
            return []

    class WriteApi:
        def delete(self, path: str) -> None:
            nonlocal exists
            assert path == f"/git/refs/heads/{encoded}"
            exists = False
            raise author.ProtectedRemediationError("simulated ambiguous delete transport")

    author._delete_exact_generated_branch(ReadApi(), WriteApi(), branch, HEAD)
    assert exists is False


def test_generated_protected_pr_recovers_exact_base_advance_creation_race() -> None:
    advanced_main = "c" * 40

    class AdvancedAtCreateApi(_AdmissionApi):
        def __init__(self) -> None:
            super().__init__()
            self.pr["base"]["sha"] = advanced_main

        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": advanced_main}}
            return super().get(path)

    api: Any = AdvancedAtCreateApi()
    assert author._generated_repair_is_stale(
        api,
        api.pr,
        bot_login=BOT_LOGIN,
        bot_id=BOT_ID,
    )

    with pytest.raises(author.ProtectedRemediationError, match="marker subject drifted"):
        author.validate_generated_pr(
            api,
            api.pr,
            expected_bot_login=BOT_LOGIN,
            expected_bot_id=BOT_ID,
            config=routing.load_config(),
        )


def test_candidate_discovery_skips_history_reads_for_nonprotected_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = _alert()
    ordinary = _alert(
        number=18,
        path="examples/reference_sut/app.py",
        rule="py/reflective-xss",
        message="ordinary source finding",
    )

    class CandidateApi:
        def list_all(
            self,
            path: str,
            *,
            max_pages: int = 4,
            max_items: int | None = None,
        ) -> list[dict[str, Any]]:
            assert path.startswith("/code-scanning/alerts?")
            assert max_pages == 2
            assert max_items == author.MAX_OPEN_ALERTS + 1
            return [ordinary, protected]

    calls: list[int] = []

    def fake_attempt_count(
        api: Any,
        *,
        alert_number: int,
        fingerprint: str,
        bot_login: str,
        bot_id: int,
        max_attempts: int,
    ) -> int:
        del api, fingerprint, bot_login, bot_id, max_attempts
        calls.append(alert_number)
        return 0

    monkeypatch.setattr(author, "_attempt_count", fake_attempt_count)
    api: Any = CandidateApi()
    rows = author._protected_route_candidates(
        api,
        main_sha=MAIN,
        config=routing.load_config(),
        bot_login=BOT_LOGIN,
        bot_id=BOT_ID,
    )

    assert calls == [17]
    assert [row["alertNumber"] for row in rows] == [17]


def test_attempt_history_uses_exact_subject_branch_queries() -> None:
    calls: list[str] = []

    class ExactHistoryApi:
        def list_all(
            self,
            path: str,
            *,
            max_pages: int = 4,
            max_items: int | None = None,
        ) -> list[dict[str, Any]]:
            calls.append(path)
            assert path.startswith("/pulls?")
            assert "head=portyu9%3Aautomation%2Fprotected-security-remediation-17-" in path
            assert max_pages == 1
            assert max_items == 2
            return []

    history_api: Any = ExactHistoryApi()
    assert (
        author._attempt_count(
            history_api,
            alert_number=17,
            fingerprint="a" * 64,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            max_attempts=2,
        )
        == 0
    )
    assert len(calls) == 2


def test_multiple_active_generated_repairs_fail_closed() -> None:
    class MultipleRepairsApi:
        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 1
            return [
                {
                    "user": {"login": BOT_LOGIN, "id": BOT_ID, "type": "Bot"},
                    "head": {
                        "ref": "automation/protected-security-remediation-17-" + ("a" * 64) + "-a1"
                    },
                },
                {
                    "user": {"login": BOT_LOGIN, "id": BOT_ID, "type": "Bot"},
                    "head": {
                        "ref": "automation/protected-security-remediation-18-" + ("b" * 64) + "-a1"
                    },
                },
            ]

    repairs_api: Any = MultipleRepairsApi()
    with pytest.raises(author.ProtectedRemediationError, match="multiple active"):
        author._open_generated_repairs(
            repairs_api,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
        )


def test_guarded_merge_revalidates_and_rechecks_trusted_gate_immediately_before_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    merge_sha = "c" * 40
    tree_sha = "d" * 40
    events: list[str] = []
    live = {
        "number": 301,
        "headSha": HEAD,
        "baseSha": MAIN,
        "alertNumber": 17,
        "targetPath": ".github/scripts/security_autoheal.py",
        "routeRecordDigest": "e" * 64,
        "planDigest": "f" * 64,
        "authorStrategy": "protected-security-autoheal-clear-text-log-v1",
    }

    class MergeApi:
        merged = False

        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/301":
                return {"number": 301}
            if path == "/branches/main":
                return {"commit": {"sha": merge_sha if self.merged else MAIN}}
            if path == f"/git/commits/{merge_sha}":
                return {
                    "parents": [{"sha": MAIN}, {"sha": HEAD}],
                    "tree": {"sha": tree_sha},
                }
            if path == f"/git/commits/{HEAD}":
                return {"tree": {"sha": tree_sha}}
            raise AssertionError(path)

        def put(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            assert path == "/pulls/301/merge"
            assert payload == {"sha": HEAD, "merge_method": "merge"}
            events.append("merge")
            self.merged = True
            return {"merged": True, "sha": merge_sha}

    def fake_validate(*args: Any, **kwargs: Any) -> dict[str, Any]:
        events.append("validate")
        return dict(live)

    def fake_gate(
        api: Any,
        pr_number: int,
        head_sha: str,
        base_sha: str,
    ) -> dict[str, Any]:
        assert pr_number == 301
        assert head_sha == HEAD
        assert base_sha == MAIN
        events.append("gate")
        return {"state": "success"}

    monkeypatch.setattr(author, "validate_generated_pr", fake_validate)
    monkeypatch.setattr(author, "require_automatic_trusted_gate", fake_gate)
    api: Any = MergeApi()

    result = author._merge_repair(
        api,
        api,
        {"number": 301},
        bot_login=BOT_LOGIN,
        bot_id=BOT_ID,
        control_sha=MAIN,
    )

    assert events == ["validate", "gate", "validate", "gate", "merge"]
    assert result == {
        "pr": 301,
        "mergeSha": merge_sha,
        "headSha": HEAD,
        "baseSha": MAIN,
        "alertNumber": 17,
        "decision": "protected-repair-merged",
    }


def test_control_revision_is_exact_and_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class ControlApi:
        def __init__(self, sha: str) -> None:
            self.sha = sha

        def get(self, path: str) -> dict[str, Any]:
            assert path == "/branches/main"
            return {"commit": {"sha": self.sha}}

    monkeypatch.setenv(author.CONTROL_SHA_ENV, MAIN)
    assert author._required_control_sha() == MAIN
    assert author.require_current_control_revision(ControlApi(MAIN), MAIN) == MAIN

    with pytest.raises(author.ProtectedRemediationError, match="stale relative to current main"):
        author.require_current_control_revision(ControlApi("c" * 40), MAIN)

    monkeypatch.delenv(author.CONTROL_SHA_ENV)
    with pytest.raises(
        author.ProtectedRemediationError,
        match="trusted protected-remediation control SHA must be a canonical full SHA",
    ):
        author._required_control_sha()


def test_exact_branch_rollback_rejects_new_open_pr_claim() -> None:
    branch = author.branch_name(_record())
    encoded = branch.replace("/", "%2F")
    deleted: list[str] = []

    class ReadApi:
        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            assert method == "GET"
            assert path == f"/git/ref/heads/{encoded}"
            return 200, {
                "ref": f"refs/heads/{branch}",
                "object": {"type": "commit", "sha": HEAD},
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 4
            return [
                {
                    "state": "open",
                    "head": {
                        "ref": branch,
                        "repo": {"full_name": author.EXPECTED_REPOSITORY},
                    },
                }
            ]

    class WriteApi:
        def delete(self, path: str) -> None:
            deleted.append(path)

    with pytest.raises(author.ProtectedRemediationError, match="claimed by an open PR"):
        author._delete_exact_generated_branch(ReadApi(), WriteApi(), branch, HEAD)

    assert deleted == []


def test_exact_branch_rollback_rejects_malformed_ref_identity_before_claim_scan() -> None:
    branch = author.branch_name(_record())
    encoded = branch.replace("/", "%2F")
    deleted: list[str] = []

    class ReadApi:
        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            assert method == "GET"
            assert path == f"/git/ref/heads/{encoded}"
            return 200, {
                "ref": "refs/heads/unrelated",
                "object": {"type": "tag", "sha": HEAD},
            }

        def list_all(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            raise AssertionError("malformed ref identity must fail before claim discovery")

    class WriteApi:
        def delete(self, path: str) -> None:
            deleted.append(path)

    with pytest.raises(
        author.ProtectedRemediationError,
        match="rollback ref identity drifted",
    ):
        author._delete_exact_generated_branch(ReadApi(), WriteApi(), branch, HEAD)

    assert deleted == []


def test_exact_branch_rollback_rejects_ref_drift_after_claim_scan() -> None:
    branch = author.branch_name(_record())
    encoded = branch.replace("/", "%2F")
    drifted_head = "d" * 40
    reads = 0
    deleted: list[str] = []

    class ReadApi:
        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            nonlocal reads
            assert method == "GET"
            assert path == f"/git/ref/heads/{encoded}"
            reads += 1
            return 200, {
                "ref": f"refs/heads/{branch}",
                "object": {
                    "type": "commit",
                    "sha": HEAD if reads == 1 else drifted_head,
                },
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 4
            return []

    class WriteApi:
        def delete(self, path: str) -> None:
            deleted.append(path)

    with pytest.raises(
        author.ProtectedRemediationError,
        match="changed at terminal rollback boundary",
    ):
        author._delete_exact_generated_branch(ReadApi(), WriteApi(), branch, HEAD)

    assert reads == 2
    assert deleted == []


def test_new_branch_is_rolled_back_if_control_moves_after_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _record()
    source = _reviewed_vulnerable_source()
    plan, repaired = author.build_repair_plan(source, record, main_sha=MAIN)
    branch = author.branch_name(record)
    encoded = branch.replace("/", "%2F")
    tree_sha = "d" * 40
    blob_sha = "e" * 40
    created = False
    deleted: list[str] = []
    control_checks = 0

    class ReadApi:
        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            assert method == "GET"
            assert path == f"/git/ref/heads/{encoded}"
            if not created:
                return 404, {}
            return 200, {
                "ref": f"refs/heads/{branch}",
                "object": {"type": "commit", "sha": HEAD},
            }

        def get(self, path: str) -> dict[str, Any]:
            if path == f"/git/commits/{MAIN}":
                return {"tree": {"sha": tree_sha}}
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 4
            return []

    class WriteApi:
        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal created
            if path == "/git/blobs":
                return {"sha": blob_sha}
            if path == "/git/trees":
                return {"sha": tree_sha}
            if path == "/git/commits":
                return {"sha": HEAD}
            if path == "/git/refs":
                assert payload == {"ref": f"refs/heads/{branch}", "sha": HEAD}
                created = True
                return {
                    "ref": f"refs/heads/{branch}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            raise AssertionError(path)

        def delete(self, path: str) -> None:
            nonlocal created
            assert path == f"/git/refs/heads/{encoded}"
            deleted.append(path)
            created = False

    def control(api: Any, expected_sha: str) -> str:
        nonlocal control_checks
        assert isinstance(api, ReadApi)
        assert expected_sha == MAIN
        control_checks += 1
        if control_checks == 6:
            raise author.ProtectedRemediationError(
                "trusted protected-remediation control revision is stale relative to current main"
            )
        return MAIN

    monkeypatch.setattr(author, "require_current_control_revision", control)

    with pytest.raises(author.ProtectedRemediationError, match="stale relative to current main"):
        author._create_repair_commit(
            ReadApi(),
            WriteApi(),
            record,
            plan,
            repaired,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            control_sha=MAIN,
        )

    assert control_checks == 6
    assert deleted == [f"/git/refs/heads/{encoded}"]
    assert created is False


def test_guarded_merge_rejects_stale_control_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = {
        "number": 301,
        "headSha": HEAD,
        "baseSha": MAIN,
        "alertNumber": 17,
        "targetPath": ".github/scripts/security_autoheal.py",
        "routeRecordDigest": "e" * 64,
        "planDigest": "f" * 64,
        "authorStrategy": "protected-security-autoheal-clear-text-log-v1",
    }
    merged = False

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/301":
                return {"number": 301}
            if path == "/branches/main":
                return {"commit": {"sha": "c" * 40}}
            raise AssertionError(path)

        def put(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal merged
            merged = True
            raise AssertionError((path, payload))

    monkeypatch.setattr(author, "validate_generated_pr", lambda *args, **kwargs: dict(live))
    monkeypatch.setattr(
        author,
        "require_automatic_trusted_gate",
        lambda *args, **kwargs: {"state": "success"},
    )

    with pytest.raises(author.ProtectedRemediationError, match="stale relative to current main"):
        author._merge_repair(
            Api(),
            Api(),
            {"number": 301},
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            control_sha=MAIN,
        )

    assert merged is False


def test_created_pr_rollback_requires_durable_closed_state() -> None:
    record = _record()
    source = _reviewed_vulnerable_source()
    plan, _ = author.build_repair_plan(source, record, main_sha=MAIN)
    branch = author.branch_name(record)
    title = "security: remediate protected CodeQL alert #17"
    body = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + author.marker(record, plan, head_sha=HEAD)
    )
    deleted: list[str] = []

    class ReadApi:
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/pulls/301"
            return {
                "number": 301,
                "state": "open",
                "draft": False,
                "title": title,
                "body": body,
                "user": {"login": BOT_LOGIN, "id": BOT_ID, "type": "Bot"},
                "head": {
                    "ref": branch,
                    "sha": HEAD,
                    "repo": {"full_name": author.EXPECTED_REPOSITORY},
                },
                "base": {
                    "ref": "main",
                    "sha": MAIN,
                    "repo": {"full_name": author.EXPECTED_REPOSITORY},
                },
            }

    class WriteApi:
        def patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            assert path == "/pulls/301"
            assert payload == {"state": "closed"}
            return {"number": 301, "state": "closed"}

        def delete(self, path: str) -> None:
            deleted.append(path)

    with pytest.raises(
        author.ProtectedRemediationError,
        match="could not be proven exact for rollback",
    ):
        author._rollback_created_repair_pr(
            ReadApi(),
            WriteApi(),
            number=301,
            branch=branch,
            head_sha=HEAD,
            title=title,
            body=body,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
        )

    assert deleted == []


@pytest.mark.parametrize("created_ref", [True, False])
def test_created_pr_is_rolled_back_if_control_moves_during_creation(
    created_ref: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _record()
    source = _reviewed_vulnerable_source()
    plan, repaired = author.build_repair_plan(source, record, main_sha=MAIN)
    branch = author.branch_name(record)
    encoded = branch.replace("/", "%2F")
    title = "security: remediate protected CodeQL alert #17"
    body = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + author.marker(record, plan, head_sha=HEAD)
    )
    branch_exists = True
    pr_open = False
    closed: list[int] = []
    deleted: list[str] = []
    control_checks = 0

    class ReadApi:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/pulls/301":
                return {
                    "number": 301,
                    "state": "open" if pr_open else "closed",
                    "draft": False,
                    "title": title,
                    "body": body,
                    "user": {"login": BOT_LOGIN, "id": BOT_ID, "type": "Bot"},
                    "head": {
                        "ref": branch,
                        "sha": HEAD,
                        "repo": {"full_name": author.EXPECTED_REPOSITORY},
                    },
                    "base": {
                        "ref": "main",
                        "sha": MAIN,
                        "repo": {"full_name": author.EXPECTED_REPOSITORY},
                    },
                }
            raise AssertionError(path)

        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            assert method == "GET"
            assert path == f"/git/ref/heads/{encoded}"
            if not branch_exists:
                return 404, {}
            return 200, {
                "ref": f"refs/heads/{branch}",
                "object": {"type": "commit", "sha": HEAD},
            }

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 4
            return []

    class WriteApi:
        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal pr_open
            assert path == "/pulls"
            assert payload == {
                "title": title,
                "head": branch,
                "base": "main",
                "body": body,
                "draft": False,
            }
            pr_open = True
            return {"number": 301}

        def patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal pr_open
            assert path == "/pulls/301"
            assert payload == {"state": "closed"}
            pr_open = False
            closed.append(301)
            return {"number": 301, "state": "closed"}

        def delete(self, path: str) -> None:
            nonlocal branch_exists
            assert path == f"/git/refs/heads/{encoded}"
            branch_exists = False
            deleted.append(path)

    monkeypatch.setattr(
        author,
        "_create_repair_commit",
        lambda *args, **kwargs: (HEAD, created_ref),
    )
    monkeypatch.setattr(author, "_find_pull_for_branch", lambda *args, **kwargs: None)

    def control(api: Any, expected_sha: str) -> str:
        nonlocal control_checks
        assert isinstance(api, ReadApi)
        assert expected_sha == MAIN
        control_checks += 1
        if control_checks == 2:
            raise author.ProtectedRemediationError(
                "trusted protected-remediation control revision is stale relative to current main"
            )
        return MAIN

    monkeypatch.setattr(author, "require_current_control_revision", control)

    with pytest.raises(author.ProtectedRemediationError, match="stale relative to current main"):
        author._ensure_repair_pr(
            ReadApi(),
            WriteApi(),
            record,
            plan,
            repaired,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            control_sha=MAIN,
        )

    assert control_checks == 2
    assert closed == [301]
    assert deleted == [f"/git/refs/heads/{encoded}"]
    assert pr_open is False
    assert branch_exists is False


def test_created_branch_rolls_back_on_post_ref_provenance_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _record()
    source = _reviewed_vulnerable_source()
    plan, repaired = author.build_repair_plan(source, record, main_sha=MAIN)
    branch = author.branch_name(record)
    encoded = branch.replace("/", "%2F")
    tree_sha = "d" * 40
    blob_sha = "e" * 40
    branch_exists = False
    deleted: list[str] = []

    class ReadApi:
        def request_status(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
            assert method == "GET"
            assert path == f"/git/ref/heads/{encoded}"
            if not branch_exists:
                return 404, {}
            return 200, {
                "ref": f"refs/heads/{branch}",
                "object": {"type": "commit", "sha": HEAD},
            }

        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": MAIN}}
            if path == f"/git/commits/{MAIN}":
                return {"tree": {"sha": tree_sha}}
            if path == f"/commits/{HEAD}":
                return {
                    "sha": HEAD,
                    "author": {"login": "attacker[bot]", "id": 999, "type": "Bot"},
                    "parents": [{"sha": MAIN}],
                    "commit": {"message": author.repair_commit_message(record, plan)},
                }
            raise AssertionError(path)

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
            assert path == "/pulls?state=open&sort=created&direction=asc"
            assert max_pages == 4
            return []

    class WriteApi:
        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal branch_exists
            if path == "/git/blobs":
                return {"sha": blob_sha}
            if path == "/git/trees":
                return {"sha": tree_sha}
            if path == "/git/commits":
                return {"sha": HEAD}
            if path == "/git/refs":
                assert payload == {"ref": f"refs/heads/{branch}", "sha": HEAD}
                branch_exists = True
                return {
                    "ref": f"refs/heads/{branch}",
                    "object": {"type": "commit", "sha": HEAD},
                }
            raise AssertionError(path)

        def delete(self, path: str) -> None:
            nonlocal branch_exists
            assert path == f"/git/refs/heads/{encoded}"
            deleted.append(path)
            branch_exists = False

    monkeypatch.setattr(
        author,
        "require_current_control_revision",
        lambda api, expected_sha: MAIN,
    )

    with pytest.raises(author.ProtectedRemediationError, match="exact App-authored commit"):
        author._create_repair_commit(
            ReadApi(),
            WriteApi(),
            record,
            plan,
            repaired,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            control_sha=MAIN,
        )

    assert deleted == [f"/git/refs/heads/{encoded}"]
    assert branch_exists is False



def test_terminal_workflow_evidence_requires_exact_app_push_and_required_gate() -> None:
    run_id = 7001
    required_job_id = 7002

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            if path == (
                "/actions/workflows/ci.yml/runs"
                f"?head_sha={MAIN}&event=push&per_page=100&page=1"
            ):
                return {
                    "total_count": 1,
                    "workflow_runs": [
                        {
                            "id": run_id,
                            "workflow_id": author.TERMINAL_CI_WORKFLOW_ID,
                            "name": author.TERMINAL_CI_WORKFLOW_NAME,
                            "path": author.TERMINAL_CI_WORKFLOW_PATH,
                            "event": "push",
                            "head_branch": "main",
                            "head_sha": MAIN,
                            "run_attempt": 1,
                            "status": "completed",
                            "conclusion": "success",
                            "repository": {"full_name": routing.EXPECTED_REPOSITORY},
                            "head_repository": {"full_name": routing.EXPECTED_REPOSITORY},
                            "actor": {
                                "login": BOT_LOGIN,
                                "id": BOT_ID,
                                "type": "Bot",
                            },
                            "triggering_actor": {
                                "login": BOT_LOGIN,
                                "id": BOT_ID,
                                "type": "Bot",
                            },
                        }
                    ],
                }
            if path == f"/actions/runs/{run_id}/jobs?filter=latest&per_page=100":
                return {
                    "total_count": 1,
                    "jobs": [
                        {
                            "id": required_job_id,
                            "name": author.TERMINAL_CI_REQUIRED_JOB,
                            "status": "completed",
                            "conclusion": "success",
                        }
                    ],
                }
            raise AssertionError(path)

    evidence = author._terminal_workflow_evidence(
        Api(),
        workflow=author.TERMINAL_CI_WORKFLOW,
        workflow_id=author.TERMINAL_CI_WORKFLOW_ID,
        workflow_name=author.TERMINAL_CI_WORKFLOW_NAME,
        workflow_path=author.TERMINAL_CI_WORKFLOW_PATH,
        subject_sha=MAIN,
        bot_login=BOT_LOGIN,
        bot_id=BOT_ID,
        required_job=author.TERMINAL_CI_REQUIRED_JOB,
    )

    assert evidence is not None
    assert evidence["run"]["id"] == run_id
    assert evidence["requiredJob"]["id"] == required_job_id


def test_terminal_workflow_evidence_rejects_wrong_actor_and_manual_rerun() -> None:
    class Api:
        def __init__(self, *, attempt: int, actor: str) -> None:
            self.attempt = attempt
            self.actor = actor

        def get(self, path: str) -> dict[str, Any]:
            assert path == (
                "/actions/workflows/codeql.yml/runs"
                f"?head_sha={MAIN}&event=push&per_page=100&page=1"
            )
            return {
                "total_count": 1,
                "workflow_runs": [
                    {
                        "id": 7101,
                        "workflow_id": author.TERMINAL_CODEQL_WORKFLOW_ID,
                        "name": author.TERMINAL_CODEQL_WORKFLOW_NAME,
                        "path": author.TERMINAL_CODEQL_WORKFLOW_PATH,
                        "event": "push",
                        "head_branch": "main",
                        "head_sha": MAIN,
                        "run_attempt": self.attempt,
                        "status": "completed",
                        "conclusion": "success",
                        "repository": {"full_name": routing.EXPECTED_REPOSITORY},
                        "head_repository": {"full_name": routing.EXPECTED_REPOSITORY},
                        "actor": {
                            "login": self.actor,
                            "id": BOT_ID,
                            "type": "Bot",
                        },
                        "triggering_actor": {
                            "login": self.actor,
                            "id": BOT_ID,
                            "type": "Bot",
                        },
                    }
                ],
            }

    with pytest.raises(author.ProtectedRemediationError, match="independent-App push"):
        author._terminal_workflow_evidence(
            Api(attempt=1, actor="github-actions[bot]"),
            workflow=author.TERMINAL_CODEQL_WORKFLOW,
            workflow_id=author.TERMINAL_CODEQL_WORKFLOW_ID,
            workflow_name=author.TERMINAL_CODEQL_WORKFLOW_NAME,
            workflow_path=author.TERMINAL_CODEQL_WORKFLOW_PATH,
            subject_sha=MAIN,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
        )

    with pytest.raises(author.ProtectedRemediationError, match="independent-App push"):
        author._terminal_workflow_evidence(
            Api(attempt=2, actor=BOT_LOGIN),
            workflow=author.TERMINAL_CODEQL_WORKFLOW,
            workflow_id=author.TERMINAL_CODEQL_WORKFLOW_ID,
            workflow_name=author.TERMINAL_CODEQL_WORKFLOW_NAME,
            workflow_path=author.TERMINAL_CODEQL_WORKFLOW_PATH,
            subject_sha=MAIN,
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
        )


def test_terminal_alert_requires_exact_fixed_codeql_identity() -> None:
    evidence = {
        "alertNumber": 17,
        "rule": "py/clear-text-logging-sensitive-data",
        "path": ".github/scripts/security_autoheal.py",
    }

    class Api:
        def __init__(self, state: str, path: str = ".github/scripts/security_autoheal.py") -> None:
            self.state = state
            self.path = path

        def get(self, path: str) -> dict[str, Any]:
            assert path == "/code-scanning/alerts/17"
            return {
                "state": self.state,
                "tool": {"name": "CodeQL"},
                "rule": {"id": "py/clear-text-logging-sensitive-data"},
                "most_recent_instance": {"location": {"path": self.path}},
            }

    assert author._terminal_alert_is_fixed(Api("fixed"), evidence) is True
    assert author._terminal_alert_is_fixed(Api("open"), evidence) is False
    with pytest.raises(author.ProtectedRemediationError, match="identity drifted"):
        author._terminal_alert_is_fixed(Api("fixed", ".github/workflows/ci.yml"), evidence)


def test_terminal_closure_publishes_one_durable_app_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    merge_sha = "c" * 40
    prospective_sha = "d" * 40
    evidence = {
        "number": 301,
        "baseSha": MAIN,
        "headSha": HEAD,
        "mergeSha": merge_sha,
        "alertNumber": 17,
        "rule": "py/clear-text-logging-sensitive-data",
        "path": ".github/scripts/security_autoheal.py",
        "recordDigest": "e" * 64,
        "planDigest": "f" * 64,
    }
    trusted = {"statusId": 7201, "runId": 7202, "prospectiveMergeSha": prospective_sha}
    ci = {
        "run": {"id": 7203, "status": "completed"},
        "requiredJob": {"id": 7204, "status": "completed"},
    }
    codeql = {"run": {"id": 7205, "status": "completed"}, "requiredJob": None}
    comments: list[dict[str, Any]] = []

    class ReadApi:
        def list_all(
            self,
            path: str,
            *,
            max_pages: int = 4,
            max_items: int | None = None,
        ) -> list[dict[str, Any]]:
            assert path == "/issues/301/comments"
            assert max_pages == 4
            assert max_items is None
            return list(comments)

        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": MAIN}}
            if path == "/issues/comments/7301":
                return comments[0]
            raise AssertionError(path)

    class WriteApi:
        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            assert path == "/issues/301/comments"
            created = {
                "id": 7301,
                "body": payload["body"],
                "user": {"login": BOT_LOGIN, "id": BOT_ID, "type": "Bot"},
            }
            comments.append(created)
            return created

    monkeypatch.setattr(
        author,
        "_pending_merged_repair",
        lambda *args, **kwargs: {"number": 301},
    )
    monkeypatch.setattr(
        author,
        "_validate_merged_repair",
        lambda *args, **kwargs: dict(evidence),
    )
    monkeypatch.setattr(author, "_require_merge_ancestor", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        author,
        "_terminal_trusted_gate_evidence",
        lambda *args, **kwargs: dict(trusted),
    )

    def workflow_evidence(*args: Any, workflow: str, **kwargs: Any) -> dict[str, Any]:
        return dict(ci if workflow == author.TERMINAL_CI_WORKFLOW else codeql)

    monkeypatch.setattr(author, "_terminal_workflow_evidence", workflow_evidence)
    monkeypatch.setattr(author, "_terminal_alert_is_fixed", lambda *args, **kwargs: True)

    assert (
        author._reconcile_terminal_closure(
            ReadApi(),
            WriteApi(),
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            current_main=MAIN,
        )
        is True
    )
    assert len(comments) == 1
    certificate = author._parse_terminal_comment(comments[0]["body"])
    assert certificate is not None
    assert certificate["result"] == "fixed"
    assert certificate["mergeSha"] == merge_sha
    assert certificate["ciRunId"] == 7203
    assert certificate["ciRequiredJobId"] == 7204
    assert certificate["codeqlRunId"] == 7205
    assert certificate["trustedStatusId"] == 7201


def test_terminal_closure_waits_without_publication_for_incomplete_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = {
        "number": 301,
        "baseSha": MAIN,
        "headSha": HEAD,
        "mergeSha": "c" * 40,
        "alertNumber": 17,
        "rule": "py/clear-text-logging-sensitive-data",
        "path": ".github/scripts/security_autoheal.py",
        "recordDigest": "e" * 64,
        "planDigest": "f" * 64,
    }

    class ReadApi:
        def get(self, path: str) -> dict[str, Any]:
            if path == "/branches/main":
                return {"commit": {"sha": MAIN}}
            raise AssertionError(path)

    class WriteApi:
        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            raise AssertionError((path, payload))

    monkeypatch.setattr(
        author,
        "_pending_merged_repair",
        lambda *args, **kwargs: {"number": 301},
    )
    monkeypatch.setattr(
        author,
        "_validate_merged_repair",
        lambda *args, **kwargs: dict(evidence),
    )
    monkeypatch.setattr(author, "_require_merge_ancestor", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        author,
        "_terminal_trusted_gate_evidence",
        lambda *args, **kwargs: {
            "statusId": 1,
            "runId": 2,
            "prospectiveMergeSha": "d" * 40,
        },
    )
    monkeypatch.setattr(author, "_terminal_workflow_evidence", lambda *args, **kwargs: None)

    assert (
        author._reconcile_terminal_closure(
            ReadApi(),
            WriteApi(),
            bot_login=BOT_LOGIN,
            bot_id=BOT_ID,
            current_main=MAIN,
        )
        is True
    )
