from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.models import ToolDecision
from ai_qa_automation.policy import PolicyEngine


def make_policy(tmp_path: Path, *, writes: bool = False) -> PolicyEngine:
    target = tmp_path / "target"
    target.mkdir()
    return PolicyEngine(tmp_path, target, allow_test_writes=writes)


def test_path_traversal_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_path(Path("../secret.txt"), write=False)
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "FS-001"


def test_absolute_path_outside_workspace_is_denied(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")

    decision = policy.authorize_path(outside, write=False)

    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "FS-001"


def test_symlink_escape_is_denied_after_resolution(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = policy.target_workspace / "tests-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    decision = policy.authorize_path(Path("tests-link/secret.txt"), write=False)

    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "FS-001"


def test_secret_file_read_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_path(Path(".env"), write=False)
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "GOV-001"


def test_env_example_remains_readable_documentation(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_path(Path(".env.example"), write=False)
    assert decision.decision is ToolDecision.ALLOW
    assert decision.rule_id == "FS-ALLOW"


def test_normalized_governance_path_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path, writes=True).authorize_path(
        Path("tests/../CLAUDE.md"), write=True
    )
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "GOV-001"


def test_governance_file_write_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path, writes=True).authorize_path(Path("CLAUDE.md"), write=True)
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "GOV-001"


def test_test_write_requires_approval_by_default(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_path(Path("tests/test_checkout.py"), write=True)
    assert decision.decision is ToolDecision.REQUIRE_APPROVAL
    assert decision.rule_id == "WRITE-001"


def test_test_write_can_be_enabled_but_app_write_stays_denied(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, writes=True)
    assert (
        policy.authorize_path(Path("tests/test_checkout.py"), write=True).decision
        is ToolDecision.ALLOW
    )
    decision = policy.authorize_path(Path("src/app.py"), write=True)
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "WRITE-002"


def test_generated_test_directory_is_an_explicit_write_boundary(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, writes=True)
    assert (
        policy.authorize_path(Path("generated_tests/test_generated.py"), write=True).decision
        is ToolDecision.ALLOW
    )
    assert (
        policy.authorize_path(Path("generated_tests_backup/test_generated.py"), write=True).decision
        is ToolDecision.DENY
    )


def test_unofficial_mcp_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).validate_mcp_server("github", "someone/random-github-mcp")
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "MCP-001"


def test_official_mcp_identity_requires_exact_match(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert (
        policy.validate_mcp_server("github", "github/github-mcp-server").decision
        is ToolDecision.ALLOW
    )
    assert (
        policy.validate_mcp_server("github", "GitHub/github-mcp-server").decision
        is ToolDecision.DENY
    )
    assert (
        policy.validate_mcp_server("unknown", "github/github-mcp-server").decision
        is ToolDecision.DENY
    )


def test_external_mcp_read_write_and_destructive_are_separated(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert policy.authorize_tool("mcp__github__get_issue", {}).decision is ToolDecision.ALLOW
    assert (
        policy.authorize_tool("mcp__github__create_issue", {}).decision
        is ToolDecision.REQUIRE_APPROVAL
    )
    assert (
        policy.authorize_tool("mcp__github__merge_pull_request", {}).decision is ToolDecision.DENY
    )


def test_mixed_external_mcp_action_cannot_smuggle_write_under_read_prefix(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)

    write = policy.authorize_tool("mcp__github__getOrCreateIssue", {})
    destructive = policy.authorize_tool("mcp__github__listAndDeleteIssues", {})

    assert write.decision is ToolDecision.REQUIRE_APPROVAL
    assert write.rule_id == "MCP-TOOL-002"
    assert destructive.decision is ToolDecision.DENY
    assert destructive.rule_id == "MCP-TOOL-003"


def test_destructive_token_dominates_write_and_read_tokens(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    decision = policy.authorize_tool("mcp__github__getUpdateAndRemoveLabel", {})
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "MCP-TOOL-003"


def test_production_load_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_performance_target(
        "https://prod.example.com", environment="production"
    )
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "PERF-001"


@pytest.mark.parametrize(
    ("target", "environment"),
    [
        ("https://example.test", "prod"),
        ("https://production.example.test", "staging"),
        ("https://api.production-us.example.test", "staging"),
        ("https://api.prod-us.example.test", "qa"),
        ("https://PROD.example.test./load", "test"),
    ],
)
def test_production_aliases_and_dns_labels_fail_closed(
    tmp_path: Path, target: str, environment: str
) -> None:
    decision = make_policy(tmp_path).authorize_performance_target(target, environment=environment)
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "PERF-001"


def test_preprod_is_not_accidentally_classified_as_production(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_performance_target(
        "https://preprod.example.test", environment="preprod"
    )
    assert decision.decision is ToolDecision.ALLOW
    assert decision.rule_id == "PERF-ALLOW"


def test_malformed_performance_urls_are_denied(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    for target in ("", "example.test", "ftp://qa.example.test", "https:///missing-host"):
        decision = policy.authorize_performance_target(target, environment="qa")
        assert decision.decision is ToolDecision.DENY, target
        assert decision.rule_id == "PERF-URL-001", target


def test_unsafe_test_patch_patterns_are_detected(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    diff = (
        "+pytest.skip('green')\n"
        "+time.sleep(8)\n"
        "-assert total == 5\n"
        "+page.set_default_timeout(timeout=30000)\n"
    )
    violations = policy.validate_patch(diff)
    assert {"test_skip", "arbitrary_sleep", "assertion_removal", "timeout_inflation"} <= set(
        violations
    )


@pytest.mark.parametrize(
    ("line", "violation"),
    [
        ("+@pytest.mark.xfail\n", "xfail"),
        ("+test.only('x', () => {})\n", "focused_test"),
        ("+assert True\n", "assertion_tautology"),
        ("+except Exception: pass\n", "broad_exception_suppression"),
        ("+cy.wait(5000)\n", "arbitrary_sleep"),
    ],
)
def test_patch_safety_detects_individual_shortcuts(
    tmp_path: Path, line: str, violation: str
) -> None:
    assert violation in make_policy(tmp_path).validate_patch(line)


def test_assertion_replacement_with_equal_or_stronger_assertion_is_not_removal(
    tmp_path: Path,
) -> None:
    diff = "-assert response.status_code == 200\n+assert response.status_code == 201\n"
    assert "assertion_removal" not in make_policy(tmp_path).validate_patch(diff)


def test_mutating_api_methods_are_never_generic_runtime_authority(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert policy.authorize_api_method("GET").decision is ToolDecision.ALLOW
    denied = policy.authorize_api_method(" post ")
    assert denied.decision is ToolDecision.DENY
    assert denied.rule_id == "API-WRITE-001"
    legacy = policy.authorize_api_method("POST", allow_mutating=True)
    assert legacy.decision is ToolDecision.DENY
    assert legacy.rule_id == "API-WRITE-001"
    assert policy.authorize_api_method("TRACE").decision is ToolDecision.DENY


def test_unknown_performance_environment_is_fail_closed(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_performance_target(
        "https://perf.example.test", environment="mystery"
    )
    assert decision.decision is ToolDecision.REQUIRE_APPROVAL
    assert decision.rule_id == "PERF-ENV-001"


def test_unknown_tool_and_unapproved_mcp_namespace_are_fail_closed(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert policy.authorize_tool("mcp__evil__read_secrets", {}).decision is ToolDecision.DENY
    assert policy.authorize_tool("unexpected_tool", {}).decision is ToolDecision.DENY


def test_generic_builtin_tools_are_denied_even_when_input_looks_harmless(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    for tool in ("Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch"):
        decision = policy.authorize_tool(tool, {})
        assert decision.decision is ToolDecision.DENY, tool
        assert decision.rule_id == "TOOL-001", tool


def test_internal_write_tool_honors_test_write_policy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    denied_policy = PolicyEngine(tmp_path, target, allow_test_writes=False)
    allowed_policy = PolicyEngine(tmp_path, target, allow_test_writes=True)
    denied = denied_policy.authorize_tool(
        "mcp__qa__apply_locator_heal", {"path": "tests/test_x.py"}
    )
    assert denied.decision is ToolDecision.REQUIRE_APPROVAL
    allowed = allowed_policy.authorize_tool(
        "mcp__qa__apply_locator_heal", {"path": "tests/test_x.py"}
    )
    assert allowed.decision is ToolDecision.ALLOW


def test_internal_write_tool_cannot_escape_test_directories(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, writes=True)
    decision = policy.authorize_tool("mcp__qa__create_test_file", {"path": "src/generated_test.py"})
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "WRITE-002"


def test_external_mcp_read_names_are_not_misclassified_by_nouns(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert (
        policy.authorize_tool("mcp__github__get_issue_comments", {}).decision is ToolDecision.ALLOW
    )
    assert (
        policy.authorize_tool("mcp__github__pull_request_read", {}).decision is ToolDecision.ALLOW
    )
    assert (
        policy.authorize_tool("mcp__github__add_comment", {}).decision
        is ToolDecision.REQUIRE_APPROVAL
    )
    assert (
        policy.authorize_tool("mcp__github__resolve_review_thread", {}).decision
        is ToolDecision.REQUIRE_APPROVAL
    )


def test_only_explicit_project_skills_are_allowed(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert (
        policy.authorize_tool("Skill", {"skill": "self-heal-test"}).decision is ToolDecision.ALLOW
    )
    assert (
        policy.authorize_tool("Skill", {"skill": "untrusted-skill"}).decision is ToolDecision.DENY
    )
    assert policy.authorize_tool("Skill", {}).decision is ToolDecision.DENY


def test_external_mcp_camel_case_reads_are_allowed(tmp_path: Path) -> None:
    control = tmp_path / "control"
    target = tmp_path / "target"
    control.mkdir()
    target.mkdir()
    policy = PolicyEngine(control, target)

    for tool_name in (
        "mcp__atlassian__getJiraIssue",
        "mcp__atlassian__searchJiraIssuesUsingJql",
        "mcp__atlassian__getConfluencePage",
        "mcp__atlassian__lookupJiraAccountId",
        "mcp__atlassian__atlassianUserInfo",
    ):
        decision = policy.authorize_tool(tool_name, {})
        assert decision.decision == ToolDecision.ALLOW, tool_name


def test_external_mcp_camel_case_writes_require_approval(tmp_path: Path) -> None:
    control = tmp_path / "control"
    target = tmp_path / "target"
    control.mkdir()
    target.mkdir()
    policy = PolicyEngine(control, target)

    for tool_name in (
        "mcp__atlassian__addCommentToJiraIssue",
        "mcp__atlassian__createJiraIssue",
        "mcp__atlassian__editJiraIssue",
        "mcp__atlassian__transitionJiraIssue",
        "mcp__atlassian__updateConfluencePage",
    ):
        decision = policy.authorize_tool(tool_name, {})
        assert decision.decision == ToolDecision.REQUIRE_APPROVAL, tool_name


def test_unknown_external_mcp_action_remains_fail_closed(tmp_path: Path) -> None:
    control = tmp_path / "control"
    target = tmp_path / "target"
    control.mkdir()
    target.mkdir()
    policy = PolicyEngine(control, target)

    decision = policy.authorize_tool("mcp__atlassian__execute", {})
    assert decision.decision == ToolDecision.REQUIRE_APPROVAL
    assert decision.rule_id == "MCP-TOOL-UNKNOWN"
