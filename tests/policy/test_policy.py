from pathlib import Path

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


def test_secret_file_read_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_path(Path(".env"), write=False)
    assert decision.decision is ToolDecision.DENY


def test_governance_file_write_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path, writes=True).authorize_path(Path("CLAUDE.md"), write=True)
    assert decision.decision is ToolDecision.DENY


def test_test_write_requires_approval_by_default(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_path(Path("tests/test_checkout.py"), write=True)
    assert decision.decision is ToolDecision.REQUIRE_APPROVAL


def test_test_write_can_be_enabled_but_app_write_stays_denied(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, writes=True)
    assert policy.authorize_path(Path("tests/test_checkout.py"), write=True).decision is ToolDecision.ALLOW
    assert policy.authorize_path(Path("src/app.py"), write=True).decision is ToolDecision.DENY


def test_unofficial_mcp_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).validate_mcp_server("github", "someone/random-github-mcp")
    assert decision.decision is ToolDecision.DENY


def test_external_mcp_read_write_and_destructive_are_separated(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert policy.authorize_tool("mcp__github__get_issue", {}).decision is ToolDecision.ALLOW
    assert policy.authorize_tool("mcp__github__create_issue", {}).decision is ToolDecision.REQUIRE_APPROVAL
    assert policy.authorize_tool("mcp__github__merge_pull_request", {}).decision is ToolDecision.DENY


def test_production_load_is_denied(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_performance_target("https://prod.example.com", environment="production")
    assert decision.decision is ToolDecision.DENY


def test_unsafe_test_patch_patterns_are_detected(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    diff = "+pytest.skip('green')\n+time.sleep(8)\n-assert total == 5\n+page.set_default_timeout(timeout=30000)\n"
    violations = policy.validate_patch(diff)
    assert {"test_skip", "arbitrary_sleep", "assertion_removal", "timeout_inflation"} <= set(violations)


def test_mutating_api_methods_require_explicit_enablement(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert policy.authorize_api_method("GET").decision is ToolDecision.ALLOW
    assert policy.authorize_api_method("POST").decision is ToolDecision.REQUIRE_APPROVAL
    assert policy.authorize_api_method("POST", allow_mutating=True).decision is ToolDecision.ALLOW
    assert policy.authorize_api_method("TRACE").decision is ToolDecision.DENY


def test_unknown_performance_environment_is_fail_closed(tmp_path: Path) -> None:
    decision = make_policy(tmp_path).authorize_performance_target(
        "https://perf.example.test", environment="mystery"
    )
    assert decision.decision is ToolDecision.REQUIRE_APPROVAL


def test_unknown_tool_and_unapproved_mcp_namespace_are_fail_closed(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert policy.authorize_tool("mcp__evil__read_secrets", {}).decision is ToolDecision.DENY
    assert policy.authorize_tool("unexpected_tool", {}).decision is ToolDecision.DENY


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


def test_external_mcp_read_names_are_not_misclassified_by_nouns(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    assert (
        policy.authorize_tool("mcp__github__get_issue_comments", {}).decision
        is ToolDecision.ALLOW
    )
    assert (
        policy.authorize_tool("mcp__github__pull_request_read", {}).decision
        is ToolDecision.ALLOW
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
    assert policy.authorize_tool(
        "Skill", {"skill": "self-heal-test"}
    ).decision is ToolDecision.ALLOW
    assert policy.authorize_tool(
        "Skill", {"skill": "untrusted-skill"}
    ).decision is ToolDecision.DENY
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
