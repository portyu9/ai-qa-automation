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
