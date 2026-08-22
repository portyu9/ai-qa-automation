from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.config import Settings
from ai_qa_automation.integrations.atlassian_mcp import (
    ATLASSIAN_ROVO_MCP_URL,
    atlassian_mcp_config,
)
from ai_qa_automation.integrations.github_mcp import github_mcp_config
from ai_qa_automation.integrations.mcp_registry import build_external_mcp
from ai_qa_automation.models import MCPStatus
from ai_qa_automation.policy import PolicyEngine


def make_policy(tmp_path: Path) -> PolicyEngine:
    control = tmp_path / "control"
    target = tmp_path / "target"
    control.mkdir()
    target.mkdir()
    return PolicyEngine(control, target)


def test_disabled_external_integrations_are_explicitly_not_configured(tmp_path: Path) -> None:
    settings = Settings(
        control_root=tmp_path,
        enable_github_mcp=False,
        enable_atlassian_mcp=False,
    )
    servers, statuses = build_external_mcp(settings, make_policy(tmp_path))

    assert servers == {}
    assert statuses == {
        "github": MCPStatus.NOT_CONFIGURED,
        "atlassian": MCPStatus.NOT_CONFIGURED,
    }


def test_github_enabled_without_token_is_not_configured_and_never_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    settings = Settings(control_root=tmp_path, enable_github_mcp=True)

    servers, statuses = build_external_mcp(settings, make_policy(tmp_path))

    assert "github" not in servers
    assert statuses["github"] is MCPStatus.NOT_CONFIGURED
    assert MCPStatus.AVAILABLE not in statuses.values()


def test_github_configuration_is_read_only_and_does_not_claim_availability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "unit-test-github-token-not-a-credential"
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", token)
    settings = Settings(control_root=tmp_path, enable_github_mcp=True)

    servers, statuses = build_external_mcp(settings, make_policy(tmp_path))

    github = servers["github"]
    assert github["type"] == "stdio"
    assert github["command"] == "docker"
    assert "GITHUB_READ_ONLY=1" in github["args"]
    assert "ghcr.io/github/github-mcp-server:v1.0.5" in github["args"]
    assert token not in github["args"]
    assert github["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"] == token
    assert statuses.get("github") is not MCPStatus.AVAILABLE


def test_github_config_function_never_marks_config_presence_as_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", "unit-test-token")
    status, config = github_mcp_config()

    assert status is None
    assert config is not None
    assert status is not MCPStatus.AVAILABLE


def test_atlassian_configuration_uses_only_official_endpoint_and_not_availability() -> None:
    status, config = atlassian_mcp_config(enabled=True)

    assert status is None
    assert config == {"type": "http", "url": ATLASSIAN_ROVO_MCP_URL}
    assert ATLASSIAN_ROVO_MCP_URL == "https://mcp.atlassian.com/v1/mcp/authv2"
    assert status is not MCPStatus.AVAILABLE


def test_atlassian_disabled_is_not_configured() -> None:
    status, config = atlassian_mcp_config(enabled=False)
    assert status is MCPStatus.NOT_CONFIGURED
    assert config is None


def test_enabling_atlassian_adds_server_without_fabricating_available_status(
    tmp_path: Path,
) -> None:
    settings = Settings(control_root=tmp_path, enable_atlassian_mcp=True)
    servers, statuses = build_external_mcp(settings, make_policy(tmp_path))

    assert servers["atlassian"] == {"type": "http", "url": ATLASSIAN_ROVO_MCP_URL}
    assert statuses.get("atlassian") is not MCPStatus.AVAILABLE


def test_provider_configuration_contains_no_unapproved_community_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", "unit-test-token")
    settings = Settings(
        control_root=tmp_path,
        enable_github_mcp=True,
        enable_atlassian_mcp=True,
    )
    servers, _ = build_external_mcp(settings, make_policy(tmp_path))
    rendered = repr(servers).lower()

    assert "github/github-mcp-server" in rendered
    assert "mcp.atlassian.com" in rendered
    assert "community" not in rendered
    assert "testrail" not in rendered
