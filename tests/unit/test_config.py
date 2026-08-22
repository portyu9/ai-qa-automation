from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_qa_automation.config import Settings, canonicalize_network_host


def test_runtime_budget_settings_are_independently_configurable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("AI_QA_MAX_TOOL_CALLS", "31")
    monkeypatch.setenv("AI_QA_MAX_NETWORK_CALLS", "7")
    monkeypatch.setenv("AI_QA_MAX_MUTATIONS", "2")
    monkeypatch.setenv("AI_QA_MAX_REPEATED_ACTION", "4")
    monkeypatch.setenv("AI_QA_MAX_SDK_RETRIES", "1")
    monkeypatch.setenv("AI_QA_SDK_RETRY_BACKOFF_SECONDS", "0.5")
    monkeypatch.setenv("AI_QA_SDK_RETRY_MAX_BACKOFF_SECONDS", "2.0")

    settings = Settings(control_root=tmp_path)

    assert settings.max_tool_calls == 31
    assert settings.max_network_calls == 7
    assert settings.max_mutations == 2
    assert settings.max_repeated_action == 4
    assert settings.max_sdk_retries == 1
    assert settings.sdk_retry_backoff_seconds == 0.5
    assert settings.sdk_retry_max_backoff_seconds == 2.0


def test_safe_capability_defaults_are_fail_closed(tmp_path: Path) -> None:
    settings = Settings(control_root=tmp_path)

    assert settings.allow_external_network is False
    assert settings.allow_test_writes is False
    assert settings.allow_mutating_api_methods is False
    assert settings.k6_external_egress_enforced is False
    assert settings.enable_github_mcp is False
    assert settings.enable_atlassian_mcp is False
    assert settings.allowed_network_hosts == ["127.0.0.1", "localhost"]
    assert settings.max_sdk_retries == 2
    assert settings.sdk_retry_backoff_seconds == 1.0
    assert settings.sdk_retry_max_backoff_seconds == 4.0


def test_network_hosts_are_canonicalized_and_deduplicated(tmp_path: Path) -> None:
    settings = Settings(
        control_root=tmp_path,
        allowed_network_hosts=[" QA.Example.Test. ", "qa.example.test", "[::1]", "127.0.0.1"],
    )
    assert settings.allowed_network_hosts == ["qa.example.test", "::1", "127.0.0.1"]


@pytest.mark.parametrize(
    "host",
    [
        "",
        "*",
        "*.example.test",
        "https://example.test",
        "example.test:443",
        "user@example.test",
        "example.test/path",
        "example.test?x=1",
        "example.test#fragment",
        "bad_label.example.test",
        "-bad.example.test",
        "fe80::1%eth0",
        "[fe80::1%eth0]",
        "[127.0.0.1]",
        "[example.test]",
        "999.999.999.999",
    ],
)
def test_network_allowlist_rejects_ambiguous_or_non_host_entries(
    tmp_path: Path, host: str
) -> None:
    with pytest.raises(ValidationError):
        Settings(control_root=tmp_path, allowed_network_hosts=[host])


def test_network_host_canonicalizer_supports_idna() -> None:
    assert canonicalize_network_host("BÜCHER.example") == "xn--bcher-kva.example"


def test_artifact_root_defaults_to_trusted_control_root(tmp_path: Path) -> None:
    settings = Settings(control_root=tmp_path)

    assert settings.control_root == tmp_path.resolve()
    assert settings.artifact_root == (tmp_path / "artifacts").resolve()


def test_explicit_roots_are_expanded_and_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    settings = Settings(
        control_root=Path("~/control"),
        artifact_root=Path("~/evidence"),
    )

    assert settings.control_root == (home / "control").resolve()
    assert settings.artifact_root == (home / "evidence").resolve()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_turns", 0),
        ("max_turns", 41),
        ("max_tool_calls", 0),
        ("max_tool_calls", 101),
        ("max_network_calls", 0),
        ("max_network_calls", 101),
        ("max_mutations", 0),
        ("max_mutations", 21),
        ("max_repeated_action", 0),
        ("max_repeated_action", 11),
        ("max_sdk_retries", -1),
        ("max_sdk_retries", 6),
        ("tool_timeout_seconds", 0),
        ("tool_timeout_seconds", 901),
        ("global_timeout_seconds", 9),
        ("global_timeout_seconds", 3601),
        ("max_cost_usd", 0),
        ("max_cost_usd", 101),
    ],
)
def test_runtime_safety_bounds_reject_out_of_range_values(
    tmp_path: Path, field: str, value: int
) -> None:
    with pytest.raises(ValidationError):
        Settings(control_root=tmp_path, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sdk_retry_backoff_seconds", 0.0),
        ("sdk_retry_backoff_seconds", 31.0),
        ("sdk_retry_max_backoff_seconds", 0.0),
        ("sdk_retry_max_backoff_seconds", 61.0),
    ],
)
def test_sdk_retry_timing_bounds_reject_out_of_range_values(
    tmp_path: Path, field: str, value: float
) -> None:
    with pytest.raises(ValidationError):
        Settings(control_root=tmp_path, **{field: value})


def test_sdk_retry_max_backoff_cannot_be_lower_than_base(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(
            control_root=tmp_path,
            sdk_retry_backoff_seconds=2.0,
            sdk_retry_max_backoff_seconds=1.0,
        )


def test_dotenv_file_is_not_implicitly_loaded_as_trusted_runtime_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text(
        "AI_QA_ALLOW_TEST_WRITES=true\nAI_QA_MAX_TURNS=40\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AI_QA_ALLOW_TEST_WRITES", raising=False)
    monkeypatch.delenv("AI_QA_MAX_TURNS", raising=False)

    settings = Settings(control_root=tmp_path)

    assert settings.allow_test_writes is False
    assert settings.max_turns == 12


def test_explicit_environment_values_are_loaded_with_ai_qa_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_QA_ALLOW_TEST_WRITES", "true")
    monkeypatch.setenv("AI_QA_ALLOWED_NETWORK_HOSTS", '["localhost","qa.example.test"]')
    monkeypatch.setenv("UNRELATED_MAX_TURNS", "2")

    settings = Settings(control_root=tmp_path)

    assert settings.allow_test_writes is True
    assert settings.allowed_network_hosts == ["localhost", "qa.example.test"]
    assert settings.max_turns == 12


def test_constructor_value_has_explicit_precedence_over_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_QA_MAX_TURNS", "7")
    settings = Settings(control_root=tmp_path, max_turns=5)
    assert settings.max_turns == 5


def test_unknown_environment_variables_do_not_expand_settings_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_QA_UNDOCUMENTED_ADMIN_MODE", "true")
    settings = Settings(control_root=tmp_path)
    assert not hasattr(settings, "undocumented_admin_mode")
