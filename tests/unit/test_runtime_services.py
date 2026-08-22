from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.internal_tools import RuntimeServices
from ai_qa_automation.state import StateStore


def make_services(
    tmp_path: Path,
    *,
    max_tool_calls: int = 3,
    max_repeated_action: int = 2,
    hosts: set[str] | None = None,
    external: bool = False,
    with_state_store: bool = False,
) -> RuntimeServices:
    state = AgentRunState(objective="test runtime boundaries", workspace=str(tmp_path))
    return RuntimeServices(
        workspace=tmp_path,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=max_tool_calls,
        max_repeated_action=max_repeated_action,
        allowed_network_hosts=hosts or {"localhost", "127.0.0.1"},
        allow_external_network=external,
        state_store=StateStore(tmp_path / "state.json") if with_state_store else None,
    )


def test_tool_call_budget_fails_before_incrementing_past_limit(tmp_path: Path) -> None:
    services = make_services(tmp_path, max_tool_calls=2, max_repeated_action=5)

    services.consume("inspect_repository", {"n": 1})
    services.consume("inspect_repository", {"n": 2})
    with pytest.raises(RuntimeError, match="tool-call budget exhausted"):
        services.consume("inspect_repository", {"n": 3})

    assert services.state.tool_call_count == 2


def test_identical_action_repetition_budget_is_content_sensitive(tmp_path: Path) -> None:
    services = make_services(tmp_path, max_tool_calls=10, max_repeated_action=2)

    services.consume("probe_api", {"url": "http://localhost/a"})
    services.consume("probe_api", {"url": "http://localhost/a"})
    services.consume("probe_api", {"url": "http://localhost/b"})

    with pytest.raises(RuntimeError, match="repeated identical action"):
        services.consume("probe_api", {"url": "http://localhost/a"})

    # Rejected repetition is not counted as an executed tool call.
    assert services.state.tool_call_count == 3


def test_repetition_fingerprint_is_stable_across_input_key_order(tmp_path: Path) -> None:
    services = make_services(tmp_path, max_tool_calls=10, max_repeated_action=1)
    services.consume("tool", {"a": 1, "b": 2})

    with pytest.raises(RuntimeError, match="repeated identical action"):
        services.consume("tool", {"b": 2, "a": 1})


def test_local_network_is_allowed_only_when_host_is_explicitly_allowlisted(tmp_path: Path) -> None:
    services = make_services(tmp_path, hosts={"localhost", "127.0.0.1"}, external=False)

    assert services.network_hosts("http://LOCALHOST:8000/path") == {
        "localhost",
        "127.0.0.1",
    }

    with pytest.raises(PermissionError, match="not explicitly allowlisted"):
        services.network_hosts("http://127.0.0.2:8000")


def test_external_host_stays_blocked_even_if_allowlisted_when_external_network_disabled(
    tmp_path: Path,
) -> None:
    services = make_services(
        tmp_path,
        hosts={"localhost", "qa.example.test"},
        external=False,
    )

    with pytest.raises(PermissionError, match="external network access is disabled"):
        services.network_hosts("https://qa.example.test/path")


def test_external_host_requires_both_allowlist_and_explicit_external_enablement(
    tmp_path: Path,
) -> None:
    services = make_services(
        tmp_path,
        hosts={"qa.example.test", "api.example.test"},
        external=True,
    )

    assert services.network_hosts("https://QA.EXAMPLE.TEST/path") == {
        "qa.example.test",
        "api.example.test",
    }
    with pytest.raises(PermissionError, match="not explicitly allowlisted"):
        services.network_hosts("https://unapproved.example.test")


def test_malformed_or_hostless_url_is_denied(tmp_path: Path) -> None:
    services = make_services(tmp_path)
    for value in ("", "not-a-url", "file:///tmp/data"):
        with pytest.raises(PermissionError, match="<missing>"):
            services.network_hosts(value)


def test_consume_checkpoint_persists_tool_count_without_conversation_state(tmp_path: Path) -> None:
    services = make_services(tmp_path, with_state_store=True)
    services.consume("inspect_repository", {"scope": "bounded"})

    loaded = StateStore(tmp_path / "state.json").load()
    assert loaded.run_id == services.state.run_id
    assert loaded.tool_call_count == 1
