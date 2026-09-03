from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.network_authority import (
    AuthorizedNetworkHosts,
    NetworkAuthorityCode,
    NetworkAuthorityError,
    NetworkDestinationClass,
    authorize_network_url,
    canonicalize_network_host,
    classify_network_host,
)
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.internal_tools import RuntimeServices
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.api_testing import ApiProbe
from ai_qa_automation.tools.browser_evidence import BrowserProbe


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("localhost", NetworkDestinationClass.LOOPBACK),
        ("127.0.0.1", NetworkDestinationClass.LOOPBACK),
        ("::1", NetworkDestinationClass.LOOPBACK),
        ("example.test", NetworkDestinationClass.EXTERNAL),
        ("8.8.8.8", NetworkDestinationClass.EXTERNAL),
        ("2001:4860:4860::8888", NetworkDestinationClass.EXTERNAL),
        ("10.0.0.1", NetworkDestinationClass.DISALLOWED_LITERAL),
        ("169.254.169.254", NetworkDestinationClass.DISALLOWED_LITERAL),
        ("224.0.0.1", NetworkDestinationClass.DISALLOWED_LITERAL),
        ("0.0.0.0", NetworkDestinationClass.DISALLOWED_LITERAL),
        ("fc00::1", NetworkDestinationClass.DISALLOWED_LITERAL),
        ("fe80::1", NetworkDestinationClass.DISALLOWED_LITERAL),
        ("ff02::1", NetworkDestinationClass.DISALLOWED_LITERAL),
        ("::", NetworkDestinationClass.DISALLOWED_LITERAL),
    ],
)
def test_network_host_classification_is_deterministic_without_dns(
    host: str,
    expected: NetworkDestinationClass,
) -> None:
    assert classify_network_host(host).destination_class is expected


@pytest.mark.parametrize(
    "host",
    [
        "127.1",
        "2130706433",
        "0177.0.0.1",
        "0x7f000001",
        "0x7f.0.0.1",
        "127.0x0.0.1",
    ],
)
def test_legacy_numeric_ipv4_spellings_are_rejected_before_resolver_use(host: str) -> None:
    with pytest.raises(ValueError, match="non-canonical numeric"):
        canonicalize_network_host(host)


def test_external_dns_requires_deployment_egress_authority() -> None:
    with pytest.raises(NetworkAuthorityError) as caught:
        authorize_network_url(
            "https://example.test/data",
            allowed_hosts={"example.test"},
            allow_external_network=True,
            external_egress_enforced=False,
        )
    assert caught.value.code is NetworkAuthorityCode.EXTERNAL_EGRESS_UNVERIFIED


def test_loopback_does_not_require_external_egress_authority() -> None:
    destination = authorize_network_url(
        "http://127.0.0.1:8080/health",
        allowed_hosts={"127.0.0.1"},
        allow_external_network=False,
        external_egress_enforced=False,
    )
    assert destination.destination_class is NetworkDestinationClass.LOOPBACK


def _services(tmp_path: Path, *, egress: bool) -> RuntimeServices:
    state = AgentRunState(objective="observe external API", workspace=str(tmp_path))
    return RuntimeServices(
        workspace=tmp_path,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=5,
        max_repeated_action=2,
        allowed_network_hosts={"example.test"},
        allow_external_network=True,
        api_browser_external_egress_enforced=egress,
    )


def test_runtime_returns_authority_bearing_host_set_only_after_egress_prerequisite(
    tmp_path: Path,
) -> None:
    with pytest.raises(NetworkAuthorityError) as caught:
        _services(tmp_path, egress=False).network_hosts("https://example.test/data")
    assert caught.value.code is NetworkAuthorityCode.EXTERNAL_EGRESS_UNVERIFIED

    hosts = _services(tmp_path, egress=True).network_hosts("https://example.test/data")
    assert isinstance(hosts, AuthorizedNetworkHosts)
    assert hosts == {"example.test"}
    assert hosts.external_egress_enforced is True


def test_private_literal_remains_configurable_but_api_browser_use_is_denied(
    tmp_path: Path,
) -> None:
    services = RuntimeServices(
        workspace=tmp_path,
        state=AgentRunState(objective="observe metadata", workspace=str(tmp_path)),
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=5,
        max_repeated_action=2,
        allowed_network_hosts={"169.254.169.254"},
        allow_external_network=True,
        api_browser_external_egress_enforced=True,
    )
    assert services.generic_network_hosts("http://169.254.169.254/") == {"169.254.169.254"}
    with pytest.raises(NetworkAuthorityError) as caught:
        services.network_hosts("http://169.254.169.254/")
    assert caught.value.code is NetworkAuthorityCode.DISALLOWED_LITERAL


@pytest.mark.asyncio
async def test_api_probe_plain_external_host_set_is_denied_before_transport(tmp_path: Path) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "api-denied"),
        allow_hosts={"example.test"},
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(NetworkAuthorityError) as caught:
        await probe.request("GET", "https://example.test/data")
    assert caught.value.code is NetworkAuthorityCode.EXTERNAL_EGRESS_UNVERIFIED
    assert calls == 0


@pytest.mark.asyncio
async def test_api_probe_external_target_executes_only_with_explicit_egress_authority(
    tmp_path: Path,
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "api-authorized"),
        allow_hosts={"example.test"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )
    result = await probe.request("GET", "https://example.test/data")
    assert result.status_code == 200
    assert calls == 1


@pytest.mark.asyncio
async def test_api_probe_disallowed_literal_stays_blocked_with_egress_assertion(
    tmp_path: Path,
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "api-private"),
        allow_hosts={"169.254.169.254"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(NetworkAuthorityError) as caught:
        await probe.request("GET", "http://169.254.169.254/latest/meta-data")
    assert caught.value.code is NetworkAuthorityCode.DISALLOWED_LITERAL
    assert calls == 0


def test_browser_applies_destination_authority_to_navigation_subresources_and_websockets(
    tmp_path: Path,
) -> None:
    plain = BrowserProbe(EvidenceStore(tmp_path, "browser-plain"), allow_hosts={"example.test"})
    assert plain._url_allowed("https://example.test/") is False
    assert plain._url_allowed("wss://example.test/socket") is False

    authorized = BrowserProbe(
        EvidenceStore(tmp_path, "browser-authorized"),
        allow_hosts={"example.test"},
        external_egress_enforced=True,
    )
    assert authorized._url_allowed("https://example.test/") is True
    assert authorized._url_allowed("wss://example.test/socket") is True
    assert authorized._url_allowed("https://other.test/") is False

    private = BrowserProbe(
        EvidenceStore(tmp_path, "browser-private"),
        allow_hosts={"169.254.169.254"},
        external_egress_enforced=True,
    )
    assert private._url_allowed("http://169.254.169.254/") is False


def test_browser_inherits_runtime_egress_authority_without_widening_host_set(
    tmp_path: Path,
) -> None:
    hosts = _services(tmp_path, egress=True).network_hosts("https://example.test/")
    probe = BrowserProbe(EvidenceStore(tmp_path, "browser-carrier"), allow_hosts=hosts)
    assert probe._url_allowed("https://example.test/") is True
    assert probe._url_allowed("https://other.test/") is False


def _live_services(tmp_path: Path) -> tuple[LiveRuntimeServices, StateStore, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state = AgentRunState(objective="observe external browser", workspace=str(workspace))
    store = StateStore(run_dir / "state.json")
    store.save(state)
    journal_path = run_dir / "journal.jsonl"
    journal = RunJournal(journal_path, regulated_mode=False, max_events=100)
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=5,
            max_network_calls=5,
            max_mutations=1,
            max_wall_seconds=30.0,
        ),
        journal=journal,
        metadata_path=run_dir / "runtime.json",
        lease_id="test-network-authority",
    )
    services = LiveRuntimeServices(
        workspace=workspace,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=5,
        max_repeated_action=2,
        allowed_network_hosts={"example.test"},
        allow_external_network=True,
        api_browser_external_egress_enforced=False,
        state_store=store,
        workspace_root_identity=control.workspace_identity,
        control=control,
    )
    return services, store, journal_path


def test_live_missing_egress_authority_latches_blocked_and_persists_reason(
    tmp_path: Path,
) -> None:
    services, store, journal_path = _live_services(tmp_path)

    with pytest.raises(NetworkAuthorityError) as caught:
        services.network_hosts("https://example.test/data")

    assert caught.value.code is NetworkAuthorityCode.EXTERNAL_EGRESS_UNVERIFIED
    assert services.state.terminal_status is TerminalStatus.BLOCKED
    assert "post-resolution outbound destinations" in (services.state.terminal_reason or "")
    persisted = store.load()
    assert persisted.terminal_status is TerminalStatus.BLOCKED
    assert persisted.terminal_reason == services.state.terminal_reason
    journal_text = journal_path.read_text(encoding="utf-8")
    assert "external_network_authority_blocked" in journal_text
    assert NetworkAuthorityCode.EXTERNAL_EGRESS_UNVERIFIED.value in journal_text
