from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from ...evidence import EvidenceStore
from ...models import AgentRunState, ValidationResult, ValidationStatus
from ...network_authority import (
    AuthorizedNetworkHosts,
    authorize_network_url,
    canonicalize_network_host,
)
from ...policy import PolicyEngine
from ...state import StateStore
from ...tools.test_execution import TestRunner
from ..model_source_observation import CoverageSearchObservation, search_test_coverage_confined
from ..validation_truth import evaluate_revision_closure

MAX_MODEL_SOURCE_CHARS = 12_000
ToolHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class ToolDecorator(Protocol):
    """Static contract for the SDK tool decorator; produced tool objects stay opaque here."""

    def __call__(
        self, name: str, description: str, input_schema: dict[str, Any]
    ) -> Callable[[ToolHandler], object]: ...


def stable_gate_id(prefix: str, payload: Any) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def pytest_scope(args: list[str]) -> str:
    """Classify pytest as full regression or filtered/targeted execution."""
    selectors: list[str] = []
    filtered = False
    skip_next = False
    for raw in args:
        item = str(raw)
        if skip_next:
            skip_next = False
            continue
        if item in {"-k", "-m"}:
            filtered = True
            skip_next = True
            continue
        if item in {"--maxfail", "--tb"}:
            skip_next = True
            continue
        if item.startswith(("-k=", "-m=")):
            filtered = True
            continue
        if item.startswith(("--maxfail=", "--tb=")) or item.startswith("-"):
            continue
        selectors.append(item)
    return "targeted" if filtered or selectors else "regression"


def change_revision_closed(state: AgentRunState) -> bool:
    """Use the shared revision-closure authority before another mutation begins."""
    return evaluate_revision_closure(
        state.validation_results,
        current_revision=state.change_revision,
    ).closed


def require_closed_revision_before_mutation(services: RuntimeServices) -> str | None:
    if change_revision_closed(services.state):
        return None
    return (
        f"change revision {services.state.change_revision} is not closed; "
        "run an exact-path-bound targeted pytest gate and a passing full regression before another mutation"
    )


def pytest_validation_status(exit_code: int) -> ValidationStatus:
    if exit_code == 0:
        return ValidationStatus.PASS
    if exit_code == 1:
        return ValidationStatus.FAIL
    return ValidationStatus.NOT_VERIFIED


def coverage_search(
    workspace: Path,
    *,
    query: str,
    max_results: int = 100,
    max_scan_files: int = 5_000,
    expected_root_identity: tuple[int, int] | None = None,
) -> CoverageSearchObservation:
    return search_test_coverage_confined(
        workspace,
        query=query,
        max_results=max_results,
        max_scan_entries=max_scan_files,
        expected_root_identity=expected_root_identity,
    )


def record_patch_safety_validation(
    services: RuntimeServices,
    *,
    path: str,
    evidence_id: str,
    summary: str,
) -> None:
    services.state.validation_results.append(
        ValidationResult(
            name="test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            revision=services.state.change_revision,
            status=ValidationStatus.PASS,
            summary=summary,
            evidence_ids=[evidence_id],
            details={"path": path, "scope": "static_patch_safety"},
        )
    )


@dataclass
class RuntimeServices:
    workspace: Path
    state: AgentRunState
    evidence: EvidenceStore
    policy: PolicyEngine
    test_runner: TestRunner
    max_tool_calls: int
    max_repeated_action: int
    allowed_network_hosts: set[str] = field(default_factory=set)
    allow_external_network: bool = False
    api_browser_external_egress_enforced: bool = False
    allow_mutating_api_methods: bool = False
    k6_external_egress_enforced: bool = False
    state_store: StateStore | None = None
    workspace_root_identity: tuple[int, int] | None = None
    _fingerprints: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, value in {
            "max_tool_calls": self.max_tool_calls,
            "max_repeated_action": self.max_repeated_action,
        }.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in {
            "allow_external_network": self.allow_external_network,
            "api_browser_external_egress_enforced": self.api_browser_external_egress_enforced,
            "allow_mutating_api_methods": self.allow_mutating_api_methods,
            "k6_external_egress_enforced": self.k6_external_egress_enforced,
        }.items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be a boolean")
        self.allowed_network_hosts = {
            canonicalize_network_host(host) for host in self.allowed_network_hosts
        }
        if self.allow_mutating_api_methods:
            raise ValueError(
                "allow_mutating_api_methods=true cannot authorize generic remote mutation"
            )
        if self.workspace_root_identity is not None and (
            not isinstance(self.workspace_root_identity, tuple)
            or len(self.workspace_root_identity) != 2
            or any(type(part) is not int or part < 0 for part in self.workspace_root_identity)
        ):
            raise ValueError("workspace_root_identity must be a (device, inode) integer tuple")

    def consume(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        if self.state.tool_call_count >= self.max_tool_calls:
            raise RuntimeError("tool-call budget exhausted")
        payload = json.dumps(tool_input, sort_keys=True, default=str)
        fingerprint = hashlib.sha256(f"{tool_name}:{payload}".encode()).hexdigest()
        seen = self._fingerprints.get(fingerprint, 0) + 1
        self._fingerprints[fingerprint] = seen
        if seen > self.max_repeated_action:
            raise RuntimeError("repeated identical action budget exhausted")
        self.state.tool_call_count += 1
        self.checkpoint()

    def checkpoint(self) -> None:
        if self.state_store is not None:
            self.state_store.save(self.state)

    def network_hosts(self, url: str) -> set[str]:
        authorize_network_url(
            url,
            allowed_hosts=self.allowed_network_hosts,
            allow_external_network=self.allow_external_network,
            external_egress_enforced=self.api_browser_external_egress_enforced,
        )
        return AuthorizedNetworkHosts(
            set(self.allowed_network_hosts),
            external_egress_enforced=self.api_browser_external_egress_enforced,
        )

    def generic_network_hosts(self, url: str) -> set[str]:
        """Preserve pre-#95 host semantics for non-API/browser controlled consumers."""

        host = (urlparse(url).hostname or "").lower()
        if not host or host not in self.allowed_network_hosts:
            raise PermissionError(
                f"network host is not explicitly allowlisted: {host or '<missing>'}"
            )
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if not self.allow_external_network and host not in local_hosts:
            raise PermissionError("external network access is disabled")
        if not self.allow_external_network:
            return self.allowed_network_hosts & local_hosts
        return set(self.allowed_network_hosts)
