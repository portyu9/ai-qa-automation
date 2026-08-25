from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def canonicalize_network_host(value: str) -> str:
    """Validate and canonicalize one trusted host-only allowlist entry.

    The configuration surface accepts hostnames/IP literals, not URLs, ports,
    wildcard patterns, paths, user-info, query strings, fragments, or scoped
    interface identifiers. Keeping this boundary host-only prevents ambiguous
    policy interpretation later in API, browser, and performance adapters.
    """

    raw = str(value).strip()
    if not raw:
        raise ValueError("network allowlist entries must not be empty")
    if raw == "*" or raw.startswith("*."):
        raise ValueError("wildcard network allowlist entries are not supported")
    if "://" in raw or any(token in raw for token in ("/", "?", "#", "@", "%")):
        raise ValueError("network allowlist entries must be unscoped hostnames or IP literals")

    bracketed = raw.startswith("[") or raw.endswith("]")
    if bracketed and not (raw.startswith("[") and raw.endswith("]")):
        raise ValueError("network allowlist entry has mismatched IP-literal brackets")
    candidate = raw[1:-1] if bracketed else raw
    candidate = candidate.rstrip(".").casefold()
    if not candidate:
        raise ValueError("network allowlist entry is invalid")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        if bracketed and address.version != 6:
            raise ValueError("brackets are supported only for IPv6 allowlist literals")
        return address.compressed.casefold()
    if bracketed:
        raise ValueError("bracketed network allowlist entry must be a valid IPv6 literal")

    if ":" in candidate:
        raise ValueError("network allowlist entries must not include ports")
    dotted_parts = candidate.split(".")
    if len(dotted_parts) == 4 and all(part.isdigit() for part in dotted_parts):
        raise ValueError("invalid dotted IPv4 literal is not accepted as a DNS hostname")
    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("network allowlist hostname is not valid IDNA") from exc
    if len(ascii_host) > 253:
        raise ValueError("network allowlist hostname exceeds 253 characters")
    labels = ascii_host.split(".")
    if any(not label or not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("network allowlist hostname contains an invalid DNS label")
    return ascii_host


class Settings(BaseSettings):
    """Trusted runtime configuration. Environment values are explicit inputs, not SUT config."""

    model_config = SettingsConfigDict(env_prefix="AI_QA_", env_file=None, extra="ignore")

    model: str = "claude-sonnet-5"
    control_root: Path = Field(default_factory=lambda: Path.cwd())
    artifact_root: Path | None = None
    regulated_mode: bool = False
    allow_external_network: bool = False
    allowed_network_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allow_test_writes: bool = False
    allow_mutating_api_methods: bool = False
    pytest_process_isolation_enforced: bool = False
    pytest_external_egress_enforced: bool = False
    k6_external_egress_enforced: bool = False
    enable_github_mcp: bool = False
    enable_atlassian_mcp: bool = False
    max_turns: int = Field(default=12, ge=1, le=40)
    max_tool_calls: int = Field(default=30, ge=1, le=100)
    max_network_calls: int = Field(default=12, ge=1, le=100)
    max_mutations: int = Field(default=3, ge=1, le=20)
    max_repeated_action: int = Field(default=3, ge=1, le=10)
    max_sdk_retries: int = Field(default=2, ge=0, le=5)
    sdk_retry_backoff_seconds: float = Field(default=1.0, ge=0.1, le=30.0)
    sdk_retry_max_backoff_seconds: float = Field(default=4.0, ge=0.1, le=60.0)
    tool_timeout_seconds: int = Field(default=120, ge=1, le=900)
    global_timeout_seconds: int = Field(default=600, ge=10, le=3600)
    max_cost_usd: float = Field(default=5.0, gt=0, le=100)

    @field_validator("allowed_network_hosts")
    @classmethod
    def normalize_network_hosts(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            host = canonicalize_network_host(value)
            if host not in seen:
                normalized.append(host)
                seen.add(host)
        if not normalized:
            raise ValueError("allowed_network_hosts must contain at least one explicit host")
        return normalized

    @model_validator(mode="after")
    def resolve_roots(self) -> Settings:
        self.control_root = self.control_root.expanduser().resolve()
        if self.artifact_root is None:
            self.artifact_root = self.control_root / "artifacts"
        else:
            self.artifact_root = self.artifact_root.expanduser().resolve()
        if self.sdk_retry_max_backoff_seconds < self.sdk_retry_backoff_seconds:
            raise ValueError(
                "sdk_retry_max_backoff_seconds must be greater than or equal to sdk_retry_backoff_seconds"
            )
        return self
