from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .network_authority import (
    NetworkDestinationClass,
    canonicalize_network_host,
    classify_network_host,
)


class Settings(BaseSettings):
    """Trusted runtime configuration. Environment values are explicit inputs, not SUT config."""

    model_config = SettingsConfigDict(env_prefix="AI_QA_", env_file=None, extra="ignore")

    model: str = "claude-sonnet-5"
    control_root: Path = Field(default_factory=lambda: Path.cwd())
    artifact_root: Path | None = None
    base_ref: str | None = None
    regulated_mode: bool = False
    allow_external_network: bool = False
    api_browser_external_egress_enforced: bool = False
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

    @field_validator("allow_mutating_api_methods")
    @classmethod
    def reject_generic_api_mutation(cls, value: bool) -> bool:
        if value:
            raise ValueError(
                "generic mutating API methods are not supported; use a separately typed operation "
                "with explicit reversible side-effect authority"
            )
        return False

    @field_validator("base_ref")
    @classmethod
    def normalize_base_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("allowed_network_hosts")
    @classmethod
    def normalize_network_hosts(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            host = canonicalize_network_host(value)
            if classify_network_host(host).destination_class is NetworkDestinationClass.DISALLOWED_LITERAL:
                raise ValueError(
                    "allowed_network_hosts must not include private, link-local, multicast, "
                    "reserved, unspecified, or other non-global IP literals"
                )
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
