from __future__ import annotations

from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    k6_external_egress_enforced: bool = False
    enable_github_mcp: bool = False
    enable_atlassian_mcp: bool = False
    max_turns: int = Field(default=12, ge=1, le=40)
    max_tool_calls: int = Field(default=30, ge=1, le=100)
    max_repeated_action: int = Field(default=3, ge=1, le=10)
    tool_timeout_seconds: int = Field(default=120, ge=1, le=900)
    global_timeout_seconds: int = Field(default=600, ge=10, le=3600)
    max_cost_usd: float = Field(default=5.0, gt=0, le=100)

    @model_validator(mode="after")
    def resolve_roots(self) -> "Settings":
        self.control_root = self.control_root.expanduser().resolve()
        if self.artifact_root is None:
            self.artifact_root = self.control_root / "artifacts"
        else:
            self.artifact_root = self.artifact_root.expanduser().resolve()
        return self
