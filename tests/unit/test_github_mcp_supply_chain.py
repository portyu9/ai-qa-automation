from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.verify_supply_chain as supply_chain

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_IMAGE = (
    "ghcr.io/github/github-mcp-server:v1.0.4@"
    "sha256:e3816a476a977cfb836e7d221510011436c654d11861db66ecfd826601aba6a4"
)


def _write_mcp_fixture(
    root: Path,
    *,
    config_image: str = EXPECTED_IMAGE,
    runtime_image: str = EXPECTED_IMAGE,
) -> None:
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "args": ["run", "--rm", config_image],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    runtime_path = root / "src" / "ai_qa_automation" / "integrations" / "github_mcp.py"
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_text(f"GITHUB_MCP_IMAGE = {runtime_image!r}\n", encoding="utf-8")


def test_repository_uses_reviewed_immutable_github_mcp_image() -> None:
    assert supply_chain._verify_github_mcp(ROOT) == EXPECTED_IMAGE


@pytest.mark.parametrize(
    "image",
    [
        "ghcr.io/github/github-mcp-server:v1.0.4",
        "ghcr.io/github/github-mcp-server:latest",
        "ghcr.io/github/github-mcp-server:v1.0.4@sha256:deadbeef",
        "docker.io/github/github-mcp-server:v1.0.4@sha256:" + "0" * 64,
    ],
)
def test_github_mcp_image_validator_rejects_mutable_or_malformed_references(image: str) -> None:
    with pytest.raises(ValueError):
        supply_chain._validate_github_mcp_image_reference(image)


def test_github_mcp_image_validator_rejects_unreviewed_digest() -> None:
    unreviewed = "ghcr.io/github/github-mcp-server:v1.0.4@sha256:" + "0" * 64

    with pytest.raises(ValueError, match="unexpected immutable GitHub MCP image"):
        supply_chain._validate_github_mcp_image_reference(unreviewed)


def test_github_mcp_verifier_rejects_tag_only_config(tmp_path: Path) -> None:
    _write_mcp_fixture(
        tmp_path,
        config_image="ghcr.io/github/github-mcp-server:v1.0.4",
    )

    with pytest.raises(ValueError, match="immutable"):
        supply_chain._verify_github_mcp(tmp_path)


def test_github_mcp_verifier_rejects_runtime_config_drift(tmp_path: Path) -> None:
    _write_mcp_fixture(
        tmp_path,
        runtime_image="ghcr.io/github/github-mcp-server:v1.0.4@sha256:" + "0" * 64,
    )

    with pytest.raises(ValueError, match="unexpected immutable GitHub MCP image"):
        supply_chain._verify_github_mcp(tmp_path)


def test_github_mcp_verifier_rejects_duplicate_image_authority(tmp_path: Path) -> None:
    _write_mcp_fixture(tmp_path)
    config_path = tmp_path / ".mcp.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["mcpServers"]["github"]["args"].insert(-1, EXPECTED_IMAGE)
    config_path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one"):
        supply_chain._verify_github_mcp(tmp_path)
