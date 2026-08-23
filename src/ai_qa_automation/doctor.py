from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path

from .config import Settings
from .models import ValidationStatus
from .tools.mobile import MobileRuntimeInspector


def environment_report(
    control_root: Path,
    settings: Settings | None = None,
) -> dict[str, dict[str, str]]:
    """Inspect local capability/configuration without contacting external providers."""
    cfg = settings or Settings(control_root=control_root)

    def package(name: str) -> dict[str, str]:
        found = importlib.util.find_spec(name) is not None
        return {
            "status": ValidationStatus.PASS if found else ValidationStatus.NOT_VERIFIED,
            "detail": "installed" if found else "not installed",
        }

    def executable(name: str) -> dict[str, str]:
        path = shutil.which(name)
        return {
            "status": ValidationStatus.PASS if path else ValidationStatus.NOT_VERIFIED,
            "detail": path or "not found",
        }

    playwright_package = package("playwright")
    playwright_browser = _playwright_browser_runtime()
    mobile = MobileRuntimeInspector().inspect()
    return {
        "python": {"status": ValidationStatus.PASS, "detail": "runtime available"},
        "pydantic": package("pydantic"),
        "claude_agent_sdk": package("claude_agent_sdk"),
        "playwright_package": playwright_package,
        "playwright_chromium": playwright_browser,
        "pytest": package("pytest"),
        "docker": executable("docker"),
        "k6": executable("k6"),
        "git": executable("git"),
        "control_root": _control_root_status(control_root),
        "mobile_appium_runtime": {
            "status": mobile.status,
            "detail": mobile.summary,
        },
        "live_model_credential": _credential_presence(
            "ANTHROPIC_API_KEY",
            configured_detail="present in environment; value not inspected and validity not tested",
            missing_detail="not set; required only for live Claude execution",
        ),
        "github_mcp": _github_mcp_readiness(cfg),
        "atlassian_mcp": _atlassian_mcp_readiness(cfg),
        "change_baseline": _base_ref_readiness(),
        "runtime_write_posture": _runtime_write_posture(cfg),
    }


def _credential_presence(
    name: str,
    *,
    configured_detail: str,
    missing_detail: str,
) -> dict[str, str]:
    # Deliberately inspect presence only. Never return, hash, log, or partially reveal the secret value.
    if os.getenv(name):
        return {"status": "CONFIGURED_NOT_VERIFIED", "detail": configured_detail}
    return {"status": "NOT_CONFIGURED", "detail": missing_detail}


def _github_mcp_readiness(settings: Settings) -> dict[str, str]:
    if not settings.enable_github_mcp:
        return {
            "status": "DISABLED",
            "detail": "AI_QA_ENABLE_GITHUB_MCP=false; no GitHub MCP connection will be attempted",
        }
    if not os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN"):
        return {
            "status": "NOT_CONFIGURED",
            "detail": "enabled, but GITHUB_PERSONAL_ACCESS_TOKEN is not set",
        }
    if shutil.which("docker") is None:
        return {
            "status": "BLOCKED",
            "detail": "enabled and token present, but Docker is not available",
        }
    return {
        "status": "CONFIGURED_NOT_VERIFIED",
        "detail": "enabled; token presence and Docker observed; authentication/provider response not tested",
    }


def _atlassian_mcp_readiness(settings: Settings) -> dict[str, str]:
    if not settings.enable_atlassian_mcp:
        return {
            "status": "DISABLED",
            "detail": "AI_QA_ENABLE_ATLASSIAN_MCP=false; no Atlassian MCP connection will be attempted",
        }
    return {
        "status": "CONFIGURED_NOT_VERIFIED",
        "detail": "official endpoint enabled; OAuth/token session and provider response are not tested by doctor",
    }


def _base_ref_readiness() -> dict[str, str]:
    base_ref = os.getenv("AI_QA_BASE_REF")
    if not base_ref:
        return {
            "status": "NOT_CONFIGURED",
            "detail": "no explicit change baseline; set AI_QA_BASE_REF when merge-base analysis is required",
        }
    return {
        "status": "CONFIGURED_NOT_VERIFIED",
        "detail": "AI_QA_BASE_REF is set; ref validity/merge-base resolution occurs during deterministic bootstrap",
    }


def _runtime_write_posture(settings: Settings) -> dict[str, str]:
    if settings.allow_test_writes or settings.allow_mutating_api_methods:
        enabled: list[str] = []
        if settings.allow_test_writes:
            enabled.append("test writes")
        if settings.allow_mutating_api_methods:
            enabled.append("mutating API methods")
        return {
            "status": "ELEVATED_EXPLICIT",
            "detail": ", ".join(enabled)
            + " explicitly enabled; deterministic policy still applies",
        }
    return {
        "status": "SAFE_DEFAULT",
        "detail": "autonomous test writes and mutating API methods are disabled",
    }


def _playwright_browser_runtime() -> dict[str, str]:
    if importlib.util.find_spec("playwright") is None:
        return {
            "status": ValidationStatus.NOT_VERIFIED,
            "detail": "playwright package not installed",
        }
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            executable = Path(playwright.chromium.executable_path)
    except Exception as exc:
        return {
            "status": ValidationStatus.NOT_VERIFIED,
            "detail": f"runtime inspection failed: {type(exc).__name__}",
        }
    return {
        "status": ValidationStatus.PASS if executable.is_file() else ValidationStatus.NOT_VERIFIED,
        "detail": str(executable) if executable.is_file() else "Chromium executable not installed",
    }


def _control_root_status(control_root: Path) -> dict[str, str]:
    root = control_root.expanduser().resolve()
    required = [root / "CLAUDE.md", root / ".claude" / "settings.json"]
    missing = [path.relative_to(root).as_posix() for path in required if not path.is_file()]
    if missing:
        return {
            "status": ValidationStatus.FAIL,
            "detail": f"{root}; missing trusted control markers: {', '.join(missing)}",
        }
    return {"status": ValidationStatus.PASS, "detail": str(root)}
