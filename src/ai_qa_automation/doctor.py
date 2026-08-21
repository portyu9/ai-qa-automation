from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

from .models import ValidationStatus
from .tools.mobile import MobileRuntimeInspector


def environment_report(control_root: Path) -> dict[str, dict[str, str]]:
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
    }


def _playwright_browser_runtime() -> dict[str, str]:
    if importlib.util.find_spec("playwright") is None:
        return {"status": ValidationStatus.NOT_VERIFIED, "detail": "playwright package not installed"}
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
