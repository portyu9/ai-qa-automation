from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

from .models import ValidationStatus


def environment_report(control_root: Path) -> dict[str, dict[str, str]]:
    def package(name: str) -> dict[str, str]:
        found = importlib.util.find_spec(name) is not None
        return {"status": ValidationStatus.PASS if found else ValidationStatus.NOT_VERIFIED, "detail": "installed" if found else "not installed"}

    def executable(name: str) -> dict[str, str]:
        path = shutil.which(name)
        return {"status": ValidationStatus.PASS if path else ValidationStatus.NOT_VERIFIED, "detail": path or "not found"}

    return {
        "python": {"status": ValidationStatus.PASS, "detail": "runtime available"},
        "pydantic": package("pydantic"),
        "claude_agent_sdk": package("claude_agent_sdk"),
        "playwright": package("playwright"),
        "pytest": package("pytest"),
        "docker": executable("docker"),
        "k6": executable("k6"),
        "git": executable("git"),
        "control_root": {"status": ValidationStatus.PASS if control_root.is_dir() else ValidationStatus.FAIL, "detail": str(control_root)},
        "mobile_appium_runtime": {"status": ValidationStatus.NOT_VERIFIED, "detail": "requires external app/device/emulator"},
    }
