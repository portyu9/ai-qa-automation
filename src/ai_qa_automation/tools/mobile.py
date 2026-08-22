from __future__ import annotations

import importlib.util
import os

from ..models import ValidationResult, ValidationStatus


class MobileRuntimeInspector:
    """Truthful Appium capability check; never reports mobile E2E without a real runtime."""

    def inspect(self) -> ValidationResult:
        client_installed = importlib.util.find_spec("appium") is not None
        server_url = os.getenv("APPIUM_SERVER_URL")
        app_ref = os.getenv("AI_QA_MOBILE_APP")
        device = os.getenv("AI_QA_MOBILE_DEVICE")
        missing = [
            name
            for name, value in {
                "appium_python_client": client_installed,
                "APPIUM_SERVER_URL": server_url,
                "AI_QA_MOBILE_APP": app_ref,
                "AI_QA_MOBILE_DEVICE": device,
            }.items()
            if not value
        ]
        if missing:
            return ValidationResult(
                name="mobile_runtime",
                status=ValidationStatus.NOT_VERIFIED,
                summary="Mobile E2E requires a real app + Appium server + device/emulator.",
                details={"missing": missing},
            )
        return ValidationResult(
            name="mobile_runtime",
            status=ValidationStatus.NOT_VERIFIED,
            summary="Configuration is present, but a live Appium session must execute before PASS.",
            details={"configured": True},
        )
