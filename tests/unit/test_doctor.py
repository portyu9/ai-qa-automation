import json
from pathlib import Path

from ai_qa_automation.config import Settings
from ai_qa_automation.doctor import environment_report


def test_doctor_distinguishes_playwright_package_from_browser_runtime(tmp_path: Path) -> None:
    report = environment_report(tmp_path)
    assert "playwright_package" in report
    assert "playwright_chromium" in report
    assert report["playwright_package"]["status"] in {"PASS", "NOT_VERIFIED"}
    assert report["playwright_chromium"]["status"] in {"PASS", "NOT_VERIFIED"}


def test_doctor_requires_trusted_control_markers(tmp_path: Path) -> None:
    report = environment_report(tmp_path)
    assert report["control_root"]["status"] == "FAIL"
    (tmp_path / ".claude").mkdir()
    (tmp_path / "CLAUDE.md").write_text("trusted")
    (tmp_path / ".claude" / "settings.json").write_text("{}")
    report = environment_report(tmp_path)
    assert report["control_root"]["status"] == "PASS"


def test_doctor_reports_secret_presence_without_revealing_secret(
    monkeypatch, tmp_path: Path
) -> None:
    secret = "test-only-secret-that-must-never-appear"
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)

    report = environment_report(tmp_path)

    assert report["live_model_credential"]["status"] == "CONFIGURED_NOT_VERIFIED"
    assert secret not in json.dumps(report)


def test_doctor_distinguishes_disabled_and_incomplete_github_mcp(
    monkeypatch, tmp_path: Path
) -> None:
    disabled = Settings(control_root=tmp_path, enable_github_mcp=False)
    assert environment_report(tmp_path, disabled)["github_mcp"]["status"] == "DISABLED"

    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    enabled = Settings(control_root=tmp_path, enable_github_mcp=True)
    assert environment_report(tmp_path, enabled)["github_mcp"]["status"] == "NOT_CONFIGURED"


def test_doctor_surfaces_elevated_write_posture(tmp_path: Path) -> None:
    settings = Settings(control_root=tmp_path, allow_test_writes=True)

    report = environment_report(tmp_path, settings)

    assert report["runtime_write_posture"]["status"] == "ELEVATED_EXPLICIT"
