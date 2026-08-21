from pathlib import Path

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
