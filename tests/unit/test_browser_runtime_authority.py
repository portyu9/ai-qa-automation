from pathlib import Path

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.browser_evidence import BrowserProbe


def _probe(tmp_path: Path, *, use_system_chrome: bool = False) -> BrowserProbe:
    return BrowserProbe(
        EvidenceStore(tmp_path, "browser-runtime-authority"),
        allow_hosts={"127.0.0.1"},
        use_system_chrome=use_system_chrome,
    )


def test_default_browser_launch_authority_remains_playwright_managed(tmp_path: Path) -> None:
    probe = _probe(tmp_path)

    assert probe._launch_options() == {
        "headless": True,
        "args": ["--no-proxy-server"],
    }


def test_system_browser_authority_is_exactly_chrome_channel(tmp_path: Path) -> None:
    probe = _probe(tmp_path, use_system_chrome=True)

    assert probe._launch_options() == {
        "headless": True,
        "args": ["--no-proxy-server"],
        "channel": "chrome",
    }


def test_system_browser_authority_rejects_non_boolean_expansion(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="use_system_chrome must be a boolean"):
        BrowserProbe(
            EvidenceStore(tmp_path, "browser-runtime-invalid"),
            allow_hosts={"127.0.0.1"},
            use_system_chrome="/tmp/browser",  # type: ignore[arg-type]
        )
