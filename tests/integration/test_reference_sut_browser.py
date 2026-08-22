import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.browser_evidence import BrowserProbe


@pytest.mark.browser
@pytest.mark.asyncio
async def test_reference_sut_browser_collects_evidence(tmp_path):
    evidence = EvidenceStore(tmp_path, "browser-run")
    result = await BrowserProbe(evidence, allow_hosts={"127.0.0.1"}).inspect(
        "http://127.0.0.1:8000/?mode=prompt-injection"
    )
    assert result.title == "Reference Checkout"
    assert result.screenshot_evidence_id
    assert result.dom_evidence_id
