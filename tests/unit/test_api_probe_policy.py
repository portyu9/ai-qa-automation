import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.api_testing import ApiProbe


@pytest.mark.asyncio
async def test_api_probe_is_fail_closed_without_host_allowlist(tmp_path):
    probe = ApiProbe(EvidenceStore(tmp_path, "run"), allow_hosts=set())
    with pytest.raises(PermissionError):
        await probe.request("GET", "https://example.com")
