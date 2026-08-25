from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.browser_evidence import BrowserProbe, BrowserProbeExecutionError


@pytest.mark.asyncio
async def test_browser_failure_evidence_strips_arbitrary_url_sensitive_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirect_url = (
        "https://"
        + "redirect-user:"
        + "redirect-pass"
        + "@example.test/next?session=redirect-opaque#state"
    )
    request_url = (
        "https://"
        + "request-user:"
        + "request-pass"
        + "@example.test/start?session=request-opaque#client"
    )

    class FakePage:
        url = "https://example.test/start"

        async def goto(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError(f"navigation failed at {redirect_url}")

    @asynccontextmanager
    async def fake_guarded_page(**_kwargs: Any) -> AsyncIterator[FakePage]:
        yield FakePage()

    evidence = EvidenceStore(tmp_path, "run-browser-url-redaction")
    probe = BrowserProbe(evidence, allow_hosts={"example.test"})
    monkeypatch.setattr(probe, "_guarded_page", fake_guarded_page)

    with pytest.raises(BrowserProbeExecutionError) as raised:
        await probe.inspect(request_url)

    item = evidence.get(raised.value.evidence_id)
    rendered = f"{item.source_identifier} {item.structured_data}"
    assert item.source_identifier is not None
    assert item.source_identifier.startswith("https://example.test/_redacted_path_sha256/")
    assert "request-user" not in rendered
    assert "request-pass" not in rendered
    assert "request-opaque" not in rendered
    assert "/start" not in rendered
    assert "redirect-user" not in rendered
    assert "redirect-pass" not in rendered
    assert "redirect-opaque" not in rendered
    assert "/next" not in rendered
    assert "#state" not in rendered
    assert "https://example.test/_redacted_path_sha256/" in rendered
