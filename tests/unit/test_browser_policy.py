from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.browser_evidence import BrowserProbe


def test_browser_url_guard_applies_to_subresources_and_navigation(tmp_path) -> None:
    probe = BrowserProbe(EvidenceStore(tmp_path, "run"), allow_hosts={"127.0.0.1", "example.test"})
    assert probe._url_allowed("http://127.0.0.1:8000/checkout") is True
    assert probe._url_allowed("https://example.test/app.js") is True
    assert probe._url_allowed("data:text/plain,ok") is True
    assert probe._url_allowed("https://attacker.test/exfil") is False
    assert probe._url_allowed("file:///etc/passwd") is False


def test_browser_url_guard_covers_websockets(tmp_path) -> None:
    probe = BrowserProbe(EvidenceStore(tmp_path, "run-ws"), allow_hosts={"example.test"})
    assert probe._url_allowed("wss://example.test/socket") is True
    assert probe._url_allowed("ws://example.test/socket") is True
    assert probe._url_allowed("wss://attacker.test/socket") is False


async def _raise_navigation_error(*_args, **_kwargs):
    raise RuntimeError("navigation failed token=super-secret-token")


def test_browser_execution_failure_is_recorded_as_evidence(tmp_path, monkeypatch) -> None:
    import asyncio
    import sys
    import types

    from ai_qa_automation.models import EvidenceKind
    from ai_qa_automation.tools.browser_evidence import BrowserProbeExecutionError

    class FakePage:
        url = "https://example.test/start"

        def on(self, *_args, **_kwargs):
            return None

        goto = _raise_navigation_error

    class FakeContext:
        async def route(self, *_args, **_kwargs):
            return None

        async def route_web_socket(self, *_args, **_kwargs):
            return None

        async def new_page(self):
            return FakePage()

        async def close(self):
            return None

    class FakeBrowser:
        async def new_context(self, **_kwargs):
            return FakeContext()

        async def close(self):
            return None

    class FakeChromium:
        async def launch(self, **_kwargs):
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

    class FakeManager:
        async def __aenter__(self):
            return FakePlaywright()

        async def __aexit__(self, *_args):
            return None

    fake_module = types.ModuleType("playwright.async_api")
    fake_module.async_playwright = lambda: FakeManager()
    fake_package = types.ModuleType("playwright")
    fake_package.async_api = fake_module
    monkeypatch.setitem(sys.modules, "playwright", fake_package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)

    evidence = EvidenceStore(tmp_path, "run-browser-failure")
    probe = BrowserProbe(evidence, allow_hosts={"example.test"})
    try:
        asyncio.run(probe.inspect("https://example.test/start?token=super-secret-token"))
    except BrowserProbeExecutionError as exc:
        records = evidence.all()
        assert exc.evidence_id == records[-1].id
        assert records[-1].kind == EvidenceKind.EXCEPTION
        assert "super-secret-token" not in records[-1].source_identifier
        assert "super-secret-token" not in str(records[-1].structured_data)
    else:
        raise AssertionError("browser navigation failure must be surfaced with evidence")


def test_locator_verification_overwrites_model_supplied_uniqueness(tmp_path, monkeypatch) -> None:
    import asyncio
    from contextlib import asynccontextmanager

    from ai_qa_automation.models import LocatorCandidate

    class FakeLocator:
        async def count(self):
            return 2

    class FakeBody:
        async def aria_snapshot(self):
            return '- button "Save"'

    class FakePage:
        url = "https://example.test/page"

        async def goto(self, *_args, **_kwargs):
            return None

        async def screenshot(self, **_kwargs):
            return b"png"

        def locator(self, selector):
            assert selector == "body"
            return FakeBody()

        def get_by_role(self, *_args, **_kwargs):
            return FakeLocator()

    @asynccontextmanager
    async def fake_guarded_page(**_kwargs):
        yield FakePage()

    evidence = EvidenceStore(tmp_path, "run-verify")
    probe = BrowserProbe(evidence, allow_hosts={"example.test"})
    monkeypatch.setattr(probe, "_guarded_page", fake_guarded_page)
    candidates = [
        LocatorCandidate(
            locator="page.get_by_role('button', name='Save')",
            strategy="role_name",
            uniqueness_count=1,
            semantic_match=0.99,
            stability_score=0.99,
        )
    ]
    verified, evidence_id = asyncio.run(
        probe.verify_locator_candidates(
            "https://example.test/page",
            "page.get_by_role('button', name='Old Save')",
            candidates,
        )
    )
    assert verified[0].uniqueness_count == 2
    verification = evidence.get(evidence_id)
    assert verification.source == "playwright_locator_verification"
    context_ids = verification.structured_data["context_evidence_ids"]
    assert len(context_ids) == 2
    assert {evidence.get(eid).kind.value for eid in context_ids} == {
        "screenshot",
        "accessibility_snapshot",
    }


def test_locator_verification_failure_creates_evidence(tmp_path, monkeypatch) -> None:
    import asyncio
    from contextlib import asynccontextmanager

    from ai_qa_automation.models import EvidenceKind, LocatorCandidate
    from ai_qa_automation.tools.browser_evidence import BrowserProbeExecutionError

    class FakePage:
        url = "https://example.test/page"

        async def goto(self, *_args, **_kwargs):
            raise RuntimeError("locator verification failed token=secret-value")

    @asynccontextmanager
    async def fake_guarded_page(**_kwargs):
        yield FakePage()

    evidence = EvidenceStore(tmp_path, "run-verify-fail")
    probe = BrowserProbe(evidence, allow_hosts={"example.test"})
    monkeypatch.setattr(probe, "_guarded_page", fake_guarded_page)
    candidate = LocatorCandidate(
        locator="page.get_by_role('button', name='Save')",
        strategy="role_name",
        uniqueness_count=1,
        semantic_match=0.9,
        stability_score=0.9,
    )
    try:
        asyncio.run(
            probe.verify_locator_candidates(
                "https://example.test/page",
                "page.get_by_role('button', name='Old Save')",
                [candidate],
            )
        )
    except BrowserProbeExecutionError as exc:
        item = evidence.get(exc.evidence_id)
        assert item.kind is EvidenceKind.EXCEPTION
        assert "secret-value" not in str(item.structured_data)
    else:
        raise AssertionError("locator verification failure must preserve evidence")
