from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind


@dataclass
class BrowserEvidenceResult:
    url: str
    title: str
    console_errors: list[str] = field(default_factory=list)
    failed_requests: list[str] = field(default_factory=list)
    screenshot_evidence_id: str | None = None
    dom_evidence_id: str | None = None


class BrowserProbe:
    """Optional Playwright evidence collector. Browser installation is a separate runtime concern."""

    def __init__(self, evidence: EvidenceStore, *, allow_hosts: set[str], timeout_ms: int = 15_000) -> None:
        self.evidence = evidence
        self.allow_hosts = {host.lower() for host in allow_hosts}
        self.timeout_ms = timeout_ms

    async def inspect(self, url: str) -> BrowserEvidenceResult:
        host = (urlparse(url).hostname or "").lower()
        if host not in self.allow_hosts:
            raise PermissionError(f"browser host is not allowlisted: {host}")
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright optional dependency is not installed") from exc

        console_errors: list[str] = []
        failed_requests: list[str] = []
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("requestfailed", lambda req: failed_requests.append(req.url))
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            title = await page.title()
            dom = await page.locator("body").aria_snapshot()
            png = await page.screenshot(full_page=True)
            await browser.close()

        screenshot_path, digest = self.evidence.register_artifact(
            relative_path="browser/screenshot.png", content=png, originating_tool="browser_probe"
        )
        screenshot_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.SCREENSHOT,
                source="playwright",
                source_identifier=url,
                summary="Browser screenshot captured",
                artifact_reference=screenshot_path,
                content_hash=digest,
            )
        )
        dom_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
                source="playwright",
                source_identifier=url,
                summary="Accessibility snapshot captured",
                structured_data={"snapshot": dom[:20000]},
            )
        )
        return BrowserEvidenceResult(
            url=url,
            title=title,
            console_errors=console_errors,
            failed_requests=failed_requests,
            screenshot_evidence_id=screenshot_item.id,
            dom_evidence_id=dom_item.id,
        )
