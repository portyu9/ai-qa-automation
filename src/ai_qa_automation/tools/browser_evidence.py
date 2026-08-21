from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
from urllib.parse import urlparse
from uuid import uuid4

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind, LocatorCandidate, SanitizationStatus
from ..redaction import redact_text
from .locators import LocatorSpec, parse_locator_expression


class BrowserProbeExecutionError(RuntimeError):
    """Browser execution failure that retains the evidence record for the attempt."""

    def __init__(self, message: str, evidence_id: str) -> None:
        super().__init__(message)
        self.evidence_id = evidence_id


@dataclass
class BrowserEvidenceResult:
    url: str
    title: str
    accessibility_snapshot: str
    console_errors: list[str] = field(default_factory=list)
    failed_requests: list[str] = field(default_factory=list)
    http_errors: list[dict[str, Any]] = field(default_factory=list)
    screenshot_evidence_id: str | None = None
    dom_evidence_id: str | None = None
    network_evidence_id: str | None = None


class BrowserProbe:
    """Optional Playwright evidence collector with per-request host authorization."""

    def __init__(
        self,
        evidence: EvidenceStore,
        *,
        allow_hosts: set[str],
        timeout_ms: int = 15_000,
    ) -> None:
        self.evidence = evidence
        self.allow_hosts = {host.lower() for host in allow_hosts}
        self.timeout_ms = timeout_ms

    def _url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme in {"data", "blob", "about"}:
            return True
        if parsed.scheme not in {"http", "https", "ws", "wss"}:
            return False
        return bool(parsed.hostname and parsed.hostname.lower() in self.allow_hosts)

    @staticmethod
    def _page_locator(page: Any, spec: LocatorSpec) -> Any:
        if spec.strategy == "test_id":
            return page.get_by_test_id(spec.value)
        if spec.strategy == "role_name":
            return page.get_by_role(spec.role, name=spec.name, exact=True)
        if spec.strategy == "label":
            return page.get_by_label(spec.value, exact=True)
        if spec.strategy == "placeholder":
            return page.get_by_placeholder(spec.value, exact=True)
        if spec.strategy == "exact_text":
            return page.get_by_text(spec.value, exact=True)
        if spec.strategy == "semantic_css":
            return page.locator(spec.value)
        raise ValueError(f"unsupported locator strategy: {spec.strategy}")

    @asynccontextmanager
    async def _guarded_page(
        self,
        *,
        failed_requests: list[str],
        http_errors: list[dict[str, Any]],
        console_errors: list[str] | None = None,
    ) -> AsyncIterator[Any]:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright optional dependency is not installed") from exc

        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(headless=True, args=["--no-proxy-server"])
            except Exception as exc:
                if "Executable doesn't exist" in str(exc):
                    raise RuntimeError(
                        "Playwright Chromium runtime is not installed; browser validation is NOT_VERIFIED"
                    ) from exc
                raise
            context = None
            try:
                context = await browser.new_context(service_workers="block")

                async def guard_route(route: Any) -> None:
                    request_url = route.request.url
                    if self._url_allowed(request_url):
                        await route.continue_()
                    else:
                        failed_requests.append(f"BLOCKED {redact_text(request_url)}")
                        await route.abort("blockedbyclient")

                async def guard_websocket(websocket: Any) -> None:
                    websocket_url = websocket.url
                    if self._url_allowed(websocket_url):
                        await websocket.connect()
                    else:
                        failed_requests.append(
                            f"BLOCKED WEBSOCKET {redact_text(websocket_url)}"
                        )
                        await websocket.close(code=1008, reason="Blocked by network policy")

                await context.route("**/*", guard_route)
                await context.route_web_socket("**/*", guard_websocket)
                page = await context.new_page()
                if console_errors is not None:
                    page.on(
                        "console",
                        lambda msg: console_errors.append(redact_text(msg.text))
                        if msg.type == "error"
                        else None,
                    )
                page.on("requestfailed", lambda req: failed_requests.append(redact_text(req.url)))
                page.on(
                    "response",
                    lambda response: http_errors.append(
                        {"status_code": response.status, "url": redact_text(response.url)}
                    )
                    if response.status >= 400
                    else None,
                )
                yield page
            finally:
                if context is not None:
                    await context.close()
                await browser.close()

    async def inspect(self, url: str) -> BrowserEvidenceResult:
        host = (urlparse(url).hostname or "").lower()
        safe_url = redact_text(url)
        if not self._url_allowed(url):
            raise PermissionError(f"browser host is not allowlisted: {host or '<missing>'}")
        console_errors: list[str] = []
        failed_requests: list[str] = []
        http_errors: list[dict[str, Any]] = []
        async with self._guarded_page(
            failed_requests=failed_requests,
            http_errors=http_errors,
            console_errors=console_errors,
        ) as page:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                if not self._url_allowed(page.url):
                    raise PermissionError(
                        f"browser navigation escaped allowlist: {redact_text(page.url)}"
                    )
                title = redact_text(await page.title())
                accessibility_snapshot = redact_text(
                    (await page.locator("body").aria_snapshot())[:12000]
                )
                png = await page.screenshot(full_page=True)
            except Exception as exc:
                item = self.evidence.add(
                    EvidenceItem(
                        run_id=self.evidence.run_id,
                        kind=EvidenceKind.EXCEPTION,
                        source="playwright",
                        source_identifier=safe_url,
                        summary="Browser evidence collection failed",
                        structured_data={
                            "error_type": type(exc).__name__,
                            "error": redact_text(str(exc)),
                            "failed_requests": failed_requests[-50:],
                            "http_errors": http_errors[-50:],
                        },
                    )
                )
                raise BrowserProbeExecutionError(redact_text(str(exc)), item.id) from exc

        screenshot_path, digest = self.evidence.register_artifact(
            relative_path=f"browser/screenshot-{uuid4().hex}.png",
            content=png,
            originating_tool="browser_probe",
        )
        screenshot_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.SCREENSHOT,
                source="playwright",
                source_identifier=safe_url,
                summary="Browser screenshot captured",
                artifact_reference=screenshot_path,
                content_hash=digest,
                sanitization_status=SanitizationStatus.RAW,
            )
        )
        dom_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
                source="playwright",
                source_identifier=safe_url,
                summary="Accessibility snapshot captured",
                structured_data={"snapshot": accessibility_snapshot},
            )
        )
        network_item = None
        if failed_requests or http_errors:
            network_item = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.NETWORK_ERROR,
                    source="playwright",
                    source_identifier=safe_url,
                    summary="Browser network failures or HTTP error responses observed",
                    structured_data={
                        "failed_requests": failed_requests[-50:],
                        "http_errors": http_errors[-50:],
                    },
                )
            )

        return BrowserEvidenceResult(
            url=safe_url,
            title=title,
            accessibility_snapshot=accessibility_snapshot,
            console_errors=console_errors,
            failed_requests=failed_requests,
            http_errors=http_errors,
            screenshot_evidence_id=screenshot_item.id,
            dom_evidence_id=dom_item.id,
            network_evidence_id=network_item.id if network_item else None,
        )

    async def verify_locator_candidates(
        self,
        url: str,
        original_locator: str,
        candidates: list[LocatorCandidate],
    ) -> tuple[list[LocatorCandidate], str]:
        """Deterministically measure candidate uniqueness in the live DOM.

        Candidate semantic scores may originate from model reasoning, but match
        counts and supported locator syntax are computed here and cannot be
        supplied as authoritative input by the model.
        """
        if len(candidates) > 20:
            raise ValueError("at most 20 locator candidates may be verified per call")
        if not self._url_allowed(url):
            raise PermissionError("browser locator verification URL is not allowlisted")

        original_spec = parse_locator_expression(original_locator)
        if original_spec is None:
            raise ValueError("original locator is not a supported literal Playwright locator expression")
        failed_requests: list[str] = []
        http_errors: list[dict[str, Any]] = []
        verified: list[LocatorCandidate] = []
        original_count = 0
        context_png = b""
        context_snapshot = ""
        try:
            async with self._guarded_page(
                failed_requests=failed_requests,
                http_errors=http_errors,
            ) as page:
                await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                if not self._url_allowed(page.url):
                    raise PermissionError(
                        f"browser navigation escaped allowlist: {redact_text(page.url)}"
                    )
                original_count = int(await self._page_locator(page, original_spec).count())
                for candidate in candidates:
                    spec = parse_locator_expression(candidate.locator)
                    rejected = candidate.rejected_reason
                    count = 0
                    if spec is None:
                        rejected = rejected or "unsupported/non-literal locator expression"
                    elif candidate.strategy != spec.strategy:
                        rejected = rejected or "declared locator strategy does not match expression"
                    else:
                        try:
                            count = int(await self._page_locator(page, spec).count())
                        except Exception as exc:
                            rejected = rejected or f"locator evaluation failed: {type(exc).__name__}"
                    verified.append(
                        candidate.model_copy(
                            update={
                                "uniqueness_count": count,
                                "rejected_reason": rejected,
                            }
                        )
                    )
                context_snapshot = redact_text(
                    (await page.locator("body").aria_snapshot())[:12000]
                )
                context_png = await page.screenshot(full_page=True)
        except BrowserProbeExecutionError:
            raise
        except Exception as exc:
            item = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.EXCEPTION,
                    source="playwright_locator_verification",
                    source_identifier=redact_text(url),
                    summary="Locator candidate verification failed",
                    structured_data={
                        "error_type": type(exc).__name__,
                        "error": redact_text(str(exc)),
                        "failed_requests": failed_requests[-50:],
                        "http_errors": http_errors[-50:],
                    },
                )
            )
            raise BrowserProbeExecutionError(redact_text(str(exc)), item.id) from exc

        safe_url = redact_text(url)
        context_path, context_digest = self.evidence.register_artifact(
            relative_path=f"browser/locator-verification-{uuid4().hex}.png",
            content=context_png,
            originating_tool="browser_locator_verification",
        )
        screenshot_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.SCREENSHOT,
                source="playwright_locator_verification",
                source_identifier=safe_url,
                summary="Same-DOM screenshot captured for locator verification",
                artifact_reference=context_path,
                content_hash=context_digest,
                sanitization_status=SanitizationStatus.RAW,
            )
        )
        accessibility_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
                source="playwright_locator_verification",
                source_identifier=safe_url,
                summary="Same-DOM accessibility snapshot captured for locator verification",
                structured_data={"snapshot": context_snapshot},
            )
        )
        observed = [
            {
                "locator": item.locator,
                "strategy": item.strategy,
                "uniqueness_count": item.uniqueness_count,
                "rejected_reason": item.rejected_reason,
            }
            for item in verified
        ]
        evidence_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                source="playwright_locator_verification",
                source_identifier=safe_url,
                summary="Playwright measured locator candidate uniqueness",
                structured_data={
                    "original_locator": original_locator,
                    "original_strategy": original_spec.strategy,
                    "original_count": original_count,
                    "candidates": observed,
                    "context_evidence_ids": [screenshot_item.id, accessibility_item.id],
                    "failed_requests": failed_requests[-50:],
                    "http_errors": http_errors[-50:],
                },
            )
        )
        return verified, evidence_item.id
