from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from scanner.browser.dom_observer import DOM_COLLECTION_SCRIPT, DOM_OBSERVER_SCRIPT, DomMutationObservation, parse_dom_observations
from scanner.browser.network_capture import NETWORK_INSTRUMENTATION, RuntimeApiRequest, api_request_from_capture, classify_runtime_api
from scanner.browser.routes import ROUTE_COLLECTION_SCRIPT, ROUTE_INSTRUMENTATION, SpaRoute, normalize_route

logger = logging.getLogger(__name__)


@dataclass
class BrowserObservation:
    url: str
    screenshot_path: str | None = None
    console_errors: list[str] = field(default_factory=list)
    network_requests: list[str] = field(default_factory=list)
    csp_violations: list[str] = field(default_factory=list)
    mixed_content: list[str] = field(default_factory=list)
    discovered_routes: list[str] = field(default_factory=list)
    spa_routes: list[SpaRoute] = field(default_factory=list)
    runtime_apis: list[RuntimeApiRequest] = field(default_factory=list)
    dom_mutations: list[DomMutationObservation] = field(default_factory=list)


class PlaywrightAnalyzer:
    """Optional browser-assisted analyzer.

    Playwright is intentionally optional so the scanner remains usable in
    restricted environments. Install the browser extras and opt in from the CLI
    before using this component.
    """

    def __init__(
        self,
        timeout_ms: int = 15_000,
        screenshot_dir: Path | None = None,
        capture_screenshots: bool = False,
    ) -> None:
        self.timeout_ms = timeout_ms
        self.screenshot_dir = screenshot_dir
        self.capture_screenshots = capture_screenshots

    async def analyze(self, url: str) -> BrowserObservation:
        try:
            from playwright.async_api import (
                TimeoutError as PlaywrightTimeoutError,
            )
            from playwright.async_api import (
                async_playwright,
            )
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "Playwright support requires installing the browser extra."
            ) from exc

        observation = BrowserObservation(url=url)

        async with async_playwright() as p:
            browser = None
            context = None
            page = None

            try:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                        "--disable-background-networking",
                        "--disable-sync",
                        "--disable-default-apps",
                        "--disable-popup-blocking",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ],
                )

                context = await browser.new_context(
                    ignore_https_errors=False
                )

                page = await context.new_page()
                await page.add_init_script(ROUTE_INSTRUMENTATION)
                await page.add_init_script(NETWORK_INSTRUMENTATION)
                await page.add_init_script(DOM_OBSERVER_SCRIPT)

                # Console monitoring
                page.on(
                    "console",
                    lambda msg: observation.console_errors.append(msg.text)
                    if msg.type == "error"
                    else None,
                )

                # Network monitoring
                page.on(
                    "request",
                    lambda request: _capture_request(observation, request, url),
                )

                # Mixed-content detection
                page.on(
                    "response",
                    lambda response: _capture_mixed_content(
                        observation,
                        response.url,
                    ),
                )

                # Best-effort navigation
                try:
                    await page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=self.timeout_ms,
                    )
                except PlaywrightTimeoutError:
                    logger.warning(
                        "Browser navigation timeout for %s",
                        url,
                    )
                    observation.console_errors.append(
                        f"Navigation timeout for {url}"
                    )

                # Allow hydration / client-side rendering
                try:
                    await page.wait_for_timeout(3000)
                except Exception as exc:
                    observation.console_errors.append(
                        f"Wait-for-timeout failed: {exc}"
                    )

                # Extract discovered routes
                try:
                    routes = await page.evaluate(ROUTE_COLLECTION_SCRIPT)

                    for route in routes:
                        spa_route = normalize_route(route)
                        if not spa_route:
                            continue
                        observation.spa_routes.append(spa_route)
                        observation.discovered_routes.append(spa_route.url)

                except Exception as exc:
                    logger.warning(
                        "Route extraction failed for %s: %s",
                        url,
                        exc,
                    )

                    observation.console_errors.append(
                        f"Route extraction failed: {exc}"
                    )

                try:
                    captured_apis = await page.evaluate("() => (window.__scannerApiCalls || []).slice(0, 1000)")
                    for raw_api in captured_apis:
                        api = api_request_from_capture(raw_api, url)
                        if api:
                            observation.runtime_apis.append(api)
                except Exception as exc:
                    logger.warning("Runtime API extraction failed for %s: %s", url, exc)
                    observation.console_errors.append(f"Runtime API extraction failed: {exc}")

                try:
                    observation.dom_mutations.extend(parse_dom_observations(await page.evaluate(DOM_COLLECTION_SCRIPT)))
                except Exception as exc:
                    logger.warning("DOM observation extraction failed for %s: %s", url, exc)
                    observation.console_errors.append(f"DOM observation extraction failed: {exc}")

                # Screenshot capture
                if self.capture_screenshots and self.screenshot_dir:
                    try:
                        self.screenshot_dir.mkdir(
                            parents=True,
                            exist_ok=True,
                        )

                        screenshot_path = (
                            self.screenshot_dir
                            / "browser-screenshot.png"
                        )

                        await page.screenshot(
                            path=str(screenshot_path),
                            full_page=True,
                        )

                        observation.screenshot_path = str(
                            screenshot_path
                        )

                    except Exception as exc:
                        logger.warning(
                            "Screenshot capture failed for %s: %s",
                            url,
                            exc,
                        )

                        observation.console_errors.append(
                            f"Screenshot failed: {exc}"
                        )

            except Exception as exc:
                logger.exception(
                    "Browser analysis failed for %s",
                    url,
                )

                observation.console_errors.append(
                    f"Browser analysis failed: {exc}"
                )

            finally:
                try:
                    if page:
                        await page.close()
                except Exception:
                    pass

                try:
                    if context:
                        await context.close()
                except Exception:
                    pass

                try:
                    if browser:
                        await browser.close()
                except Exception:
                    pass

        return observation


def _capture_mixed_content(
    observation: BrowserObservation,
    url: str,
) -> None:
    if url.startswith("http://"):
        observation.mixed_content.append(url)


def _capture_request(observation: BrowserObservation, request: object, route_url: str) -> None:
    url = str(getattr(request, "url", ""))
    method = str(getattr(request, "method", "GET"))
    resource_type = str(getattr(request, "resource_type", "") or "")
    if url:
        observation.network_requests.append(url)
        api = classify_runtime_api(url=url, method=method, resource_type=resource_type)
        observation.runtime_apis.append(
            RuntimeApiRequest(
                url=api.url,
                method=api.method,
                route_url=route_url,
                kind=api.kind,
                status=api.status,
                resource_type=resource_type,
                auth_required=api.auth_required,
                auth_metadata=api.auth_metadata,
                request_fields=api.request_fields,
                response_content_type=api.response_content_type,
                metadata=api.metadata,
            )
        )
