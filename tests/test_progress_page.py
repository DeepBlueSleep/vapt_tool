from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_progress_keeps_polling_with_htmx_recovers_and_stops():
    playwright_module = pytest.importorskip("playwright.async_api")

    script = Path("platform/webui/static/js/app.js").read_text(encoding="utf-8")
    requests = []
    async with playwright_module.async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).exists():
            pytest.skip("Chromium is not installed")
        browser = await playwright.chromium.launch()
        try:
            page = await browser.new_page()

            async def respond(route):
                if route.request.url.endswith("/status"):
                    requests.append(route.request.url)
                    if len(requests) == 2:
                        await route.fulfill(status=503, body="Unavailable")
                    else:
                        done = "true" if len(requests) >= 4 else "false"
                        await route.fulfill(
                            content_type="text/html",
                            body=f'<section id="scan-status" data-done="{done}">{len(requests)}</section>',
                        )
                else:
                    await route.fulfill(content_type="text/html", body=f"""
                        <p id="scan-refresh-message"></p>
                        <section id="scan-status" data-done="false">initial</section>
                        <script>window.htmx = {{}};</script>
                        <script>{script}</script>
                    """)

            await page.route("http://progress.test/**", respond)
            await page.goto("http://progress.test/scan/1")
            await page.wait_for_function("document.querySelector('#scan-status').textContent === '1'")
            await page.wait_for_function(
                "document.querySelector('#scan-refresh-message').textContent.includes('Retrying')"
            )
            await page.wait_for_function("document.querySelector('#scan-status').dataset.done === 'true'")
            assert await page.locator("#scan-refresh-message").inner_text() == ""
            await page.wait_for_timeout(2300)
            assert len(requests) == 4
            assert await page.locator("#scan-status").count() == 1
        finally:
            await browser.close()
