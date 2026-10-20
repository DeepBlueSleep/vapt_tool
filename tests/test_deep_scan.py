from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
import asyncio

from aiohttp import web
import pytest

from scanner.checks.active import SafeActiveCheck
from scanner.checks.content import ContentCheck
from scanner.core.config import ScanConfig, ScopeConfig, apply_scan_profile
from scanner.core.http import HttpClient
from scanner.core.models import Page
from scanner.core.orchestrator import Scanner
from scanner.core.scope import Scope
from scanner.crawlers.sitemap import discover_sitemap_urls
from scanner.checks.discovery import check_common_exposures
from scanner.discovery.apis import _parse_openapi
from scanner.discovery.apis import discover_api_surfaces
from scanner.discovery.expansion import expand_attack_surface, ExpansionSettings
from scanner.js.analyzer import analyze_javascript


@asynccontextmanager
async def serve(handler):
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


def test_deep_profile_preserves_scope_and_rate():
    config = ScanConfig(rate_limit_per_second=2, scope=ScopeConfig(allowed_hosts=frozenset({"example.test"})))
    deep = apply_scan_profile(config, "deep")
    assert deep.max_pages == 500 and deep.max_requests == 5000
    assert deep.enable_browser_checks and deep.enable_active_checks
    assert deep.scope == config.scope and deep.rate_limit_per_second == 2


def test_openapi_server_base_and_malformed_data():
    endpoints, _ = _parse_openapi('{"openapi":"3.0.0","servers":[{"url":"/api/v2"}],"paths":{"/users":{"get":{}}}}', "https://example.test/openapi.json")
    assert endpoints[0].url == "https://example.test/api/v2/users"
    assert _parse_openapi('[]', "https://example.test/schema")[0] == ()
    assert _parse_openapi('{"paths": []}', "https://example.test/schema")[0] == ()
    discovery = analyze_javascript("https://example.test/assets/app.js", "import('./chunk.js')", "https://example.test/")
    assert discovery.dynamic_imports == ("https://example.test/assets/chunk.js",)


@pytest.mark.asyncio
async def test_exposures_require_content_evidence_and_reject_catchall():
    async def handler(request):
        if request.path == "/.env":
            return web.Response(text="DATABASE_URL=postgres://redacted\n")
        return web.json_response({"app": "catchall"})

    async with serve(handler) as url:
        config = ScanConfig(rate_limit_per_second=0)
        async with HttpClient(config, Scope(config.scope)) as client:
            findings = await check_common_exposures(client, url)
    assert len(findings) == 1
    assert findings[0].url.endswith("/.env")
    assert "postgres" not in findings[0].evidence


@pytest.mark.asyncio
async def test_spa_fallback_is_not_an_api_or_verified_route():
    async def handler(request):
        return web.Response(text='<html><body><div id="root">Login</div></body></html>', content_type="text/html")

    async with serve(handler) as url:
        config = ScanConfig(rate_limit_per_second=0)
        async with HttpClient(config, Scope(config.scope)) as client:
            assert await discover_api_surfaces(client, url) == ()
            candidates = await expand_attack_surface(client, url, technologies={}, inventory={},
                                                     settings=ExpansionSettings(max_candidates=5, max_probe_requests=5))
            assert not any(candidate.verified for candidate in candidates)


@pytest.mark.asyncio
async def test_redirect_scope_and_global_request_limit():
    received = []

    async def handler(request):
        received.append(request.path)
        if request.path == "/escape":
            return web.Response(status=302, headers={"Location": "http://localhost/forbidden"})
        if request.path == "/redirect":
            return web.Response(status=302, headers={"Location": "/ok"})
        return web.Response(text="ok")

    async with serve(handler) as url:
        config = ScanConfig(max_requests=3, rate_limit_per_second=0,
                            scope=ScopeConfig(allowed_hosts=frozenset({"127.0.0.1"})))
        async with HttpClient(config, Scope(config.scope)) as client:
            blocked = await client.get(url + "/escape")
            assert blocked.status == 302 and "outside" in blocked.error
            allowed = await client.get(url + "/redirect")
            assert allowed.status == 200
            exhausted = await client.get(url + "/ok")
            assert exhausted.status is None and client.budget_exhausted
            assert client.request_count == 3
    assert received == ["/escape", "/redirect", "/ok"]


@pytest.mark.asyncio
async def test_streamed_responses_and_concurrent_request_cap():
    async def handler(request):
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b"first")
        await asyncio.sleep(0.01)
        await response.write(b"second")
        await response.write_eof()
        return response

    async with serve(handler) as url:
        config = ScanConfig(rate_limit_per_second=0, max_requests=3)
        async with HttpClient(config, Scope(config.scope)) as client:
            results = await asyncio.gather(*(client.get(url) for _ in range(8)))
            assert client.request_count == 3
            assert sum(item.status == 200 for item in results) == 3
            assert all(item.body == b"firstsecond" for item in results if item.status == 200)


@pytest.mark.asyncio
async def test_active_cors_redirect_and_target_budget():
    async def handler(request):
        if "next" in request.query:
            return web.Response(status=302, headers={"Location": request.query["next"]})
        return web.Response(text="ok", headers={
            "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
            "Access-Control-Allow-Credentials": "true",
        })

    async with serve(handler) as url:
        config = ScanConfig(rate_limit_per_second=0, request_budget=2)
        async with HttpClient(config, Scope(config.scope)) as client:
            check = SafeActiveCheck(client)
            page = Page(url, url, 200, {}, b"", parameters=("next",))
            assert len(await check._cors(page)) == 1
            assert len(await check._open_redirect(page)) == 1
            assert await check._cors(page) == []
            assert client.request_count == 2


@pytest.mark.asyncio
async def test_sitemap_index_and_robots_maps_stay_in_scope():
    received = []

    async def handler(request):
        received.append(request.path)
        if request.path == "/robots.txt":
            return web.Response(text="Sitemap: /extra.xml")
        if request.path == "/sitemap.xml":
            return web.Response(text='<sitemapindex><sitemap><loc>/nested.xml</loc></sitemap><sitemap><loc>http://outside.test/map.xml</loc></sitemap></sitemapindex>')
        if request.path == "/nested.xml":
            return web.Response(text='<urlset><url><loc>/nested-page</loc></url></urlset>')
        if request.path == "/extra.xml":
            return web.Response(text='<urlset><url><loc>/extra-page</loc></url></urlset>')
        return web.Response(status=404)

    async with serve(handler) as url:
        config = ScanConfig(rate_limit_per_second=0, scope=ScopeConfig(allowed_hosts=frozenset({"127.0.0.1"})))
        async with HttpClient(config, Scope(config.scope)) as client:
            pages = await discover_sitemap_urls(client, client.scope, url)
            assert set(pages) == {url + "/nested-page", url + "/extra-page"}
    assert len(received) == 4


@pytest.mark.asyncio
async def test_public_content_findings_redact_credential_values():
    body = b'<script src="http://cdn.test/app.js"></script><p>-----BEGIN PRIVATE KEY-----</p>Traceback (most recent call last):'
    page = Page("https://example.test", "https://example.test", 200, {}, body, content_type="text/html")
    findings = await ContentCheck().analyze(page, None)
    assert {f.title for f in findings} >= {
        "Private key material exposed", "Public response exposes diagnostic error details",
        "HTTPS page references insecure resources",
    }
    assert all("BEGIN PRIVATE KEY" not in finding.evidence for finding in findings)


@pytest.mark.asyncio
async def test_scan_analyzes_openapi_get_endpoints_and_obeys_page_limit():
    async def handler(request):
        if request.path == "/":
            return web.Response(text='<a href="/one">one</a><a href="/two">two</a>', content_type="text/html")
        if request.path == "/openapi.json":
            return web.json_response({"openapi": "3.0.0", "paths": {"/api/diagnostic": {"get": {}}}})
        if request.path == "/api/diagnostic":
            return web.Response(text="Traceback (most recent call last):")
        return web.Response(status=404)

    async with serve(handler) as url:
        config = ScanConfig(rate_limit_per_second=0, max_depth=0, max_pages=5,
                            enable_attack_surface_expansion=False, include_exposure_checks=False)
        report = (await Scanner(config).scan([url]))[0]
        assert url + "/api/diagnostic" in report.inventory["pages"]
        assert any("diagnostic error" in finding.title for finding in report.findings)
        assert report.inventory["coverage"]
        limited = (await Scanner(replace(config, max_pages=1, max_depth=2)).scan([url]))[0]
        assert limited.pages_crawled == 1
        exhausted = (await Scanner(replace(config, max_requests=1)).scan([url]))[0]
        assert exhausted.pages_crawled == 0 and not exhausted.findings
        assert any("No pages" in error for error in exhausted.errors)


def test_deep_profile_api_and_form(tmp_path: Path):
    from fastapi.testclient import TestClient
    from platform.api.app import create_app
    from platform.api.schemas import ScanCreate
    from platform.api.queue import scan_config_from_payload

    config = scan_config_from_payload(ScanCreate(url="https://example.test", profile="deep", max_requests=17), tmp_path)
    assert config.max_requests == 17 and config.enable_browser_checks
    app = create_app(f"sqlite+aiosqlite:///{tmp_path / 'deep.db'}")
    queued = []
    app.state.scan_queue.enqueue = lambda scan_id, url, config: queued.append(config)
    with TestClient(app) as client:
        assert client.get("/scans").status_code == 200
        response = client.post("/scan", data={"target_url": "https://example.test", "profile": "deep"}, follow_redirects=False)
        assert response.status_code == 303
    assert queued[0].max_pages == 500 and queued[0].enable_active_checks
