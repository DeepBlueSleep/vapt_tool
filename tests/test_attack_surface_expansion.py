from __future__ import annotations

from dataclasses import dataclass

import pytest

from scanner.browser.network_capture import RuntimeApiKind, RuntimeApiRequest
from scanner.browser.runtime_expansion import expand_runtime_apis
from scanner.core.http import HttpResponse
from scanner.discovery.api_expansion import expand_api_urls
from scanner.discovery.expansion import ExpansionSettings, expand_attack_surface
from scanner.discovery.frameworks import framework_routes
from scanner.discovery.prioritization import prioritize_candidates


def test_framework_routes_for_next_and_wordpress() -> None:
    routes = framework_routes(
        {"js_framework:next.js": "detected"},
        {"api_surfaces": ["rest 200 https://example.com/wp-json/"]},
    )
    paths = {route.path for route in routes}
    assert "/_next/static/build-manifest.js" in paths
    assert "/wp-json/" in paths
    assert any(route.framework == "wordpress" for route in routes)


def test_api_expansion_infers_resource_siblings() -> None:
    expansions = expand_api_urls(["https://example.com/api/v1/users?id=1"])
    urls = {item.url for item in expansions}
    assert "https://example.com/api/v1/admin" in urls
    assert "https://example.com/api/v1/auth" in urls
    assert all(item.lineage for item in expansions)


def test_runtime_expansion_infers_api_and_spa_siblings() -> None:
    expansions = expand_runtime_apis(
        [
            RuntimeApiRequest(
                url="https://example.com/api/v1/users",
                method="GET",
                route_url="https://example.com/app",
                kind=RuntimeApiKind.REST,
            )
        ],
        ["https://example.com/dashboard"],
    )
    urls = {item.url for item in expansions}
    assert "https://example.com/api/v1/admin" in urls
    assert "https://example.com/login" in urls


@pytest.mark.asyncio
async def test_attack_surface_expansion_prioritizes_and_probes() -> None:
    client = FakeClient({"https://example.com/graphql": 200, "https://example.com/admin": 403, "https://example.com/api/v1/admin": 403})
    candidates = await expand_attack_surface(
        client,
        "https://example.com/",
        technologies={"js_framework:react": "detected"},
        inventory={"runtime_apis": ["GET rest https://example.com/api/v1/users"], "pages": ["https://example.com/"]},
        settings=ExpansionSettings(max_candidates=30, max_probe_requests=9),
    )
    lines = [candidate.inventory_line() for candidate in candidates]
    assert any("graphql" in line for line in lines)
    assert any(candidate.verified for candidate in candidates)
    assert client.requests <= 9  # Eight candidate probes plus the missing-page baseline.


def test_prioritization_prefers_high_value_routes() -> None:
    candidates = [
        Candidate("https://example.com/static/app.js", "route", "framework", 0.8),
        Candidate("https://example.com/admin", "admin", "predictable", 0.5),
    ]
    assert prioritize_candidates(candidates, limit=1)[0].url == "https://example.com/admin"


@dataclass(frozen=True)
class Candidate:
    url: str
    kind: str
    source: str
    confidence: float


class FakeScope:
    def is_allowed(self, url: str) -> bool:
        return url.startswith("https://example.com/")


class FakeClient:
    def __init__(self, statuses: dict[str, int]) -> None:
        self.statuses = statuses
        self.scope = FakeScope()
        self.requests = 0

    async def head(self, url: str) -> HttpResponse:
        self.requests += 1
        status = self.statuses.get(url, 404)
        return HttpResponse(url=url, final_url=url, status=status, headers={}, body=b"")

    async def get(self, url: str) -> HttpResponse:
        return await self.head(url)
