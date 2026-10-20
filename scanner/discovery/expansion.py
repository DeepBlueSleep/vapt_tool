from __future__ import annotations

import urllib.parse
import secrets
from dataclasses import dataclass, field

from scanner.browser.network_capture import RuntimeApiRequest
from scanner.browser.runtime_expansion import expand_runtime_apis
from scanner.core.http import HttpClient
from scanner.discovery.api_expansion import expand_api_urls
from scanner.discovery.confidence import DiscoveryConfidence, classify_confidence
from scanner.discovery.frameworks import framework_routes
from scanner.discovery.predictable import predictable_locations
from scanner.discovery.prioritization import prioritize_candidates
from scanner.utils.url import origin_for


@dataclass(frozen=True)
class ExpansionCandidate:
    url: str
    kind: str
    source: str
    confidence: float
    confidence_label: DiscoveryConfidence
    rationale: str
    lineage: tuple[str, ...] = ()
    status: int | None = None
    verified: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    def inventory_line(self) -> str:
        status = f" status={self.status}" if self.status is not None else ""
        lineage = f" lineage={' <- '.join(self.lineage)}" if self.lineage else ""
        return (
            f"{self.kind} {self.source} {self.confidence_label.value} {self.confidence:.2f}{status} "
            f"{self.url} :: {self.rationale}{lineage}"
        )


@dataclass(frozen=True)
class ExpansionSettings:
    enabled: bool = True
    framework_routes: bool = True
    predictable_locations: bool = True
    api_expansion: bool = True
    runtime_expansion: bool = True
    max_candidates: int = 50
    max_probe_requests: int = 25
    min_confidence: float = 0.35


async def expand_attack_surface(
    client: HttpClient,
    base_url: str,
    *,
    technologies: dict[str, str],
    inventory: dict[str, list[str]],
    runtime_apis: list[RuntimeApiRequest] | None = None,
    settings: ExpansionSettings | None = None,
) -> tuple[ExpansionCandidate, ...]:
    settings = settings or ExpansionSettings()
    if not settings.enabled:
        return ()
    candidates: list[ExpansionCandidate] = []
    origin = origin_for(base_url)
    if settings.predictable_locations:
        for predictable in predictable_locations():
            candidates.append(
                ExpansionCandidate(
                    url=urllib.parse.urljoin(origin, predictable.path),
                    kind=predictable.kind,
                    source="predictable",
                    confidence=predictable.confidence,
                    confidence_label=classify_confidence(predictable.confidence),
                    rationale=predictable.rationale,
                )
            )
    if settings.framework_routes:
        for route in framework_routes(technologies, inventory):
            candidates.append(
                ExpansionCandidate(
                    url=urllib.parse.urljoin(origin, route.path),
                    kind=route.kind,
                    source="framework",
                    confidence=route.confidence,
                    confidence_label=classify_confidence(route.confidence),
                    rationale=route.rationale,
                    metadata={"framework": route.framework},
                )
            )
    api_urls = _inventory_urls(inventory, ("runtime_apis", "endpoints", "js_endpoints", "api_surfaces"))
    if settings.api_expansion:
        for api_candidate in expand_api_urls(api_urls, limit=settings.max_candidates):
            candidates.append(
                ExpansionCandidate(
                    url=api_candidate.url,
                    kind=api_candidate.kind,
                    source="api-expansion",
                    confidence=api_candidate.confidence,
                    confidence_label=classify_confidence(api_candidate.confidence),
                    rationale=api_candidate.rationale,
                    lineage=api_candidate.lineage,
                )
            )
    if settings.runtime_expansion and runtime_apis:
        routes = inventory.get("browser_routes", []) + inventory.get("pages", [])
        for runtime_candidate in expand_runtime_apis(runtime_apis, routes, limit=settings.max_candidates):
            candidates.append(
                ExpansionCandidate(
                    url=runtime_candidate.url,
                    kind=runtime_candidate.kind,
                    source="runtime",
                    confidence=runtime_candidate.confidence,
                    confidence_label=classify_confidence(runtime_candidate.confidence, runtime=True),
                    rationale=runtime_candidate.rationale,
                    lineage=runtime_candidate.lineage,
                )
            )
    candidates = [
        candidate
        for candidate in candidates
        if candidate.confidence >= settings.min_confidence and client.scope.is_allowed(candidate.url)
    ]
    prioritized = prioritize_candidates(candidates, settings.max_candidates)
    return await _probe_candidates(client, prioritized, settings.max_probe_requests)


async def _probe_candidates(client: HttpClient, candidates: list[ExpansionCandidate], budget: int) -> tuple[ExpansionCandidate, ...]:
    verified: list[ExpansionCandidate] = []
    baseline = None
    if candidates and budget > 0:
        baseline = await client.get(origin_for(candidates[0].url) + "/scanner-missing-" + secrets.token_hex(8))
        budget -= 1
    for candidate in candidates:
        if budget <= 0:
            verified.append(candidate)
            continue
        response = await client.get(candidate.url)
        budget -= 1
        status = response.status
        matches_fallback = bool(baseline and baseline.status == 200 and response.body == baseline.body)
        is_verified = bool(status and status in {200, 201, 204, 401, 403} and not response.error and not matches_fallback)
        verified.append(
            ExpansionCandidate(
                url=response.final_url if is_verified else candidate.url,
                kind=candidate.kind,
                source=candidate.source,
                confidence=min(0.99, candidate.confidence + (0.25 if is_verified else 0)),
                confidence_label=classify_confidence(candidate.confidence, runtime=candidate.source == "runtime", verified=is_verified),
                rationale=candidate.rationale,
                lineage=candidate.lineage,
                status=status,
                verified=is_verified,
                metadata=candidate.metadata,
            )
        )
    return tuple(verified)


def _inventory_urls(inventory: dict[str, list[str]], keys: tuple[str, ...]) -> list[str]:
    urls: list[str] = []
    for key in keys:
        for item in inventory.get(key, []):
            candidate = item.split()[-1]
            parsed = urllib.parse.urlparse(candidate)
            if parsed.scheme and parsed.netloc:
                urls.append(candidate)
    return urls
