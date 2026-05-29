from __future__ import annotations

from dataclasses import dataclass, field

from scanner.analysis.browser_fp import is_browser_noise, semantic_normalize
from scanner.browser.network_capture import RuntimeApiKind, RuntimeApiRequest
from scanner.browser.routes import SpaRoute
from scanner.core.scope import Scope
from scanner.crawlers.prioritization import CrawlCandidate, SurfaceKind, score_candidate
from scanner.utils.url import normalize_url


@dataclass
class BrowserFeedbackState:
    seen: set[str] = field(default_factory=set)
    max_candidates: int = 50


def feedback_candidates(
    routes: tuple[SpaRoute, ...],
    apis: tuple[RuntimeApiRequest, ...],
    scope: Scope,
    state: BrowserFeedbackState,
    depth: int,
    route_budget: int,
    api_budget: int,
) -> tuple[CrawlCandidate, ...]:
    candidates: list[CrawlCandidate] = []
    for route in routes[:route_budget]:
        _add_candidate(candidates, route.url, "browser_route", scope, state, depth)
    for api in apis[:api_budget]:
        if api.kind in {RuntimeApiKind.ANALYTICS, RuntimeApiKind.ASSET, RuntimeApiKind.WEBSOCKET}:
            continue
        _add_candidate(candidates, api.url, "browser_runtime_api", scope, state, depth)
    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    return tuple(candidate for candidate in candidates if candidate.kind != SurfaceKind.ASSET)[: state.max_candidates]


def _add_candidate(
    candidates: list[CrawlCandidate],
    raw_url: str,
    source: str,
    scope: Scope,
    state: BrowserFeedbackState,
    depth: int,
) -> None:
    try:
        url = normalize_url(raw_url)
    except ValueError:
        return
    normalized = semantic_normalize(url)
    if normalized in state.seen or not scope.is_allowed(url) or is_browser_noise(url):
        return
    state.seen.add(normalized)
    candidates.append(score_candidate(url, source, depth))
