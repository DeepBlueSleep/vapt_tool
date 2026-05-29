from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from scanner.browser.network_capture import RuntimeApiKind, RuntimeApiRequest
from scanner.discovery.confidence import confidence_score


@dataclass(frozen=True)
class RuntimeExpansion:
    url: str
    confidence: float
    rationale: str
    lineage: tuple[str, ...]
    kind: str


def expand_runtime_apis(apis: list[RuntimeApiRequest], routes: list[str], *, limit: int = 30) -> tuple[RuntimeExpansion, ...]:
    candidates: list[RuntimeExpansion] = []
    seen = {api.url for api in apis}
    for api in apis:
        if api.kind == RuntimeApiKind.ANALYTICS or api.kind == RuntimeApiKind.ASSET:
            continue
        parsed = urllib.parse.urlparse(api.url)
        base = parsed.path.rstrip("/")
        if api.kind == RuntimeApiKind.GRAPHQL:
            _add(candidates, seen, _replace_path(parsed, "/graphql"), api.url, "Runtime GraphQL traffic", "graphql")
            _add(candidates, seen, _replace_path(parsed, "/api/graphql"), api.url, "Runtime GraphQL traffic", "graphql")
        if "/api/" in base:
            parent = base.rsplit("/", 1)[0]
            for suffix in ("me", "profile", "search", "auth", "admin"):
                _add(candidates, seen, _replace_path(parsed, f"{parent}/{suffix}"), api.url, "Runtime API sibling inference", "api")
        if len(candidates) >= limit:
            break
    for route in routes[:10]:
        parsed = urllib.parse.urlparse(route)
        for suffix in ("login", "admin", "settings"):
            _add(candidates, seen, _replace_path(parsed, "/" + suffix), route, "SPA route family inference", "route")
    return tuple(candidates[:limit])


def _replace_path(parsed: urllib.parse.ParseResult, path: str) -> str:
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _add(candidates: list[RuntimeExpansion], seen: set[str], url: str, parent: str, rationale: str, kind: str) -> None:
    if not url or url in seen:
        return
    seen.add(url)
    candidates.append(
        RuntimeExpansion(
            url=url,
            confidence=confidence_score(runtime_evidence=True),
            rationale=rationale,
            lineage=(parent,),
            kind=kind,
        )
    )
