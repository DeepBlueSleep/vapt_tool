from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from scanner.discovery.confidence import confidence_score


@dataclass(frozen=True)
class ApiExpansion:
    url: str
    confidence: float
    rationale: str
    lineage: tuple[str, ...]
    kind: str = "api"


RESOURCE_HINTS = ("users", "user", "admin", "auth", "login", "profile", "search", "settings", "roles", "me")
VERSION_HINTS = ("v1", "v2")


def expand_api_urls(urls: list[str], *, limit: int = 40) -> tuple[ApiExpansion, ...]:
    expansions: list[ApiExpansion] = []
    seen: set[str] = set(urls)
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        path = parsed.path.rstrip("/")
        segments = [segment for segment in path.split("/") if segment]
        if "graphql" in path.lower():
            for candidate in _same_origin(parsed, ("/graphql", "/api/graphql")):
                _add(expansions, seen, candidate, url, "GraphQL route family", "graphql")
        if "api" in segments:
            api_index = segments.index("api")
            bases = ["/" + "/".join(segments[: api_index + 1])]
            if len(segments) > api_index + 1 and segments[api_index + 1] in VERSION_HINTS:
                bases.append("/" + "/".join(segments[: api_index + 2]))
            for base in bases:
                for resource in RESOURCE_HINTS:
                    candidate = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, f"{base}/{resource}", "", "", ""))
                    _add(expansions, seen, candidate, url, "REST resource naming heuristic", "api")
        if len(expansions) >= limit:
            break
    return tuple(expansions[:limit])


def _same_origin(parsed: urllib.parse.ParseResult, paths: tuple[str, ...]) -> list[str]:
    return [urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", "")) for path in paths]


def _add(expansions: list[ApiExpansion], seen: set[str], url: str, parent: str, rationale: str, kind: str) -> None:
    if url in seen:
        return
    seen.add(url)
    expansions.append(
        ApiExpansion(
            url=url,
            confidence=confidence_score(api_lineage=True),
            rationale=rationale,
            lineage=(parent,),
            kind=kind,
        )
    )
