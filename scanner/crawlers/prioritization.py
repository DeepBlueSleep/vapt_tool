from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from enum import StrEnum


class SurfaceKind(StrEnum):
    PAGE = "page"
    API = "api"
    FORM = "form"
    AUTH = "auth"
    GRAPHQL = "graphql"
    ASSET = "asset"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CrawlCandidate:
    url: str
    source: str
    kind: SurfaceKind
    depth: int
    score: float


def classify_url(url: str) -> SurfaceKind:
    lower = url.lower()
    path = urllib.parse.urlparse(lower).path
    if "graphql" in lower:
        return SurfaceKind.GRAPHQL
    if any(token in lower for token in ("/api/", "/v1/", "/v2/", "/wp-json/", "openapi", "swagger")):
        return SurfaceKind.API
    if any(token in lower for token in ("login", "signin", "account", "session", "auth")):
        return SurfaceKind.AUTH
    if path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".woff", ".woff2")):
        return SurfaceKind.ASSET
    return SurfaceKind.PAGE


def score_candidate(url: str, source: str, depth: int) -> CrawlCandidate:
    kind = classify_url(url)
    parsed = urllib.parse.urlparse(url)
    query_count = len(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    score = {
        SurfaceKind.GRAPHQL: 95.0,
        SurfaceKind.API: 90.0,
        SurfaceKind.FORM: 85.0,
        SurfaceKind.AUTH: 80.0,
        SurfaceKind.PAGE: 50.0,
        SurfaceKind.UNKNOWN: 30.0,
        SurfaceKind.ASSET: 5.0,
    }[kind]
    score += min(15, query_count * 3)
    if source.startswith("browser"):
        score += 10
    score -= depth * 5
    return CrawlCandidate(url=url, source=source, kind=kind, depth=depth, score=max(0.0, score))
