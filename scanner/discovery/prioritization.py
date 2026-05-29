from __future__ import annotations

import urllib.parse
from typing import Protocol, TypeVar


class PrioritizableCandidate(Protocol):
    @property
    def url(self) -> str: ...

    @property
    def confidence(self) -> float: ...

    @property
    def kind(self) -> str: ...

    @property
    def source(self) -> str: ...


T = TypeVar("T", bound=PrioritizableCandidate)


HIGH_VALUE_TOKENS = ("admin", "auth", "login", "graphql", "token", "session", "user", "account", "profile", "api", "health")
LOW_VALUE_TOKENS = ("static", "assets", "image", "font", "analytics", "favicon", ".css", ".png", ".jpg", ".svg", ".woff")


def prioritize_candidates(candidates: list[T], limit: int) -> list[T]:
    unique: dict[str, T] = {}
    for candidate in candidates:
        existing = unique.get(candidate.url)
        if existing is None or _priority(candidate) > _priority(existing):
            unique[candidate.url] = candidate
    return sorted(unique.values(), key=_priority, reverse=True)[:limit]


def _priority(candidate: PrioritizableCandidate) -> float:
    parsed = urllib.parse.urlparse(candidate.url)
    lower = parsed.path.lower()
    score = candidate.confidence * 100
    score += sum(8 for token in HIGH_VALUE_TOKENS if token in lower)
    score -= sum(12 for token in LOW_VALUE_TOKENS if token in lower)
    if candidate.kind in {"graphql", "api", "auth", "admin"}:
        score += 15
    if candidate.source in {"runtime", "api-expansion"}:
        score += 10
    return score
