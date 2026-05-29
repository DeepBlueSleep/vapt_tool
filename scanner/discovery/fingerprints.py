from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechnologyFingerprint:
    name: str
    confidence: float
    evidence: tuple[str, ...]


def correlate_fingerprints(
    headers: dict[str, list[str]],
    technologies: dict[str, str],
    inventory: dict[str, list[str]],
) -> tuple[TechnologyFingerprint, ...]:
    evidence_parts = [
        *(value for values in headers.values() for value in values),
        *technologies.keys(),
        *(item for values in inventory.values() for item in values[:50]),
    ]
    evidence_text = " ".join(evidence_parts).lower()
    fingerprints: list[TechnologyFingerprint] = []
    rules = {
        "wordpress": ("wp-json", "wp-content", "wordpress"),
        "next.js": ("_next", "next.js"),
        "fastapi": ("openapi.json", "fastapi", "swagger-ui"),
        "spring boot": ("actuator", "x-application-context"),
        "express": ("x-powered-by express", "express"),
        "laravel": ("laravel_session", "x-powered-by php"),
        "django": ("csrftoken", "django"),
    }
    for name, markers in rules.items():
        matched = tuple(marker for marker in markers if marker in evidence_text)
        if matched:
            fingerprints.append(
                TechnologyFingerprint(
                    name=name,
                    confidence=min(0.95, 0.45 + len(matched) * 0.2),
                    evidence=matched,
                )
            )
    return tuple(fingerprints)
