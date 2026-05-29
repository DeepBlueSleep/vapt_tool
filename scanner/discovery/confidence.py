from __future__ import annotations

from enum import StrEnum


class DiscoveryConfidence(StrEnum):
    INFERRED = "inferred"
    PROBABLE = "probable"
    RUNTIME_CONFIRMED = "runtime-confirmed"
    VERIFIED = "verified"


def classify_confidence(score: float, *, runtime: bool = False, verified: bool = False) -> DiscoveryConfidence:
    if verified:
        return DiscoveryConfidence.VERIFIED
    if runtime:
        return DiscoveryConfidence.RUNTIME_CONFIRMED
    if score >= 0.7:
        return DiscoveryConfidence.PROBABLE
    return DiscoveryConfidence.INFERRED


def confidence_score(
    *,
    runtime_evidence: bool = False,
    js_reference: bool = False,
    framework_fingerprint: bool = False,
    api_lineage: bool = False,
    repeated_observation: bool = False,
    predictable_location: bool = False,
) -> float:
    score = 0.25
    if runtime_evidence:
        score += 0.35
    if js_reference:
        score += 0.22
    if framework_fingerprint:
        score += 0.18
    if api_lineage:
        score += 0.18
    if repeated_observation:
        score += 0.12
    if predictable_location:
        score += 0.1
    return min(0.98, round(score, 2))
