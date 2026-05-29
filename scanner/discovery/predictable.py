from __future__ import annotations

from dataclasses import dataclass

from scanner.discovery.confidence import confidence_score


@dataclass(frozen=True)
class PredictableLocation:
    path: str
    kind: str
    confidence: float
    rationale: str


PREDICTABLE_LOCATIONS: tuple[PredictableLocation, ...] = (
    PredictableLocation("/admin", "admin", confidence_score(predictable_location=True), "Common administrative route"),
    PredictableLocation("/login", "auth", confidence_score(predictable_location=True), "Common login route"),
    PredictableLocation("/logout", "auth", confidence_score(predictable_location=True), "Common session route"),
    PredictableLocation("/api/", "api", confidence_score(predictable_location=True), "Common API prefix"),
    PredictableLocation("/api/v1/", "api", confidence_score(predictable_location=True), "Common versioned API prefix"),
    PredictableLocation("/graphql", "graphql", confidence_score(predictable_location=True), "Common GraphQL endpoint"),
    PredictableLocation("/api/graphql", "graphql", confidence_score(predictable_location=True), "Common GraphQL API endpoint"),
    PredictableLocation("/openapi.json", "api", confidence_score(predictable_location=True), "Common OpenAPI document"),
    PredictableLocation("/swagger.json", "api", confidence_score(predictable_location=True), "Common Swagger document"),
    PredictableLocation(
        "/.well-known/security.txt",
        "well-known",
        confidence_score(predictable_location=True),
        "Security contact metadata",
    ),
    PredictableLocation("/health", "health", confidence_score(predictable_location=True), "Common health check"),
    PredictableLocation("/metrics", "metrics", confidence_score(predictable_location=True), "Common metrics endpoint"),
    PredictableLocation("/debug", "debug", confidence_score(predictable_location=True), "Common debug route"),
)


def predictable_locations() -> tuple[PredictableLocation, ...]:
    return PREDICTABLE_LOCATIONS
