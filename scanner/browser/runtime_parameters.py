from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from scanner.browser.network_capture import RuntimeApiRequest


class RuntimeParameterKind(StrEnum):
    QUERY = "query"
    JSON_FIELD = "json_field"
    GRAPHQL_VARIABLE = "graphql_variable"
    ROUTE = "route"
    AUTH_METADATA = "auth_metadata"
    PAGINATION = "pagination"
    FILTER = "filter"


@dataclass(frozen=True)
class RuntimeParameter:
    name: str
    kind: RuntimeParameterKind
    source_url: str
    confidence: float
    api_url: str | None = None


def parameters_from_api(api: RuntimeApiRequest, response_fields: tuple[str, ...] = ()) -> tuple[RuntimeParameter, ...]:
    parameters: list[RuntimeParameter] = []
    for field in api.request_fields:
        parameters.append(
            RuntimeParameter(name=field, kind=_semantic_kind(field), source_url=api.route_url, confidence=0.85, api_url=api.url)
        )
    for field in response_fields:
        parameters.append(
            RuntimeParameter(
                name=field,
                kind=RuntimeParameterKind.JSON_FIELD,
                source_url=api.route_url,
                confidence=0.65,
                api_url=api.url,
            )
        )
    for hint in api.auth_metadata:
        parameters.append(
            RuntimeParameter(
                name=hint,
                kind=RuntimeParameterKind.AUTH_METADATA,
                source_url=api.route_url,
                confidence=0.7,
                api_url=api.url,
            )
        )
    return tuple(_dedupe(parameters))


def _semantic_kind(name: str) -> RuntimeParameterKind:
    lowered = name.lower()
    if lowered in {"page", "limit", "offset", "cursor", "per_page"}:
        return RuntimeParameterKind.PAGINATION
    if any(token in lowered for token in ("filter", "sort", "search", "query", "q")):
        return RuntimeParameterKind.FILTER
    if any(token in lowered for token in ("token", "auth", "session", "key")):
        return RuntimeParameterKind.AUTH_METADATA
    return RuntimeParameterKind.QUERY


def _dedupe(parameters: list[RuntimeParameter]) -> list[RuntimeParameter]:
    seen: set[tuple[str, str, str | None]] = set()
    unique = []
    for parameter in parameters:
        key = (parameter.name, parameter.kind.value, parameter.api_url)
        if key in seen:
            continue
        seen.add(key)
        unique.append(parameter)
    return unique
