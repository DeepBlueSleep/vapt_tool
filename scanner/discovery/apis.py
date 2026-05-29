from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from scanner.core.http import HttpClient
from scanner.discovery.parameters import EndpointSignature, Parameter, ParameterType
from scanner.utils.url import origin_for

API_CANDIDATES = (
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger",
    "/swagger-ui/",
    "/api/",
    "/wp-json/",
    "/graphql",
    "/api/graphql",
)


@dataclass(frozen=True)
class ApiSurface:
    url: str
    kind: str
    status: int | None
    endpoints: tuple[EndpointSignature, ...] = ()
    auth_hints: tuple[str, ...] = ()
    schemas: dict[str, Any] = field(default_factory=dict)


async def discover_api_surfaces(client: HttpClient, base_url: str) -> tuple[ApiSurface, ...]:
    surfaces: list[ApiSurface] = []
    origin = origin_for(base_url)
    for path in API_CANDIDATES:
        response = await client.get(origin + path)
        if response.status not in {200, 401, 403}:
            continue
        body_text = response.body.decode("utf-8", "ignore")
        kind = _classify_api(path, body_text, response.headers)
        endpoints: tuple[EndpointSignature, ...] = ()
        schemas: dict[str, Any] = {}
        if response.status == 200 and kind in {"openapi", "swagger"}:
            endpoints, schemas = _parse_openapi(body_text, response.final_url)
        surfaces.append(
            ApiSurface(
                url=response.final_url,
                kind=kind,
                status=response.status,
                endpoints=endpoints,
                auth_hints=_auth_hints(response.headers, body_text),
                schemas=schemas,
            )
        )
    return tuple(surfaces)


def _classify_api(path: str, body: str, headers: dict[str, list[str]]) -> str:
    content_type = ((headers.get("content-type") or [""])[0]).lower()
    lower = body[:5000].lower()
    if "openapi" in lower:
        return "openapi"
    if "swagger" in lower:
        return "swagger"
    if "graphql" in path or "graphql" in lower:
        return "graphql"
    if "json" in content_type or path.endswith("/wp-json/"):
        return "rest"
    return "api"


def _parse_openapi(body: str, source_url: str) -> tuple[tuple[EndpointSignature, ...], dict[str, Any]]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return (), {}
    endpoints: list[EndpointSignature] = []
    for path, methods in payload.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, spec in methods.items():
            if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
                continue
            parameters = []
            if isinstance(spec, dict):
                for parameter in spec.get("parameters", []):
                    name = parameter.get("name") if isinstance(parameter, dict) else None
                    if name:
                        parameters.append(
                            Parameter(
                                name=str(name),
                                type=ParameterType.QUERY,
                                source_url=source_url,
                                context="openapi",
                                method=method.upper(),
                            )
                        )
            endpoints.append(EndpointSignature(url=path, method=method.upper(), parameters=tuple(parameters)))
    schemas = payload.get("components", {}).get("schemas", {})
    return tuple(endpoints), schemas if isinstance(schemas, dict) else {}


def _auth_hints(headers: dict[str, list[str]], body: str) -> tuple[str, ...]:
    hints = set()
    www_auth = ",".join(headers.get("www-authenticate", []))
    if www_auth:
        hints.add(www_auth)
    lower = body[:5000].lower()
    for token in ("bearer", "api_key", "oauth", "authorization"):
        if token in lower:
            hints.add(token)
    return tuple(sorted(hints))
