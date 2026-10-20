from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from scanner.core.http import HttpClient, HttpResponse
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


def api_response_evidence(response: HttpResponse, path: str) -> bool:
    if response.status in {401, 403}:
        return True
    if response.status != 200 or not response.body:
        return False
    text = response.body.decode("utf-8", "ignore")
    if path.endswith("security.txt"):
        return any(line.lower().startswith("contact:") for line in text.splitlines())
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return any(marker in text.lower() for marker in ("swagger-ui", "swaggerui", "<redoc"))
    if path.endswith(("openapi.json", "swagger.json")):
        return isinstance(payload, dict) and bool(payload.get("openapi") or payload.get("swagger")) and isinstance(payload.get("paths"), dict)
    return isinstance(payload, (dict, list))


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
        if not api_response_evidence(response, path):
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
    if not isinstance(payload, dict) or not isinstance(payload.get("paths", {}), dict):
        return (), {}
    base_url = origin_for(source_url) + "/"
    servers = payload.get("servers", [])
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server = servers[0].get("url")
        if isinstance(server, str) and "{" not in server:
            base_url = urllib.parse.urljoin(source_url, server).rstrip("/") + "/"
    elif isinstance(payload.get("basePath"), str):
        base_url = urllib.parse.urljoin(base_url, payload["basePath"]).rstrip("/") + "/"
    endpoints: list[EndpointSignature] = []
    for path, methods in list(payload.get("paths", {}).items())[:1000]:
        if not isinstance(methods, dict):
            continue
        for method, spec in methods.items():
            if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
                continue
            parameters = []
            if isinstance(spec, dict):
                raw_parameters = spec.get("parameters", [])
                for parameter in raw_parameters if isinstance(raw_parameters, list) else []:
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
            endpoint_url = urllib.parse.urljoin(base_url, path.lstrip("/"))
            endpoints.append(EndpointSignature(url=endpoint_url, method=method.upper(), parameters=tuple(parameters)))
    components = payload.get("components", {})
    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
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
