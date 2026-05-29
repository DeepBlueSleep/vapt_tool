from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from enum import StrEnum


class RuntimeApiKind(StrEnum):
    REST = "rest"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    ASSET = "asset"
    ANALYTICS = "analytics"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RuntimeApiRequest:
    url: str
    method: str
    route_url: str
    kind: RuntimeApiKind
    status: int | None = None
    resource_type: str | None = None
    auth_required: bool = False
    auth_metadata: tuple[str, ...] = ()
    request_fields: tuple[str, ...] = ()
    response_content_type: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


NETWORK_INSTRUMENTATION = """
() => {
  window.__scannerApiCalls = window.__scannerApiCalls || [];
  const record = (entry) => {
    try {
      window.__scannerApiCalls.push({...entry, route: location.href, at: Date.now()});
    } catch (e) {}
  };
  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = async function(input, init) {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      const method = (init && init.method) || (input && input.method) || 'GET';
      record({url, method, api: 'fetch'});
      return originalFetch.apply(this, arguments);
    };
  }
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    record({url, method, api: 'xhr'});
    return originalOpen.apply(this, arguments);
  };
  const OriginalWebSocket = window.WebSocket;
  if (OriginalWebSocket) {
    window.WebSocket = function(url, protocols) {
      record({url, method: 'WEBSOCKET', api: 'websocket'});
      return new OriginalWebSocket(url, protocols);
    };
  }
}
"""


def classify_runtime_api(
    url: str,
    method: str,
    resource_type: str | None = None,
    content_type: str | None = None,
    status: int | None = None,
) -> RuntimeApiRequest:
    kind = _kind(url, resource_type, content_type)
    auth_hints = _auth_hints(url, status)
    return RuntimeApiRequest(
        url=url,
        method=method.upper(),
        route_url="",
        kind=kind,
        status=status,
        resource_type=resource_type,
        auth_required=bool(status in {401, 403}),
        auth_metadata=auth_hints,
        response_content_type=content_type,
        request_fields=tuple(_request_fields(url)),
    )


def api_request_from_capture(raw: object, current_route: str) -> RuntimeApiRequest | None:
    if not isinstance(raw, dict):
        return None
    url = str(raw.get("url") or "")
    if not url:
        return None
    try:
        resolved = urllib.parse.urljoin(current_route, url)
    except ValueError:
        return None
    method = str(raw.get("method") or "GET").upper()
    kind = _kind(resolved, None, None)
    return RuntimeApiRequest(
        url=resolved,
        method=method,
        route_url=str(raw.get("route") or current_route),
        kind=kind,
        request_fields=tuple(_request_fields(resolved)),
    )


def _kind(url: str, resource_type: str | None, content_type: str | None) -> RuntimeApiKind:
    lower = url.lower()
    if lower.startswith(("ws://", "wss://")):
        return RuntimeApiKind.WEBSOCKET
    if any(token in lower for token in ("google-analytics", "googletagmanager", "doubleclick", "facebook.com/tr")):
        return RuntimeApiKind.ANALYTICS
    if "graphql" in lower:
        return RuntimeApiKind.GRAPHQL
    if resource_type in {"image", "font", "stylesheet", "script"}:
        return RuntimeApiKind.ASSET
    if content_type and "json" in content_type.lower():
        return RuntimeApiKind.REST
    if any(token in lower for token in ("/api/", "/v1/", "/v2/", "/wp-json/", "supabase.co", "firebaseio.com")):
        return RuntimeApiKind.REST
    return RuntimeApiKind.UNKNOWN


def _auth_hints(url: str, status: int | None) -> tuple[str, ...]:
    hints = set()
    lower = url.lower()
    if status in {401, 403}:
        hints.add("auth_required_status")
    for token in ("token", "session", "auth", "apikey", "api_key"):
        if token in lower:
            hints.add(f"metadata_only:{token}")
    return tuple(sorted(hints))


def _request_fields(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    return [name for name, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]


def json_fields(body: bytes, max_fields: int = 100) -> tuple[str, ...]:
    try:
        payload = json.loads(body.decode("utf-8", "ignore"))
    except json.JSONDecodeError:
        return ()
    fields: set[str] = set()

    def walk(value: object) -> None:
        if len(fields) >= max_fields:
            return
        if isinstance(value, dict):
            for key, nested in value.items():
                fields.add(str(key))
                walk(nested)
        elif isinstance(value, list):
            for nested in value[:10]:
                walk(nested)

    walk(payload)
    return tuple(sorted(fields))
