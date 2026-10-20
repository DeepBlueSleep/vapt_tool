from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

from scanner.discovery.parameters import Parameter, harvest_javascript_parameters
from scanner.utils.url import normalize_url

URL_RE = re.compile(r"""(?P<quote>["'`])(?P<url>(?:https?://|wss?://|/)[^"'`\s<>]+)(?P=quote)""")
FETCH_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest|\.open)\s*\(\s*["'`](?P<url>[^"'`]+)""")
IMPORT_RE = re.compile(r"""import\s*\(\s*["'`](?P<url>[^"'`]+)["'`]\s*\)""")
ROUTE_RE = re.compile(r"""(?:path|route|url)\s*:\s*["'`](?P<route>/[^"'`]+)["'`]""")


@dataclass(frozen=True)
class JavaScriptDiscovery:
    source_url: str
    endpoints: tuple[str, ...] = ()
    routes: tuple[str, ...] = ()
    websocket_urls: tuple[str, ...] = ()
    dynamic_imports: tuple[str, ...] = ()
    frameworks: dict[str, str] = field(default_factory=dict)
    parameters: tuple[Parameter, ...] = ()


def analyze_javascript(source_url: str, content: str, base_url: str) -> JavaScriptDiscovery:
    endpoints: set[str] = set()
    websockets: set[str] = set()
    imports: set[str] = set()
    routes: set[str] = set()

    for match in URL_RE.finditer(content):
        _collect_url(match.group("url"), base_url, endpoints, websockets)
    for match in FETCH_RE.finditer(content):
        _collect_url(match.group("url"), base_url, endpoints, websockets)
    for match in IMPORT_RE.finditer(content):
        try:
            imports.add(normalize_url(match.group("url"), source_url))
        except ValueError:
            continue
    for match in ROUTE_RE.finditer(content):
        route = match.group("route")
        routes.add(route)
        try:
            endpoints.add(normalize_url(route, base_url))
        except ValueError:
            continue

    return JavaScriptDiscovery(
        source_url=source_url,
        endpoints=tuple(sorted(endpoints)),
        routes=tuple(sorted(routes)),
        websocket_urls=tuple(sorted(websockets)),
        dynamic_imports=tuple(sorted(imports)),
        frameworks=detect_frameworks(content),
        parameters=harvest_javascript_parameters(source_url, content),
    )


def detect_frameworks(content: str) -> dict[str, str]:
    lower = content.lower()
    frameworks: dict[str, str] = {}
    markers = {
        "react": ("react.createelement", "__react", "react-dom"),
        "vue": ("__vue__", "vue.runtime", "createapp("),
        "angular": ("ng-version", "@angular/", "angular.module"),
        "next.js": ("__next_data__", "/_next/static/"),
        "nuxt": ("__nuxt__", "/_nuxt/"),
        "jquery": ("jquery.fn", "jquery.min.js"),
        "axios": ("axios.create", "axios.get", "axios.post"),
    }
    for name, tokens in markers.items():
        if any(token in lower for token in tokens):
            frameworks[name] = "detected"
    return frameworks


def _collect_url(raw_url: str, base_url: str, endpoints: set[str], websockets: set[str]) -> None:
    if raw_url.startswith(("ws://", "wss://")):
        websockets.add(raw_url)
        return
    if raw_url.startswith("//"):
        raw_url = urllib.parse.urlparse(base_url).scheme + ":" + raw_url
    try:
        endpoints.add(normalize_url(raw_url, base_url))
    except ValueError:
        return
