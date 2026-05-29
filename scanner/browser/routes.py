from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class RouteSource(StrEnum):
    LINK = "link"
    HISTORY_API = "history_api"
    HASH = "hash"
    DOM_MUTATION = "dom_mutation"
    FRAMEWORK = "framework"


@dataclass(frozen=True)
class SpaRoute:
    url: str
    path: str
    source: RouteSource
    parameters: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


ROUTE_INSTRUMENTATION = """
() => {
  window.__scannerRoutes = window.__scannerRoutes || [];
  const record = (url, source) => {
    try {
      const resolved = new URL(String(url || location.href), location.href);
      window.__scannerRoutes.push({url: resolved.href, path: resolved.pathname + resolved.search + resolved.hash, source});
    } catch (e) {}
  };
  const wrap = (name) => {
    const original = history[name];
    history[name] = function(state, title, url) {
      const result = original.apply(this, arguments);
      if (url) record(url, name);
      return result;
    };
  };
  wrap('pushState');
  wrap('replaceState');
  window.addEventListener('popstate', () => record(location.href, 'popstate'));
  window.addEventListener('hashchange', () => record(location.href, 'hashchange'));
  record(location.href, 'initial');
}
"""


ROUTE_COLLECTION_SCRIPT = """
() => {
  const routes = new Map();
  const add = (url, source) => {
    try {
      const resolved = new URL(String(url), location.href);
      routes.set(resolved.href, {url: resolved.href, path: resolved.pathname + resolved.search + resolved.hash, source});
    } catch (e) {}
  };
  document.querySelectorAll('a[href], area[href]').forEach(a => add(a.href, 'link'));
  if (Array.isArray(window.__scannerRoutes)) {
    window.__scannerRoutes.forEach(r => add(r.url, r.source || 'history_api'));
  }
  document.querySelectorAll('[data-route], [data-href], [to], [routerlink]').forEach(el => {
    const target = el.getAttribute('data-route') || el.getAttribute('data-href')
      || el.getAttribute('to') || el.getAttribute('routerlink');
    add(target, 'framework');
  });
  return Array.from(routes.values()).slice(0, 1000);
}
"""


def route_parameters(path: str) -> tuple[str, ...]:
    names = set(re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_-]*)=", path))
    names.update(re.findall(r"/[:{]([A-Za-z_][A-Za-z0-9_-]*)}?(?=[/?#]|$)", path))
    return tuple(sorted(names))


def normalize_route(raw: object) -> SpaRoute | None:
    if not isinstance(raw, dict):
        return None
    url = str(raw.get("url") or "")
    path = str(raw.get("path") or "")
    source_raw = str(raw.get("source") or "link")
    if not url:
        return None
    source = _route_source(source_raw)
    return SpaRoute(url=url, path=path, source=source, parameters=route_parameters(path))


def _route_source(source: str) -> RouteSource:
    lowered = source.lower()
    if lowered in {"pushstate", "replacestate", "popstate"}:
        return RouteSource.HISTORY_API
    if lowered == "hashchange":
        return RouteSource.HASH
    if lowered == "framework":
        return RouteSource.FRAMEWORK
    return RouteSource.LINK
