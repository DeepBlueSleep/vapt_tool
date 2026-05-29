from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from scanner.core.models import TargetReport


@dataclass(frozen=True)
class AttackSurfaceSummary:
    pages: int
    apis: int
    runtime_apis: int
    auth_routes: int
    forms: int
    dynamic_forms: int
    js_assets: int
    external_services: int
    websockets: int
    parameters: int
    complexity_score: float
    expanded: int = 0
    verified_expanded: int = 0
    external_hosts: tuple[str, ...] = ()
    highlights: tuple[str, ...] = ()


def summarize_attack_surface(report: TargetReport) -> AttackSurfaceSummary:
    inventory = report.inventory
    external_hosts = _external_hosts(report)
    pages = len(inventory.get("pages", []))
    apis = len(inventory.get("endpoints", [])) + len(inventory.get("api_surfaces", []))
    runtime_apis = len(inventory.get("runtime_apis", []))
    auth_routes = len(inventory.get("auth_signals", []))
    forms = len(inventory.get("forms", []))
    dynamic_forms = len(inventory.get("dynamic_forms", []))
    js_assets = len(inventory.get("assets", [])) + len(inventory.get("scripts", []))
    websockets = len(inventory.get("websockets", []))
    parameters = len(inventory.get("parameters", [])) + len(inventory.get("runtime_parameters", []))
    expanded = len(inventory.get("expanded_attack_surface", []))
    verified_expanded = len(inventory.get("verified_expanded_routes", []))
    complexity = min(
        100.0,
        round(
            pages * 1.2
            + apis * 2.0
            + runtime_apis * 2.5
            + auth_routes * 3.0
            + forms * 2.0
            + dynamic_forms * 2.5
            + js_assets * 0.4
            + len(external_hosts) * 2.0
            + websockets * 2.5
            + parameters * 0.6
            + expanded * 0.8
            + verified_expanded * 1.5,
            1,
        ),
    )
    return AttackSurfaceSummary(
        pages=pages,
        apis=apis,
        runtime_apis=runtime_apis,
        auth_routes=auth_routes,
        forms=forms,
        dynamic_forms=dynamic_forms,
        js_assets=js_assets,
        external_services=len(external_hosts),
        websockets=websockets,
        parameters=parameters,
        expanded=expanded,
        verified_expanded=verified_expanded,
        complexity_score=complexity,
        external_hosts=external_hosts,
        highlights=tuple(_highlights(runtime_apis, auth_routes, dynamic_forms, external_hosts, websockets)),
    )


def summarize_all(reports: list[TargetReport]) -> dict[str, int | float]:
    summaries = [summarize_attack_surface(report) for report in reports]
    return {
        "pages": sum(item.pages for item in summaries),
        "apis": sum(item.apis for item in summaries),
        "runtime_apis": sum(item.runtime_apis for item in summaries),
        "auth_routes": sum(item.auth_routes for item in summaries),
        "forms": sum(item.forms for item in summaries),
        "dynamic_forms": sum(item.dynamic_forms for item in summaries),
        "external_services": sum(item.external_services for item in summaries),
        "complexity_score": round(sum(item.complexity_score for item in summaries) / max(1, len(summaries)), 1),
        "expanded": sum(item.expanded for item in summaries),
        "verified_expanded": sum(item.verified_expanded for item in summaries),
    }


def _external_hosts(report: TargetReport) -> tuple[str, ...]:
    first_host = urllib.parse.urlparse(report.final_url or report.input_url).hostname or ""
    hosts: set[str] = set()
    for key in ("assets", "browser_network", "runtime_apis", "js_endpoints", "websockets"):
        for item in report.inventory.get(key, []):
            host = urllib.parse.urlparse(item.split()[-1]).hostname
            if host and host != first_host:
                hosts.add(host)
    return tuple(sorted(hosts))


def _highlights(runtime_apis: int, auth_routes: int, dynamic_forms: int, external_hosts: tuple[str, ...], websockets: int) -> list[str]:
    highlights = []
    if runtime_apis:
        highlights.append(f"{runtime_apis} runtime API interactions were observed in the browser.")
    if auth_routes:
        highlights.append(f"{auth_routes} authentication-related routes or controls were identified.")
    if dynamic_forms:
        highlights.append(f"{dynamic_forms} dynamic forms were rendered after page load.")
    if external_hosts:
        highlights.append(f"{len(external_hosts)} external service trust boundaries were observed.")
    if websockets:
        highlights.append(f"{websockets} websocket surfaces were discovered.")
    return highlights
