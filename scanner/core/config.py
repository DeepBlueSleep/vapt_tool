from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ScopeConfig:
    allowed_hosts: frozenset[str] = frozenset()
    deny_hosts: frozenset[str] = frozenset()
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    allow_subdomains: bool = False
    respect_robots_txt: bool = True


@dataclass(frozen=True)
class ScanConfig:
    out_dir: Path = Path("audit-reports")
    timeout_seconds: float = 10.0
    max_depth: int = 1
    max_pages: int = 25
    concurrency: int = 4
    rate_limit_per_second: float = 1.0
    user_agent: str = "SafeWebsiteScanner/0.2 (+authorized defensive security assessment)"
    include_exposure_checks: bool = True
    enable_active_checks: bool = False
    enable_browser_checks: bool = False
    browser_timeout_ms: int = 15_000
    capture_screenshots: bool = False
    request_budget: int = 40
    max_requests: int = 2000
    browser_page_budget: int = 10
    sitemap_budget: int = 10
    discovery_page_budget: int = 25
    javascript_budget: int = 50
    analyze_source_maps: bool = False
    enable_tls_checks: bool = True
    probe_legacy_tls: bool = False
    browser_route_budget: int = 20
    browser_api_budget: int = 20
    browser_max_rounds: int = 1
    browser_concurrency: int = 1
    trace_requests: bool = False
    emit_metrics: bool = False
    trace_spa: bool = False
    trace_dom: bool = False
    trace_runtime_api: bool = False
    trace_feedback_loop: bool = False
    enable_cve_enrichment: bool = False
    aggressive_checks: bool = False
    enable_attack_surface_expansion: bool = True
    enable_framework_expansion: bool = True
    enable_predictable_locations: bool = True
    enable_api_expansion: bool = True
    enable_runtime_expansion: bool = True
    expansion_max_candidates: int = 50
    expansion_probe_budget: int = 25
    expansion_min_confidence: float = 0.35
    cache_dir: Path = Path(".scanner-cache")
    scope: ScopeConfig = field(default_factory=ScopeConfig)


def apply_scan_profile(config: ScanConfig, profile: str = "standard") -> ScanConfig:
    """Deep public-page assessment; scope and request rate remain explicit."""
    from dataclasses import replace

    if profile == "standard":
        return config
    if profile != "deep":
        raise ValueError(f"Unknown scan profile: {profile}")
    return replace(
        config, max_depth=max(config.max_depth, 5), max_pages=max(config.max_pages, 500),
        enable_browser_checks=True, enable_active_checks=True, capture_screenshots=True,
        request_budget=max(config.request_budget, 500), max_requests=max(config.max_requests, 5000),
        browser_page_budget=max(config.browser_page_budget, 30), browser_route_budget=50,
        browser_api_budget=100, browser_max_rounds=3, browser_timeout_ms=30000,
        sitemap_budget=25, discovery_page_budget=150, enable_attack_surface_expansion=True,
        enable_framework_expansion=True, enable_predictable_locations=True,
        enable_api_expansion=True, enable_runtime_expansion=True,
        expansion_max_candidates=250, expansion_probe_budget=100, emit_metrics=True,
        javascript_budget=200, analyze_source_maps=True,
        enable_tls_checks=True, probe_legacy_tls=True,
    )
