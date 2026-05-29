from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FrameworkInsight:
    name: str
    confidence: float
    router_markers: tuple[str, ...] = ()
    api_patterns: tuple[str, ...] = ()
    build_artifacts: tuple[str, ...] = ()
    runtime_config_keys: tuple[str, ...] = ()
    environment_leak_hints: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


def analyze_frameworks(script_url: str, content: str) -> tuple[FrameworkInsight, ...]:
    lower = content.lower()
    insights: list[FrameworkInsight] = []
    rules = {
        "react": ("react.createelement", "__react", "react-router", "jsx-runtime"),
        "vue": ("__vue__", "vue-router", "createapp(", "data-v-"),
        "angular": ("@angular/", "ng-version", "angular.module"),
        "next.js": ("__next_data__", "/_next/static/", "next/router"),
        "nuxt": ("__nuxt__", "/_nuxt/", "nuxt.config"),
        "remix": ("@remix-run", "__remixcontext"),
        "svelte": ("svelte/internal", "__svelte"),
        "astro": ("astro-island", "__astro"),
    }
    for name, markers in rules.items():
        matched = tuple(marker for marker in markers if marker in lower)
        if matched:
            insights.append(
                FrameworkInsight(
                    name=name,
                    confidence=min(0.95, 0.45 + len(matched) * 0.2),
                    router_markers=tuple(marker for marker in matched if "router" in marker),
                    api_patterns=_api_patterns(lower),
                    build_artifacts=_build_artifacts(script_url, lower),
                    runtime_config_keys=_runtime_config_keys(content),
                    environment_leak_hints=_environment_hints(content),
                )
            )
    return tuple(insights)


def _api_patterns(lower: str) -> tuple[str, ...]:
    patterns = []
    for token in ("fetch(", "axios.", "/api/", "graphql", "supabase", "firebase"):
        if token in lower:
            patterns.append(token)
    return tuple(patterns)


def _build_artifacts(script_url: str, lower: str) -> tuple[str, ...]:
    artifacts = []
    if "/_next/static/" in script_url or "/_next/static/" in lower:
        artifacts.append("next_static")
    if ".map" in lower:
        artifacts.append("source_map_reference")
    if "webpack" in lower:
        artifacts.append("webpack")
    if "vite" in lower:
        artifacts.append("vite")
    return tuple(artifacts)


def _runtime_config_keys(content: str) -> tuple[str, ...]:
    keys = []
    for token in ("PUBLIC_", "NEXT_PUBLIC_", "VITE_", "NUXT_PUBLIC_", "REACT_APP_"):
        if token in content:
            keys.append(token)
    return tuple(keys)


def _environment_hints(content: str) -> tuple[str, ...]:
    hints = []
    for token in ("API_KEY", "SECRET", "PRIVATE_KEY", "ACCESS_TOKEN"):
        if token in content:
            hints.append(f"metadata_only:{token}")
    return tuple(hints)
