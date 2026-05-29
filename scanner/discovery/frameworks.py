from __future__ import annotations

from dataclasses import dataclass

from scanner.discovery.confidence import confidence_score


@dataclass(frozen=True)
class FrameworkRoute:
    path: str
    framework: str
    confidence: float
    rationale: str
    kind: str = "route"


def framework_routes(technologies: dict[str, str], inventory: dict[str, list[str]]) -> tuple[FrameworkRoute, ...]:
    names = _framework_names(technologies, inventory)
    routes: list[FrameworkRoute] = []
    for name in names:
        for path, kind, rationale in _rules_for(name):
            routes.append(
                FrameworkRoute(
                    path=path,
                    framework=name,
                    kind=kind,
                    confidence=confidence_score(framework_fingerprint=True),
                    rationale=rationale,
                )
            )
    return tuple(routes)


def _framework_names(technologies: dict[str, str], inventory: dict[str, list[str]]) -> set[str]:
    names = {key.split(":", 1)[-1].lower() for key in technologies}
    joined = " ".join(value.lower() for values in inventory.values() for value in values[:100])
    if "wp-json" in joined or "wp-admin" in joined:
        names.add("wordpress")
    if "_next" in joined:
        names.add("next.js")
    if "actuator" in joined:
        names.add("spring boot")
    if "fastapi" in joined or "openapi.json" in joined:
        names.add("fastapi")
    return names


def _rules_for(name: str) -> tuple[tuple[str, str, str], ...]:
    rules = {
        "wordpress": (
            ("/wp-admin/", "admin", "WordPress admin convention"),
            ("/wp-json/", "api", "WordPress REST API convention"),
            ("/xmlrpc.php", "api", "WordPress XML-RPC convention"),
            ("/wp-login.php", "auth", "WordPress login convention"),
        ),
        "react": (
            ("/api/", "api", "React SPA commonly calls API backends under /api"),
            ("/login", "auth", "React SPA route convention"),
            ("/admin", "admin", "React SPA protected route convention"),
        ),
        "vue": (
            ("/api/", "api", "Vue SPA commonly calls API backends under /api"),
            ("/login", "auth", "Vue router auth route convention"),
        ),
        "angular": (
            ("/api/", "api", "Angular applications commonly call /api backends"),
            ("/auth/login", "auth", "Angular auth flow convention"),
        ),
        "next.js": (
            ("/_next/static/", "asset", "Next.js static asset convention"),
            ("/_next/static/build-manifest.js", "asset", "Next.js build manifest"),
            ("/_next/server/middleware-manifest.json", "route", "Next.js middleware manifest convention"),
            ("/api/", "api", "Next.js API route convention"),
        ),
        "django": (
            ("/admin/", "admin", "Django admin convention"),
            ("/api/", "api", "Common Django REST framework prefix"),
        ),
        "flask": (
            ("/api/", "api", "Common Flask API prefix"),
            ("/admin", "admin", "Common Flask admin route"),
        ),
        "fastapi": (
            ("/openapi.json", "api", "FastAPI OpenAPI convention"),
            ("/docs", "docs", "FastAPI Swagger UI convention"),
            ("/redoc", "docs", "FastAPI ReDoc convention"),
        ),
        "express": (
            ("/api/", "api", "Express API prefix convention"),
            ("/health", "health", "Express health route convention"),
        ),
        "laravel": (
            ("/api/", "api", "Laravel API route convention"),
            ("/login", "auth", "Laravel auth route convention"),
            ("/admin", "admin", "Common Laravel admin route"),
        ),
        "spring boot": (
            ("/actuator", "admin", "Spring Boot actuator convention"),
            ("/actuator/health", "health", "Spring Boot health endpoint"),
            ("/actuator/metrics", "metrics", "Spring Boot metrics endpoint"),
            ("/actuator/env", "debug", "Spring Boot environment endpoint"),
        ),
    }
    return rules.get(name, ())
