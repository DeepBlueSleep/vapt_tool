from scanner.browser.feedback import BrowserFeedbackState, feedback_candidates
from scanner.browser.network_capture import RuntimeApiKind, RuntimeApiRequest
from scanner.browser.routes import RouteSource, SpaRoute, normalize_route, route_parameters
from scanner.core.config import ScopeConfig
from scanner.core.scope import Scope


def test_route_normalization_and_parameters() -> None:
    route = normalize_route({"url": "https://example.com/users/123?tab=a", "path": "/users/:id?tab=a", "source": "pushState"})
    assert route is not None
    assert route.source == RouteSource.HISTORY_API
    assert route_parameters(route.path) == ("id", "tab")


def test_feedback_candidates_scope_and_noise_filtering() -> None:
    scope = Scope(ScopeConfig(allowed_hosts=frozenset({"example.com"})))
    routes = (
        SpaRoute(url="https://example.com/app", path="/app", source=RouteSource.LINK),
        SpaRoute(url="https://other.test/app", path="/app", source=RouteSource.LINK),
        SpaRoute(url="https://example.com/font.woff2", path="/font.woff2", source=RouteSource.LINK),
    )
    apis = (
        RuntimeApiRequest(url="https://example.com/api/users?q=a", method="GET", route_url="/app", kind=RuntimeApiKind.REST),
    )
    candidates = feedback_candidates(routes, apis, scope, BrowserFeedbackState(), depth=1, route_budget=10, api_budget=10)
    assert [candidate.url for candidate in candidates] == ["https://example.com/api/users?q=a", "https://example.com/app"]
