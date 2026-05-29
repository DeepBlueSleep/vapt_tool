from scanner.auth.detection import detect_auth_signals
from scanner.browser.network_capture import RuntimeApiKind, RuntimeApiRequest, json_fields
from scanner.browser.runtime_parameters import RuntimeParameterKind, parameters_from_api
from scanner.core.models import Form, Page
from scanner.graph.surface import AttackSurfaceGraph, NodeKind


def test_runtime_parameters_from_api() -> None:
    api = RuntimeApiRequest(
        url="https://example.com/api/search?q=test&page=1",
        method="GET",
        route_url="https://example.com/search",
        kind=RuntimeApiKind.REST,
        request_fields=("q", "page"),
    )
    parameters = parameters_from_api(api, response_fields=("items",))
    assert {parameter.name for parameter in parameters} == {"q", "page", "items"}
    assert any(parameter.kind == RuntimeParameterKind.PAGINATION for parameter in parameters)


def test_json_field_extraction() -> None:
    assert json_fields(b'{"items":[{"id":1}],"debug":"x"}') == ("debug", "id", "items")


def test_auth_signal_detection_and_graph_summary() -> None:
    page = Page(
        url="https://example.com/login",
        final_url="https://example.com/login",
        status=200,
        headers={},
        body=b"",
        forms=(Form(action="https://example.com/login", method="post", has_password=True, inputs=("csrf", "password")),),
    )
    signals = detect_auth_signals(page)
    assert {signal.kind for signal in signals} >= {"auth_route", "login_form", "csrf_token"}
    graph = AttackSurfaceGraph()
    page_node = graph.add_node(NodeKind.PAGE, page.final_url)
    auth_node = graph.add_node(NodeKind.AUTH, page.final_url)
    graph.add_edge(page_node, auth_node, "auth_signal")
    assert graph.summary()["page"] == 1
    assert graph.summary()["auth"] == 1
    assert graph.summary()["edges"] == 1
