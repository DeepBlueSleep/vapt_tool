from scanner.core.models import Form, Page
from scanner.discovery.parameters import ParameterType, endpoint_signatures_from_page, harvest_page_parameters
from scanner.js.analyzer import analyze_javascript


def test_parameter_harvesting_from_query_and_forms() -> None:
    page = Page(
        url="https://example.com/search?q=test",
        final_url="https://example.com/search?q=test",
        status=200,
        headers={},
        body=b"",
        forms=(
            Form(
                action="https://example.com/login",
                method="post",
                has_password=True,
                inputs=("csrf", "user"),
                hidden_inputs=("csrf",),
            ),
        ),
    )
    parameters = harvest_page_parameters(page)
    assert {parameter.name for parameter in parameters} == {"q", "csrf", "user"}
    assert any(parameter.type == ParameterType.HIDDEN for parameter in parameters)
    assert endpoint_signatures_from_page(page)[1].auth_hint == "password_form"


def test_javascript_endpoint_and_framework_discovery() -> None:
    js = """
      import('/static/chunk.js');
      fetch('/api/users?id=1');
      const socket = "wss://example.com/ws";
      React.createElement('div');
      axios.get('/graphql?query=test');
    """
    discovery = analyze_javascript("https://example.com/app.js", js, "https://example.com/")
    assert "https://example.com/api/users?id=1" in discovery.endpoints
    assert "https://example.com/graphql?query=test" in discovery.endpoints
    assert "wss://example.com/ws" in discovery.websocket_urls
    assert "react" in discovery.frameworks
    assert any(parameter.name == "query" for parameter in discovery.parameters)
