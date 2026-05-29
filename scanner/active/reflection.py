from __future__ import annotations

import html.parser
import secrets
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum

from scanner.analysis.diffing import ResponseDiff, ResponseSnapshot, compare_responses
from scanner.core.http import HttpClient
from scanner.core.models import Page
from scanner.discovery.parameters import Parameter, ParameterType, harvest_page_parameters


class ReflectionContext(StrEnum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT_STRING = "javascript_string"
    HTML_COMMENT = "html_comment"
    JSON_VALUE = "json_value"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReflectionMarker:
    value: str
    safety_class: str = "benign-marker"


@dataclass(frozen=True)
class ReflectionObservation:
    parameter: Parameter
    test_url: str
    marker: ReflectionMarker
    contexts: tuple[ReflectionContext, ...]
    diff: ResponseDiff


def make_marker() -> ReflectionMarker:
    return ReflectionMarker(value=f"scanner-marker-{secrets.token_hex(6)}")


async def analyze_reflections(client: HttpClient, page: Page, budget: int = 5) -> list[ReflectionObservation]:
    observations: list[ReflectionObservation] = []
    parameters = [parameter for parameter in harvest_page_parameters(page) if parameter.type in {ParameterType.QUERY, ParameterType.FORM}]
    baseline = ResponseSnapshot(page.url, page.final_url, page.status, page.headers, page.body)
    for parameter in parameters[:budget]:
        if parameter.method != "GET":
            continue
        marker = make_marker()
        test_url = _url_with_parameter(page.final_url, parameter.name, marker.value)
        response = await client.get(test_url)
        snapshot = ResponseSnapshot(response.url, response.final_url, response.status, response.headers, response.body)
        diff = compare_responses(baseline, snapshot, (marker.value,))
        if not diff.reflected_markers:
            continue
        contexts = classify_reflection_contexts(snapshot.text, marker.value, snapshot.headers)
        observations.append(ReflectionObservation(parameter=parameter, test_url=test_url, marker=marker, contexts=contexts, diff=diff))
    return observations


def classify_reflection_contexts(text: str, marker: str, headers: dict[str, list[str]] | None = None) -> tuple[ReflectionContext, ...]:
    content_type = ((headers or {}).get("content-type") or [""])[0].lower()
    contexts: set[ReflectionContext] = set()
    if "json" in content_type and marker in text:
        contexts.add(ReflectionContext.JSON_VALUE)
    if "<!--" in text and marker in _comments_containing(text, marker):
        contexts.add(ReflectionContext.HTML_COMMENT)
    if _in_script_string(text, marker):
        contexts.add(ReflectionContext.JAVASCRIPT_STRING)
    parser = _MarkerContextParser(marker)
    parser.feed(text)
    contexts.update(parser.contexts)
    if marker in text and not contexts:
        contexts.add(ReflectionContext.UNKNOWN)
    return tuple(sorted(contexts, key=lambda item: item.value))


def _url_with_parameter(url: str, name: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[name] = value
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


def _comments_containing(text: str, marker: str) -> str:
    comments = []
    start = 0
    while True:
        left = text.find("<!--", start)
        if left < 0:
            break
        right = text.find("-->", left + 4)
        if right < 0:
            break
        comment = text[left : right + 3]
        if marker in comment:
            comments.append(comment)
        start = right + 3
    return "\n".join(comments)


def _in_script_string(text: str, marker: str) -> bool:
    for script in re_find_scripts(text):
        marker_index = script.find(marker)
        if marker_index < 0:
            continue
        prefix = script[:marker_index]
        quote = prefix.rstrip()[-1:] if prefix.rstrip() else ""
        if quote in {"'", '"', "`"}:
            return True
    return False


def re_find_scripts(text: str) -> list[str]:
    lower = text.lower()
    scripts = []
    start = 0
    while True:
        left = lower.find("<script", start)
        if left < 0:
            break
        body_start = lower.find(">", left)
        right = lower.find("</script>", body_start)
        if body_start < 0 or right < 0:
            break
        scripts.append(text[body_start + 1 : right])
        start = right + 9
    return scripts


class _MarkerContextParser(html.parser.HTMLParser):
    def __init__(self, marker: str) -> None:
        super().__init__()
        self.marker = marker
        self.contexts: set[ReflectionContext] = set()

    def handle_data(self, data: str) -> None:
        if self.marker in data:
            self.contexts.add(ReflectionContext.HTML_BODY)

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if any(value and self.marker in value for _name, value in attrs):
            self.contexts.add(ReflectionContext.HTML_ATTRIBUTE)
