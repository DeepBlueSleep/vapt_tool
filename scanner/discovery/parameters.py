from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum

from scanner.core.models import Form, Page


class ParameterType(StrEnum):
    QUERY = "query"
    FORM = "form"
    HIDDEN = "hidden"
    JAVASCRIPT = "javascript"
    REST_ROUTE = "rest_route"
    GRAPHQL = "graphql"


@dataclass(frozen=True)
class FormField:
    name: str
    field_type: str
    form_action: str
    method: str


@dataclass(frozen=True)
class Parameter:
    name: str
    type: ParameterType
    source_url: str
    context: str
    method: str = "GET"
    form_action: str | None = None


@dataclass(frozen=True)
class EndpointSignature:
    url: str
    method: str
    parameters: tuple[Parameter, ...] = ()
    content_type: str | None = None
    auth_hint: str | None = None


REST_ROUTE_PARAM_RE = re.compile(r"/[:{]([A-Za-z_][A-Za-z0-9_-]*)}?(?=/|$)")
JS_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]*)=")


def harvest_page_parameters(page: Page) -> tuple[Parameter, ...]:
    parameters: list[Parameter] = []
    parsed = urllib.parse.urlparse(page.final_url)
    for name, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        parameters.append(Parameter(name=name, type=ParameterType.QUERY, source_url=page.final_url, context="url_query"))
    for form in page.forms:
        parameters.extend(_parameters_from_form(form, page.final_url))
    for name in REST_ROUTE_PARAM_RE.findall(parsed.path):
        parameters.append(Parameter(name=name, type=ParameterType.REST_ROUTE, source_url=page.final_url, context="route_path"))
    return tuple(_dedupe(parameters))


def harvest_javascript_parameters(script_url: str, content: str) -> tuple[Parameter, ...]:
    parameters = [
        Parameter(name=name, type=ParameterType.JAVASCRIPT, source_url=script_url, context="javascript_url_template")
        for name in sorted(set(JS_PARAM_RE.findall(content)))
    ]
    if "graphql" in content.lower():
        parameters.append(
            Parameter(name="query", type=ParameterType.GRAPHQL, source_url=script_url, context="graphql_operation", method="POST")
        )
    return tuple(_dedupe(parameters))


def endpoint_signatures_from_page(page: Page) -> tuple[EndpointSignature, ...]:
    signatures = [
        EndpointSignature(url=page.final_url, method="GET", parameters=harvest_page_parameters(page), content_type=page.content_type)
    ]
    for form in page.forms:
        signatures.append(
            EndpointSignature(
                url=form.action,
                method=form.method.upper(),
                parameters=tuple(_parameters_from_form(form, page.final_url)),
                content_type="application/x-www-form-urlencoded",
                auth_hint="password_form" if form.has_password else None,
            )
        )
    return tuple(signatures)


def _parameters_from_form(form: Form, source_url: str) -> list[Parameter]:
    parameters = []
    for name in form.inputs:
        parameter_type = ParameterType.HIDDEN if name in form.hidden_inputs else ParameterType.FORM
        parameters.append(
            Parameter(
                name=name,
                type=parameter_type,
                source_url=source_url,
                context="form_input",
                method=form.method.upper(),
                form_action=form.action,
            )
        )
    return parameters


def _dedupe(parameters: list[Parameter]) -> list[Parameter]:
    seen: set[tuple[str, str, str, str]] = set()
    unique = []
    for parameter in parameters:
        key = (parameter.name, parameter.type.value, parameter.source_url, parameter.method)
        if key in seen:
            continue
        seen.add(key)
        unique.append(parameter)
    return unique
