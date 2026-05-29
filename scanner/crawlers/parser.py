from __future__ import annotations

from bs4 import BeautifulSoup

from scanner.core.models import Form
from scanner.utils.url import normalize_url, parameter_names


def parse_html(body: bytes, base_url: str) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[Form, ...]]:
    soup = BeautifulSoup(body, "lxml")
    links: set[str] = set()
    assets: set[str] = set()
    scripts: set[str] = set()
    forms: list[Form] = []

    for tag in soup.find_all(["a", "link"]):
        href = tag.get("href")
        if href:
            try:
                normalized = normalize_url(str(href), base_url)
            except ValueError:
                continue
            if tag.name == "a":
                links.add(normalized)
            else:
                assets.add(normalized)

    for tag in soup.find_all(["img", "source", "iframe"]):
        src = tag.get("src")
        if src:
            try:
                assets.add(normalize_url(str(src), base_url))
            except ValueError:
                continue

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            try:
                scripts.add(normalize_url(str(src), base_url))
            except ValueError:
                continue

    for form in soup.find_all("form"):
        action = str(form.get("action") or base_url)
        try:
            action = normalize_url(action, base_url)
        except ValueError:
            action = base_url
        method = str(form.get("method") or "get").lower()
        fields = form.find_all(["input", "textarea", "select"])
        inputs = tuple(sorted({str(field.get("name")) for field in fields if field.get("name")}))
        hidden_inputs = tuple(
            sorted({str(field.get("name")) for field in fields if field.get("name") and str(field.get("type") or "").lower() == "hidden"})
        )
        has_password = any(str(field.get("type") or "").lower() == "password" for field in form.find_all("input"))
        forms.append(Form(action=action, method=method, has_password=has_password, inputs=inputs, hidden_inputs=hidden_inputs))

    return tuple(sorted(links)), tuple(sorted(assets)), tuple(sorted(scripts)), tuple(forms)


def extract_parameters(urls: list[str], forms: tuple[Form, ...]) -> tuple[str, ...]:
    params: set[str] = set()
    for url in urls:
        params.update(parameter_names(url))
    for form in forms:
        params.update(form.inputs)
    return tuple(sorted(params))
