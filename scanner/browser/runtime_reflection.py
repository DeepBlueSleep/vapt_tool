from __future__ import annotations

from dataclasses import dataclass

from scanner.active.reflection import ReflectionContext, classify_reflection_contexts


@dataclass(frozen=True)
class RuntimeReflectionEvidence:
    url: str
    marker: str
    raw_reflection: bool
    rendered_reflection: bool
    contexts: tuple[ReflectionContext, ...]


def classify_runtime_reflection(url: str, html: str, marker: str, rendered_text: str | None = None) -> RuntimeReflectionEvidence:
    contexts = classify_reflection_contexts(html, marker)
    rendered = bool(rendered_text and marker in rendered_text)
    return RuntimeReflectionEvidence(
        url=url,
        marker=marker,
        raw_reflection=marker in html,
        rendered_reflection=rendered,
        contexts=contexts,
    )
