from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from bs4 import BeautifulSoup


@dataclass(frozen=True)
class ResponseSnapshot:
    url: str
    final_url: str
    status: int | None
    headers: dict[str, list[str]]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "ignore")


@dataclass(frozen=True)
class ResponseDiff:
    status_changed: bool
    redirect_changed: bool
    content_hash_changed: bool
    dom_hash_changed: bool
    reflected_markers: tuple[str, ...]
    size_delta: int


def compare_responses(baseline: ResponseSnapshot, candidate: ResponseSnapshot, markers: tuple[str, ...] = ()) -> ResponseDiff:
    return ResponseDiff(
        status_changed=baseline.status != candidate.status,
        redirect_changed=baseline.final_url != candidate.final_url,
        content_hash_changed=_hash(_normalize_text(baseline.text)) != _hash(_normalize_text(candidate.text)),
        dom_hash_changed=_dom_hash(baseline.text) != _dom_hash(candidate.text),
        reflected_markers=tuple(marker for marker in markers if marker and marker in candidate.text),
        size_delta=len(candidate.body) - len(baseline.body),
    )


def _normalize_text(value: str) -> str:
    value = re.sub(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?", "<timestamp>", value)
    value = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", value, flags=re.I)
    return re.sub(r"\s+", " ", value).strip()


def _dom_hash(text: str) -> str:
    soup = BeautifulSoup(text, "lxml")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return _hash(_normalize_text(soup.get_text(" ")))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
