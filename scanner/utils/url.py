from __future__ import annotations

import posixpath
import urllib.parse


def normalize_url(raw_url: str, base_url: str | None = None) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("empty URL")
    if base_url:
        raw_url = urllib.parse.urljoin(base_url, raw_url)
    parsed = urllib.parse.urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "https://" + raw_url
        parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("URL is missing a hostname")
    path = posixpath.normpath(parsed.path or "/")
    if parsed.path.endswith("/") and not path.endswith("/"):
        path += "/"
    if path == ".":
        path = "/"
    parsed = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=path,
        fragment="",
    )
    return urllib.parse.urlunparse(parsed)


def origin_for(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def parameter_names(url: str) -> tuple[str, ...]:
    parsed = urllib.parse.urlparse(url)
    return tuple(sorted({key for key, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}))
