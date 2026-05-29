from __future__ import annotations

import math
import re
import urllib.parse

NOISE_HOST_TOKENS = (
    "google-analytics",
    "googletagmanager",
    "doubleclick",
    "facebook.com",
    "hotjar",
    "sentry.io",
)
LOW_VALUE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".css", ".map")


def is_browser_noise(url: str) -> bool:
    lower = url.lower()
    if any(token in lower for token in NOISE_HOST_TOKENS):
        return True
    if urllib.parse.urlparse(lower).path.endswith(LOW_VALUE_EXTENSIONS):
        return True
    return path_entropy(urllib.parse.urlparse(url).path) > 4.2 and len(url) > 140


def semantic_normalize(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = re.sub(r"/[0-9a-f]{16,}(?=/|$)", "/<hash>", parsed.path, flags=re.I)
    path = re.sub(r"/\d+(?=/|$)", "/<id>", path)
    query_names = sorted(name for name, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query = "&".join(f"{name}=<value>" for name in query_names)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", query, ""))


def path_entropy(path: str) -> float:
    if not path:
        return 0.0
    counts = {char: path.count(char) for char in set(path)}
    length = len(path)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
