from __future__ import annotations

import xml.etree.ElementTree as ET

from scanner.core.http import HttpClient
from scanner.core.scope import Scope
from scanner.utils.url import normalize_url, origin_for


async def discover_sitemap_urls(client: HttpClient, scope: Scope, base_url: str) -> tuple[str, ...]:
    response = await client.get(origin_for(base_url) + "/sitemap.xml")
    if response.status != 200 or not response.body:
        return ()
    try:
        root = ET.fromstring(response.body)
    except ET.ParseError:
        return ()
    urls: set[str] = set()
    for loc in root.findall(".//{*}loc"):
        if loc.text:
            try:
                url = normalize_url(loc.text)
            except ValueError:
                continue
            if scope.is_allowed(url):
                urls.add(url)
    return tuple(sorted(urls))
