from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import deque
import urllib.parse

from scanner.core.http import HttpClient
from scanner.core.scope import Scope
from scanner.utils.url import normalize_url, origin_for


async def discover_sitemap_urls(client: HttpClient, scope: Scope, base_url: str) -> tuple[str, ...]:
    origin = origin_for(base_url)
    queue = deque([origin + "/sitemap.xml"])
    robots = await client.get(origin + "/robots.txt")
    if robots.status == 200:
        for line in robots.body.decode("utf-8", "ignore").splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() == "sitemap":
                queue.append(urllib.parse.urljoin(origin + "/", value.strip()))
    seen: set[str] = set()
    urls: set[str] = set()
    config = getattr(client, "config", None)
    budget = getattr(config, "sitemap_budget", 10)
    max_urls = getattr(config, "max_pages", 500)
    while queue and len(seen) < budget and len(urls) < max_urls:
        map_url = queue.popleft()
        if map_url in seen or not scope.is_allowed(map_url):
            continue
        seen.add(map_url)
        response = await client.get(map_url)
        if response.status != 200 or not response.body:
            continue
        try:
            root = ET.fromstring(response.body)
        except ET.ParseError:
            continue
        is_index = root.tag.rsplit("}", 1)[-1] == "sitemapindex"
        for loc in root.findall(".//{*}loc"):
            if not loc.text:
                continue
            try:
                url = normalize_url(urllib.parse.urljoin(map_url, loc.text.strip()))
            except ValueError:
                continue
            if not scope.is_allowed(url):
                continue
            if is_index:
                if len(queue) < budget * 2:
                    queue.append(url)
            else:
                urls.add(url)
                if len(urls) >= max_urls:
                    break
    return tuple(sorted(urls))
