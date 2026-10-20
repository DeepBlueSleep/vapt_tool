from __future__ import annotations

import asyncio
import logging
from collections import deque

from scanner.core.config import ScanConfig
from scanner.core.http import HttpClient
from scanner.core.models import Form, Page
from scanner.core.scope import Scope
from scanner.crawlers.parser import extract_parameters, parse_html
from scanner.crawlers.robots import RobotsCache
from scanner.crawlers.sitemap import discover_sitemap_urls
from scanner.utils.url import normalize_url

LOGGER = logging.getLogger(__name__)


class AsyncCrawler:
    def __init__(self, config: ScanConfig, client: HttpClient, scope: Scope) -> None:
        self.config = config
        self.client = client
        self.scope = scope
        self.robots = RobotsCache()
        self.depth_limited_urls: set[str] = set()
        self.robots_excluded = 0
        self.pending_urls = 0

    async def crawl(self, start_url: str) -> list[Page]:
        start = normalize_url(start_url)
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        seen: set[str] = set()
        pages: list[Page] = []

        for sitemap_url in await discover_sitemap_urls(self.client, self.scope, start):
            queue.append((sitemap_url, 0))

        while queue and len(pages) < self.config.max_pages:
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < min(self.config.concurrency, self.config.max_pages - len(pages)):
                url, depth = queue.popleft()
                if url in seen or depth > self.config.max_depth or not self.scope.is_allowed(url):
                    continue
                seen.add(url)
                batch.append((url, depth))
            if not batch:
                continue
            crawled = await asyncio.gather(*(self._fetch_page(url, depth) for url, depth in batch))
            for page, depth in crawled:
                if page is None:
                    continue
                pages.append(page)
                if depth >= self.config.max_depth:
                    self.depth_limited_urls.update(link for link in page.links if link not in seen and self.scope.is_allowed(link))
                    continue
                for link in page.links:
                    if link not in seen and self.scope.is_allowed(link):
                        queue.append((link, depth + 1))
        self.pending_urls = len({url for url, _ in queue if url not in seen})
        self.depth_limited_urls.difference_update(page.url for page in pages)
        return pages

    async def _fetch_page(self, url: str, depth: int) -> tuple[Page | None, int]:
        if self.config.scope.respect_robots_txt:
            allowed = await self.robots.allowed(self.client, url, self.config.user_agent)
            if not allowed:
                self.robots_excluded += 1
                LOGGER.info("robots_disallowed", extra={"url": url})
                return None, depth
        response = await self.client.get(url)
        content_type = (response.headers.get("content-type") or [""])[0]
        links: tuple[str, ...] = ()
        assets: tuple[str, ...] = ()
        scripts: tuple[str, ...] = ()
        forms: tuple[Form, ...] = ()
        if response.body and "html" in content_type.lower():
            links, assets, scripts, forms = parse_html(response.body, response.final_url)
        parameters = extract_parameters(list(links), forms)
        return (
            Page(
                url=url,
                final_url=response.final_url,
                status=response.status,
                headers=response.headers,
                body=response.body,
                content_type=content_type,
                links=links,
                assets=assets,
                scripts=scripts,
                forms=forms,
                parameters=parameters,
            ),
            depth,
        )
