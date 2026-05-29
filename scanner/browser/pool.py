from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from scanner.browser.playwright_analyzer import BrowserObservation, PlaywrightAnalyzer


@dataclass(frozen=True)
class BrowserPoolConfig:
    concurrency: int = 1


class BrowserAnalysisPool:
    def __init__(self, analyzer_factory: Callable[[], PlaywrightAnalyzer], config: BrowserPoolConfig | None = None) -> None:
        self.analyzer_factory = analyzer_factory
        self.config = config or BrowserPoolConfig()
        self._semaphore = asyncio.Semaphore(max(1, self.config.concurrency))

    async def analyze(self, url: str) -> BrowserObservation:
        async with self._semaphore:
            return await self.analyzer_factory().analyze(url)

    async def map(self, urls: list[str]) -> list[BrowserObservation]:
        return await asyncio.gather(*(self.analyze(url) for url in urls))
