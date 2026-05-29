from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import aiohttp

from scanner.core.config import ScanConfig
from scanner.core.rate_limit import AsyncRateLimiter
from scanner.core.scope import Scope

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class HttpResponse:
    url: str
    final_url: str
    status: int | None
    headers: dict[str, list[str]]
    body: bytes
    error: str | None = None


class HttpClient:
    def __init__(self, config: ScanConfig, scope: Scope) -> None:
        self.config = config
        self.scope = scope
        self.rate_limiter = AsyncRateLimiter(config.rate_limit_per_second)
        self._session: aiohttp.ClientSession | None = None
        self.request_count = 0
        self.total_request_time_ms = 0.0

    async def __aenter__(self) -> HttpClient:
        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        connector = aiohttp.TCPConnector(limit=max(1, self.config.concurrency), ssl=True)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
            raise_for_status=False,
        )
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._session:
            await self._session.close()

    async def request(self, method: str, url: str, *, max_body: int = 512_000, retries: int = 1) -> HttpResponse:
        if not self.scope.is_allowed(url):
            return HttpResponse(url=url, final_url=url, status=None, headers={}, body=b"", error="URL is outside configured scope")
        if self._session is None:
            raise RuntimeError("HttpClient must be used as an async context manager")
        last_error: str | None = None
        for attempt in range(retries + 1):
            await self.rate_limiter.wait()
            started = time.perf_counter()
            try:
                async with self._session.request(method, url, allow_redirects=True) as response:
                    body = b"" if method.upper() == "HEAD" else await response.content.read(max_body)
                    headers: dict[str, list[str]] = {}
                    for key, value in response.headers.items():
                        headers.setdefault(key.lower(), []).append(value)
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    self.request_count += 1
                    self.total_request_time_ms += elapsed_ms
                    if self.config.trace_requests:
                        LOGGER.info(
                            "http_request",
                            extra={"method": method, "url": url, "status": response.status, "elapsed_ms": round(elapsed_ms, 2)},
                        )
                    return HttpResponse(
                        url=url,
                        final_url=str(response.url),
                        status=response.status,
                        headers=headers,
                        body=body,
                    )
            except (TimeoutError, aiohttp.ClientError) as exc:
                elapsed_ms = (time.perf_counter() - started) * 1000
                self.request_count += 1
                self.total_request_time_ms += elapsed_ms
                last_error = str(exc)
                LOGGER.debug("request_failed", extra={"url": url, "attempt": attempt, "error": last_error})
                if attempt < retries:
                    await asyncio.sleep(0.25 * (attempt + 1))
        return HttpResponse(url=url, final_url=url, status=None, headers={}, body=b"", error=last_error)

    async def get(self, url: str) -> HttpResponse:
        return await self.request("GET", url)

    async def head(self, url: str) -> HttpResponse:
        return await self.request("HEAD", url, max_body=0)
