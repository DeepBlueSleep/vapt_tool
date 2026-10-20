from __future__ import annotations

import asyncio
import logging
import time
import urllib.parse
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
        self.budget_exhausted = False
        self.blocked_redirects = 0
        self.truncated_responses = 0
        self.errors: list[str] = []
        self._active_remaining = config.request_budget

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

    async def request(
        self, method: str, url: str, *, max_body: int = 512_000, retries: int = 1,
        headers: dict[str, str] | None = None, follow_redirects: bool = True,
        active: bool = False,
    ) -> HttpResponse:
        if not self.scope.is_allowed(url):
            return HttpResponse(url=url, final_url=url, status=None, headers={}, body=b"", error="URL is outside configured scope")
        if self._session is None:
            raise RuntimeError("HttpClient must be used as an async context manager")
        if active and self._active_remaining <= 0:
            return HttpResponse(url, url, None, {}, b"", "Active request budget exhausted")
        if self.request_count >= self.config.max_requests:
            self.budget_exhausted = True
            return HttpResponse(url, url, None, {}, b"", "Total request budget exhausted")
        last_error: str | None = None
        current_url = url
        for attempt in range(retries + 1):
            await self.rate_limiter.wait()
            started = time.perf_counter()
            try:
                for hop in range(11):
                    if active and self._active_remaining <= 0:
                        return HttpResponse(url, current_url, None, {}, b"", "Active request budget exhausted")
                    if self.request_count >= self.config.max_requests:
                        self.budget_exhausted = True
                        return HttpResponse(url, current_url, None, {}, b"", "Total request budget exhausted")
                    # Reserve before awaiting network I/O so concurrent callers cannot overspend.
                    self.request_count += 1
                    if active:
                        self._active_remaining -= 1
                    async with self._session.request(method, current_url, headers=headers, allow_redirects=False) as response:
                        body = b""
                        if method.upper() != "HEAD" and max_body > 0:
                            try:
                                body = await response.content.readexactly(max_body)
                                self.truncated_responses += 1
                            except asyncio.IncompleteReadError as exc:
                                body = exc.partial
                        response_headers: dict[str, list[str]] = {}
                        for key, value in response.headers.items():
                            response_headers.setdefault(key.lower(), []).append(value)
                        result = HttpResponse(url, str(response.url), response.status, response_headers, body)
                        if self.config.trace_requests:
                            LOGGER.info("http_request", extra={"method": method, "url": current_url, "status": response.status})
                        location = response.headers.get("Location")
                        if not follow_redirects or response.status not in {301, 302, 303, 307, 308} or not location:
                            self.total_request_time_ms += (time.perf_counter() - started) * 1000
                            return result
                        destination = urllib.parse.urljoin(str(response.url), location)
                        if not self.scope.is_allowed(destination):
                            self.blocked_redirects += 1
                            return HttpResponse(url, str(response.url), response.status, response_headers, body,
                                                "Redirect destination is outside configured scope")
                        current_url = destination
                    if hop < 10:
                        await self.rate_limiter.wait()
                return HttpResponse(url, current_url, None, {}, b"", "Too many redirects")
            except (TimeoutError, aiohttp.ClientError) as exc:
                elapsed_ms = (time.perf_counter() - started) * 1000
                self.total_request_time_ms += elapsed_ms
                last_error = str(exc)
                LOGGER.debug("request_failed", extra={"url": url, "attempt": attempt, "error": last_error})
                if attempt < retries:
                    await asyncio.sleep(0.25 * (attempt + 1))
        if len(self.errors) < 20:
            self.errors.append(f"{url}: {last_error}")
        return HttpResponse(url=url, final_url=url, status=None, headers={}, body=b"", error=last_error)

    async def get(self, url: str) -> HttpResponse:
        return await self.request("GET", url)

    async def head(self, url: str) -> HttpResponse:
        return await self.request("HEAD", url, max_body=0)
