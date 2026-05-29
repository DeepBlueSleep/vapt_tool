from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    def __init__(self, rate_per_second: float) -> None:
        self._interval = 0.0 if rate_per_second <= 0 else 1.0 / rate_per_second
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            sleep_for = self._next_at - now
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._next_at = time.monotonic() + self._interval
