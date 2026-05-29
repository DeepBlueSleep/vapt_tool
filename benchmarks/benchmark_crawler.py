from __future__ import annotations

import asyncio
import time

from scanner.core.config import ScanConfig
from scanner.core.orchestrator import Scanner


async def main() -> None:
    config = ScanConfig(max_depth=0, max_pages=1, include_exposure_checks=False, enable_browser_checks=False)
    started = time.perf_counter()
    reports = await Scanner(config).scan(["http://127.0.0.1:8765"])
    elapsed = time.perf_counter() - started
    pages = sum(report.pages_crawled for report in reports)
    print(f"pages={pages} elapsed_seconds={elapsed:.3f}")


if __name__ == "__main__":
    asyncio.run(main())
