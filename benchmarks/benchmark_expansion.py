from __future__ import annotations

import time

from scanner.discovery.api_expansion import expand_api_urls
from scanner.discovery.frameworks import framework_routes
from scanner.discovery.predictable import predictable_locations


def main() -> None:
    started = time.perf_counter()
    api_inputs = [f"https://example.com/api/v1/resource{i}" for i in range(100)]
    api_expansions = expand_api_urls(api_inputs, limit=500)
    routes = framework_routes(
        {"js_framework:next.js": "detected", "js_framework:react": "detected"},
        {"api_surfaces": ["rest 200 https://example.com/wp-json/"]},
    )
    predictable = predictable_locations()
    elapsed_ms = (time.perf_counter() - started) * 1000
    print(
        {
            "api_inputs": len(api_inputs),
            "api_expansions": len(api_expansions),
            "framework_routes": len(routes),
            "predictable_locations": len(predictable),
            "elapsed_ms": round(elapsed_ms, 2),
        }
    )


if __name__ == "__main__":
    main()
