from __future__ import annotations

import urllib.parse
import urllib.robotparser

from scanner.core.http import HttpClient
from scanner.utils.url import origin_for


class RobotsCache:
    def __init__(self) -> None:
        self._cache: dict[str, urllib.robotparser.RobotFileParser] = {}

    async def allowed(self, client: HttpClient, url: str, user_agent: str) -> bool:
        origin = origin_for(url)
        parser = self._cache.get(origin)
        if parser is None:
            parser = urllib.robotparser.RobotFileParser()
            parser.set_url(origin + "/robots.txt")
            response = await client.get(origin + "/robots.txt")
            if response.status == 200:
                parser.parse(response.body.decode("utf-8", "ignore").splitlines())
            else:
                parser.parse([])
            self._cache[origin] = parser
        return parser.can_fetch(user_agent, url)
