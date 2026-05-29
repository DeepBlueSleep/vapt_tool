from __future__ import annotations

import asyncio
import datetime as dt
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum


class EventType(StrEnum):
    URL_DISCOVERED = "url_discovered"
    RESPONSE_RECEIVED = "response_received"
    PARAMETER_FOUND = "parameter_found"
    FORM_FOUND = "form_found"
    JS_DISCOVERED = "js_discovered"
    FINDING_CREATED = "finding_created"


@dataclass(frozen=True)
class ScannerEvent:
    type: EventType
    payload: dict[str, object]
    created_at_utc: str = field(default_factory=lambda: dt.datetime.now(dt.UTC).isoformat())


EventHandler = Callable[[ScannerEvent], Awaitable[None]]


class EventDispatcher:
    def __init__(self) -> None:
        self._handlers: dict[EventType, list[EventHandler]] = defaultdict(list)
        self.counts: dict[str, int] = defaultdict(int)

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        self._handlers[event_type].append(handler)

    async def publish(self, event_type: EventType, **payload: object) -> None:
        self.counts[event_type.value] += 1
        event = ScannerEvent(type=event_type, payload=payload)
        handlers = self._handlers.get(event_type, [])
        if handlers:
            await asyncio.gather(*(handler(event) for handler in handlers))
