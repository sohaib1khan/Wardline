"""Progress events streamed from the scan engine to the TUI/CLI."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EventKind(StrEnum):
    SCAN_STARTED = "scan_started"
    SCAN_FINISHED = "scan_finished"
    PLUGIN_STARTED = "plugin_started"
    PLUGIN_FINISHED = "plugin_finished"
    PLUGIN_SKIPPED = "plugin_skipped"
    OUTPUT_LINE = "output_line"
    FINDING = "finding"
    LOG = "log"


@dataclass(frozen=True, slots=True)
class Event:
    kind: EventKind
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    plugin: str | None = None
    message: str = ""
    stream: str | None = None  # "stdout" | "stderr" for OUTPUT_LINE
    data: dict[str, Any] = field(default_factory=dict)


class EventBus:
    """Fan-out async event bus. Subscribers each get their own queue."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Event | None]] = []
        self._history: list[Event] = []

    def subscribe(self) -> asyncio.Queue[Event | None]:
        queue: asyncio.Queue[Event | None] = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event | None]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def publish(self, event: Event) -> None:
        self._history.append(event)
        for queue in list(self._subscribers):
            await queue.put(event)

    def publish_nowait(self, event: Event) -> None:
        self._history.append(event)
        for queue in list(self._subscribers):
            queue.put_nowait(event)

    @property
    def history(self) -> list[Event]:
        return list(self._history)

    async def close(self) -> None:
        """Signal subscribers that the stream is done."""
        for queue in list(self._subscribers):
            await queue.put(None)

    async def iter_events(self, queue: asyncio.Queue[Event | None]) -> AsyncIterator[Event]:
        while True:
            item = await queue.get()
            if item is None:
                break
            yield item
