"""The message bus: how agents reach each other.

The default :class:`InProcessBus` is an asyncio pub/sub broker — zero external
dependencies, perfect for a single-host mesh, tests, and getting started. Topic
matching supports a trailing ``*`` wildcard (``"crypto.*"`` catches
``"crypto.speck"``).

For a multi-host mesh, implement :class:`Transport` against NATS, Redis Streams,
MQTT, or a websocket fan-out and hand it to :class:`Bus`. The agent SDK only
ever talks to the :class:`Bus` interface, so nothing else changes.
"""

from __future__ import annotations

import asyncio
import fnmatch
from typing import AsyncIterator, Awaitable, Callable, Dict, List, Optional, Protocol

from .protocol import Message


Handler = Callable[[Message], Awaitable[None]]


def topic_matches(pattern: str, topic: str) -> bool:
    """``mesh.*`` matches ``mesh.tasks``; exact match otherwise."""
    if pattern == topic:
        return True
    return fnmatch.fnmatchcase(topic, pattern)


class Transport(Protocol):
    """Pluggable wire. Implement this to span hosts."""

    async def publish(self, message: Message) -> None: ...

    def subscribe(self, pattern: str) -> AsyncIterator[Message]: ...

    async def close(self) -> None: ...


class _Subscription:
    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.queue: "asyncio.Queue[Message]" = asyncio.Queue()

    async def __aiter__(self) -> AsyncIterator[Message]:  # pragma: no cover
        while True:
            yield await self.queue.get()


class InProcessBus:
    """An in-memory asyncio pub/sub broker.

    Thread-safety note: this is single-event-loop. Run every agent in the same
    loop (see :func:`security_seti.coordinator.run_mesh`) or put a real
    :class:`Transport` behind :class:`Bus` for multi-process use.
    """

    def __init__(self) -> None:
        self._subs: List[_Subscription] = []
        self._log: List[Message] = []          # full audit trail (bounded below)
        self._log_cap = 10_000
        self._closed = False

    async def publish(self, message: Message) -> None:
        if self._closed:
            raise RuntimeError("bus is closed")
        self._log.append(message)
        if len(self._log) > self._log_cap:
            self._log = self._log[-self._log_cap :]
        for sub in list(self._subs):
            if topic_matches(sub.pattern, message.topic):
                await sub.queue.put(message)

    def subscribe(self, pattern: str = "*") -> AsyncIterator[Message]:
        sub = _Subscription(pattern)
        self._subs.append(sub)

        async def _iter() -> AsyncIterator[Message]:
            try:
                while not self._closed:
                    yield await sub.queue.get()
            finally:
                if sub in self._subs:
                    self._subs.remove(sub)

        return _iter()

    @property
    def audit_log(self) -> List[Message]:
        """Every message seen, oldest first (bounded)."""
        return list(self._log)

    async def close(self) -> None:
        self._closed = True


class Bus:
    """The interface agents use. Wraps a transport (in-process by default)."""

    def __init__(self, transport: Optional[Transport] = None) -> None:
        self._t = transport or InProcessBus()

    async def publish(self, message: Message) -> None:
        await self._t.publish(message)

    def subscribe(self, pattern: str = "*") -> AsyncIterator[Message]:
        return self._t.subscribe(pattern)

    async def request(
        self, message: Message, *, timeout: float = 30.0
    ) -> Optional[Message]:
        """Publish and await the first message whose ``reply_to`` is ``message.id``."""
        sub = self.subscribe("*")

        async def _wait() -> Optional[Message]:
            async for m in sub:
                if m.reply_to == message.id:
                    return m
            return None

        waiter = asyncio.ensure_future(_wait())
        await self.publish(message)
        try:
            return await asyncio.wait_for(waiter, timeout=timeout)
        except asyncio.TimeoutError:
            waiter.cancel()
            return None

    @property
    def transport(self) -> Transport:
        return self._t

    async def close(self) -> None:
        await self._t.close()
