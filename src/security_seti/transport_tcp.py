"""A TCP hub transport: the decentralized rendezvous for a multi-host mesh.

The in-process bus (`bus.py`) is one machine. This turns the *same* `Bus`
interface into a networked mesh: run one `HubServer` (the hub), and every agent
anywhere opens a `TcpTransport` to it. Agents, the coordinator, the store — none
of them change; only the transport does.

Pure standard library (asyncio streams, newline-delimited JSON) so it runs and
tests anywhere with no dependencies. The hub can optionally persist every message
to a SQLite journal and **replay recent history to a newly-connecting agent** —
that replay is what makes the hub the shared ledger node: deploy it (Docker /
Akash) and it is where the moltbook lives for the whole mesh.

Production notes (see docs/DECENTRALIZED.md): terminate TLS in front of the hub,
use the shared-token auth below at minimum, and swap in NATS/Redis or libp2p for
scale. The token is a coarse membership gate, not a substitute for the scope and
approval layers, which still apply on every node.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from typing import AsyncIterator, List, Optional, Set

from .bus import Transport, topic_matches
from .protocol import Message


def _frame(obj: dict) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


# --------------------------------------------------------------------------- #
# Client side
# --------------------------------------------------------------------------- #


class _LocalSub:
    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.queue: "asyncio.Queue[Message]" = asyncio.Queue()


class TcpTransport:
    """Client transport. Hand it to `Bus(TcpTransport(host, port))`."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765,
                 token: Optional[str] = None) -> None:
        self.host = host
        self.port = port
        self.token = token
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._subs: List[_LocalSub] = []
        self._sent_patterns: Set[str] = set()
        self._wlock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Future] = None
        self._closed = False

    async def _connect(self) -> None:
        if self._writer is not None:
            return
        self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
        self._writer.write(_frame({"op": "hello", "token": self.token or ""}))
        await self._writer.drain()
        line = await self._reader.readline()
        resp = json.loads(line.decode("utf-8")) if line else {}
        if resp.get("op") != "welcome":
            raise ConnectionError(f"hub rejected connection: {resp.get('reason')}")
        self._reader_task = asyncio.ensure_future(self._read_loop())

    async def _read_loop(self) -> None:
        assert self._reader is not None
        try:
            while not self._closed:
                line = await self._reader.readline()
                if not line:
                    break
                frame = json.loads(line.decode("utf-8"))
                if frame.get("op") != "msg":
                    continue
                msg = Message.from_json(json.dumps(frame["msg"]))
                for sub in list(self._subs):
                    if topic_matches(sub.pattern, msg.topic):
                        await sub.queue.put(msg)
        except (asyncio.CancelledError, ConnectionError, json.JSONDecodeError):
            pass

    async def _send(self, obj: dict) -> None:
        assert self._writer is not None
        async with self._wlock:
            self._writer.write(_frame(obj))
            await self._writer.drain()

    async def publish(self, message: Message) -> None:
        await self._connect()
        await self._send({"op": "pub", "msg": json.loads(message.to_json())})

    def subscribe(self, pattern: str = "*") -> AsyncIterator[Message]:
        sub = _LocalSub(pattern)
        self._subs.append(sub)

        async def _iter() -> AsyncIterator[Message]:
            await self._connect()
            if pattern not in self._sent_patterns:
                self._sent_patterns.add(pattern)
                await self._send({"op": "sub", "pattern": pattern})
            try:
                while not self._closed:
                    yield await sub.queue.get()
            finally:
                if sub in self._subs:
                    self._subs.remove(sub)

        return _iter()

    async def close(self) -> None:
        self._closed = True
        if self._reader_task:
            self._reader_task.cancel()
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._writer = None


# --------------------------------------------------------------------------- #
# Hub (server) side
# --------------------------------------------------------------------------- #


class _ClientConn:
    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self.writer = writer
        self.patterns: Set[str] = set()
        self.authed = False
        self.lock = asyncio.Lock()

    async def send(self, obj: dict) -> None:
        async with self.lock:
            self.writer.write(_frame(obj))
            await self.writer.drain()


class HubServer:
    """The decentralized rendezvous point. Run one; agents connect to it.

    With `store_path`, every message is journaled and the last `replay_limit`
    matching messages are replayed to each new subscriber — so an agent that joins
    late inherits the shared history instead of starting blind.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8765,
                 token: Optional[str] = None, store_path: Optional[str] = None,
                 replay_limit: int = 500) -> None:
        self.host = host
        self.port = port
        self.token = token or ""
        self.replay_limit = replay_limit
        self._clients: List[_ClientConn] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._db: Optional[sqlite3.Connection] = None
        if store_path:
            self._db = sqlite3.connect(store_path)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS hub_journal "
                "(seq INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT, raw TEXT, ts REAL)"
            )
            if store_path != ":memory:":
                # WAL lets the live dashboard read the ledger while the hub writes.
                try:
                    self._db.execute("PRAGMA journal_mode=WAL;")
                except sqlite3.OperationalError:
                    pass
            self._db.commit()

    async def start(self) -> asyncio.AbstractServer:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        return self._server

    async def serve_forever(self) -> None:
        await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    @property
    def bound_port(self) -> Optional[int]:
        if not self._server:
            return None
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        client = _ClientConn(writer)
        self._clients.append(client)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    frame = json.loads(line.decode("utf-8"))
                except ValueError:
                    continue
                op = frame.get("op")
                if op == "hello":
                    if self.token and frame.get("token", "") != self.token:
                        await client.send({"op": "denied", "reason": "bad token"})
                        break
                    client.authed = True
                    await client.send({"op": "welcome"})
                elif not client.authed:
                    await client.send({"op": "denied", "reason": "not authenticated"})
                    break
                elif op == "sub":
                    pattern = frame.get("pattern", "*")
                    client.patterns.add(pattern)
                    await self._replay(client, pattern)
                elif op == "pub":
                    msgd = frame.get("msg") or {}
                    topic = msgd.get("topic", "mesh")
                    self._journal(topic, msgd)
                    await self._fanout(topic, msgd)
        finally:
            if client in self._clients:
                self._clients.remove(client)
            writer.close()

    def _journal(self, topic: str, msgd: dict) -> None:
        if self._db is None:
            return
        self._db.execute(
            "INSERT INTO hub_journal (topic, raw, ts) VALUES (?,?,?)",
            (topic, json.dumps(msgd), time.time()),
        )
        self._db.commit()

    async def _replay(self, client: _ClientConn, pattern: str) -> None:
        if self._db is None:
            return
        rows = self._db.execute(
            "SELECT topic, raw FROM hub_journal ORDER BY seq DESC LIMIT ?",
            (self.replay_limit,),
        ).fetchall()
        for topic, raw in reversed(rows):   # oldest first
            if topic_matches(pattern, topic):
                await client.send({"op": "msg", "msg": json.loads(raw)})

    async def _fanout(self, topic: str, msgd: dict) -> None:
        for c in list(self._clients):
            if any(topic_matches(p, topic) for p in c.patterns):
                try:
                    await c.send({"op": "msg", "msg": msgd})
                except Exception:  # noqa: BLE001
                    pass

    def journal_count(self) -> int:
        if self._db is None:
            return 0
        return int(self._db.execute("SELECT COUNT(*) FROM hub_journal").fetchone()[0])
