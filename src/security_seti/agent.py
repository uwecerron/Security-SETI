"""The base Agent SDK.

Subclass :class:`Agent`, declare ``capabilities``, and implement
:meth:`on_task` (and optionally :meth:`propose`). The base class handles joining
the mesh, announcing, heart-beating, claiming offered tasks that match your
capabilities, and the plumbing for posting hypotheses, facts, and findings with
provenance filled in.

An agent is the unit that *reasons and iterates*: it proposes hypotheses, runs
tests, reads what other agents have found, and refines. It is not a fixed work
unit.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from .bus import Bus
from .protocol import (
    Fact,
    Finding,
    Hypothesis,
    Message,
    MessageType,
    new_id,
)
from .scope import Scope
from .store import Store


class Agent:
    """Base class for every agent on the mesh."""

    #: topics this agent listens to; ``*`` for everything
    subscriptions: List[str] = ["mesh.*", "tasks.*"]
    #: capability tags the coordinator matches tasks against
    capabilities: List[str] = []

    def __init__(
        self,
        bus: Bus,
        store: Store,
        scope: Scope,
        name: Optional[str] = None,
    ) -> None:
        self.bus = bus
        self.store = store
        self.scope = scope
        self.name = name or f"{self.__class__.__name__.lower()}_{new_id('')[1:7]}"
        self._running = False
        self._claimed: set[str] = set()

    # -- lifecycle --------------------------------------------------------- #

    async def start(self) -> None:
        self._running = True
        await self.announce()
        await asyncio.gather(self._listen(), self._heartbeat())

    async def stop(self) -> None:
        self._running = False

    async def announce(self) -> None:
        await self.publish(
            MessageType.ANNOUNCE,
            topic="mesh.presence",
            payload={"name": self.name, "capabilities": self.capabilities},
        )

    async def _heartbeat(self, period: float = 15.0) -> None:
        while self._running:
            await asyncio.sleep(period)
            if not self._running:
                break
            await self.publish(MessageType.HEARTBEAT, topic="mesh.presence",
                               payload={"name": self.name})

    async def _listen(self) -> None:
        subs = [self.bus.subscribe(p) for p in self.subscriptions]

        async def pump(sub: Any) -> None:
            async for msg in sub:
                if not self._running:
                    break
                if msg.sender == self.name:
                    continue
                await self._dispatch(msg)

        await asyncio.gather(*(pump(s) for s in subs))

    async def _dispatch(self, msg: Message) -> None:
        try:
            if msg.type is MessageType.TASK_OFFER:
                await self._maybe_claim(msg)
            elif msg.type is MessageType.GOAL:
                await self.on_goal(msg)
            elif msg.type is MessageType.HYPOTHESIS:
                await self.on_hypothesis(msg)
            elif msg.type is MessageType.FACT:
                await self.on_fact(msg)
            elif msg.type is MessageType.CRITIQUE:
                await self.on_critique(msg)
        except Exception as exc:  # keep one bad message from killing the agent
            await self.publish(
                MessageType.ERROR, topic="mesh.errors",
                payload={"error": str(exc), "about": msg.id},
            )

    async def _maybe_claim(self, offer: Message) -> None:
        need = set(offer.payload.get("requires", []))
        if need and not need.issubset(set(self.capabilities)):
            return
        task_id = offer.payload.get("task_id", offer.id)
        if task_id in self._claimed:
            return
        self._claimed.add(task_id)
        await self.publish(
            MessageType.TASK_CLAIM, topic="tasks.claims",
            payload={"task_id": task_id}, reply_to=offer.id,
        )
        try:
            result = await self.on_task(offer.payload)
            await self.publish(
                MessageType.TASK_DONE, topic="tasks.done",
                payload={"task_id": task_id, "result": result or {}},
            )
        except Exception as exc:
            await self.publish(
                MessageType.TASK_DONE, topic="tasks.done",
                payload={"task_id": task_id, "error": str(exc), "ok": False},
            )

    # -- things subclasses override --------------------------------------- #

    async def on_task(self, task: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Do a unit of work. Return a small result dict. Override me."""
        return None

    async def on_goal(self, msg: Message) -> None:
        """A new goal was seeded. Optionally propose hypotheses. Override me."""

    async def on_hypothesis(self, msg: Message) -> None:
        """Another agent proposed an idea. React / critique / test. Override me."""

    async def on_fact(self, msg: Message) -> None:
        """A new measured fact landed. Build on it. Override me."""

    async def on_critique(self, msg: Message) -> None:
        """Someone challenged a claim. Respond. Override me."""

    # -- publishing helpers (provenance filled in) ------------------------- #

    async def publish(
        self,
        mtype: MessageType,
        topic: str = "mesh",
        payload: Optional[Dict[str, Any]] = None,
        reply_to: Optional[str] = None,
    ) -> Message:
        msg = Message(
            type=mtype, topic=topic, payload=payload or {},
            sender=self.name, reply_to=reply_to,
        )
        self.store.journal_message(msg)
        await self.bus.publish(msg)
        return msg

    async def propose_hypothesis(self, h: Hypothesis) -> Hypothesis:
        h.proposed_by = h.proposed_by or self.name
        self.store.add_hypothesis(h)
        await self.publish(MessageType.HYPOTHESIS, topic="mesh.hypotheses",
                           payload=h.to_dict())
        return h

    async def record_fact(self, f: Fact) -> Fact:
        f.produced_by = f.produced_by or self.name
        self.store.add_fact(f)
        await self.publish(MessageType.FACT, topic="mesh.facts", payload=f.to_dict())
        return f

    async def record_finding(self, f: Finding) -> Finding:
        f.produced_by = f.produced_by or self.name
        # scope is enforced inside the store; let it raise if out of scope
        self.store.add_finding(f)
        await self.publish(MessageType.FINDING, topic="mesh.findings",
                           payload=f.to_dict())
        return f

    async def critique(self, about_id: str, reason: str, verdict: str = "doubt") -> Message:
        return await self.publish(
            MessageType.CRITIQUE, topic="mesh.critiques",
            payload={"about": about_id, "reason": reason, "verdict": verdict},
        )

    async def request_approval(self, action_class: str, detail: Dict[str, Any]) -> bool:
        """Block for a human yes/no on an intrusive action.

        Returns False (deny) on timeout — fail safe. A real deployment wires
        APPROVAL_RES to a human console; the local coordinator auto-denies unless
        configured otherwise.
        """
        if not self.scope.needs_approval(action_class):
            return True
        req = Message(
            type=MessageType.APPROVAL_REQ, topic="mesh.approvals",
            sender=self.name,
            payload={"action_class": action_class, "detail": detail},
        )
        self.store.journal_message(req)
        res = await self.bus.request(req, timeout=120.0)
        return bool(res and res.payload.get("approved") is True)
