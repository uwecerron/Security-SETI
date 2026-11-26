"""The coordinator: seeds goals and keeps the mesh pointed at *novel* vectors.

Its job is not to hand out fixed work units (that would be distributed.net). Its
job is to:

* seed a GOAL,
* turn open hypotheses into TASK_OFFERs,
* score each new hypothesis for **novelty** against everything already tried, so
  the mesh rewards proposing new attack vectors over re-grinding known ones,
* mark hypotheses confirmed / refuted / abandoned as facts arrive,
* optionally answer approval requests (auto-deny by default — fail safe).

``run_mesh`` is a convenience to spin up a coordinator and a set of agents in one
event loop for local, single-host runs.
"""

from __future__ import annotations

import asyncio
import difflib
from typing import Any, Callable, Dict, List, Optional

from .agent import Agent
from .bus import Bus
from .protocol import Hypothesis, Message, MessageType, new_id
from .scope import Scope
from .store import Store


#: test-spec keys that don't define the attack vector (don't count toward novelty)
_VOLATILE_SPEC_KEYS = {"samples", "seed", "requires"}


def _signature(test_spec: Dict[str, Any]) -> str:
    """A canonical string for the attack *vector* a hypothesis tests.

    Novelty must reward a new vector (a different input difference, round count,
    technique), not a reworded sentence. Volatile params (sample size, RNG seed)
    are excluded so re-running the same vector with more samples still reads as a
    duplicate, while a genuinely different vector reads as novel.
    """
    items = sorted(
        (k, v) for k, v in (test_spec or {}).items() if k not in _VOLATILE_SPEC_KEYS
    )
    return ";".join(f"{k}={v}" for k, v in items)


def _novelty(signature: str, prior_signatures: List[str]) -> float:
    """1.0 = unlike anything tried; 0.0 = an exact repeat of a past vector."""
    if not signature:
        return 1.0
    if signature in prior_signatures:
        return 0.0
    if not prior_signatures:
        return 1.0
    best = 0.0
    for s in prior_signatures:
        best = max(best, difflib.SequenceMatcher(None, signature, s).ratio())
    return round(1.0 - best, 3)


class Coordinator:
    def __init__(
        self,
        bus: Bus,
        store: Store,
        scope: Scope,
        *,
        novelty_floor: float = 0.15,
        approve: Optional[Callable[[Message], bool]] = None,
    ) -> None:
        self.bus = bus
        self.store = store
        self.scope = scope
        self.novelty_floor = novelty_floor
        self.name = "coordinator"
        self._running = False
        # vectors already accepted/offered, per goal — so duplicate proposals
        # from different agents are coalesced, not fought over.
        self._seen_sigs: Dict[str, set] = {}
        # default: auto-DENY every approval (fail safe). Override for a lab.
        self._approve = approve or (lambda _m: False)

    async def start(self) -> None:
        self._running = True
        await asyncio.gather(self._listen())

    async def stop(self) -> None:
        self._running = False

    async def seed_goal(self, description: str, target: str = "", meta: Optional[Dict] = None) -> str:
        if target:
            self.scope.require_target(target)   # refuse out-of-scope goals up front
        goal_id = new_id("goal")
        msg = Message(
            type=MessageType.GOAL, topic="mesh.goals", sender=self.name,
            payload={"goal_id": goal_id, "description": description,
                     "target": target, "meta": meta or {}},
        )
        self.store.journal_message(msg)
        await self.bus.publish(msg)
        return goal_id

    async def _listen(self) -> None:
        async for msg in self.bus.subscribe("*"):
            if not self._running:
                break
            if msg.sender == self.name:
                continue
            if msg.type is MessageType.HYPOTHESIS:
                await self._on_hypothesis(msg)
            elif msg.type is MessageType.FACT:
                await self._on_fact(msg)
            elif msg.type is MessageType.APPROVAL_REQ:
                await self._on_approval(msg)

    async def _on_hypothesis(self, msg: Message) -> None:
        h = Hypothesis(**{k: v for k, v in msg.payload.items()
                          if k in Hypothesis.__dataclass_fields__})
        sig = _signature(h.test_spec)
        seen = self._seen_sigs.setdefault(h.goal_id, set())

        # Coalesce: the same vector proposed again (e.g. by another agent) is not
        # a novelty failure, it's a duplicate — accept it quietly without a second
        # offer so agents don't fight over identical work.
        if sig in seen:
            self.store.add_hypothesis(h)
            self.store.set_hypothesis_status(h.id, "abandoned")
            return

        # Judge novelty on the attack vector against what we've already accepted.
        h.novelty = _novelty(sig, list(seen))
        self.store.add_hypothesis(h)

        if h.novelty < self.novelty_floor:
            # Too close to something already tried: don't spend workers on it.
            await self.bus.publish(Message(
                type=MessageType.CRITIQUE, topic="mesh.critiques", sender=self.name,
                reply_to=msg.id,
                payload={"about": h.id, "verdict": "stale",
                         "reason": f"novelty {h.novelty} below floor {self.novelty_floor}; "
                                   "propose a new vector rather than re-running a known one"},
            ))
            self.store.set_hypothesis_status(h.id, "abandoned")
            return

        seen.add(sig)

        # Offer it as a task, ranked implicitly by the order agents see it.
        await self.bus.publish(Message(
            type=MessageType.TASK_OFFER, topic="tasks.offers", sender=self.name,
            payload={"task_id": h.id, "goal_id": h.goal_id,
                     "requires": (h.test_spec or {}).get("requires", []),
                     "hypothesis": h.to_dict(),
                     "test_spec": h.test_spec},
        ))

    async def _on_fact(self, msg: Message) -> None:
        hyp_id = msg.payload.get("hypothesis_id")
        if not hyp_id:
            return
        conf = float(msg.payload.get("confidence", 0.0))
        # Simple decision rule; richer policies can read all facts for the hyp.
        if conf >= 0.8:
            self.store.set_hypothesis_status(hyp_id, "confirmed")
        elif conf <= 0.05:
            self.store.set_hypothesis_status(hyp_id, "refuted")

    async def _on_approval(self, msg: Message) -> None:
        approved = bool(self._approve(msg))
        await self.bus.publish(Message(
            type=MessageType.APPROVAL_RES, topic="mesh.approvals", sender=self.name,
            reply_to=msg.id, payload={"approved": approved},
        ))


async def run_mesh(
    agents: List[Agent],
    *,
    bus: Bus,
    store: Store,
    scope: Scope,
    goal: Optional[Dict[str, Any]] = None,
    run_seconds: float = 5.0,
    approve: Optional[Callable[[Message], bool]] = None,
) -> Store:
    """Spin up a coordinator + agents, optionally seed a goal, run, then stop.

    Returns the store so the caller can read findings. For local runs/tests.
    """
    coord = Coordinator(bus, store, scope, approve=approve)
    tasks = [asyncio.ensure_future(coord.start())]
    tasks += [asyncio.ensure_future(a.start()) for a in agents]

    await asyncio.sleep(0.2)  # let everyone announce/subscribe
    if goal:
        await coord.seed_goal(
            goal.get("description", ""),
            goal.get("target", ""),
            goal.get("meta"),
        )

    await asyncio.sleep(run_seconds)

    await coord.stop()
    for a in agents:
        await a.stop()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    return store
