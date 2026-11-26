"""The wire protocol agents speak on the mesh.

Everything is a :class:`Message`. Messages carry a ``type`` drawn from
:class:`MessageType`, a ``topic`` for routing, and a JSON-serialisable
``payload``. Three payload shapes recur often enough to get dataclasses of
their own: :class:`Hypothesis`, :class:`Fact`, and :class:`Finding`.

Design intent (from the thread that started this project): the mesh is for
*proposing and testing novel attack vectors*, not scaling known searches. So the
protocol makes hypotheses first-class, binds every fact to the exact evidence
that produced it, and lets any agent CRITIQUE another's claim.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


def new_id(prefix: str = "msg") -> str:
    """A short, sortable-enough unique id."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def now() -> float:
    return time.time()


class MessageType(str, Enum):
    """The verbs of the mesh.

    Coordination:
        ANNOUNCE      an agent joins and advertises its capabilities
        GOAL          a top-level objective is seeded into the mesh
        TASK_OFFER    the coordinator (or any agent) offers a unit of work
        TASK_CLAIM    an agent claims an offered task
        TASK_DONE     a claimed task is finished (success or give-up)
        HEARTBEAT     an agent is still alive

    Knowledge (the part that makes it reasoning, not crunching):
        HYPOTHESIS    a proposed, testable idea ("4-round differential, p≈2^-12")
        FACT          a measured, evidence-bound result
        FINDING       a consequential conclusion assembled from facts
        CRITIQUE      a challenge to a hypothesis/fact/finding (peer review)

    Control:
        APPROVAL_REQ  an intrusive action needs human sign-off
        APPROVAL_RES  the human answered
        ERROR         something went wrong
    """

    ANNOUNCE = "announce"
    GOAL = "goal"
    TASK_OFFER = "task_offer"
    TASK_CLAIM = "task_claim"
    TASK_DONE = "task_done"
    HEARTBEAT = "heartbeat"

    HYPOTHESIS = "hypothesis"
    FACT = "fact"
    FINDING = "finding"
    CRITIQUE = "critique"

    APPROVAL_REQ = "approval_req"
    APPROVAL_RES = "approval_res"
    ERROR = "error"


# --------------------------------------------------------------------------- #
# Knowledge payloads
# --------------------------------------------------------------------------- #


@dataclass
class Evidence:
    """What proves a fact. The anti-hallucination anchor.

    A fact without reproducible evidence is just an assertion. ``script`` +
    ``params`` + ``seed`` must be enough to re-run and reproduce ``value``.
    """

    tool: str = ""                       # "trail_search", "msfconsole", ...
    script: str = ""                     # path or inline source that produced it
    params: Dict[str, Any] = field(default_factory=dict)
    seed: Optional[int] = None
    stdout_digest: str = ""              # sha256 of captured output, for audit
    artifacts: List[str] = field(default_factory=list)  # paths to pcaps, logs

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Hypothesis:
    """A proposed, testable idea. First-class, because the point is to propose.

    ``statement`` is human-readable; ``test_spec`` tells a worker exactly how to
    confirm or kill it; ``prior`` is the proposer's rough confidence [0, 1].
    """

    id: str = field(default_factory=lambda: new_id("hyp"))
    goal_id: str = ""
    statement: str = ""
    test_spec: Dict[str, Any] = field(default_factory=dict)
    prior: float = 0.5
    novelty: float = 0.5                 # how unlike prior attempts (coordinator sets)
    parent_id: Optional[str] = None      # a refinement of an earlier hypothesis
    proposed_by: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Fact:
    """A measured result, bound to the evidence that produced it."""

    id: str = field(default_factory=lambda: new_id("fact"))
    hypothesis_id: Optional[str] = None
    statement: str = ""                  # "input diff 0x0040 -> output diff 0x8000"
    value: Any = None                    # measured quantity (prob, bias, count)
    confidence: float = 0.0              # [0, 1], from sample size / statistics
    evidence: Evidence = field(default_factory=Evidence)
    produced_by: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class Finding:
    """A consequential conclusion, assembled from one or more facts.

    ``severity`` is advisory: "info" | "low" | "medium" | "high" | "critical".
    ``target`` must fall inside the authorized scope or the store will reject it.
    """

    id: str = field(default_factory=lambda: new_id("find"))
    goal_id: str = ""
    title: str = ""
    summary: str = ""
    severity: str = "info"
    target: str = ""
    fact_ids: List[str] = field(default_factory=list)
    remediation: str = ""
    produced_by: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# The envelope
# --------------------------------------------------------------------------- #


@dataclass
class Message:
    """The envelope every agent sends and receives."""

    type: MessageType
    topic: str = "mesh"
    payload: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("msg"))
    sender: str = ""
    reply_to: Optional[str] = None       # id of the message this answers
    ts: float = field(default_factory=now)

    # -- serialisation ----------------------------------------------------- #

    def to_json(self) -> str:
        d = asdict(self)
        d["type"] = self.type.value
        return json.dumps(d, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "Message":
        d = json.loads(raw)
        d["type"] = MessageType(d["type"])
        # Only keep known fields so forward-compatible extensions don't crash us.
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{self.type.value} topic={self.topic} from={self.sender or '?'}>"
