"""security_seti — a coordination mesh for autonomous security-research agents.

The anti-distributed.net: instead of handing out fixed work units to grind a
known search space, security_seti lets autonomous agents *propose and test novel
attack vectors*, share evidence, and build on one another's findings over a
common bus.

Core pieces:
    protocol    the message schema agents speak
    bus         an async pub/sub broker (in-process; pluggable transport)
    store       a sqlite knowledge store with provenance / evidence binding
    scope       authorization + rules-of-engagement gate (authorized targets only)
    agent       the base Agent SDK
    coordinator goal seeding + novelty-aware orchestration
    adapters    wrappers for external toolkits (Metasploit, ARTEX, generic CLI)
    agents      example agents (recon, differential cryptanalysis)

Only ever point this at assets you own or have written authorization to test.
"""

__version__ = "0.1.0"

from .protocol import (  # noqa: F401
    Message,
    MessageType,
    Finding,
    Fact,
    Hypothesis,
    new_id,
)

__all__ = [
    "Message",
    "MessageType",
    "Finding",
    "Fact",
    "Hypothesis",
    "new_id",
    "__version__",
]
