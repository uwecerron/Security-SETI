"""Spin up a local mesh and watch agents coordinate on a cryptanalysis goal.

Run:  python examples/run_local_mesh.py

Two cryptanalysis agents join the same mesh. The coordinator seeds a goal, scores
each proposed differential for novelty, and offers the surviving ones as tasks.
Agents measure them, record evidence-bound facts, and chain confirmed
characteristics into new hypotheses. At the end we print the findings and the
knowledge the mesh accumulated.
"""

from __future__ import annotations

import asyncio

from security_seti.agents.cryptanalysis import DifferentialCryptanalysisAgent
from security_seti.bus import Bus
from security_seti.coordinator import run_mesh
from security_seti.scope import Authorization, Scope
from security_seti.store import Store


async def main() -> None:
    scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))
    store = Store(":memory:", scope=scope)
    bus = Bus()

    agents = [
        DifferentialCryptanalysisAgent(bus, store, scope, name="crypto-1"),
        DifferentialCryptanalysisAgent(bus, store, scope, name="crypto-2"),
    ]

    await run_mesh(
        agents, bus=bus, store=store, scope=scope,
        goal={
            "description": "find biased differentials for reduced-round SPECK32",
            "meta": {"kind": "cryptanalysis", "rounds": 3, "samples": 15000},
        },
        run_seconds=8.0,
        approve=lambda _m: True,   # local lab: auto-approve
    )

    print("\n=== FINDINGS ===")
    for f in store.findings():
        print(f"[{f['severity']}] {f['title']}")
        print(f"    {f['summary']}")

    print("\n=== HYPOTHESES (by novelty) ===")
    for h in store.open_hypotheses():
        print(f"  novelty={h['novelty']:.2f}  {h['statement']}")

    print(f"\njournal entries: {len(store.journal(limit=10000))}")


if __name__ == "__main__":
    asyncio.run(main())
