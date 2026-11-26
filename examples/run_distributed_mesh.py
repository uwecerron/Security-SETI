"""Run the mesh over the network: one hub, a coordinator and an agent as separate
clients, all talking TCP. This is the single-process demo of the distributed
path; in a real deployment you run `security-seti hub` on one host (or on Akash)
and the agents anywhere else.

Run:  python examples/run_distributed_mesh.py
"""

from __future__ import annotations

import asyncio

from security_seti.agents.cryptanalysis import DifferentialCryptanalysisAgent
from security_seti.bus import Bus
from security_seti.coordinator import Coordinator
from security_seti.scope import Authorization, Scope
from security_seti.store import Store
from security_seti.transport_tcp import HubServer, TcpTransport


async def main() -> None:
    # 1. the hub (broker + shared ledger). On its own host this is `security-seti hub`.
    hub = HubServer(host="127.0.0.1", port=0, store_path=":memory:")
    await hub.start()
    port = hub.bound_port
    print(f"hub up on 127.0.0.1:{port}")

    scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))

    # 2. a coordinator and an agent, each a separate client over TCP
    coord = Coordinator(Bus(TcpTransport("127.0.0.1", port)),
                        Store(":memory:", scope=scope), scope,
                        approve=lambda _m: True)
    agent = DifferentialCryptanalysisAgent(
        Bus(TcpTransport("127.0.0.1", port)),
        Store(":memory:", scope=scope), scope, name="crypto-remote")
    agent.samples = 4000
    agent.max_rounds = 4

    # 3. a sniffer so we can print findings as they come back over the wire
    sniffer = Bus(TcpTransport("127.0.0.1", port))
    findings = []
    fsub = sniffer.subscribe("mesh.findings")

    async def watch() -> None:
        async for m in fsub:
            findings.append(m)
            print(f"  finding over the wire: {m.payload.get('summary', '')}")

    tasks = [asyncio.ensure_future(coord.start()),
             asyncio.ensure_future(agent.start()),
             asyncio.ensure_future(watch())]

    await asyncio.sleep(0.4)
    await coord.seed_goal("reduced SPECK32 differentials", "",
                          {"kind": "cryptanalysis", "rounds": 3, "samples": 4000})
    await asyncio.sleep(6.0)

    await coord.stop()
    await agent.stop()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\n{len(findings)} finding(s) travelled over the hub; "
          f"ledger journaled {hub.journal_count()} messages.")

    # close the client sockets so the process exits cleanly
    for b in (coord.bus, agent.bus, sniffer):
        await b.close()
    await hub.stop()


if __name__ == "__main__":
    asyncio.run(main())
