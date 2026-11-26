import asyncio

import pytest

from security_seti.agents.cryptanalysis import DifferentialCryptanalysisAgent
from security_seti.bus import Bus
from security_seti.coordinator import Coordinator
from security_seti.protocol import Fact, Message, MessageType
from security_seti.scope import Authorization, Scope
from security_seti.store import Store
from security_seti.transport_tcp import HubServer, TcpTransport


async def _start_hub(**kw) -> HubServer:
    hub = HubServer(host="127.0.0.1", port=0, **kw)
    await hub.start()
    return hub


@pytest.mark.asyncio
async def test_pubsub_over_tcp():
    hub = await _start_hub()
    port = hub.bound_port
    sender = Bus(TcpTransport("127.0.0.1", port))
    receiver = Bus(TcpTransport("127.0.0.1", port))

    got = []
    sub = receiver.subscribe("mesh.*")

    async def reader():
        async for m in sub:
            got.append(m)
            break

    task = asyncio.ensure_future(reader())
    await asyncio.sleep(0.2)  # let the subscribe frame reach the hub
    await sender.publish(Message(type=MessageType.FACT, topic="mesh.facts",
                                 sender="a", payload={"x": 1}))
    await asyncio.wait_for(task, timeout=3.0)

    assert len(got) == 1
    assert got[0].type is MessageType.FACT
    assert got[0].payload == {"x": 1}

    await sender.close()
    await receiver.close()
    await hub.stop()


@pytest.mark.asyncio
async def test_wildcard_and_isolation_over_tcp():
    hub = await _start_hub()
    port = hub.bound_port
    sender = Bus(TcpTransport("127.0.0.1", port))
    receiver = Bus(TcpTransport("127.0.0.1", port))

    got = []
    sub = receiver.subscribe("crypto.*")

    async def reader():
        async for m in sub:
            got.append(m.topic)
            break

    task = asyncio.ensure_future(reader())
    await asyncio.sleep(0.2)
    await sender.publish(Message(type=MessageType.FACT, topic="other.x"))   # ignored
    await sender.publish(Message(type=MessageType.FACT, topic="crypto.speck"))
    await asyncio.wait_for(task, timeout=3.0)

    assert got == ["crypto.speck"]
    await sender.close()
    await receiver.close()
    await hub.stop()


@pytest.mark.asyncio
async def test_auth_rejects_bad_token():
    hub = await _start_hub(token="secret")
    port = hub.bound_port
    bad = TcpTransport("127.0.0.1", port, token="wrong")
    with pytest.raises(ConnectionError):
        await bad.publish(Message(type=MessageType.FACT, topic="mesh.facts"))
    # correct token works
    good = Bus(TcpTransport("127.0.0.1", port, token="secret"))
    await good.publish(Message(type=MessageType.FACT, topic="mesh.facts"))
    await good.close()
    await hub.stop()


@pytest.mark.asyncio
async def test_replay_to_late_joiner(tmp_path):
    db = str(tmp_path / "hub.db")
    hub = await _start_hub(store_path=db)
    port = hub.bound_port

    # publish before anyone is listening
    writer = Bus(TcpTransport("127.0.0.1", port))
    await writer.publish(Message(type=MessageType.FACT, topic="mesh.facts",
                                 sender="early", payload={"n": 1}))
    await asyncio.sleep(0.1)
    assert hub.journal_count() == 1

    # a late joiner subscribes and should receive the replayed history
    late = Bus(TcpTransport("127.0.0.1", port))
    got = []
    sub = late.subscribe("mesh.*")

    async def reader():
        async for m in sub:
            got.append(m)
            break

    task = asyncio.ensure_future(reader())
    await asyncio.wait_for(task, timeout=3.0)
    assert got[0].payload == {"n": 1}

    await writer.close()
    await late.close()
    await hub.stop()


@pytest.mark.asyncio
async def test_distributed_mesh_produces_findings(tmp_path):
    """Full end-to-end over the network: a coordinator and a crypto agent, each on
    their own Bus/Store, coordinate through one hub and produce a finding that a
    separate sniffer observes over TCP. Waits for the first finding, then tears
    down — bounded, so it can't run away."""
    db = str(tmp_path / "moltbook.db")
    hub = await _start_hub(store_path=db)
    port = hub.bound_port

    scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))

    coord_bus = Bus(TcpTransport("127.0.0.1", port))
    coord = Coordinator(coord_bus, Store(":memory:", scope=scope), scope,
                        approve=lambda _m: True)

    agent = DifferentialCryptanalysisAgent(
        Bus(TcpTransport("127.0.0.1", port)),
        Store(":memory:", scope=scope), scope, name="crypto-0")
    agent.samples = 800
    agent.max_rounds = 3

    sniffer = Bus(TcpTransport("127.0.0.1", port))
    first_finding = asyncio.Event()
    findings = []
    fsub = sniffer.subscribe("mesh.findings")

    async def sniff():
        async for m in fsub:
            findings.append(m)
            first_finding.set()

    tasks = [
        asyncio.ensure_future(coord.start()),
        asyncio.ensure_future(agent.start()),
        asyncio.ensure_future(sniff()),
    ]
    try:
        await asyncio.sleep(0.4)  # everyone connects and subscribes
        await coord.seed_goal("reduced SPECK32 differentials", "",
                              {"kind": "cryptanalysis", "rounds": 2, "samples": 800})
        await asyncio.wait_for(first_finding.wait(), timeout=25)
    finally:
        await coord.stop()
        await agent.stop()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for b in (coord_bus, agent.bus, sniffer):
            await b.close()
        await hub.stop()

    # A finding travelled back over the network, and the hub journaled the
    # shared conversation (the moltbook ledger node).
    assert len(findings) >= 1
    assert findings[0].type is MessageType.FINDING
    assert hub.journal_count() > 0
