import asyncio

import pytest

from security_seti.bus import Bus, InProcessBus, topic_matches
from security_seti.protocol import Message, MessageType


def test_topic_matches():
    assert topic_matches("mesh.tasks", "mesh.tasks")
    assert topic_matches("mesh.*", "mesh.tasks")
    assert topic_matches("*", "anything.at.all")
    assert not topic_matches("mesh.tasks", "mesh.facts")


@pytest.mark.asyncio
async def test_pub_sub_delivers():
    bus = Bus()
    sub = bus.subscribe("mesh.*")
    received = []

    async def reader():
        async for m in sub:
            received.append(m)
            break

    task = asyncio.ensure_future(reader())
    await asyncio.sleep(0.05)
    await bus.publish(Message(type=MessageType.FACT, topic="mesh.facts", sender="s"))
    await asyncio.wait_for(task, timeout=2.0)
    assert len(received) == 1
    assert received[0].type is MessageType.FACT


@pytest.mark.asyncio
async def test_wildcard_scope():
    bus = Bus()
    sub = bus.subscribe("crypto.*")
    got = []

    async def reader():
        async for m in sub:
            got.append(m.topic)
            if len(got) == 1:
                break

    task = asyncio.ensure_future(reader())
    await asyncio.sleep(0.05)
    await bus.publish(Message(type=MessageType.FACT, topic="other.x"))
    await bus.publish(Message(type=MessageType.FACT, topic="crypto.speck"))
    await asyncio.wait_for(task, timeout=2.0)
    assert got == ["crypto.speck"]


@pytest.mark.asyncio
async def test_request_reply():
    bus = Bus()

    async def responder():
        sub = bus.subscribe("*")
        async for m in sub:
            if m.type is MessageType.APPROVAL_REQ:
                await bus.publish(Message(
                    type=MessageType.APPROVAL_RES, topic="mesh.approvals",
                    reply_to=m.id, payload={"approved": True},
                ))
                break

    task = asyncio.ensure_future(responder())
    await asyncio.sleep(0.05)
    req = Message(type=MessageType.APPROVAL_REQ, topic="mesh.approvals", sender="a")
    res = await bus.request(req, timeout=2.0)
    await asyncio.wait_for(task, timeout=2.0)
    assert res is not None and res.payload["approved"] is True


def test_audit_log_records():
    async def go():
        t = InProcessBus()
        await t.publish(Message(type=MessageType.GOAL, topic="mesh.goals"))
        return t.audit_log

    log = asyncio.run(go())
    assert len(log) == 1
