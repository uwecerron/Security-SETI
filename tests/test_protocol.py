from security_seti.protocol import (
    Evidence, Fact, Finding, Hypothesis, Message, MessageType, new_id,
)


def test_message_roundtrip():
    m = Message(
        type=MessageType.HYPOTHESIS, topic="mesh.hypotheses",
        payload={"a": 1, "b": [1, 2, 3]}, sender="agent-x",
    )
    raw = m.to_json()
    back = Message.from_json(raw)
    assert back.type is MessageType.HYPOTHESIS
    assert back.topic == "mesh.hypotheses"
    assert back.payload == {"a": 1, "b": [1, 2, 3]}
    assert back.sender == "agent-x"
    assert back.id == m.id


def test_from_json_ignores_unknown_fields():
    raw = '{"type":"fact","topic":"t","payload":{},"id":"x","sender":"s",' \
          '"reply_to":null,"ts":1.0,"future_field":"ignored"}'
    m = Message.from_json(raw)
    assert m.type is MessageType.FACT
    assert m.id == "x"


def test_new_id_unique_and_prefixed():
    ids = {new_id("hyp") for _ in range(1000)}
    assert len(ids) == 1000
    assert all(i.startswith("hyp_") for i in ids)


def test_fact_carries_evidence():
    f = Fact(statement="x->y", value={"p": 0.25},
             evidence=Evidence(tool="t", seed=7))
    assert f.evidence.seed == 7
    assert f.to_dict()["evidence"]["tool"] == "t"


def test_hypothesis_defaults():
    h = Hypothesis(statement="s")
    assert 0.0 <= h.prior <= 1.0
    assert h.id.startswith("hyp_")
