import json
import sqlite3
import time

from security_seti.dashboard import build_state


def _journal(path, msgs):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE hub_journal (seq INTEGER PRIMARY KEY AUTOINCREMENT,"
               " topic TEXT, raw TEXT, ts REAL)")
    now = time.time()
    for m in msgs:
        db.execute("INSERT INTO hub_journal (topic, raw, ts) VALUES (?,?,?)",
                   (m.get("topic", "mesh"), json.dumps(m), now))
    db.commit()
    db.close()


def test_build_state_reconstructs_mesh(tmp_path):
    path = str(tmp_path / "ledger.db")
    _journal(path, [
        {"type": "announce", "sender": "crypto-0", "topic": "mesh.presence",
         "payload": {"name": "crypto-0", "capabilities": ["cryptanalysis", "differential"]}},
        {"type": "goal", "sender": "coordinator", "topic": "mesh.goals",
         "payload": {"goal_id": "g1", "description": "reduced SPECK32 differentials"}},
        {"type": "hypothesis", "sender": "crypto-0", "topic": "mesh.hypotheses",
         "payload": {"id": "h1", "statement": "0x0040 biased", "novelty": 0.9,
                     "proposed_by": "crypto-0"}},
        {"type": "fact", "sender": "crypto-0", "topic": "mesh.facts",
         "payload": {"statement": "0x0040 -> 0x8000 p~2^-3", "confidence": 0.9,
                     "hypothesis_id": "h1", "produced_by": "crypto-0",
                     "value": {"prob_bits": 3.0}}},
        {"type": "finding", "sender": "crypto-0", "topic": "mesh.findings",
         "payload": {"title": "3-round characteristic", "summary": "p~2^-3",
                     "severity": "info", "produced_by": "crypto-0"}},
    ])

    s = build_state(path)
    assert s["counts"]["agents_online"] == 1
    assert s["counts"]["hypotheses"] == 1
    assert s["counts"]["facts"] == 1
    assert s["counts"]["findings"] == 1
    assert s["agents"][0]["name"] == "crypto-0"
    assert "differential" in s["agents"][0]["capabilities"]
    # a high-confidence fact promotes its hypothesis to confirmed
    assert s["hypotheses"][0]["status"] == "confirmed"
    assert s["findings"][0]["title"] == "3-round characteristic"
    assert len(s["messages"]) == 5


def test_build_state_missing_db_is_empty(tmp_path):
    s = build_state(str(tmp_path / "nope.db"))
    assert s["agents"] == [] and s["counts"] == {}
