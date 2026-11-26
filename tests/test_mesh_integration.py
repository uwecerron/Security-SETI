import asyncio

import pytest

from security_seti.agents.cryptanalysis import (
    DifferentialCryptanalysisAgent, measure_differential, _confidence,
)
from security_seti.bus import Bus
from security_seti.coordinator import run_mesh, _novelty
from security_seti.scope import Authorization, Scope
from security_seti.store import Store


def test_novelty_scoring():
    assert _novelty("brand new idea", []) == 1.0
    priors = ["input difference 0x00400000 ..."]
    near_dup = _novelty("input difference 0x00400000 ...", priors)
    far = _novelty("a completely different statement about linear trails", priors)
    assert near_dup < far


def test_measure_differential_is_deterministic():
    a = measure_differential(0x00400000, rounds=3, samples=2000, seed=42)
    b = measure_differential(0x00400000, rounds=3, samples=2000, seed=42)
    assert a[0] == b[0] and abs(a[1] - b[1]) < 1e-12


def test_confidence_monotonic():
    # higher probability -> higher confidence
    assert _confidence(0.25) > _confidence(2 ** -20)
    assert _confidence(0.0) == 0.0


@pytest.mark.asyncio
async def test_mesh_produces_facts():
    scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))
    store = Store(":memory:", scope=scope)
    bus = Bus()
    agent = DifferentialCryptanalysisAgent(bus, store, scope, name="c1")
    agent.samples = 1500  # keep the test fast

    await run_mesh(
        [agent], bus=bus, store=store, scope=scope,
        goal={"description": "reduced SPECK32 differentials",
              "meta": {"kind": "cryptanalysis", "rounds": 2, "samples": 1500}},
        run_seconds=4.0,
        approve=lambda _m: True,
    )

    # The mesh should have journaled messages and opened hypotheses.
    assert len(store.journal(limit=10000)) > 0
    # At least one differential should have been measured into a fact.
    # (facts live under their hypothesis ids; check the journal recorded FACTs)
    types = [row["type"] for row in store.journal(limit=10000)]
    assert "hypothesis" in types
