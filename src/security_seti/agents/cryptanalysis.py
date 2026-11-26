"""A differential-cryptanalysis agent for round-reduced SPECK32.

This is the showcase for the project's thesis: *propose and test novel attack
vectors, don't scale known searches.* The agent

1. proposes several differential hypotheses (candidate input differences),
2. for each, **empirically measures** the differential's probability over random
   keys and plaintext pairs — real computation, not an assertion,
3. records a fact bound to the exact seed, sample size, and parameters, so anyone
   can reproduce the number,
4. promotes a sufficiently strong differential to a finding.

The coordinator scores each proposed input difference for novelty, so the mesh
keeps exploring new differences instead of re-measuring the same one.

Nothing here is a weapon: it analyses a cipher you are studying. The same loop
shape (propose → test → bind evidence → refine) is what a linear, integral, or
lattice agent would use.
"""

from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Optional, Tuple

from ..agent import Agent
from ..ciphers.speck import WORD, MASK, Speck32
from ..protocol import Evidence, Fact, Finding, Hypothesis, Message, new_id


def measure_differential(
    delta_in: int,
    rounds: int,
    samples: int,
    seed: int,
) -> Tuple[int, float, Dict[int, int]]:
    """Empirically measure the expected differential probability.

    Averages over random keys (expected differential probability). Returns the
    most frequent output difference, its empirical probability, and the raw
    histogram. Deterministic given ``seed`` — that is what makes it reproducible.
    """
    rng = random.Random(seed)
    dx = (delta_in >> WORD) & MASK
    dy = delta_in & MASK
    counts: Dict[int, int] = {}
    for _ in range(samples):
        key = [rng.getrandbits(WORD) for _ in range(4)]
        cipher = Speck32(key, rounds)
        x0, y0 = rng.getrandbits(WORD), rng.getrandbits(WORD)
        x1, y1 = x0 ^ dx, y0 ^ dy
        ox0, oy0 = cipher.encrypt(x0, y0)
        ox1, oy1 = cipher.encrypt(x1, y1)
        dout = ((ox0 ^ ox1) << WORD) | (oy0 ^ oy1)
        counts[dout] = counts.get(dout, 0) + 1
    best = max(counts, key=lambda k: counts[k])
    prob = counts[best] / samples
    return best, prob, counts


def _confidence(prob: float) -> float:
    """Map a differential probability to [0, 1].

    A specific 32-bit output difference occurs by chance with prob 2^-32. The
    closer the measured probability is to 2^0, the stronger the characteristic.
    """
    if prob <= 0:
        return 0.0
    bits = -math.log2(prob)                 # e.g. 2^-6 -> 6 bits
    return max(0.0, min(0.99, 1.0 - bits / 32.0))


class DifferentialCryptanalysisAgent(Agent):
    capabilities = ["cryptanalysis", "differential", "speck"]

    #: input differences to seed when a crypto goal arrives (single/low-weight
    #: differences are the usual starting points for ARX differentials)
    SEED_DIFFS: List[int] = [
        0x00400000,  # single bit, high word
        0x80000000,
        0x00000040,
        0x00008000,
        0x02110A04,  # a higher-weight difference, for contrast
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.rounds = 3
        self.samples = 20000
        self.finding_threshold = 0.8     # confidence to promote to a finding

    async def on_goal(self, msg: Message) -> None:
        meta = msg.payload.get("meta") or {}
        if meta.get("kind") != "cryptanalysis":
            return
        self.rounds = int(meta.get("rounds", self.rounds))
        self.samples = int(meta.get("samples", self.samples))
        goal_id = msg.payload.get("goal_id", "")
        for i, d in enumerate(meta.get("seed_diffs", self.SEED_DIFFS)):
            await self.propose_hypothesis(Hypothesis(
                goal_id=goal_id,
                statement=f"input difference 0x{d:08X} yields a biased "
                          f"{self.rounds}-round SPECK32 output difference",
                test_spec={
                    "requires": ["differential"],
                    "delta_in": d, "rounds": self.rounds,
                    "samples": self.samples, "seed": 0x5E71 + i,
                },
                prior=0.4,
                proposed_by=self.name,
            ))

    async def on_task(self, task: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        spec = task.get("test_spec") or {}
        if "delta_in" not in spec:
            return None
        delta_in = int(spec["delta_in"])
        rounds = int(spec.get("rounds", self.rounds))
        samples = int(spec.get("samples", self.samples))
        seed = int(spec.get("seed", 0x5E71))
        goal_id = task.get("goal_id", "")

        best, prob, _ = measure_differential(delta_in, rounds, samples, seed)
        conf = _confidence(prob)
        prob_bits = -math.log2(prob) if prob > 0 else float("inf")

        fact = Fact(
            id=new_id("fact"),
            hypothesis_id=task.get("task_id"),
            statement=(f"0x{delta_in:08X} -> 0x{best:08X} over {rounds}r SPECK32 "
                       f"with p ≈ 2^-{prob_bits:.1f}"),
            value={"delta_in": delta_in, "delta_out": best, "prob": prob,
                   "prob_bits": round(prob_bits, 2), "rounds": rounds},
            confidence=conf,
            evidence=Evidence(
                tool="measure_differential",
                script="security_seti.agents.cryptanalysis.measure_differential",
                params={"delta_in": delta_in, "rounds": rounds, "samples": samples},
                seed=seed,
            ),
            produced_by=self.name,
        )
        await self.record_fact(fact)

        if conf >= self.finding_threshold:
            await self.record_finding(Finding(
                goal_id=goal_id,
                title=f"{rounds}-round SPECK32 differential characteristic",
                summary=(f"Input difference 0x{delta_in:08X} propagates to "
                         f"0x{best:08X} with probability ≈ 2^-{prob_bits:.1f} "
                         f"over {rounds} rounds (measured, {samples} pairs)."),
                severity="info",
                target="",       # a cipher under study, not a network target
                fact_ids=[fact.id],
                remediation="Use the full round count; reduced-round SPECK is not secure.",
                produced_by=self.name,
            ))

        return {"delta_in": delta_in, "delta_out": best,
                "prob_bits": round(prob_bits, 2), "confidence": conf}

    async def on_fact(self, msg: Message) -> None:
        """Iterate: when a strong differential lands, propose a refinement.

        Reusing the same output difference as the next round's input difference is
        how multi-round characteristics are chained — a new, more ambitious
        hypothesis built on a confirmed one.
        """
        if msg.sender == self.name:
            return
        val = msg.payload.get("value") or {}
        if not isinstance(val, dict) or msg.payload.get("confidence", 0) < 0.7:
            return
        delta_out = val.get("delta_out")
        rounds = val.get("rounds", self.rounds)
        if delta_out is None:
            return
        # Propose extending the characteristic by one round.
        await self.propose_hypothesis(Hypothesis(
            statement=f"input difference 0x{delta_out:08X} extends the "
                      f"characteristic to {rounds + 1}-round SPECK32",
            test_spec={"requires": ["differential"], "delta_in": delta_out,
                       "rounds": rounds + 1, "samples": self.samples,
                       "seed": 0x5E71},
            prior=0.5,
            parent_id=msg.payload.get("hypothesis_id"),
            proposed_by=self.name,
        ))
