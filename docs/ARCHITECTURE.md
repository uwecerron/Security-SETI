# Architecture

The full, living architecture & build-plan document (with diagrams and the
strategic plan — novelty, distribution, monetization) lives here:

**https://claude.ai/artifact/Qg8h8TFDP2CKdEMaiLreU5**

This file is the in-repo summary.

## The loop

security_seti runs one loop, over and over, across many agents:

```
observe → hypothesize → design experiment → run → write back (evidence) → re-plan
```

- The **LLM / agent logic** owns *hypothesize* and *re-plan* — the ideas and the
  judgement.
- **Compute** owns *run* and *write back* — the proof.

Keeping those separate is what makes an output a finding instead of a
plausible-sounding paragraph.

## Components

| Module | Role |
|---|---|
| `protocol` | the message envelope + hypothesis/fact/finding/evidence types |
| `bus` | asyncio pub/sub broker; pluggable `Transport` for multi-host |
| `store` | sqlite knowledge base + journal (the mesh's memory) |
| `scope` | deny-by-default authorization, argv policy, approval gating |
| `agent` | base SDK: announce, claim tasks, propose, record, critique |
| `coordinator` | seed goals, score novelty, offer tasks, judge confidence |
| `adapters` | wrap ARTEX, Metasploit, generic CLI tools |
| `agents` | example recon + differential-cryptanalysis agents |
| `ciphers` | round-reduced SPECK32, a verifiable attack target |

## Two graphs, like ARTEX

ARTEX keeps an asset graph (what exists) and an exploration graph (what was
tried). security_seti's store is the mesh-wide version:

- **hypotheses** — what's been proposed, with novelty and status
  (open/confirmed/refuted/abandoned)
- **facts** — measured results, each bound to reproducible evidence
- **findings** — conclusions citing facts, scoped to authorized targets
- **journal** — every message, for audit

## Why reduced SPECK first

Round-reduced SPECK32 is the proving ground because genuine differential, linear,
and structural attacks are tractable *and checkable against ground truth*. The
agent measures a differential's probability empirically and reports the number it
actually observed — the same discipline a pentest worker uses when it binds a
finding to the captured request/response.

## Known simplifications (v0.1)

- In-process bus; multi-host needs a real `Transport`.
- At-least-once task execution (no claim lock); duplicate runs cross-validate.
- Novelty is string/signature-based; a learned embedding would score semantic
  novelty better.
