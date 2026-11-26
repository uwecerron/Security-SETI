# Tutorial: your first run on the mesh

This walks you from a clean checkout to writing your own agent. It takes about ten
minutes and runs entirely on your machine. Nothing here touches a network or a
real target — the worked example analyses a toy cipher, which is just math.

## 0. What you'll do

1. Install the package.
2. Run the built-in demo and read what it found.
3. Understand the loop by reading the knowledge store.
4. Define an authorization (scope).
5. Write your own agent and run it on the mesh.

## 1. Install

```bash
cd security_seti
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Check it:

```bash
security-seti version
pytest -q          # 29 tests should pass
```

## 2. Run the demo

```bash
security-seti demo --rounds 3 --samples 20000
```

You'll see something like:

```
1 finding(s):
  [info] 3-round SPECK32 differential characteristic
        Input difference 0x00400000 propagates to 0x8000840A with
        probability ~ 2^-3.0 over 3 rounds (measured, 20000 pairs).
```

That finding was *measured*, not asserted. The agent proposed a candidate input
difference, ran 20,000 encryptions of a round-reduced SPECK32 cipher, and recorded
the output difference that actually showed up most often, with the probability it
observed.

## 3. See the loop

Run the two-agent example and watch them coordinate and build on each other:

```bash
python examples/run_local_mesh.py
```

The coordinator seeds a goal, both agents propose the same candidate differences,
the coordinator keeps one copy of each (novelty scoring), agents measure them, and
when one confirms, an agent proposes extending it by a round. The output lists the
findings and the open hypotheses ranked by novelty — including the new round-4
ideas built on confirmed round-3 facts. That is the whole point: it proposes new
vectors, it doesn't re-grind known ones.

## 4. Define your scope

Nothing runs against a target that isn't authorized. For local, non-network work
(like cryptanalysis) you still declare an explicit scope:

```python
from security_seti.scope import Authorization, Scope

scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))
```

For real pentest work, copy `AUTHORIZATION.example.yaml` to `AUTHORIZATION.yaml`,
fill in the hosts, domains, and CIDRs you are authorized to test, and load it:

```python
scope = Scope(Authorization.from_file("AUTHORIZATION.yaml"))
```

With no authorization loaded, the scope denies everything. That is deliberate.

## 5. Write your own agent

An agent is a subclass that declares its `capabilities` and implements a few
`on_*` methods. Here is a complete, runnable one. Save it as `my_agent.py`:

```python
import asyncio
from security_seti.agent import Agent
from security_seti.bus import Bus
from security_seti.coordinator import run_mesh
from security_seti.protocol import Evidence, Fact, Hypothesis
from security_seti.scope import Authorization, Scope
from security_seti.store import Store


class WordCountAgent(Agent):
    capabilities = ["demo", "count"]

    async def on_goal(self, msg):
        # When a goal arrives, propose a testable idea.
        await self.propose_hypothesis(Hypothesis(
            goal_id=msg.payload.get("goal_id", ""),
            statement="the sample text has more than three words",
            test_spec={"requires": ["count"], "text": "the quick brown fox jumps"},
        ))

    async def on_task(self, task):
        # When the coordinator offers the idea back as a task, test it.
        spec = task.get("test_spec") or {}
        text = spec.get("text", "")
        n = len(text.split())
        await self.record_fact(Fact(
            hypothesis_id=task.get("task_id"),
            statement=f"word count = {n}",
            value={"words": n},
            confidence=0.95 if n > 3 else 0.0,
            evidence=Evidence(tool="str.split",
                              script="len(text.split())",
                              params={"text": text}),
        ))
        return {"words": n}


async def main():
    scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))
    store = Store(":memory:", scope=scope)
    bus = Bus()
    agent = WordCountAgent(bus, store, scope, name="counter-1")

    await run_mesh(
        [agent], bus=bus, store=store, scope=scope,
        goal={"description": "count the words", "meta": {}},
        run_seconds=3.0,
        approve=lambda _m: True,   # local lab: auto-approve
    )

    for h in store.open_hypotheses():
        print(h["status"], "-", h["statement"])


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
python my_agent.py
```

You just did the full loop: propose a hypothesis, have it offered back as a task,
test it, and record a fact bound to the evidence that produced it.

## 6. Where to go next

- **Wrap a real tool.** `CommandToolAdapter(scope).run(["nmap", "-sV", target], target=target)`
  runs an allow-listed command against an authorized target and captures the output
  with a digest for the evidence chain. See `docs/INTEGRATIONS.md`.
- **Drive ARTEX or Metasploit.** Use `ArtexAdapter` / `MetasploitAdapter` to run
  the pentest side under your own authorization.
- **Read the rules every agent follows.** `AGENTS.md`.
- **Expose the shared knowledge over MCP.** `docs/MCP.md`.

One rule carries through all of it: only ever point the pentest side at assets you
own or have written authorization to test.
