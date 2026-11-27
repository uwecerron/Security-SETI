# security_seti

**A coordination mesh for autonomous security-research agents — the anti-distributed.net.**

distributed.net hands out fixed work units to grind a known keyspace. That's
brute force: no unit of it ever *invents* a new differential, adapts a lattice
strategy, or notices a structural flaw. security_seti is the opposite. It's a bus
where autonomous agents **propose and test novel attack vectors**, bind every
result to reproducible evidence, share what they prove, and build on one another's
findings — ARTEX's agentic loop, turned into a fleet.

> Focus on systems that **propose and test novel attack vectors** rather than just
> scale known searches. That one sentence is the whole design.

```
        ┌──────────────┐   hypotheses / facts / findings   ┌──────────────┐
        │  crypto agent │◀────────────── bus ──────────────▶│  ARTEX agent │
        └──────┬───────┘                  ▲                 └──────┬───────┘
               │                          │                        │
          measure_differential      coordinator               Metasploit /
          (evidence-bound)       (novelty scoring,            nmap / httpx /
                                  scope + approvals)           your scripts
```

Pure standard library at the core. AGPL-3.0, so it sits alongside
[ARTEX](https://github.com/BaaRai/ARTEX).

---

## Quickstart

```bash
git clone https://github.com/uwecerron/security_seti
cd security_seti
pip install -e ".[dev]"

# run a local mesh: agents propose and measure reduced-round SPECK32 differentials
security-seti demo --rounds 3 --samples 20000
```

```
1 finding(s):
  [info] 3-round SPECK32 differential characteristic
        Input difference 0x00400000 propagates to 0x8000840A with
        probability ≈ 2^-3.0 over 3 rounds (measured, 20000 pairs).
```

Two agents coordinating, and iterating onto new vectors:

```bash
python examples/run_local_mesh.py
```

New here? Start with the [tutorial](docs/TUTORIAL.md).

## Live stream

Watch the mesh work in real time, like a streamed agent swarm. One command runs a hub, a mesh, and a public message board:

```bash
security-seti live        # then open http://localhost:8080
```

The page streams agents coming online, the hypothesis board (novelty-scored), measured facts, findings, and the live message log, all reconstructed from the hub's shared ledger. Point it at a goal and watch it fill in.

## How it works

- **Protocol** (`protocol.py`) — one `Message` envelope; hypotheses, facts, and
  findings are first-class. A fact without reproducible `Evidence` (script,
  params, seed) is rejected on principle.
- **Bus** (`bus.py`) — an asyncio pub/sub broker with topic wildcards. Swap in a
  `Transport` over NATS/Redis to span hosts.
- **Store** (`store.py`) — a sqlite knowledge base that lets a late-joining agent
  build on what's already proven. The mesh's memory; the analogue of ARTEX's
  asset + exploration graphs.
- **Scope** (`scope.py`) — deny-by-default authorization, argv allow/deny,
  approval gates. Authorized targets only.
- **Agent** (`agent.py`) — subclass, declare `capabilities`, implement
  `on_task` / `on_goal` / `on_fact`. The unit that reasons and iterates.
- **Coordinator** (`coordinator.py`) — seeds goals, scores each hypothesis for
  **novelty against what's already been tried**, and offers the new ones. This is
  what stops the mesh from collapsing back into "scale known searches."
- **Adapters** (`adapters/`) — wrap Metasploit, ARTEX, and any CLI tool. No
  exploits live here; the mesh orchestrates tools you already run.

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) and
[`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md). Agents follow
[`AGENTS.md`](AGENTS.md); the shared knowledge is reachable over MCP per
[`docs/MCP.md`](docs/MCP.md).

## How agents find each other

Right now, locally. Agents share an in-process bus inside one Python process, which is what the demo runs. There is nothing to host and no central server to sign up for.

For a mesh that spans machines, every agent points at one **broker** through a `Transport` (NATS, Redis Streams, or a WebSocket fan-out) and announces itself on the `mesh.presence` topic, where it sees who else is present and what they can do. That broker is the only thing anyone hosts, and it stays optional until you actually need cross-host coordination. You, or a community, could run one shared broker as a public rendezvous point; until then every mesh is private to whoever starts it.

## What's novel here

Not "another scanner" and not "distributed cracking." The new things are:

1. **Hypotheses as first-class, novelty-scored objects.** Most security
   automation executes a fixed playbook. Here the coordinator actively rewards
   proposing a *new* attack vector over re-running a known one (`_signature` +
   `_novelty`), and kills stale duplicates. The system's pressure is toward
   invention, by construction.
2. **Evidence-binding across a multi-agent mesh.** ARTEX binds a finding to the
   request/response that proves it. security_seti extends that to a *shared*
   substrate: every fact any agent posts carries the script+params+seed to
   reproduce it, and other agents build on it. Cross-agent provenance is rare.
3. **One mesh for pentest *and* cryptanalysis.** The same propose→test→bind→refine
   loop drives a Metasploit worker and a differential-cryptanalysis worker. The
   coordination layer doesn't care what the "experiment" is — a scan, an exploit
   attempt, or a differential trail measurement.
4. **A fleet protocol for ARTEX.** ARTEX is a powerful single engine. Nothing
   today lets many ARTEX instances (plus other tools) share one knowledge graph
   and divide novel work. That gap is the product.

## Distributing it to ARTEX users

The audience already exists — ARTEX operators — so meet them where they are:

- **Ship the `ArtexAdapter` as the headline feature.** The one-line pitch:
  *"run your ARTEX instances as a coordinated fleet with a shared knowledge
  graph."* A 60-second asciinema of `run_local_mesh.py` plus an ARTEX fleet demo.
- **Open-source on GitHub, same license (AGPL-3.0) as ARTEX**, cross-linked from
  the ARTEX README via a PR ("Fleet coordination: security_seti"). Co-marketing
  that the maintainers will accept because it adds value to their project.
- **`pip install security-seti`** with zero required dependencies — trivial to
  try. Optional extras (`[metasploit]`, `[artex]`) only when needed.
- **Package a worker image** so an ARTEX user runs `docker run security_seti/agent`
  and it joins the mesh and starts claiming tasks.
- **Seed the community channels** ARTEX users already sit in (its Discord/issues,
  r/netsec, the pentest-tooling crowd on X where this thread started) with the
  fleet demo, not a wall of text.

## Monetizing it — cash or clout

**Clout (do this first; it compounds):**
- Own the phrase *"agentic security mesh"* / *"fleet coordination for autonomous
  pentest."* Publish the architecture writeup and the SPECK differential demo as a
  concrete, reproducible result. A working artifact beats a thread.
- Become the obvious name next to ARTEX. A merged PR into ARTEX's README and a
  joint demo makes you co-author of the category, not a bystander.
- Talks/CFPs: the propose-and-test-novel-vectors framing is a conference-shaped
  idea.

**Cash (the clout makes these credible):**
- **AGPL is the lever.** The network-use clause (section 13) means anyone running
  a *modified*, hosted version owes their source — unless they buy a **commercial
  license** from you. Classic open-core: AGPL for the community, paid exception for
  companies that want to keep private forks closed.
- **Managed fleet / SaaS.** Hosted coordination + storage + dashboards over the
  open-source mesh. Teams pay to not run the broker and knowledge graph themselves.
- **Pentest-as-a-service.** The mesh + ARTEX is a credible engine for continuous
  assessment; the evidence-bound findings are what make a report defensible to a
  client. You sell findings + remediation + retest, not the tool. (Get an LLC,
  E&O/cyber insurance, and a lawyer's read on the AGPL obligations first.)
- **Paid connectors / support** for specific toolkits and enterprise RoE workflows.

The honest sequence: ship the open-source mesh, land the ARTEX integration and the
SPECK demo, get the clout, *then* convert it with a commercial-license exception
and a managed offering.

## Safety

Offensive tooling. Only ever point it at assets you own or have **written
authorization** to test. Scope is deny-by-default and enforced at the gate, the
store, and the approval layer. No exploits ship in this repo. See
[`SECURITY.md`](SECURITY.md).

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE). The network-use clause is intentional
and matches ARTEX.
