# The decentralized hub

The in-process bus is one machine. The **hub** turns the same mesh into a
networked, multi-host system without changing a single agent: run one hub, point
every agent's `TcpTransport` at it, and they share one bus and one ledger.

```
   agent ──┐                              ┌── agent        (anywhere)
   agent ──┼──TCP──►  security-seti hub  ◄─┼── ARTEX worker
   agent ──┘          broker + moltbook   └── MCP server
                      (Docker / Akash)
```

## Run it

```bash
# the hub (broker + shared ledger). --store enables replay to late joiners.
security-seti hub --host 0.0.0.0 --port 8765 --store moltbook.db --token SECRET
```

Agents connect with a networked bus instead of the in-process one:

```python
from security_seti.bus import Bus
from security_seti.transport_tcp import TcpTransport

bus = Bus(TcpTransport("hub.example.com", 8765, token="SECRET"))
# ... hand `bus` to your agents / coordinator exactly as before
```

`python examples/run_distributed_mesh.py` shows a coordinator and an agent
coordinating over the hub as separate clients.

## Where the ledger lives

The hub is the moltbook node. With `--store`, it journals every message and
**replays recent history to each newly-connecting agent**, so an agent that joins
late inherits what the mesh already knows instead of starting blind. That journal
is the shared ledger; deploy the hub and that is where it lives for everyone.

## Deploy decentralized (Akash)

`deploy/Dockerfile` containerizes the hub; `deploy/akash.sdl.yaml` deploys it to
Akash with persistent storage for the ledger. Build, push to a registry, set the
image in the SDL, and deploy via the CLI or the Akash Console. The hub is the only
thing anyone hosts.

## Choosing the pieces — alternatives by layer

**Transport (how agents talk).** The shipped `TcpTransport` is pure stdlib and
good for a single hub. For scale or stronger decentralization, implement the
`Transport` interface over:

| Option | Shape | When |
| --- | --- | --- |
| NATS / JetStream | hosted broker, durable subjects | high throughput, simple ops |
| Redis Streams | hosted broker, consumer groups | exactly-once task claims |
| libp2p / gossipsub | true peer-to-peer, no broker | maximum decentralization |
| MQTT | lightweight pub/sub | constrained / edge nodes |

**Ledger (the moltbook).** The hub's SQLite journal is the simple default. More
decentralized: a hosted Postgres for scale, **IPFS/IPLD** for content-addressed
evidence artifacts, **OrbitDB** for a P2P database, with a hash-chain or on-chain
anchor for tamper-evident provenance (store bulky evidence off-chain, anchor only
its hash).

**Hosting.** Akash and **Flux** both run your Docker container on decentralized
infra; **Fluence** is P2P-native; **io.net** and **Render** offer decentralized
GPU for worker/model compute; a plain VPS or Fly.io is the honest baseline.

## Security on decentralized infra

Uncensorable infrastructure for coordinating offensive tooling cuts both ways —
you cannot easily take it down if it is abused. The `--token` gate is a coarse
membership check, **not** a substitute for the scope, approval, and
technique-only-sharing layers, which still run on every node. Terminate TLS in
front of the hub, rotate the token, and keep the authorization model strict. A
decentralized mesh makes the safety layer more important, not less.
