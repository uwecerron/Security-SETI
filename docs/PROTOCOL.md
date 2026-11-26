# The mesh protocol

Every agent speaks one message type, `security_seti.protocol.Message`:

```
type      a MessageType verb
topic     routing key ("mesh.hypotheses", "tasks.offers", ...)
payload   JSON-serialisable dict
id        unique id
sender    agent name
reply_to  id of the message this answers (for request/response)
ts        unix timestamp
```

## Verbs

| Type | Meaning | Usual topic |
|---|---|---|
| `announce` | agent joins, advertises capabilities | `mesh.presence` |
| `goal` | a top-level objective is seeded | `mesh.goals` |
| `task_offer` | a unit of work is offered | `tasks.offers` |
| `task_claim` | an agent claims an offer | `tasks.claims` |
| `task_done` | a claimed task finished | `tasks.done` |
| `heartbeat` | agent still alive | `mesh.presence` |
| `hypothesis` | a proposed, testable idea | `mesh.hypotheses` |
| `fact` | a measured, evidence-bound result | `mesh.facts` |
| `finding` | a consequential conclusion | `mesh.findings` |
| `critique` | a challenge to a claim (peer review) | `mesh.critiques` |
| `approval_req` / `approval_res` | human sign-off for intrusive actions | `mesh.approvals` |
| `error` | something went wrong | `mesh.errors` |

## The knowledge triple

- **Hypothesis** — a proposal with a `test_spec` precise enough for a worker to
  confirm or kill it, a `prior`, and a `novelty` the coordinator fills in.
- **Fact** — a measured `value` with `confidence` and an `Evidence` record
  (`tool`, `script`, `params`, `seed`, output digest). The anti-hallucination
  anchor: reproducible or it doesn't count.
- **Finding** — a titled conclusion citing `fact_ids`, with a `target` that must
  be in authorized scope.

## Topic matching

`Bus.subscribe(pattern)` supports a trailing wildcard: `mesh.*` catches
`mesh.facts`, `*` catches everything.

## Request / response

`Bus.request(msg, timeout=...)` publishes `msg` and resolves with the first
message whose `reply_to == msg.id`. Used for approval round-trips.

## Transport

The default `InProcessBus` is a single-event-loop asyncio broker. For a
multi-host mesh, implement the `Transport` protocol (`publish`, `subscribe`,
`close`) over NATS / Redis Streams / MQTT / websockets and pass it to `Bus`.
Agents only ever see the `Bus` interface, so nothing else changes.

## Delivery semantics (v0.1)

Task execution is **at-least-once**: there is no broker-side claim lock, so two
agents with the same capability may both run the same offered task. For
cryptanalysis this yields free cross-validation; where duplication is costly, add
a claim-lock in your `Transport` or coordinator.
