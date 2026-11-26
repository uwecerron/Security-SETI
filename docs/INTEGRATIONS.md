# Integrations

security_seti is the coordination layer. The actual work is done by tools you
already run, wrapped in adapters that route through the scope gate.

## ARTEX

[ARTEX](https://github.com/BaaRai/ARTEX) is an autonomous, LLM-driven pentest
platform: a planner decomposes a goal into intents, workers run real tools, and
findings come back bound to the captured request/response. security_seti turns a
*single* ARTEX into a *coordinated fleet*:

- `ArtexAdapter` launches ARTEX tasks over its HTTP API and pulls findings back
  onto the shared bus (`normalize_findings` maps them to the mesh's `Finding`
  shape).
- Multiple ARTEX instances become mesh agents that share one knowledge store, so
  a finding one instance proves is visible to all, and the coordinator keeps them
  from re-running the same vector.
- ARTEX's scope gates, approval gates, and argv allow/deny map 1:1 onto
  security_seti's `Scope`, so rules of engagement are enforced the same way on
  both sides.

```python
from security_seti.adapters import ArtexAdapter
artex = ArtexAdapter(scope, base_url="http://127.0.0.1:8787", api_token="...")
res = await artex.start_task(goal="test the login", target="app.acme.example")
```

## Metasploit

`MetasploitAdapter` drives a Metasploit instance over MSF RPC (`msfrpcd`). It
contains no exploits of its own — modules, payloads, and their use are
Metasploit's, run under your authorization. Any module run is `action_class =
"exploit"`, so it triggers an approval request unless your RoE allows it.

```bash
pip install security-seti[metasploit]   # pulls pymetasploit3
msfrpcd -P yourpassword -S -a 127.0.0.1  # start the RPC server
```

```python
from security_seti.adapters import MetasploitAdapter
msf = MetasploitAdapter(scope, password="yourpassword")
await msf.run("auxiliary", "scanner/http/http_version",
              {"RHOSTS": "10.10.0.5"}, target="10.10.0.5")
```

## Generic CLI tools (nmap, httpx, nuclei, your scripts)

`CommandToolAdapter` runs any allow-listed command against an authorized target
and captures output with a digest for the evidence chain. This is how you wrap
anything with a command-line interface.

```python
from security_seti.adapters import CommandToolAdapter
tool = CommandToolAdapter(scope)
res = await tool.run(["nmap", "-sV", "10.10.0.5"], target="10.10.0.5")
```

## Writing your own adapter

Subclass `ToolAdapter`, set an honest `action_class`, route targets through
`self.scope.require_target(...)` and commands through
`self.scope.require_argv(...)`. See `adapters/base.py`.

## A note on "blackhole" and other toolkits

The adapter interface is deliberately tool-agnostic: anything with a CLI or an
API can be wrapped the same way `ArtexAdapter` / `MetasploitAdapter` are. If
"blackhole" refers to a specific toolkit you use, tell us which one and it can get
a first-class adapter — the project does **not** integrate crimeware exploit kits
(e.g. the historical "Blackhole" exploit kit), only tools used for authorized
testing.
