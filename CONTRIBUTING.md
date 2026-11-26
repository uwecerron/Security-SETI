# Contributing to security_seti

Thanks for helping build the mesh.

## Ground rules

1. **No exploit code.** Adapters wrap tools the operator already runs. PRs that
   add weaponized payloads, or anything designed to target non-consenting systems,
   are out of scope.
2. **Evidence or it didn't happen.** Any agent that produces a `Fact` must bind it
   to reproducible `Evidence` (script, params, seed). No LLM-asserted results.
3. **Deny-by-default.** New adapters route target and command checks through
   `Scope`. Intrusive actions declare an `action_class` that triggers approval.

## Dev setup

```bash
git clone https://github.com/uwecerron/security_seti
cd security_seti
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,all]"
pytest -q
```

The core package is pure standard library on purpose — keep new runtime
dependencies in `optional-dependencies`, imported lazily inside the adapter that
needs them (see `adapters/metasploit.py`).

## Adding an agent

Subclass `security_seti.agent.Agent`, declare `capabilities`, and implement
`on_task` (and `on_goal` / `on_fact` to propose and iterate). Copy
`agents/cryptanalysis.py` as a template — it shows the full propose → test →
bind-evidence → refine loop.

## Adding a tool adapter

Subclass `ToolAdapter` (or reuse `CommandToolAdapter`). Set `action_class`
honestly. Never bypass the scope gate. Add it to `adapters/__init__.py`.

## Tests

Every new module ships with tests. Async tests use `pytest-asyncio`
(`asyncio_mode = "auto"`). Keep the suite fast — crypto measurements in tests use
small sample sizes.
