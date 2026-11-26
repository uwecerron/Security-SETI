"""A minimal recon agent that drives an allow-listed command tool.

Shows the pentest side of the mesh: on a scan task it runs a scoped, allow-listed
command (e.g. an nmap/httpx invocation you authorized) through
:class:`CommandToolAdapter`, then records a fact bound to the command's output
digest. No tool is bundled; it runs what your authorization permits.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..adapters.base import CommandToolAdapter
from ..agent import Agent
from ..protocol import Evidence, Fact, new_id


class ReconAgent(Agent):
    capabilities = ["recon", "scan", "command"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.tool = CommandToolAdapter(self.scope)

    async def on_task(self, task: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        spec = task.get("test_spec") or {}
        argv = spec.get("argv")
        target = task.get("hypothesis", {}).get("test_spec", {}).get("target") \
            or spec.get("target")
        if not argv:
            return {"ok": False, "reason": "no argv in test_spec"}

        # intrusive actions need sign-off; scan is usually allowed in RoE
        if not await self.request_approval(self.tool.action_class,
                                           {"argv": argv, "target": target}):
            return {"ok": False, "reason": "approval denied"}

        result = await self.tool.run(argv, target=target)
        fact = Fact(
            id=new_id("fact"),
            hypothesis_id=task.get("task_id"),
            statement=f"ran {' '.join(argv)} against {target or 'target'}",
            value={"returncode": result.returncode, "ok": result.ok},
            confidence=0.9 if result.ok else 0.1,
            evidence=Evidence(
                tool=result.tool, script=" ".join(result.argv),
                params={"target": target}, stdout_digest=result.stdout_digest,
            ),
            produced_by=self.name,
        )
        await self.record_fact(fact)
        return {"ok": result.ok, "fact_id": fact.id}
