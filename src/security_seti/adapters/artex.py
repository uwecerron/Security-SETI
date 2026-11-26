"""ARTEX adapter.

Lets a security_seti mesh drive one or more ARTEX instances as workers, and pull
ARTEX findings back onto the shared bus. This is the glue that makes the two
projects one system: ARTEX supplies the autonomous pentest engine (planner →
workers → evidence-bound findings); security_seti supplies the mesh that lets
many ARTEX instances (and crypto agents, and your own tools) coordinate and
iterate.

Talks to ARTEX over its local HTTP API. ``requests`` is optional; if it is not
installed the adapter falls back to urllib so the core stays dependency-free.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, List, Optional

from .base import ToolAdapter, ToolResult


class ArtexAdapter(ToolAdapter):
    name = "artex"
    action_class = "scan"

    def __init__(
        self,
        scope,
        *,
        base_url: str = "http://127.0.0.1:8787",
        api_token: str = "",
        timeout: float = 30.0,
    ) -> None:
        super().__init__(scope)
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout

    # -- transport (requests if present, else urllib) ---------------------- #

    def _http(self, method: str, path: str, body: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        data = json.dumps(body).encode() if body is not None else None
        try:  # pragma: no cover - network
            import requests  # type: ignore

            r = requests.request(method, url, headers=headers, data=data,
                                 timeout=self.timeout)
            r.raise_for_status()
            return r.json() if r.content else {}
        except ImportError:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw else {}

    # -- operations -------------------------------------------------------- #

    async def start_task(self, goal: str, target: str, meta: Optional[Dict] = None) -> ToolResult:
        """Launch an ARTEX task. ``target`` must be inside authorized scope."""
        self.scope.require_target(target)
        try:
            resp = self._http("POST", "/api/tasks", {
                "goal": goal, "target": target, "meta": meta or {},
            })
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, tool=self.name, stderr=str(exc),
                              meta={"op": "start_task"})
        return ToolResult(ok=True, tool=self.name, stdout=json.dumps(resp),
                         meta={"op": "start_task", "task": resp})

    async def get_findings(self, task_id: str) -> ToolResult:
        try:
            resp = self._http("GET", f"/api/tasks/{task_id}/findings")
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, tool=self.name, stderr=str(exc),
                              meta={"op": "get_findings"})
        return ToolResult(ok=True, tool=self.name, stdout=json.dumps(resp),
                         meta={"op": "get_findings", "findings": resp})

    @staticmethod
    def normalize_findings(raw: Any) -> List[Dict[str, Any]]:
        """Map ARTEX findings onto the mesh's finding shape (best-effort)."""
        items = raw.get("findings", raw) if isinstance(raw, dict) else raw
        out: List[Dict[str, Any]] = []
        for it in items or []:
            out.append({
                "title": it.get("title") or it.get("name", "finding"),
                "summary": it.get("summary") or it.get("description", ""),
                "severity": it.get("severity", "info"),
                "target": it.get("target") or it.get("asset", ""),
                "remediation": it.get("remediation", ""),
            })
        return out
