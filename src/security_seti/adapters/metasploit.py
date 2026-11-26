"""Metasploit adapter (stub).

Drives a Metasploit instance the operator already runs, over the MSF RPC API
(``msfrpcd``). This adapter *orchestrates* Metasploit; it contains no exploits of
its own. Exploit modules, payloads, and their use are Metasploit's, run under
your authorization and rules of engagement.

Because any exploit/session action is intrusive, ``action_class`` is
``"exploit"`` — it will trigger an approval request unless your authorization
explicitly allows it.

Requires ``pymetasploit3`` (optional):  ``pip install security-seti[metasploit]``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import ToolAdapter, ToolResult


class MetasploitAdapter(ToolAdapter):
    name = "metasploit"
    action_class = "exploit"

    def __init__(
        self,
        scope,
        *,
        host: str = "127.0.0.1",
        port: int = 55553,
        password: str = "",
        ssl: bool = False,
    ) -> None:
        super().__init__(scope)
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self._client = None

    def _connect(self):  # pragma: no cover - needs a live msfrpcd
        if self._client is not None:
            return self._client
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "pymetasploit3 is not installed. "
                "Install with: pip install security-seti[metasploit]"
            ) from exc
        self._client = MsfRpcClient(
            self.password, server=self.host, port=self.port, ssl=self.ssl
        )
        return self._client

    async def run(
        self,
        module_type: str,
        module_name: str,
        options: Dict[str, Any],
        *,
        target: Optional[str] = None,
        run_as_job: bool = True,
    ) -> ToolResult:
        """Configure and execute an MSF module.

        ``module_type``: "exploit" | "auxiliary" | "post" | "payload".
        ``target`` (RHOSTS) must be inside authorized scope.
        """
        rhosts = target or options.get("RHOSTS") or options.get("RHOST")
        if rhosts:
            for h in str(rhosts).split():
                self.scope.require_target(h)

        try:
            client = self._connect()
        except RuntimeError as exc:
            return ToolResult(ok=False, tool=self.name, stderr=str(exc),
                              meta={"module": f"{module_type}/{module_name}"})

        # pragma: no cover below — exercised only against a live msfrpcd
        mod = client.modules.use(module_type, module_name)  # type: ignore[union-attr]
        for k, v in options.items():
            mod[k] = v
        result = mod.execute()
        return ToolResult(
            ok=True, tool=self.name,
            stdout=str(result),
            meta={"module": f"{module_type}/{module_name}", "result": result},
        )

    async def hosts(self) -> List[Dict[str, Any]]:  # pragma: no cover
        client = self._connect()
        ws = client.db.workspaces.workspace  # type: ignore[union-attr]
        return list(ws.hosts.list)
