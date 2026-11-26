"""The adapter interface and a generic subprocess adapter.

:class:`CommandToolAdapter` runs an allow-listed external command against an
authorized target and captures its output with a digest for the evidence chain.
It is the building block for wrapping any CLI security tool you are licensed to
run: nmap, httpx, nuclei, ffuf, sqlmap, your own scripts.

Subclass :class:`ToolAdapter` for tools reached over an API rather than argv
(see :mod:`~security_seti.adapters.artex` and
:mod:`~security_seti.adapters.metasploit`).
"""

from __future__ import annotations

import asyncio
import hashlib
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..scope import Scope


@dataclass
class ToolResult:
    ok: bool
    tool: str
    argv: List[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    stdout_digest: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


class ToolAdapter:
    """Base class. ``action_class`` drives approval gating."""

    name = "tool"
    #: how intrusive this tool is, for approval gating: "read" | "scan" |
    #: "exploit" | "write" | "lateral" | "exfil"
    action_class = "read"

    def __init__(self, scope: Scope) -> None:
        self.scope = scope

    async def run(self, *args: Any, **kwargs: Any) -> ToolResult:  # pragma: no cover
        raise NotImplementedError


class CommandToolAdapter(ToolAdapter):
    """Run an allow-listed command against an authorized target."""

    name = "command"
    action_class = "scan"

    def __init__(self, scope: Scope, *, default_timeout: float = 120.0) -> None:
        super().__init__(scope)
        self.default_timeout = default_timeout

    async def run(
        self,
        argv: List[str],
        *,
        target: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> ToolResult:
        # 1. scope gate on the target
        if target:
            self.scope.require_target(target)
        # 2. argv allow/deny gate
        self.scope.require_argv(argv)

        # 3. execute
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(
                proc.communicate(), timeout=timeout or self.default_timeout
            )
        except FileNotFoundError:
            return ToolResult(ok=False, tool=self.name, argv=argv,
                              stderr=f"tool not installed: {argv[0]!r}")
        except asyncio.TimeoutError:
            return ToolResult(ok=False, tool=self.name, argv=argv,
                              stderr="timed out")

        stdout = out.decode("utf-8", "replace")
        digest = hashlib.sha256(out).hexdigest()
        return ToolResult(
            ok=proc.returncode == 0,
            tool=self.name,
            argv=argv,
            stdout=stdout,
            stderr=err.decode("utf-8", "replace"),
            returncode=proc.returncode,
            stdout_digest=digest,
        )

    @staticmethod
    def split(command: str) -> List[str]:
        return shlex.split(command)
