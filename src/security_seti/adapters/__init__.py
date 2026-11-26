"""Tool adapters: how agents drive external toolkits.

An adapter wraps a tool the operator has installed and is authorized to use. The
mesh never ships exploits of its own — it orchestrates the tools you already run
(Metasploit, ARTEX, scanners, your own scripts). Every adapter routes through the
:class:`~security_seti.scope.Scope` gate, so an out-of-scope target or a
disallowed command is refused before anything executes.
"""

from .base import ToolAdapter, CommandToolAdapter, ToolResult  # noqa: F401
from .artex import ArtexAdapter  # noqa: F401
from .metasploit import MetasploitAdapter  # noqa: F401

__all__ = [
    "ToolAdapter",
    "CommandToolAdapter",
    "ToolResult",
    "ArtexAdapter",
    "MetasploitAdapter",
]
