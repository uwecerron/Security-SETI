"""Authorization and rules-of-engagement — the safety core.

Nothing in security_seti touches a target that is not explicitly authorized.
This module is deliberately strict and deny-by-default:

* ``targets``      an allowlist of hosts / domains / CIDRs you may test.
* ``argv policy``  allow/deny prefixes for what commands adapters may run.
* ``approval``     action classes that require a human yes before they run.

Load it from an ``AUTHORIZATION.yaml`` (see ``AUTHORIZATION.example.yaml``). If
no authorization is loaded, the scope denies everything.

This mirrors ARTEX's scope gates, approval gates, and argv allow/deny so the two
projects enforce rules of engagement the same way.
"""

from __future__ import annotations

import ipaddress
import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional


class ScopeError(PermissionError):
    """Raised when an action falls outside authorized scope."""


def _parse_yaml_ish(text: str) -> dict:
    """Tiny YAML subset loader (top-level keys, lists, scalars).

    Avoids a hard PyYAML dependency for the common case. If the file is real
    YAML with nesting beyond what this handles, install pyyaml and the loader
    below will use it automatically.
    """
    try:  # prefer the real thing when present
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except Exception:
        pass

    data: dict = {}
    current_key: Optional[str] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- ") and current_key is not None:
            data.setdefault(current_key, [])
            if isinstance(data[current_key], list):
                data[current_key].append(line.lstrip()[2:].strip())
            continue
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val == "":
                current_key = key
                data[key] = []
            else:
                current_key = None
                if val.lower() in ("true", "false"):
                    data[key] = val.lower() == "true"
                else:
                    data[key] = val.strip('"').strip("'")
    return data


@dataclass
class Authorization:
    """A signed-off statement of what you may test and how."""

    engagement: str = ""                     # human label, e.g. "ACME external 2026-Q4"
    authorized_by: str = ""                  # who signed the RoE
    targets: List[str] = field(default_factory=list)   # hosts, domains, CIDRs
    allow_argv_prefixes: List[str] = field(default_factory=list)
    deny_argv_prefixes: List[str] = field(default_factory=list)
    require_approval: List[str] = field(default_factory=list)  # action classes
    max_requests_per_min: int = 600         # noise governor ceiling

    # -- loading ----------------------------------------------------------- #

    @classmethod
    def from_file(cls, path: str | Path) -> "Authorization":
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".json",):
            data = json.loads(text)
        else:
            data = _parse_yaml_ish(text)
        return cls(
            engagement=data.get("engagement", ""),
            authorized_by=data.get("authorized_by", ""),
            targets=list(data.get("targets", []) or []),
            allow_argv_prefixes=list(data.get("allow_argv_prefixes", []) or []),
            deny_argv_prefixes=list(data.get("deny_argv_prefixes", []) or []),
            require_approval=list(data.get("require_approval", []) or []),
            max_requests_per_min=int(data.get("max_requests_per_min", 600)),
        )

    @classmethod
    def unrestricted_lab(cls, targets: Iterable[str]) -> "Authorization":
        """Convenience for a local lab you own. Still an explicit allowlist."""
        return cls(
            engagement="local-lab",
            authorized_by="self (lab)",
            targets=list(targets),
            allow_argv_prefixes=[],      # empty = adapters decide per-tool
            deny_argv_prefixes=["rm ", "dd ", "mkfs", ":(){"],
            require_approval=["exploit", "write", "lateral", "exfil"],
        )


class Scope:
    """Enforces an :class:`Authorization`. Deny-by-default."""

    def __init__(self, auth: Optional[Authorization] = None) -> None:
        self.auth = auth
        self._nets: List[ipaddress._BaseNetwork] = []
        self._hosts: List[str] = []
        if auth:
            for t in auth.targets:
                self._register_target(t)

    def _register_target(self, t: str) -> None:
        t = t.strip().lower()
        if not t:
            return
        try:
            self._nets.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            # not an IP/CIDR -> treat as host or domain (leading-dot = wildcard)
            self._hosts.append(t.lstrip("*"))

    # -- target checks ----------------------------------------------------- #

    def is_target_authorized(self, target: str) -> bool:
        if not self.auth:
            return False
        t = target.strip().lower()
        # strip scheme / port / path for host comparison
        host = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in net for net in self._nets)
        except ValueError:
            for h in self._hosts:
                h2 = h.lstrip(".")
                if host == h2 or host.endswith("." + h2):
                    return True
            return False

    def require_target(self, target: str) -> None:
        if not self.is_target_authorized(target):
            raise ScopeError(
                f"target {target!r} is not in authorized scope "
                f"({self.auth.engagement if self.auth else 'no authorization loaded'})"
            )

    # -- command checks ---------------------------------------------------- #

    def is_argv_allowed(self, argv: List[str] | str) -> bool:
        if not self.auth:
            return False
        cmd = argv if isinstance(argv, str) else " ".join(shlex.quote(a) for a in argv)
        cmd_plain = argv if isinstance(argv, str) else " ".join(argv)
        for deny in self.auth.deny_argv_prefixes:
            if cmd_plain.startswith(deny) or cmd.startswith(deny):
                return False
        if not self.auth.allow_argv_prefixes:
            return True  # no allowlist => only deny-list governs
        return any(
            cmd_plain.startswith(a) or cmd.startswith(a)
            for a in self.auth.allow_argv_prefixes
        )

    def require_argv(self, argv: List[str] | str) -> None:
        if not self.is_argv_allowed(argv):
            shown = argv if isinstance(argv, str) else " ".join(argv)
            raise ScopeError(f"command not permitted by argv policy: {shown!r}")

    # -- approval ---------------------------------------------------------- #

    def needs_approval(self, action_class: str) -> bool:
        if not self.auth:
            return True  # deny-by-default: unknown => must ask
        return action_class in self.auth.require_approval

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        eng = self.auth.engagement if self.auth else "UNAUTHORIZED"
        return f"<Scope {eng!r} targets={len(self._nets)+len(self._hosts)}>"
