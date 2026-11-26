"""Command-line entry point: ``security-seti``.

Subcommands:
    demo          run a local mesh with the crypto agent against reduced SPECK
    findings      print findings from a store database
    journal       print the recent message journal
    version       print the version

This is a thin console over the library; real deployments import the package.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import List, Optional

from . import __version__
from .bus import Bus
from .coordinator import run_mesh
from .scope import Authorization, Scope
from .store import Store


def _demo(args: argparse.Namespace) -> int:
    from .agents.cryptanalysis import DifferentialCryptanalysisAgent

    scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))
    store = Store(args.db or ":memory:", scope=scope)
    bus = Bus()
    agent = DifferentialCryptanalysisAgent(bus, store, scope, name="crypto-1")

    async def go() -> None:
        # lab approval policy: auto-approve (local, non-network crypto work)
        await run_mesh(
            [agent], bus=bus, store=store, scope=scope,
            goal={"description": "find a reduced-round SPECK32 differential",
                  "meta": {"kind": "cryptanalysis",
                           "rounds": args.rounds, "samples": args.samples}},
            run_seconds=args.seconds,
            approve=lambda _m: True,
        )

    asyncio.run(go())
    findings = store.findings()
    print(f"\n{len(findings)} finding(s):")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']}")
        print(f"        {f['summary']}")
    return 0


def _findings(args: argparse.Namespace) -> int:
    store = Store(args.db)
    print(json.dumps(store.findings(), indent=2))
    return 0


def _journal(args: argparse.Namespace) -> int:
    store = Store(args.db)
    for row in reversed(store.journal(limit=args.limit)):
        print(f"{row['ts']:.3f} {row['type']:12} {row['topic']:16} {row['sender']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="security-seti",
                                description="coordination mesh for security-research agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run a local reduced-SPECK differential demo")
    d.add_argument("--rounds", type=int, default=3)
    d.add_argument("--samples", type=int, default=20000)
    d.add_argument("--seconds", type=float, default=6.0)
    d.add_argument("--db", default=None, help="sqlite path (default: in-memory)")
    d.set_defaults(func=_demo)

    f = sub.add_parser("findings", help="print findings from a store db")
    f.add_argument("db")
    f.set_defaults(func=_findings)

    j = sub.add_parser("journal", help="print the message journal")
    j.add_argument("db")
    j.add_argument("--limit", type=int, default=50)
    j.set_defaults(func=_journal)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=lambda _a: (print(__version__) or 0))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
