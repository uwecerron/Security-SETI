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
import os
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


def _hub(args: argparse.Namespace) -> int:
    from .transport_tcp import HubServer

    hub = HubServer(host=args.host, port=args.port, token=args.token or None,
                    store_path=args.store)
    print(f"security-seti hub listening on {args.host}:{args.port}"
          + (f", ledger at {args.store}" if args.store else " (no persistence)"))
    print("authorized agents connect a TcpTransport here. Ctrl-C to stop.")
    try:
        asyncio.run(hub.serve_forever())
    except KeyboardInterrupt:
        print("\nhub stopped")
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    from .dashboard import serve

    serve(args.store, host=args.host, port=args.port)
    return 0


def _live(args: argparse.Namespace) -> int:
    """Run a hub, a mesh, and the live stream together. Open the URL and watch."""
    import os
    import tempfile
    import threading

    from .agents.cryptanalysis import DifferentialCryptanalysisAgent
    from .bus import Bus
    from .coordinator import Coordinator
    from .dashboard import make_server
    from .scope import Authorization, Scope
    from .store import Store
    from .transport_tcp import HubServer, TcpTransport

    store_path = args.store or os.path.join(tempfile.gettempdir(), "seti_live.db")
    for p in (store_path, store_path + "-wal", store_path + "-shm"):
        try:
            os.remove(p)
        except OSError:
            pass

    async def main() -> None:
        hub = HubServer(host="127.0.0.1", port=args.hub_port, store_path=store_path)
        await hub.start()
        srv = make_server(store_path, host=args.host, port=args.port)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"live stream: http://{args.host}:{args.port}  (Ctrl-C to stop)")

        scope = Scope(Authorization.unrestricted_lab(targets=["127.0.0.1"]))
        coord = Coordinator(Bus(TcpTransport("127.0.0.1", args.hub_port)),
                            Store(":memory:", scope=scope), scope,
                            approve=lambda _m: True)
        agents = [
            DifferentialCryptanalysisAgent(
                Bus(TcpTransport("127.0.0.1", args.hub_port)),
                Store(":memory:", scope=scope), scope, name=f"crypto-{i}")
            for i in range(args.agents)
        ]
        for a in agents:
            a.samples = args.samples
        for coro in [coord.start()] + [a.start() for a in agents]:
            asyncio.ensure_future(coro)

        await asyncio.sleep(0.4)
        await coord.seed_goal("reduced-round SPECK32 differentials", "",
                              {"kind": "cryptanalysis", "rounds": args.rounds,
                               "samples": args.samples})
        await asyncio.Event().wait()   # keep the stream alive

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped")
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

    # Defaults fall back to env vars so a container / Akash deployment configures
    # the hub through its `env` block without changing the command.
    h = sub.add_parser("hub", help="run the decentralized mesh hub (broker + shared ledger)")
    h.add_argument("--host", default=os.environ.get("SETI_HUB_HOST", "0.0.0.0"))
    h.add_argument("--port", type=int, default=int(os.environ.get("SETI_HUB_PORT", "8765")))
    h.add_argument("--store", default=os.environ.get("SETI_HUB_STORE") or None,
                   help="sqlite path for the shared ledger (moltbook); enables replay")
    h.add_argument("--token", default=os.environ.get("SETI_HUB_TOKEN") or None,
                   help="shared token agents must present")
    h.set_defaults(func=_hub)

    d2 = sub.add_parser("dashboard", help="serve the live mesh stream over a ledger db")
    d2.add_argument("store", help="sqlite ledger path the hub is writing to")
    d2.add_argument("--host", default="0.0.0.0")
    d2.add_argument("--port", type=int, default=8080)
    d2.set_defaults(func=_dashboard)

    lv = sub.add_parser("live", help="run a hub + mesh + live stream together, then watch")
    lv.add_argument("--host", default="0.0.0.0")
    lv.add_argument("--port", type=int, default=8080, help="dashboard port")
    lv.add_argument("--hub-port", type=int, default=8765, dest="hub_port")
    lv.add_argument("--agents", type=int, default=2)
    lv.add_argument("--rounds", type=int, default=3)
    lv.add_argument("--samples", type=int, default=6000)
    lv.add_argument("--store", default=None, help="ledger path (default: a temp file)")
    lv.set_defaults(func=_live)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=lambda _a: (print(__version__) or 0))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
