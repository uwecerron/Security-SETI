"""The shared knowledge store: the mesh's memory.

A sqlite database holding hypotheses, facts (with evidence), and findings, plus a
full message journal for audit. This is what lets the mesh *compound*: an agent
that joins late reads what is already known and builds on it, instead of
re-deriving it. It is the direct analogue of ARTEX's asset + exploration graphs.

Scope is enforced here too: a finding whose ``target`` is outside the authorized
scope is rejected at write time, so an out-of-scope result can never be recorded
as if it were sanctioned work.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .protocol import Fact, Finding, Hypothesis, Message
from .scope import Scope, ScopeError


_SCHEMA = """
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    goal_id TEXT,
    statement TEXT,
    test_spec TEXT,
    prior REAL,
    novelty REAL,
    parent_id TEXT,
    proposed_by TEXT,
    status TEXT DEFAULT 'open',   -- open | confirmed | refuted | abandoned
    ts REAL
);
CREATE TABLE IF NOT EXISTS facts (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT,
    statement TEXT,
    value TEXT,
    confidence REAL,
    evidence TEXT,
    produced_by TEXT,
    ts REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    goal_id TEXT,
    title TEXT,
    summary TEXT,
    severity TEXT,
    target TEXT,
    fact_ids TEXT,
    remediation TEXT,
    produced_by TEXT,
    ts REAL
);
CREATE TABLE IF NOT EXISTS journal (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id TEXT,
    type TEXT,
    topic TEXT,
    sender TEXT,
    raw TEXT,
    ts REAL
);
CREATE INDEX IF NOT EXISTS idx_hyp_goal ON hypotheses(goal_id);
CREATE INDEX IF NOT EXISTS idx_fact_hyp ON facts(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_find_goal ON findings(goal_id);
"""


class Store:
    """sqlite-backed knowledge store. Safe for one process; use WAL for more."""

    def __init__(self, path: str | Path = ":memory:", scope: Optional[Scope] = None) -> None:
        self.path = str(path)
        self.scope = scope
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL;")
        self._db.commit()

    # -- hypotheses -------------------------------------------------------- #

    def add_hypothesis(self, h: Hypothesis) -> str:
        self._db.execute(
            "INSERT OR REPLACE INTO hypotheses "
            "(id, goal_id, statement, test_spec, prior, novelty, parent_id, proposed_by, status, ts) "
            "VALUES (?,?,?,?,?,?,?,?,COALESCE((SELECT status FROM hypotheses WHERE id=?),'open'),?)",
            (
                h.id, h.goal_id, h.statement, json.dumps(h.test_spec),
                h.prior, h.novelty, h.parent_id, h.proposed_by, h.id, time.time(),
            ),
        )
        self._db.commit()
        return h.id

    def set_hypothesis_status(self, hyp_id: str, status: str) -> None:
        self._db.execute(
            "UPDATE hypotheses SET status=? WHERE id=?", (status, hyp_id)
        )
        self._db.commit()

    def open_hypotheses(self, goal_id: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "SELECT * FROM hypotheses WHERE status='open'"
        args: tuple = ()
        if goal_id:
            q += " AND goal_id=?"
            args = (goal_id,)
        q += " ORDER BY novelty DESC, prior DESC"
        return [dict(r) for r in self._db.execute(q, args).fetchall()]

    def all_hypothesis_statements(self, goal_id: Optional[str] = None) -> List[str]:
        """Used by the coordinator to judge the novelty of a new proposal."""
        q = "SELECT statement FROM hypotheses"
        args: tuple = ()
        if goal_id:
            q += " WHERE goal_id=?"
            args = (goal_id,)
        return [r["statement"] for r in self._db.execute(q, args).fetchall()]

    def all_hypothesis_specs(self, goal_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return (id, test_spec) for prior hypotheses — novelty is judged on the
        attack *vector* (the test spec), not the prose statement."""
        q = "SELECT id, test_spec FROM hypotheses"
        args: tuple = ()
        if goal_id:
            q += " WHERE goal_id=?"
            args = (goal_id,)
        out: List[Dict[str, Any]] = []
        for r in self._db.execute(q, args).fetchall():
            try:
                spec = json.loads(r["test_spec"]) if r["test_spec"] else {}
            except (TypeError, ValueError):
                spec = {}
            out.append({"id": r["id"], "test_spec": spec})
        return out

    # -- facts ------------------------------------------------------------- #

    def add_fact(self, f: Fact) -> str:
        self._db.execute(
            "INSERT OR REPLACE INTO facts "
            "(id, hypothesis_id, statement, value, confidence, evidence, produced_by, ts) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                f.id, f.hypothesis_id, f.statement, json.dumps(f.value),
                f.confidence, json.dumps(f.evidence.to_dict()), f.produced_by, time.time(),
            ),
        )
        self._db.commit()
        return f.id

    def facts_for(self, hypothesis_id: str) -> List[Dict[str, Any]]:
        return [
            dict(r)
            for r in self._db.execute(
                "SELECT * FROM facts WHERE hypothesis_id=? ORDER BY ts", (hypothesis_id,)
            ).fetchall()
        ]

    # -- findings ---------------------------------------------------------- #

    def add_finding(self, f: Finding) -> str:
        if self.scope is not None and f.target:
            # Enforce scope at write time: no out-of-scope result is ever stored.
            if not self.scope.is_target_authorized(f.target):
                raise ScopeError(
                    f"refusing to store finding for out-of-scope target {f.target!r}"
                )
        self._db.execute(
            "INSERT OR REPLACE INTO findings "
            "(id, goal_id, title, summary, severity, target, fact_ids, remediation, produced_by, ts) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                f.id, f.goal_id, f.title, f.summary, f.severity, f.target,
                json.dumps(f.fact_ids), f.remediation, f.produced_by, time.time(),
            ),
        )
        self._db.commit()
        return f.id

    def findings(self, goal_id: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "SELECT * FROM findings"
        args: tuple = ()
        if goal_id:
            q += " WHERE goal_id=?"
            args = (goal_id,)
        q += " ORDER BY ts DESC"
        return [dict(r) for r in self._db.execute(q, args).fetchall()]

    # -- journal ----------------------------------------------------------- #

    def journal_message(self, m: Message) -> None:
        self._db.execute(
            "INSERT INTO journal (msg_id, type, topic, sender, raw, ts) VALUES (?,?,?,?,?,?)",
            (m.id, m.type.value, m.topic, m.sender, m.to_json(), m.ts),
        )
        self._db.commit()

    def journal(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [
            dict(r)
            for r in self._db.execute(
                "SELECT * FROM journal ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        ]

    # -- lifecycle --------------------------------------------------------- #

    def close(self) -> None:
        self._db.close()
