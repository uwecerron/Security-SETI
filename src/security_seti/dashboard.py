"""A live stream of the mesh: the public message board and status page.

Reads the hub's journal (the shared ledger) and reconstructs, in real time, who
is working, what they are proposing, what they have measured, and what they have
found. Point agents at a goal and watch the board fill in, the same shape as a
live-streamed agent swarm.

`build_state` is a pure function over the journal (easy to test). The HTTP server
serves a self-contained page that polls `/api/state`.
"""

from __future__ import annotations

import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional


def _summarize(mtype: str, payload: Dict[str, Any]) -> str:
    if mtype == "hypothesis":
        return payload.get("statement", "")
    if mtype == "fact":
        return payload.get("statement", "")
    if mtype == "finding":
        return payload.get("summary") or payload.get("title", "")
    if mtype == "goal":
        return payload.get("description", "")
    if mtype == "announce":
        caps = ", ".join(payload.get("capabilities", []))
        return f"{payload.get('name', '?')} joined ({caps})"
    if mtype == "critique":
        return payload.get("reason", "")
    return ""


def build_state(db_path: str, message_limit: int = 60) -> Dict[str, Any]:
    """Reconstruct the live mesh state from the hub journal."""
    empty = {"agents": [], "goals": [], "hypotheses": [], "facts": [],
             "findings": [], "messages": [], "counts": {}, "as_of": time.time()}
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.OperationalError:
        return empty
    try:
        rows = db.execute(
            "SELECT topic, raw, ts FROM hub_journal ORDER BY seq"
        ).fetchall()
    except sqlite3.OperationalError:
        db.close()
        return empty

    agents: Dict[str, Dict[str, Any]] = {}
    goals: Dict[str, Dict[str, Any]] = {}
    hyps: Dict[str, Dict[str, Any]] = {}
    facts: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    messages: List[Dict[str, Any]] = []
    confirmed: set = set()

    for topic, raw, ts in rows:
        try:
            m = json.loads(raw)
        except (TypeError, ValueError):
            continue
        mtype = m.get("type", "")
        payload = m.get("payload") or {}
        sender = m.get("sender", "")

        if mtype in ("announce", "heartbeat"):
            name = payload.get("name", sender)
            a = agents.setdefault(name, {"name": name, "capabilities": [], "last_seen": ts})
            a["last_seen"] = ts
            if payload.get("capabilities"):
                a["capabilities"] = payload["capabilities"]
        elif mtype == "goal":
            gid = payload.get("goal_id", "")
            goals[gid] = {"goal_id": gid, "description": payload.get("description", "")}
        elif mtype == "hypothesis":
            hyps[payload.get("id", "")] = {
                "id": payload.get("id", ""),
                "statement": payload.get("statement", ""),
                "novelty": payload.get("novelty", 0.0),
                "proposed_by": payload.get("proposed_by", sender),
                "status": "open",
            }
        elif mtype == "fact":
            val = payload.get("value") or {}
            facts.append({
                "statement": payload.get("statement", ""),
                "confidence": payload.get("confidence", 0.0),
                "produced_by": payload.get("produced_by", sender),
                "prob_bits": val.get("prob_bits") if isinstance(val, dict) else None,
            })
            hid = payload.get("hypothesis_id")
            if hid and payload.get("confidence", 0) >= 0.8:
                confirmed.add(hid)
        elif mtype == "finding":
            findings.append({
                "title": payload.get("title", ""),
                "summary": payload.get("summary", ""),
                "severity": payload.get("severity", "info"),
                "produced_by": payload.get("produced_by", sender),
            })

        messages.append({
            "ts": ts, "type": mtype, "sender": sender,
            "summary": _summarize(mtype, payload),
        })

    for hid in confirmed:
        if hid in hyps:
            hyps[hid]["status"] = "confirmed"

    now = time.time()
    agent_list = [
        {**a, "online": (now - a["last_seen"]) < 45}
        for a in sorted(agents.values(), key=lambda x: x["name"])
    ]
    db.close()
    return {
        "agents": agent_list,
        "goals": list(goals.values()),
        "hypotheses": sorted(hyps.values(), key=lambda h: -h.get("novelty", 0)),
        "facts": facts[-40:],
        "findings": findings,
        "messages": messages[-message_limit:][::-1],
        "counts": {
            "agents_online": sum(1 for a in agent_list if a["online"]),
            "hypotheses": len(hyps),
            "facts": len(facts),
            "findings": len(findings),
            "messages": len(messages),
        },
        "as_of": now,
    }


PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>security_seti — live mesh</title>
<style>
 :root{--bg:#0a0e14;--panel:#111722;--line:#1e2838;--ink:#d7e0ef;--dim:#7c8aa5;
   --good:#39d98a;--warn:#f5a623;--crit:#ff5c5c;--accent:#5b8cff}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);
   font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
 header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;
   align-items:center;gap:16px;flex-wrap:wrap}
 h1{font-size:16px;margin:0;letter-spacing:.5px}
 .live{color:var(--good)} .dot{display:inline-block;width:8px;height:8px;border-radius:50%;
   background:var(--good);margin-right:6px;animation:p 1.4s infinite}
 @keyframes p{0%,100%{opacity:1}50%{opacity:.3}}
 .stats{display:flex;gap:18px;margin-left:auto;flex-wrap:wrap}
 .stat b{color:var(--accent);font-size:16px} .stat span{color:var(--dim)}
 main{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 20px;max-width:1200px}
 @media(max-width:860px){main{grid-template-columns:1fr}}
 .panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
 .panel h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);
   margin:0 0 10px} .row{padding:7px 0;border-top:1px solid var(--line)} .row:first-child{border:0}
 .tag{font-size:11px;color:var(--dim)} .who{color:var(--accent)}
 .sev-info{color:var(--dim)} .sev-high,.sev-critical{color:var(--crit)}
 .ok{color:var(--good)} .nov{color:var(--warn)}
 .msg{font-size:12.5px;padding:4px 0;border-top:1px solid var(--line);display:flex;gap:8px}
 .msg .t{color:var(--dim);min-width:92px} .mtype{min-width:84px;color:var(--accent)}
 .full{grid-column:1/-1} .empty{color:var(--dim);font-style:italic}
</style></head><body>
<header><h1>security_seti</h1><span class="live"><span class="dot"></span>live mesh</span>
<div class="stats" id="stats"></div></header>
<main>
 <section class="panel full"><h2>Findings</h2><div id="findings"></div></section>
 <section class="panel"><h2>Hypothesis board</h2><div id="hyps"></div></section>
 <section class="panel"><h2>Measured facts</h2><div id="facts"></div></section>
 <section class="panel"><h2>Agents</h2><div id="agents"></div></section>
 <section class="panel"><h2>Goals</h2><div id="goals"></div></section>
 <section class="panel full"><h2>Message board</h2><div id="messages"></div></section>
</main>
<script>
const esc=s=>(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const el=id=>document.getElementById(id);
function render(s){
 const c=s.counts||{};
 el('stats').innerHTML=[['agents online',c.agents_online],['hypotheses',c.hypotheses],
   ['facts',c.facts],['findings',c.findings],['messages',c.messages]]
   .map(([k,v])=>`<div class="stat"><b>${v||0}</b> <span>${k}</span></div>`).join('');
 el('findings').innerHTML=(s.findings||[]).length?s.findings.map(f=>
   `<div class="row"><span class="sev-${esc(f.severity)}">[${esc(f.severity)}]</span>
     <b>${esc(f.title)}</b><br><span class="tag">${esc(f.summary)} — <span class="who">${esc(f.produced_by)}</span></span></div>`
   ).join(''):'<div class="empty">none yet</div>';
 el('hyps').innerHTML=(s.hypotheses||[]).length?s.hypotheses.slice(0,20).map(h=>
   `<div class="row">${h.status==='confirmed'?'<span class="ok">✓ </span>':''}${esc(h.statement)}
     <span class="tag"><span class="nov">novelty ${(h.novelty||0).toFixed(2)}</span> · <span class="who">${esc(h.proposed_by)}</span></span></div>`
   ).join(''):'<div class="empty">none yet</div>';
 el('facts').innerHTML=(s.facts||[]).length?s.facts.slice().reverse().slice(0,20).map(f=>
   `<div class="row">${esc(f.statement)} <span class="tag">conf ${(f.confidence||0).toFixed(2)} · <span class="who">${esc(f.produced_by)}</span></span></div>`
   ).join(''):'<div class="empty">none yet</div>';
 el('agents').innerHTML=(s.agents||[]).length?s.agents.map(a=>
   `<div class="row"><span class="${a.online?'ok':'tag'}">●</span> ${esc(a.name)}
     <span class="tag">${esc((a.capabilities||[]).join(', '))}</span></div>`
   ).join(''):'<div class="empty">none yet</div>';
 el('goals').innerHTML=(s.goals||[]).length?s.goals.map(g=>
   `<div class="row">${esc(g.description)}</div>`).join(''):'<div class="empty">none yet</div>';
 el('messages').innerHTML=(s.messages||[]).map(m=>{
   const t=new Date(m.ts*1000).toLocaleTimeString();
   return `<div class="msg"><span class="t">${t}</span><span class="mtype">${esc(m.type)}</span>
     <span><span class="who">${esc(m.sender)}</span> ${esc(m.summary)}</span></div>`;
 }).join('')||'<div class="empty">waiting for the mesh…</div>';
}
async function tick(){try{const r=await fetch('/api/state');render(await r.json());}catch(e){}}
tick();setInterval(tick,2000);
</script></body></html>"""


def _make_handler(db_path: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # quiet
            pass

        def do_GET(self):  # noqa: N802
            if self.path.startswith("/api/state"):
                body = json.dumps(build_state(db_path)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path in ("/", "/index.html"):
                body = PAGE.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

    return Handler


def make_server(db_path: str, host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), _make_handler(db_path))


def serve(db_path: str, host: str = "0.0.0.0", port: int = 8080) -> None:  # pragma: no cover
    srv = make_server(db_path, host, port)
    print(f"security_seti live stream on http://{host}:{port}  (ledger: {db_path})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstream stopped")
        srv.shutdown()
