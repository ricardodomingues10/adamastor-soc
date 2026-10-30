"""Inventário dinâmico do SOC: que aplicações temos, em que camada estão e como se ligam.

Camadas = as etapas do ciclo do SOC (ver → saber → decidir → responder → sustentar), a partir da função
de cada serviço. Ligações = os `links` do portal.yaml (com o protocolo), mais as dependências
(`depends_on`) e os componentes (`soc-component`) que não estejam descritos. Sistemas que não são
serviços do portal (a CMDB do cliente, os feeds de ameaça, os servidores por SSH) aparecem como externos.
"""

from __future__ import annotations

import re
from typing import Any

from socportal.catalog import FUNCTIONS, TEMPLATES_BY_ID
from socportal.monitor import Monitor
from socportal.registry import ServiceDef

LAYERS: list[tuple[str, str, str, list[str]]] = [
    ("ver", "Ver", "Recolher o que acontece", ["siem", "edr", "ndr", "observability"]),
    ("saber", "Saber", "O que temos e o que nos ameaça", ["assets", "surface", "vuln", "cti"]),
    ("decidir", "Decidir", "Investigar e priorizar", ["cases", "analysis"]),
    ("responder", "Responder", "Agir depressa e de forma repetível", ["soar", "dfir"]),
    ("sustentar", "Sustentar", "Acessos e segredos da equipa", ["identity", "secrets"]),
]
LAYER_OF = {fid: lid for lid, _, _, fids in LAYERS for fid in fids}
RANK = {"fail": 4, "warn": 3, "unknown": 2, "off": 1, "ok": 0}
PROBE_VIA = {
    "soc-status": "soc-status/1 (HTTP)",
    "soc-component": "componente (via soc-status)",
    "defectdojo": "API REST v2",
    "misp": "API REST",
    "http": "HTTP",
    "tcp": "TCP",
}


def _slug(text: str) -> str:
    return "ext-" + re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def function_of(s: ServiceDef, by_id: dict[str, ServiceDef]) -> str | None:
    if s.function:
        return s.function
    t = TEMPLATES_BY_ID.get(s.template or s.id)
    if t and t.get("function"):
        return t["function"]
    for p in s.probes:  # um componente fica na camada de quem o vigia
        if p.type == "soc-component" and p.service in by_id and p.service != s.id:
            return function_of(by_id[p.service], by_id)
    return None


def build(monitor: Monitor) -> dict[str, Any]:
    services = list(monitor.config.services)
    by_id = {s.id: s for s in services}
    reported = {(e["from"], e["to"]): e["status"] for e in monitor.edges()}
    nodes: dict[str, dict[str, Any]] = {}
    for s in services:
        st = monitor.state(s.id)
        fid = function_of(s, by_id)
        nodes[s.id] = {
            "id": s.id,
            "name": s.name,
            "def": s,
            "state": st,
            "status": st.status,
            "version": st.version,
            "latest": monitor.latest_for(s),
            "outdated": monitor.outdated(s),
            "function": fid,
            "function_name": FUNCTIONS.get(fid or "", {}).get("name", "Plataforma"),
            "layer": LAYER_OF.get(fid or "", "plataforma"),
            "via": sorted({PROBE_VIA.get(p.type, p.type) for p in s.probes}),
        }
    edges: list[dict[str, Any]] = []
    externals: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, str]] = set()

    def add(a: str, b: str, via: str, what: str, status: str | None) -> None:
        if (a, b) in seen:
            return
        seen.add((a, b))
        edges.append({"from": a, "to": b, "via": via, "what": what, "status": status or "unknown"})

    for s in services:
        for ln in s.links:
            if ln.to in by_id:
                add(s.id, ln.to, ln.via, ln.what, reported.get((s.id, ln.to)) or nodes[ln.to]["status"])
            else:
                eid = _slug(ln.to)
                externals.setdefault(eid, {"id": eid, "name": ln.to, "users": []})["users"].append(s.id)
                add(s.id, eid, ln.via, ln.what, None)
    for s in services:  # componentes primeiro: "controla" diz mais do que "depende de"
        for p in s.probes:
            if p.type == "soc-component" and p.service in by_id and p.service != s.id:
                add(p.service, s.id, "controla", f"{p.component} (vigiado por dentro)", nodes[s.id]["status"])
    for s in services:
        for dep in s.depends_on:
            if (dep, s.id) in seen:  # já desenhada no sentido contrário (ex.: componente)
                continue
            add(s.id, dep, "depende de", "", reported.get((s.id, dep)) or nodes[dep]["status"])

    layers = []
    for lid, name, why, fids in LAYERS:
        items = sorted(
            (n for n in nodes.values() if n["layer"] == lid), key=lambda n: (fids.index(n["function"]), n["name"])
        )
        missing = [FUNCTIONS[f]["name"] for f in fids if not any(n["function"] == f for n in items)]
        layers.append({"id": lid, "name": name, "why": why, "nodes": items, "missing": missing})
    other = sorted((n for n in nodes.values() if n["layer"] == "plataforma"), key=lambda n: n["name"])
    if other:
        layers.append(
            {
                "id": "plataforma",
                "name": "Plataforma",
                "why": "Serviços de suporte do SOC",
                "nodes": other,
                "missing": [],
            }
        )
    for n in nodes.values():
        n["out"] = [e for e in edges if e["from"] == n["id"]]
        n["in"] = [e for e in edges if e["to"] == n["id"]]
    counts = {k: sum(1 for n in nodes.values() if n["status"] == k) for k in RANK}
    names = {**{k: v["name"] for k, v in nodes.items()}, **{k: v["name"] for k, v in externals.items()}}
    return {
        "nodes": nodes,
        "layers": layers,
        "edges": edges,
        "externals": sorted(externals.values(), key=lambda e: e["name"]),
        "counts": counts,
        "total": len(nodes),
        "names": names,
        "active": sum(1 for n in nodes.values() if n["status"] in ("ok", "warn")),
        "attention": sorted(
            (n for n in nodes.values() if n["status"] in ("fail", "warn")), key=lambda n: -RANK[n["status"]]
        ),
    }
