"""Dados das páginas Servidores (painel e detalhe), já prontos para desenhar.

Os gráficos são SVG desenhados no servidor (sem JavaScript de gráficos, CSP estrita): aqui calculam-se
as larguras das barras e os pontos das linhas.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from vulnflux.config import Settings
from vulnflux.models import Host, Source, utcnow
from vulnflux.servers import cycles
from vulnflux.servers.ssh import host_key
from vulnflux.store import JsonStore

STATUS_LABEL = {"ok": "Saudável", "warn": "Atenção", "fail": "Crítico", "unknown": "Por verificar", "off": "Desligado"}
CYCLE_LABEL = {"a_decorrer": "A decorrer", "concluido": "Concluído", "parado": "Parado", "cancelado": "Cancelado"}
RING_LABEL = {
    "por_iniciar": "Por iniciar",
    "a_correr": "A atualizar",
    "ok": "Concluído",
    "falhou": "Falhou",
    "aguarda_observacao": "Em observação",
    "aguarda_aprovacao": "Aguarda aprovação",
    "vazio": "Sem servidores a atualizar",
}
SERVER_LABEL = {
    "pendente": "Pendente",
    "a_correr": "A atualizar",
    "ok": "Atualizado",
    "falhou": "Falhou",
    "so_verificar": "Só verificar",
    "nao_tentado": "Não tentado",
}


def _dt(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        return v if isinstance(v, datetime) else datetime.fromisoformat(str(v))
    except ValueError:
        return None


def spark(
    values: list[float | None], width: int = 120, height: int = 28, lo: float | None = None, hi: float | None = None
) -> str:
    """Pontos de uma polyline SVG (vazio se houver menos de 2 valores)."""
    pts = [(i, v) for i, v in enumerate(values) if v is not None]
    if len(pts) < 2:
        return ""
    vs = [v for _, v in pts]
    lo = min(vs) if lo is None else lo
    hi = max(vs) if hi is None else hi
    span = (hi - lo) or 1
    n = max(1, len(values) - 1)
    return " ".join(
        f"{round(i * width / n, 1)},{round(height - 2 - (v - lo) * (height - 4) / span, 1)}" for i, v in pts
    )


def _meter(label: str, pct: float | None, th: tuple[float, float], text: str = "") -> dict[str, Any]:
    if pct is None:
        return {"label": label, "pct": None, "w": 0, "level": "off", "text": text or "—"}
    level = "fail" if pct >= th[1] else "warn" if pct >= th[0] else "ok"
    return {"label": label, "pct": pct, "w": max(1, min(100, round(pct))), "level": level, "text": text or f"{pct:g}%"}


def card(store: JsonStore, settings: Settings, host: Host, matrix: dict) -> dict[str, Any]:
    data = store.get_server(host.id)
    rep, un = data.get("report"), data.get("unreachable")
    th = settings.server_thresholds()
    hist = data.get("history", [])[-40:]
    status = "unknown"
    if not host.enabled or not host.ssh_enabled:
        status = "off"
    elif un and (
        not rep
        or (_dt(un["at"]) or utcnow()) >= (_dt(rep.get("checked_at")) or datetime.min.replace(tzinfo=utcnow().tzinfo))
    ):
        status = "fail"
    elif rep:
        status = rep["status"]
    m = (rep or {}).get("metrics", {})
    upd = (rep or {}).get("updates", {})
    load = m.get("load_per_cpu")
    meters = [
        _meter("Memória", m.get("mem_pct"), th["mem"]),
        _meter("Disco", m.get("disk_max_pct"), th["disk"]),
        _meter("Swap", m.get("swap_pct"), th["swap"]),
        _meter(
            "Carga",
            None if load is None else round(100 * load / (th["load"][1] or 1), 1),
            (100 * th["load"][0] / th["load"][1], 100),
            f"{load:g}/CPU" if load is not None else "",
        ),
    ]
    score = (rep or {}).get("score")
    checked = _dt((rep or {}).get("checked_at"))
    stale = bool(checked and utcnow() - checked > timedelta(hours=26))
    return {
        "host": host,
        "status": status,
        "status_label": STATUS_LABEL[status],
        "report": rep,
        "unreachable": un,
        "meters": meters,
        "score": score,
        "score_dash": f"{round((score or 0) * 1.0053, 1)} 100.53",
        "score_level": "off" if score is None else "ok" if score >= 80 else "warn" if score >= 60 else "fail",
        "security": upd.get("security"),
        "updates": upd.get("total"),
        "reboot": upd.get("reboot"),
        "checked_at": checked,
        "stale": stale,
        "spark_score": spark([p.get("score") for p in hist], lo=0, hi=100),
        "spark_sec": spark([p.get("sec") for p in hist], lo=0),
        "problems": [
            c
            for c in ((rep or {}).get("health", []) + (rep or {}).get("update_checks", []))
            if c["status"] in ("fail", "warn")
        ][:3],
        "run": matrix.get((host.id, Source.SERVER)),
        "search": " ".join(
            [
                host.name,
                host.ssh_target,
                (rep or {}).get("os", ""),
                host.environment,
                *host.tags,
                STATUS_LABEL[status],
                f"anel{host.patch_ring}",
            ]
        ).lower(),
    }


def board(store: JsonStore, settings: Settings) -> dict[str, Any]:
    matrix = store.latest_matrix()
    servers = [h for h in store.list_hosts() if h.ssh_enabled]
    cards = [card(store, settings, h, matrix) for h in servers]
    order = {"fail": 0, "warn": 1, "unknown": 2, "ok": 3, "off": 4}
    cards.sort(key=lambda c: (order[c["status"]], c["host"].name))
    counts = {k: sum(1 for c in cards if c["status"] == k) for k in order}
    scores = [c["score"] for c in cards if c["score"] is not None]
    total = len(cards) or 1
    segs, x = [], 0.0
    for k in ("ok", "warn", "fail", "unknown", "off"):
        w = 100 * counts[k] / total
        if w:
            segs.append({"k": k, "x": round(x, 2), "w": round(w, 2)})
            x += w
    rings = {i: [c for c in cards if c["host"].patch_ring == i] for i in range(4)}
    cyc = cycles.active_cycle(store) or next(iter(store.list_cycles()), None)
    return {
        "cards": cards,
        "counts": counts,
        "segments": segs,
        "total": len(cards),
        "avg_score": round(sum(scores) / len(scores)) if scores else None,
        "security": sum(c["security"] or 0 for c in cards),
        "reboots": sum(1 for c in cards if c["reboot"]),
        "rings": rings,
        "ring_names": dict(cycles.RINGS),
        "ring_help": cycles.RING_HELP,
        "cycle": cycle_view(cyc, settings) if cyc else None,
        "cycles": store.list_cycles()[:8],
        "patchable": sum(1 for c in cards if c["host"].source_enabled(Source.PATCH)),
    }


def cycle_view(cyc: dict[str, Any], settings: Settings) -> dict[str, Any]:
    rings = []
    for r in cyc["rings"]:
        servers = [{**s, "label": SERVER_LABEL.get(s["status"], s["status"])} for s in r["servers"]]
        rings.append(
            {
                **r,
                "label": RING_LABEL.get(r["status"], r["status"]),
                "servers": servers,
                "opens": _dt(r.get("opens_at")),
                "patch_count": sum(1 for s in r["servers"] if s["status"] != "so_verificar"),
            }
        )
    return {
        **cyc,
        "label": CYCLE_LABEL.get(cyc["status"], cyc["status"]),
        "rings": rings,
        "created": _dt(cyc.get("created_at")),
        "finished": _dt(cyc.get("finished_at")),
        "approval": settings.patch_ring3_approval,
    }


def detail(store: JsonStore, settings: Settings, host: Host) -> dict[str, Any]:
    c = card(store, settings, host, store.latest_matrix())
    data = store.get_server(host.id)
    rep = data.get("report") or {}
    hist = data.get("history", [])[-120:]
    th = settings.server_thresholds()
    groups: dict[str, list[dict]] = {}
    for chk in rep.get("hardening", []):
        groups.setdefault(chk.get("group") or "Outros", []).append(chk)
    for g in groups.values():
        g.sort(key=lambda x: {"fail": 0, "warn": 1, "unknown": 2, "ok": 3}.get(x["status"], 4))
    disks = [
        {
            **d,
            "meter": _meter(d["mount"], d["pct"], th["disk"], f"{d['pct']:g}% · {d['free_gb']} GiB livres"),
            "imeter": _meter("inodes", d.get("inode_pct"), th["disk"]),
        }
        for d in (rep.get("metrics") or {}).get("disks", [])
    ]
    hard = rep.get("hardening", [])
    return {
        **c,
        "groups": groups,
        "disks": disks,
        "hard_counts": {k: sum(1 for x in hard if x["status"] == k) for k in ("ok", "warn", "fail", "unknown")},
        "chart_score": spark([p.get("score") for p in hist], 560, 90, 0, 100),
        "chart_mem": spark([p.get("mem") for p in hist], 560, 90, 0, 100),
        "chart_disk": spark([p.get("disk") for p in hist], 560, 90, 0, 100),
        "chart_sec": spark([p.get("sec") for p in hist], 560, 90, 0),
        "history": hist,
        "hist_from": _dt(hist[0]["at"]) if hist else None,
        "host_key": host_key(settings, host),
        "runs": [r for r in store.list_runs(host_id=host.id, limit=60) if r.source in (Source.SERVER, Source.PATCH)][
            :20
        ],
    }
