"""Páginas Ligar (URL + chave), Automatismos (tudo o que corre sozinho) e Mapa do SOC."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from starlette.datastructures import FormData

from socportal import detect
from socportal.catalog import FUNCTIONS, TEMPLATES_BY_ID, coverage
from socportal.config import Settings
from socportal.forms import PROBE_FIELDS, FormError, build_service, slugify
from socportal.monitor import Monitor
from socportal.registry import RegistryError
from socportal.ui_store import ServiceStore

# O ciclo do SOC, da esquerda para a direita (página Mapa)
STAGES = [
    ("Ver", "Recolher o que acontece", ["siem", "edr", "ndr", "observability"]),
    ("Saber", "Conhecer o que temos e o que nos ameaça", ["assets", "surface", "vuln", "cti"]),
    ("Decidir", "Investigar e priorizar", ["cases", "analysis"]),
    ("Responder", "Agir depressa e de forma repetível", ["soar", "dfir"]),
    ("Sustentar", "Acessos e segredos da própria equipa", ["identity", "secrets"]),
]
# Fluxos de informação entre funções (setas do mapa)
FLOWS = [
    ("edr", "siem", "alertas"),
    ("ndr", "siem", "eventos"),
    ("siem", "cases", "incidentes"),
    ("cti", "siem", "indicadores"),
    ("cti", "cases", "contexto"),
    ("assets", "vuln", "inventário"),
    ("surface", "vuln", "exposição"),
    ("vuln", "cases", "prioridades"),
    ("analysis", "cases", "enriquecimento"),
    ("cases", "soar", "playbooks"),
    ("soar", "edr", "contenção"),
    ("dfir", "cases", "evidências"),
]


WEEKDAYS = ["seg", "ter", "qua", "qui", "sex", "sáb", "dom"]


def _pt(d: datetime) -> str:
    return f"{WEEKDAYS[d.weekday()]} {d:%d/%m %H:%M}"


def _dt(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        d = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.astimezone()
    except ValueError:
        return None


def values_to_form(v: dict[str, Any], secret: str = "") -> FormData:
    """Valores de formulário (como forms.values_from_template) → o que o browser enviaria."""
    items: list[tuple[str, str]] = []
    for k in ("template", "name", "id", "group", "function", "description", "link", "api_url", "location", "latest"):
        items.append((k, str(v.get(k) or "")))
    for d in v.get("depends_on", []):
        items.append(("depends_on", d))
    for i, p in enumerate(v.get("probes", [])[:3]):
        for f in PROBE_FIELDS:
            items.append((f"p{i}_{f}", str(p.get(f) or "")))
        if secret and v.get("_token_slot") == i:
            items.append((f"p{i}_token", secret))
    return FormData(items)


def register(
    app: FastAPI,
    *,
    settings: Settings,
    monitor: Monitor,
    store: ServiceStore,
    render: Callable[..., Any],
    toast: Callable[..., dict[str, str]],
    auth: list,
    auth_post: list,
    changed: Callable[[], None],
) -> None:

    # ---------------------------------------------------------------- Ligar
    # A chave nunca volta ao browser: fica aqui (memória, 15 min) e o formulário leva só uma referência.
    pending: dict[str, tuple[float, str, str]] = {}

    def keep(key: str, user: str) -> str:
        now = time.time()
        for ref in [r for r, (t, _, _) in pending.items() if now - t > 900]:
            pending.pop(ref, None)
        if not key:
            return ""
        ref = secrets.token_urlsafe(16)
        pending[ref] = (now, key, user)
        return ref

    def recall(form: Any) -> tuple[str, str]:
        ref = str(form.get("ref", ""))
        if ref in pending:
            _, key, user = pending[ref]
            return key, user
        return str(form.get("key", "")).strip(), str(form.get("user", "")).strip()

    @app.get("/connect", dependencies=auth)
    async def connect_page(request: Request) -> Response:
        return render(request, "connect.html", {"hints": detect.KEY_HINTS, "templates": TEMPLATES_BY_ID})

    @app.post("/connect/detect", dependencies=auth_post)
    async def connect_detect(request: Request) -> Response:
        form = await request.form()
        raw_url = str(form.get("url", ""))
        key, user = recall(form)
        forced = str(form.get("template", "")).strip()
        try:
            url = detect.normalize_url(raw_url)
        except ValueError as exc:
            return render(request, "partials/connect_result.html", {"error": str(exc)})
        det = detect.detect(url, settings, monitor.session)
        chosen = forced if forced in TEMPLATES_BY_ID else (det.best.template if det.best else "")
        ctx: dict[str, Any] = {
            "det": det,
            "url": url,
            "ref": keep(key, user),
            "has_key": bool(key),
            "chosen": chosen,
            "hint": detect.KEY_HINTS.get(chosen, ""),
            "templates": TEMPLATES_BY_ID,
            "functions": FUNCTIONS,
            "results": [],
            "errors": {},
        }
        if chosen:
            values, secret = detect.build_values(chosen, url, key=key, user=user)
            ctx["values"] = values
            ctx["needs_key"] = (
                chosen in detect.KEYED
                and detect.KEYED[chosen].get("auth")
                and not key
                and detect.KEYED[chosen]["type"] != "http"
            )
            try:
                built = build_service(values_to_form(values, secret), store, for_test=True)
                for p in built.service.probes:
                    r = monitor.prober.run(built.service.resolve(p), monitor.components)
                    ctx["results"].append({"probe": p.label, "url": built.service.resolve(p).url, **r.to_dict()})
                ctx["service"] = built.service
            except FormError as exc:
                ctx["errors"] = exc.errors
        return render(request, "partials/connect_result.html", ctx)

    @app.post("/connect/save", dependencies=auth_post)
    async def connect_save(request: Request) -> Response:
        form = await request.form()
        tid = str(form.get("template", ""))
        if tid not in TEMPLATES_BY_ID:
            return Response(status_code=400, headers=toast("Escolhe primeiro o tipo de serviço.", "error"))
        url = detect.normalize_url(str(form.get("url", "")))
        key, user = recall(form)
        values, secret = detect.build_values(tid, url, key=key, user=user)
        name = str(form.get("name", "")).strip() or values["name"] or url
        values["name"] = name
        base = slugify(str(form.get("id", "")).strip() or name)
        sid, n = base, 2
        while monitor.config.get(sid):
            sid, n = f"{base}-{n}", n + 1
        values["id"] = sid
        values["location"] = str(form.get("location", "")).strip()
        try:
            built = build_service(values_to_form(values, secret), store)
            store.save(built.service, monitor.config)
        except (FormError, RegistryError) as exc:
            return Response(status_code=422, headers=toast(f"Não foi possível gravar: {exc}", "error"))
        for slot, value in built.secrets.items():
            store.write_secret(built.service.id, slot, value)
        pending.pop(str(form.get("ref", "")), None)
        changed()
        if request.headers.get("hx-request"):
            return Response(status_code=204, headers={"HX-Redirect": f"/s/{sid}?criado=1"})
        return RedirectResponse(f"/s/{sid}?criado=1", status_code=303)

    # ---------------------------------------------------------------- Automatismos
    def automations() -> dict[str, Any]:
        now = datetime.now().astimezone()
        rows = []
        for s in monitor.config.services:
            st = monitor.state(s.id)
            for j in st.jobs or []:
                nxt, last = _dt(j.get("next_run")), _dt(j.get("last_finished"))
                rows.append(
                    {
                        "service": s,
                        "service_status": st.status,
                        "id": j.get("id"),
                        "name": j.get("name") or j.get("id"),
                        "next": nxt,
                        "last": last,
                        "last_status": j.get("last_status") or "unknown",
                    }
                )
        # o próprio portal também trabalha sozinho
        portal_rows = [
            {"name": f"Verificar todos os serviços (a cada {settings.poll_seconds} s)", "every": settings.poll_seconds},
            {"name": f"Procurar versões novas no GitHub (a cada {settings.versions_hours:g} h)", "every": None},
        ]
        if settings.webhook_url.get_secret_value():
            portal_rows.append(
                {"name": f"Alertar no webhook quando um serviço muda ({settings.webhook_level})", "every": None}
            )
        horizon = timedelta(days=7)
        upcoming = sorted((r for r in rows if r["next"] and now <= r["next"] <= now + horizon), key=lambda r: r["next"])
        width = 1000.0
        for r in rows:
            r["x"] = round(width * (r["next"] - now) / horizon, 1) if r in upcoming else None
        days = []
        for i in range(8):
            d = now + timedelta(days=i)
            days.append({"x": round(width * i / 7, 1), "label": f"{WEEKDAYS[d.weekday()]} {d:%d}"})
        for r in rows:
            r["next_label"] = _pt(r["next"].astimezone()) if r["next"] else ""
        lanes: dict[str, list[dict]] = {}
        for r in upcoming:
            lanes.setdefault(r["service"].name, []).append(r)
        counts = {k: sum(1 for r in rows if r["last_status"] == k) for k in ("ok", "warn", "fail", "unknown")}
        late = [r for r in rows if r["next"] and r["next"] < now - timedelta(minutes=30)]
        return {
            "rows": sorted(rows, key=lambda r: (r["next"] is None, r["next"] or now)),
            "portal_rows": portal_rows,
            "lanes": lanes,
            "days": days,
            "counts": counts,
            "late": late,
            "upcoming": upcoming,
            "now": now,
        }

    @app.get("/automations", dependencies=auth)
    async def automations_page(request: Request) -> Response:
        return render(request, "automations.html", automations())

    # ---------------------------------------------------------------- Mapa
    @app.get("/map", dependencies=auth)
    async def map_page(request: Request) -> Response:
        cov = {c["id"]: c for c in coverage(monitor.config.services)}
        states = {s.id: monitor.state(s.id) for s in monitor.config.services}
        # componentes que já aparecem como serviço próprio (ex.: Greenbone, Servidores) não se repetem
        shown = {
            (p.service, p.component) for s in monitor.config.services for p in s.probes if p.type == "soc-component"
        }
        stages = []
        for name, why, fids in STAGES:
            funcs = []
            for fid in fids:
                c = cov.get(fid) or {"id": fid, **FUNCTIONS[fid], "services": []}
                svcs = [{"def": s, "state": states[s.id]} for s in c["services"]]
                comps = []
                for s in c["services"]:
                    for cid, comp in (monitor.components.get(s.id) or {}).items():
                        if (s.id, cid) in shown:
                            continue
                        comps.append(
                            {
                                "id": cid,
                                "name": comp.get("name", cid),
                                "status": comp.get("status", "unknown"),
                                "message": comp.get("message", ""),
                            }
                        )
                worst = (
                    "off"
                    if not svcs
                    else max(
                        (x["state"].status for x in svcs),
                        key=lambda st: {"fail": 4, "warn": 3, "unknown": 2, "off": 1, "ok": 0}.get(st, 2),
                    )
                )
                suggest = [t for t in TEMPLATES_BY_ID.values() if t.get("function") == fid][:3]
                funcs.append(
                    {
                        "id": fid,
                        "name": c["name"],
                        "why": c.get("why", ""),
                        "services": svcs,
                        "components": comps,
                        "status": worst,
                        "suggest": suggest,
                    }
                )
            stages.append({"name": name, "why": why, "functions": funcs})
        on = {f["id"] for st in stages for f in st["functions"] if f["services"]}
        names = {k: v["name"] for k, v in FUNCTIONS.items()}
        flows = [
            {"from": a, "to": b, "label": lbl, "live": a in on and b in on, "from_name": names[a], "to_name": names[b]}
            for a, b, lbl in FLOWS
        ]
        total = sum(len(st["functions"]) for st in stages)
        return render(
            request,
            "map.html",
            {"stages": stages, "flows": flows, "covered": len(on), "total": total, "edges": monitor.edges()},
        )
