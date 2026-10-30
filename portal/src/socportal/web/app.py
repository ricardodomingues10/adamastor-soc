"""Interface do portal (FastAPI + Jinja2 + HTMX, sem build de frontend)."""

from __future__ import annotations

import hmac
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from socportal import __version__, inventory
from socportal.catalog import FUNCTIONS, TEMPLATES, coverage
from socportal.config import Settings, get_settings
from socportal.forms import (
    PROBE_SLOTS,
    FormError,
    build_service,
    values_from_form,
    values_from_service,
    values_from_template,
)
from socportal.graph import layout
from socportal.monitor import Monitor
from socportal.registry import RegistryError, ServiceDef
from socportal.ui_store import ServiceStore
from socportal.web.security import (
    LoginRequired,
    LoginThrottle,
    SecurityHeaders,
    check_credentials,
    csrf_token,
    login_redirect,
    require_user,
    safe_next,
    verify_csrf,
)

log = logging.getLogger(__name__)
HERE = Path(__file__).parent

PROBE_TYPES = {
    "http": "HTTP (código, texto, versão)",
    "tcp": "TCP (host:porta)",
    "defectdojo": "DefectDojo (API v2)",
    "misp": "MISP (API)",
    "soc-status": "soc-status/1",
    "soc-component": "Componente de outro serviço",
}

STATUS_LABELS = {
    "ok": "OK",
    "warn": "Atenção",
    "fail": "Em baixo",
    "off": "Adormecido",
    "unknown": "Por verificar",
}


def _filters(settings: Settings) -> dict[str, Any]:
    tz = ZoneInfo(settings.timezone)

    def to_dt(value: Any) -> datetime | None:
        if not value:
            return None
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        if isinstance(value, datetime) and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value if isinstance(value, datetime) else None

    def dt(value: Any, fmt: str = "%d/%m/%Y %H:%M") -> str:
        d = to_dt(value)
        return d.astimezone(tz).strftime(fmt) if d else "—"

    def ago(value: Any) -> str:
        d = to_dt(value)
        if not d:
            return "nunca"
        secs = (datetime.now(UTC) - d).total_seconds()
        future, secs = secs < 0, abs(secs)
        if secs < 60:
            text = "segundos"
        elif secs < 3600:
            text = f"{int(secs // 60)} min"
        elif secs < 86400:
            text = f"{int(secs // 3600)} h"
        elif secs < 86400 * 60:
            text = f"{int(secs // 86400)} d"
        else:
            return dt(d, "%d/%m/%Y")
        return f"daqui a {text}" if future else f"há {text}"

    def hours(value: Any) -> str:
        if value is None:
            return "—"
        h = float(value)
        if h < 1:
            return f"{int(h * 60)} min"
        if h < 48:
            return f"{h:.0f} h"
        return f"{h / 24:.0f} dias"

    return {"dt": dt, "ago": ago, "hours": hours}


def create_app(settings: Settings | None = None, monitor: Monitor | None = None, *, start: bool = True) -> FastAPI:
    settings = settings or get_settings()
    monitor = monitor or Monitor(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        if start:
            monitor.start()
        yield
        monitor.stop()

    app = FastAPI(title="Portal SOC", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.monitor = settings, monitor
    throttle = LoginThrottle()
    app.add_middleware(SecurityHeaders)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.resolved_secret_key(),
        session_cookie="socportal_session",
        max_age=settings.session_hours * 3600,
        same_site="strict",
        https_only=settings.cookie_secure,
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters.update(_filters(settings))
    templates.env.globals.update(app_version=__version__, STATUS_LABELS=STATUS_LABELS)

    def render(request: Request, name: str, ctx: dict[str, Any] | None = None, status_code: int = 200) -> HTMLResponse:
        context = {
            "request": request,
            "csrf": csrf_token(request),
            "user": request.session.get("user"),
            "title": monitor.config.title,
            "path": request.url.path,
        }
        context.update(ctx or {})
        return templates.TemplateResponse(request, name, context, status_code=status_code)

    def toast(message: str, level: str = "ok") -> dict[str, str]:
        return {"HX-Trigger": json.dumps({"toast": {"message": message, "level": level}})}

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired) -> Response:
        return login_redirect(request, exc.next_url)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> Response:
        if request.headers.get("hx-request"):
            return Response(status_code=exc.status_code, headers=toast(str(exc.detail), "error"))
        return render(request, "error.html", {"code": exc.status_code, "message": exc.detail}, exc.status_code)

    auth = [Depends(require_user)]

    def board_ctx() -> dict[str, Any]:
        config = monitor.config
        cards = []
        for group, services in config.groups():
            items = []
            for s in services:
                items.append(
                    {
                        "def": s,
                        "state": monitor.state(s.id),
                        "latest": monitor.latest_for(s),
                        "outdated": monitor.outdated(s),
                    }
                )
            cards.append((group, items))
        states = {s.id: monitor.state(s.id).status for s in config.services}
        fresh = monitor.freshness()
        order = {"fail": 0, "warn": 1, "unknown": 2, "off": 3, "ok": 4}
        fresh.sort(key=lambda f: (order.get(f["status"], 5), f["service_name"], f.get("name", "")))
        return {
            "groups": cards,
            "summary": monitor.summary(),
            "graph": layout(config.services, states, monitor.edges()),
            "freshness": fresh,
            "events": list(monitor.events)[:15],
            "coverage": coverage(config.services),
        }

    # ------------------------------------------------------------------ público
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/login")
    async def login_page(request: Request, next: str = "/") -> Response:  # noqa: A002
        if request.session.get("user"):
            return RedirectResponse(safe_next(next), status_code=303)
        return render(
            request,
            "login.html",
            {"next": safe_next(next), "configured": bool(settings.admin_password.get_secret_value())},
        )

    @app.post("/login", dependencies=[Depends(verify_csrf)])
    async def login_submit(request: Request) -> Response:
        form = await request.form()
        username, password = str(form.get("username", "")), str(form.get("password", ""))
        next_url = safe_next(str(form.get("next", "/")))
        ip = request.client.host if request.client else "?"
        ctx = {"next": next_url, "username": username, "configured": bool(settings.admin_password.get_secret_value())}
        if throttle.blocked(ip):
            return render(
                request, "login.html", {**ctx, "error": "Demasiadas tentativas. Tenta daqui a 15 minutos."}, 429
            )
        if not check_credentials(settings, username, password):
            throttle.fail(ip)
            log.warning("login falhado para '%s' a partir de %s", username, ip)
            return render(request, "login.html", {**ctx, "error": "Utilizador ou password incorretos."}, 401)
        throttle.reset(ip)
        request.session.clear()
        request.session["user"] = username
        request.session["expires"] = time.time() + settings.session_hours * 3600
        return RedirectResponse(next_url, status_code=303)

    @app.post("/logout", dependencies=[Depends(verify_csrf)])
    async def logout(request: Request) -> Response:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    # ------------------------------------------------------------------ painel
    @app.get("/", dependencies=auth)
    async def dashboard(request: Request, partial: str | None = None) -> Response:
        ctx = {"inv": inventory.build(monitor), "config_error": monitor.registry.error}
        if partial == "inventory":
            return render(request, "partials/inventory.html", ctx)
        return render(request, "dashboard.html", ctx)

    @app.get("/inventory/{service_id}", dependencies=auth)
    async def inventory_drawer(request: Request, service_id: str) -> Response:
        inv = inventory.build(monitor)
        node = inv["nodes"].get(service_id)
        if node is None:
            raise HTTPException(404, "Serviço não encontrado")
        layer = next((ly["name"] for ly in inv["layers"] if any(x["id"] == service_id for x in ly["nodes"])), "—")
        fresh = [f for f in monitor.freshness() if f["service"] == service_id]
        return render(
            request,
            "partials/inventory_drawer.html",
            {"n": node, "names": inv["names"], "layer_name": layer, "freshness": fresh},
        )

    @app.get("/estado", dependencies=auth)
    async def estado(request: Request, partial: str | None = None) -> Response:
        ctx = board_ctx()
        if partial == "board":
            return render(request, "partials/board.html", ctx)
        return render(request, "estado.html", ctx)

    @app.get("/s/{service_id}", dependencies=auth)
    async def service_detail(request: Request, service_id: str) -> Response:
        service = monitor.config.get(service_id)
        if service is None:
            raise HTTPException(404, "Serviço não encontrado")
        state = monitor.state(service_id)
        dependents = [s for s in monitor.config.services if service_id in s.depends_on]
        return render(
            request,
            "service.html",
            {
                "s": service,
                "state": state,
                "latest": monitor.latest_for(service),
                "outdated": monitor.outdated(service),
                "freshness": [f for f in monitor.freshness() if f["service"] == service_id],
                "events": [e for e in monitor.events if e["service"] == service_id][:30],
                "dependents": dependents,
                "deps": [(monitor.config.get(d), monitor.state(d)) for d in service.depends_on],
            },
        )

    # ------------------------------------------------------------------ catálogo e serviços
    store = ServiceStore(settings.data_dir)
    auth_post = [Depends(require_user), Depends(verify_csrf)]

    def form_ctx(values: dict[str, Any], *, editing: ServiceDef | None = None, errors: dict | None = None) -> dict:
        others = [x for x in monitor.config.services if not editing or x.id != editing.id]
        return {
            "v": values,
            "editing": editing,
            "errors": errors or {},
            "functions": FUNCTIONS,
            "others": others,
            "slots": range(PROBE_SLOTS),
            "probe_types": PROBE_TYPES,
        }

    def changed() -> None:
        monitor.registry.reload(force=True)
        monitor.trigger()

    @app.get("/catalog", dependencies=auth)
    async def catalog_page(request: Request) -> Response:
        services = monitor.config.services
        used = {x.template or x.id for x in services}
        groups = [(fid, meta, [t for t in TEMPLATES if t.get("function") == fid]) for fid, meta in FUNCTIONS.items()]
        generic = [t for t in TEMPLATES if not t.get("function")]
        return render(
            request,
            "catalog.html",
            {"groups": groups, "generic": generic, "used": used, "coverage": coverage(services)},
        )

    @app.get("/services/new", dependencies=auth)
    async def service_new(request: Request, template: str = "") -> Response:
        return render(request, "service_form.html", form_ctx(values_from_template(template)))

    @app.post("/services", dependencies=auth_post)
    async def service_create(request: Request) -> Response:
        form = await request.form()
        try:
            built = build_service(form, store)
            if monitor.config.get(built.service.id):
                raise FormError({"id": f"já existe um serviço '{built.service.id}': escolhe outro id"})
            store.save(built.service, monitor.config)
        except FormError as exc:
            return render(request, "service_form.html", form_ctx(values_from_form(form), errors=exc.errors), 422)
        except RegistryError as exc:
            return render(
                request, "service_form.html", form_ctx(values_from_form(form), errors={"geral": str(exc)}), 422
            )
        for slot, value in built.secrets.items():
            store.write_secret(built.service.id, slot, value)
        changed()
        return RedirectResponse(f"/s/{built.service.id}?criado=1", status_code=303)

    @app.post("/services/test", dependencies=auth_post)
    async def service_test(request: Request) -> Response:
        form = await request.form()
        sid = str(form.get("editing", ""))
        existing = monitor.config.get(sid) if sid else None
        try:
            built = build_service(
                form, store, existing if existing and existing.origin == "ui" else None, for_test=True
            )
        except FormError as exc:
            return render(request, "partials/test_result.html", {"results": [], "errors": exc.errors})
        svc = built.service
        results = []
        for p in svc.probes:
            r = monitor.prober.run(svc.resolve(p), monitor.components)
            results.append({"probe": p.label, "url": svc.resolve(p).url, **r.to_dict()})
        return render(request, "partials/test_result.html", {"results": results, "errors": {}})

    @app.get("/s/{service_id}/edit", dependencies=auth)
    async def service_edit(request: Request, service_id: str) -> Response:
        service = monitor.config.get(service_id)
        if service is None:
            raise HTTPException(404, "Serviço não encontrado")
        if service.origin != "ui":
            raise HTTPException(409, "Este serviço está definido no portal.yaml: edita o ficheiro.")
        return render(request, "service_form.html", form_ctx(values_from_service(service), editing=service))

    @app.post("/s/{service_id}", dependencies=auth_post)
    async def service_update(request: Request, service_id: str) -> Response:
        service = monitor.config.get(service_id)
        if service is None or service.origin != "ui":
            raise HTTPException(404, "Serviço não encontrado ou definido no portal.yaml")
        form = await request.form()
        try:
            built = build_service(form, store, service)
            store.save(built.service, monitor.config, replace=service_id)
        except FormError as exc:
            return render(
                request, "service_form.html", form_ctx(values_from_form(form), editing=service, errors=exc.errors), 422
            )
        except RegistryError as exc:
            ctx = form_ctx(values_from_form(form), editing=service, errors={"geral": str(exc)})
            return render(request, "service_form.html", ctx, 422)
        for slot, value in built.secrets.items():
            store.write_secret(service_id, slot, value)
        in_use = {i for i, p in enumerate(built.service.probes) if p.token_file and "/secrets/" in p.token_file}
        store.drop_secrets(service_id, keep=in_use)
        changed()
        return RedirectResponse(f"/s/{service_id}", status_code=303)

    @app.post("/s/{service_id}/delete", dependencies=auth_post)
    async def service_delete(request: Request, service_id: str) -> Response:
        service = monitor.config.get(service_id)
        if service is None or service.origin != "ui":
            raise HTTPException(404, "Serviço não encontrado ou definido no portal.yaml")
        blocking = [x.name for x in monitor.config.services if x.origin == "file" and service_id in x.depends_on]
        if blocking:
            raise HTTPException(409, f"{', '.join(blocking)} (portal.yaml) depende deste serviço")
        store.delete(service_id)
        changed()
        return RedirectResponse("/", status_code=303)

    from socportal.web import extra_routes

    extra_routes.register(
        app,
        settings=settings,
        monitor=monitor,
        store=store,
        render=render,
        toast=toast,
        auth=auth,
        auth_post=auth_post,
        changed=changed,
    )

    @app.post("/actions/refresh", dependencies=[Depends(require_user), Depends(verify_csrf)])
    async def refresh() -> Response:
        monitor.trigger()
        return Response(status_code=204, headers=toast("A verificar todos os serviços…"))

    # ------------------------------------------------------------------ API
    @app.get("/api/summary")
    async def api_summary(request: Request) -> Response:
        expected = settings.api_token.get_secret_value()
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        has_session = bool(request.session.get("user")) and time.time() < request.session.get("expires", 0)
        if not has_session and not (expected and supplied and hmac.compare_digest(expected, supplied)):
            return JSONResponse({"error": "não autenticado"}, status_code=401)
        services = []
        for s in monitor.config.services:
            st = monitor.state(s.id)
            latest = monitor.latest_for(s) or {}
            services.append(
                {
                    "id": s.id,
                    "name": s.name,
                    "status": st.status,
                    "message": st.message,
                    "since": st.since,
                    "version": st.version,
                    "latest_version": latest.get("version"),
                    "outdated": monitor.outdated(s),
                    "checked_at": st.checked_at,
                }
            )
        return JSONResponse(
            {
                "summary": monitor.summary(),
                "services": services,
                "freshness": monitor.freshness(),
                "edges": monitor.edges(),
            }
        )

    return app
