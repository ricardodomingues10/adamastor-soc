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

from socportal import __version__
from socportal.config import Settings, get_settings
from socportal.graph import layout
from socportal.monitor import Monitor
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
        ctx = board_ctx()
        if partial == "board":
            return render(request, "partials/board.html", ctx)
        return render(request, "dashboard.html", ctx)

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
