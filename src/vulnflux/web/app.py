"""Aplicação web (FastAPI + Jinja2 + HTMX). Sem build de frontend: HTML, CSS e JS simples."""

from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from vulnflux.config import Settings, get_settings
from vulnflux.engine import Engine
from vulnflux.errors import ERROR_LABELS, ErrorKind
from vulnflux.hosts import HostValidationError, host_from_form, parse_bulk
from vulnflux.models import Host, RunStatus, Source, utcnow
from vulnflux.store import DuplicateHostError, JsonStore
from vulnflux.web.security import (
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
PAGE_SIZE = 50


# ---------------------------------------------------------------------------
# Filtros de template
# ---------------------------------------------------------------------------


def _make_filters(settings: Settings) -> dict[str, Any]:
    tz = ZoneInfo(settings.timezone)

    def to_dt(value: Any) -> datetime | None:
        if value is None or value == "":
            return None
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return None
        if isinstance(value, datetime) and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value

    def dt(value: Any, fmt: str = "%d/%m/%Y %H:%M") -> str:
        d = to_dt(value)
        return d.astimezone(tz).strftime(fmt) if d else "—"

    def ago(value: Any) -> str:
        d = to_dt(value)
        if not d:
            return "nunca"
        secs = (datetime.now(UTC) - d).total_seconds()
        future = secs < 0
        secs = abs(secs)
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

    def duration(seconds: float | None) -> str:
        if seconds is None:
            return "—"
        seconds = int(seconds)
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m {seconds % 60:02d}s"
        return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"

    return {
        "dt": dt,
        "ago": ago,
        "duration": duration,
        "tojson_pretty": lambda v: json.dumps(v, indent=2, ensure_ascii=False, default=str),
    }


# ---------------------------------------------------------------------------
# Fábrica da aplicação
# ---------------------------------------------------------------------------


def create_app(
    settings: Settings | None = None,
    store: JsonStore | None = None,
    engine: Engine | None = None,
    *,
    start_engine: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    store = store or JsonStore(settings.data_dir)
    engine = engine or Engine(settings, store, start_scheduler=start_engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        engine.start()
        yield
        engine.shutdown()

    app = FastAPI(title="VulnFlux", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.store, app.state.engine = settings, store, engine
    throttle = LoginThrottle()

    app.add_middleware(SecurityHeaders)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.resolved_secret_key(),
        session_cookie="vulnflux_session",
        max_age=settings.session_hours * 3600,
        same_site="strict",
        https_only=settings.cookie_secure,
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters.update(_make_filters(settings))
    templates.env.globals.update(
        Source=Source,
        RunStatus=RunStatus,
        ErrorKind=ErrorKind,
        ERROR_LABELS=ERROR_LABELS,
        settings=settings,
        app_version="0.1.0",
    )

    def render(
        request: Request,
        name: str,
        ctx: dict[str, Any] | None = None,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> HTMLResponse:
        context = {
            "request": request,
            "csrf": csrf_token(request),
            "user": request.session.get("user"),
            "flashes": request.session.pop("flash", []),
            "health": store.get_state("health", {}) or {},
            "path": request.url.path,
        }
        context.update(ctx or {})
        return templates.TemplateResponse(request, name, context, status_code=status_code, headers=headers)

    def flash(request: Request, message: str, level: str = "ok") -> None:
        request.session.setdefault("flash", []).append({"message": message, "level": level})

    def toast_headers(message: str, level: str = "ok", **extra: str) -> dict[str, str]:
        headers = {"HX-Trigger": json.dumps({"toast": {"message": message, "level": level}})}
        headers.update(extra)
        return headers

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired) -> Response:
        return login_redirect(request, exc.next_url)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> Response:
        if request.headers.get("hx-request"):
            return Response(status_code=exc.status_code, headers=toast_headers(str(exc.detail), "error"))
        if exc.status_code == 404:
            return render(request, "error.html", {"code": 404, "message": "Página não encontrada"}, status_code=404)
        return render(
            request, "error.html", {"code": exc.status_code, "message": exc.detail}, status_code=exc.status_code
        )

    auth = [Depends(require_user)]
    auth_post = [Depends(require_user), Depends(verify_csrf)]

    def get_host_or_404(host_id: str) -> Host:
        host = store.get_host(host_id)
        if host is None:
            raise HTTPException(404, "Host não encontrado")
        return host

    # ------------------------------------------------------------------ saúde
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "time": utcnow().isoformat()})

    # ------------------------------------------------------------------ login
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

    # ------------------------------------------------------------------ dashboard
    def _dashboard_ctx() -> dict[str, Any]:
        hosts = store.list_hosts()
        matrix = store.latest_matrix()
        since = utcnow() - timedelta(hours=24)
        recent = [r for r in store.list_runs(limit=500) if r.created_at >= since]
        failed_recent = [r for r in store.list_runs(statuses=[RunStatus.FAILED, RunStatus.INTERRUPTED], limit=8)]
        active = store.list_runs(statuses=[RunStatus.QUEUED, RunStatus.RUNNING])
        stale_cut = utcnow() - timedelta(days=7)
        stale = 0
        for h in hosts:
            for src in Source:
                if h.source_enabled(src):
                    good = store.last_run(h.id, src, good_only=True)
                    if good is None or (good.finished_at and good.finished_at < stale_cut and src is Source.WPSCAN):
                        stale += 1
        quota = (store.get_state("health", {}) or {}).get("wpscan_api", {}).get("details", {}).get("requests_remaining")
        return {
            "hosts": hosts,
            "matrix": matrix,
            "kpi": {
                "hosts_active": sum(1 for h in hosts if h.enabled),
                "hosts_total": len(hosts),
                "ok_24h": sum(1 for r in recent if r.status.good),
                "failed_24h": sum(1 for r in recent if r.status in (RunStatus.FAILED, RunStatus.INTERRUPTED)),
                "skipped_24h": sum(1 for r in recent if r.status is RunStatus.SKIPPED),
                "active": len(active),
                "stale": stale,
                "quota": quota,
            },
            "failed_recent": failed_recent,
            "active_runs": active,
            "next_runs": engine.next_runs(),
            "batch_wpscan": store.get_state("batch_wpscan"),
            "batch_greenbone": store.get_state("batch_greenbone"),
            "gb_state": store.get_state("greenbone", {}) or {},
        }

    @app.get("/", dependencies=auth)
    async def dashboard(request: Request, partial: str | None = None) -> Response:
        ctx = _dashboard_ctx()
        if partial == "matrix":
            return render(request, "partials/matrix.html", ctx)
        return render(request, "dashboard.html", ctx)

    # ------------------------------------------------------------------ hosts
    @app.get("/hosts", dependencies=auth)
    async def hosts_page(request: Request) -> Response:
        hosts = store.list_hosts()
        return render(request, "hosts.html", {"hosts": hosts, "matrix": store.latest_matrix()})

    @app.get("/hosts/export.json", dependencies=auth)
    async def hosts_export() -> Response:
        data = [h.model_dump(mode="json") for h in store.list_hosts()]
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
        return Response(
            json.dumps({"version": 1, "hosts": data}, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="vulnflux-hosts-{stamp}.json"'},
        )

    @app.get("/hosts/new", dependencies=auth)
    async def host_new(request: Request) -> Response:
        blank = {
            "wpscan_enabled": True,
            "greenbone_enabled": False,
            "enabled": True,
            "environment": settings.dd_default_product_type,
        }
        return render(request, "partials/host_form.html", {"host": None, "values": blank, "errors": {}})

    @app.post("/hosts", dependencies=auth_post)
    async def host_create(request: Request) -> Response:
        form = dict((await request.form()).items())
        try:
            host = host_from_form(form)
            store.save_host(host)
        except HostValidationError as exc:
            return render(request, "partials/host_form.html", {"host": None, "values": form, "errors": exc.errors}, 422)
        except DuplicateHostError as exc:
            return render(
                request, "partials/host_form.html", {"host": None, "values": form, "errors": {"name": str(exc)}}, 422
            )
        flash(request, f"Host {host.name} adicionado.")
        return Response(status_code=204, headers={"HX-Redirect": "/hosts"})

    @app.get("/hosts/bulk", dependencies=auth)
    async def host_bulk_form(request: Request) -> Response:
        return render(
            request,
            "partials/bulk_form.html",
            {"values": {"environment": settings.dd_default_product_type, "wpscan_enabled": True}, "result": None},
        )

    @app.post("/hosts/bulk", dependencies=auth_post)
    async def host_bulk(request: Request) -> Response:
        form = dict((await request.form()).items())
        truthy = {"on", "true", "1"}
        result = parse_bulk(
            str(form.get("lines", "")),
            default_environment=str(form.get("environment", "")).strip() or settings.dd_default_product_type,
            wpscan=str(form.get("wpscan_enabled", "")).lower() in truthy,
            greenbone=str(form.get("greenbone_enabled", "")).lower() in truthy,
            existing_names={h.name for h in store.list_hosts()},
        )
        if result.errors or not result.hosts:
            if not result.hosts and not result.errors:
                result.errors.append("Nenhum host novo para importar.")
            return render(request, "partials/bulk_form.html", {"values": form, "result": result}, 422)
        store.save_hosts(result.hosts)
        msg = f"{len(result.hosts)} hosts importados."
        if result.duplicates:
            msg += f" {len(result.duplicates)} já existiam e foram ignorados."
        flash(request, msg)
        return Response(status_code=204, headers={"HX-Redirect": "/hosts"})

    @app.get("/hosts/{host_id}", dependencies=auth)
    async def host_detail(request: Request, host_id: str) -> Response:
        host = get_host_or_404(host_id)
        runs = store.list_runs(host_id=host_id, limit=100)
        return render(request, "host_detail.html", {"host": host, "runs": runs, "matrix": store.latest_matrix()})

    @app.get("/hosts/{host_id}/edit", dependencies=auth)
    async def host_edit(request: Request, host_id: str) -> Response:
        host = get_host_or_404(host_id)
        values = host.model_dump()
        values["tags"] = ", ".join(host.tags)
        return render(request, "partials/host_form.html", {"host": host, "values": values, "errors": {}})

    @app.post("/hosts/{host_id}", dependencies=auth_post)
    async def host_update(request: Request, host_id: str) -> Response:
        existing = get_host_or_404(host_id)
        form = dict((await request.form()).items())
        try:
            host = host_from_form(form, existing)
            store.save_host(host)
        except HostValidationError as exc:
            return render(
                request, "partials/host_form.html", {"host": existing, "values": form, "errors": exc.errors}, 422
            )
        except DuplicateHostError as exc:
            return render(
                request,
                "partials/host_form.html",
                {"host": existing, "values": form, "errors": {"name": str(exc)}},
                422,
            )
        if existing.name != host.name:
            flash(
                request,
                f"Nome alterado de {existing.name} para {host.name}: no DefectDojo será um product novo.",
                "warn",
            )
        flash(request, f"Host {host.name} atualizado.")
        return Response(status_code=204, headers={"HX-Redirect": request.headers.get("hx-current-url") or "/hosts"})

    @app.post("/hosts/{host_id}/toggle", dependencies=auth_post)
    async def host_toggle(request: Request, host_id: str) -> Response:
        host = get_host_or_404(host_id)
        host = store.save_host(host.model_copy(update={"enabled": not host.enabled}))
        state = "ativado" if host.enabled else "desativado"
        return render(
            request,
            "partials/host_row.html",
            {"h": host, "matrix": store.latest_matrix()},
            headers=toast_headers(f"{host.name} {state}."),
        )

    @app.post("/hosts/{host_id}/delete", dependencies=auth_post)
    async def host_delete(request: Request, host_id: str) -> Response:
        host = get_host_or_404(host_id)
        store.delete_host(host_id)
        if request.headers.get("hx-target", "").startswith("host-"):
            return Response("", headers=toast_headers(f"{host.name} removido. O histórico de execuções mantém-se."))
        flash(request, f"{host.name} removido. O histórico de execuções mantém-se.")
        return Response(status_code=204, headers={"HX-Redirect": "/hosts"})

    @app.post("/hosts/{host_id}/run/{source}", dependencies=auth_post)
    async def host_run(request: Request, host_id: str, source: Source) -> Response:
        host = get_host_or_404(host_id)
        if not host.source_enabled(source):
            return Response(
                status_code=409, headers=toast_headers(f"{source.label} não está ativo para {host.name}.", "error")
            )
        run = engine.run_host(host, source)
        if run is None:
            return Response(
                status_code=409,
                headers=toast_headers(f"Já há uma execução {source.label} em curso para {host.name}.", "warn"),
            )
        extra = " O Greenbone pode demorar a arrancar." if source is Source.GREENBONE else ""
        return Response(status_code=204, headers=toast_headers(f"{source.label} em fila para {host.name}.{extra}"))

    # ------------------------------------------------------------------ execuções
    @app.get("/runs", dependencies=auth)
    async def runs_page(
        request: Request,
        source: str = "",
        status: str = "",
        kind: str = "",
        host: str = "",
        page: int = 1,
    ) -> Response:
        filters: dict[str, Any] = {}
        try:
            if source:
                filters["source"] = Source(source)
            if status:
                filters["statuses"] = [RunStatus(status)]
            if kind:
                filters["error_kind"] = ErrorKind(kind)
        except ValueError as exc:
            raise HTTPException(400, "Filtro inválido") from exc
        if host:
            filters["host_id"] = host
        page = max(1, page)
        total = store.count_runs(**filters)
        runs = store.list_runs(**filters, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
        ctx = {
            "runs": runs,
            "total": total,
            "page": page,
            "pages": max(1, -(-total // PAGE_SIZE)),
            "f": {"source": source, "status": status, "kind": kind, "host": host},
            "hosts": store.list_hosts(),
        }
        if request.headers.get("hx-request") and request.headers.get("hx-target") == "runs-table":
            return render(request, "partials/runs_table.html", ctx)
        return render(request, "runs.html", ctx)

    @app.get("/runs/{run_id}", dependencies=auth)
    async def run_detail(request: Request, run_id: str, partial: str | None = None) -> Response:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(404, "Execução não encontrada")
        ctx = {"run": run, "host": store.get_host(run.host_id)}
        if partial:
            # 286 = o htmx deixa de fazer polling quando a execução termina
            return render(request, "partials/run_body.html", ctx, status_code=286 if run.status.finished else 200)
        return render(request, "run_detail.html", ctx)

    @app.get("/runs/{run_id}/artifacts/{name}", dependencies=auth)
    async def run_artifact(run_id: str, name: str) -> Response:
        path = store.artifact_path(run_id, name)
        if path is None:
            raise HTTPException(404, "Artefacto não encontrado")
        media = (
            "application/json"
            if name.endswith(".json")
            else "application/xml"
            if name.endswith(".xml")
            else "text/plain"
        )
        return FileResponse(path, media_type=media, filename=name)

    # ------------------------------------------------------------------ erros
    @app.get("/errors", dependencies=auth)
    async def errors_page(request: Request, days: int = 7) -> Response:
        days = min(max(days, 1), 180)
        since = utcnow() - timedelta(days=days)
        failed = [
            r
            for r in store.list_runs(statuses=[RunStatus.FAILED, RunStatus.INTERRUPTED, RunStatus.SKIPPED])
            if r.created_at >= since
        ]
        groups: dict[str, dict[str, Any]] = {}
        for r in failed:
            key = f"{r.source.value}|{(r.error_kind or ErrorKind.TRANSIENT).value}|{(r.error_message or '')[:120]}"
            g = groups.setdefault(
                key,
                {
                    "source": r.source,
                    "kind": r.error_kind,
                    "message": r.error_message,
                    "count": 0,
                    "hosts": set(),
                    "last": r,
                },
            )
            g["count"] += 1
            g["hosts"].add(r.host_name)
            if r.created_at > g["last"].created_at:
                g["last"] = r
        by_kind: dict[str, int] = {}
        for r in failed:
            k = (r.error_kind or ErrorKind.TRANSIENT).value
            by_kind[k] = by_kind.get(k, 0) + 1
        ordered = sorted(groups.values(), key=lambda g: g["last"].created_at, reverse=True)
        return render(
            request, "errors.html", {"groups": ordered, "by_kind": by_kind, "days": days, "total": len(failed)}
        )

    # ------------------------------------------------------------------ definições e ações
    @app.get("/settings", dependencies=auth)
    async def settings_page(request: Request) -> Response:
        return render(
            request,
            "settings.html",
            {
                "config": settings.public_view(),
                "next_runs": engine.next_runs(),
                "schedule_errors": engine.schedule_errors,
                "gb_state": store.get_state("greenbone", {}) or {},
                "lanes": {name: engine.busy(name) for name in engine.lanes},
            },
        )

    @app.post("/actions/health", dependencies=auth_post)
    async def action_health(request: Request) -> Response:
        engine.refresh_health()
        return Response(
            status_code=204, headers=toast_headers("A verificar dependências… atualiza daqui a uns segundos.")
        )

    @app.post("/actions/batch/{source}", dependencies=auth_post)
    async def action_batch(request: Request, source: Source) -> Response:
        if source is Source.WPSCAN:
            ids = engine.trigger_wpscan_batch()
            msg = f"Lote WPScan em fila com {len(ids)} host(s)." if ids else "Nenhum host elegível para WPScan."
        else:
            ids = engine.trigger_greenbone_batch()
            msg = f"Lote Greenbone em fila com {len(ids)} host(s)." if ids else "Nenhum host com Greenbone ativo."
        return Response(status_code=204, headers=toast_headers(msg, "ok" if ids else "warn"))

    return app
