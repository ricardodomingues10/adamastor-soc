"""Rotas da página Servidores: painel, detalhe, ligação (comando de bootstrap) e ciclos de atualização."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

from vulnflux.config import Settings
from vulnflux.engine import Engine
from vulnflux.hosts import PATCH_MODES
from vulnflux.models import Source, Trigger
from vulnflux.servers import bootstrap, cycles, ssh, view
from vulnflux.store import JsonStore


def register(
    app: FastAPI,
    *,
    settings: Settings,
    store: JsonStore,
    engine: Engine,
    render: Callable[..., Any],
    toast_headers: Callable[..., dict[str, str]],
    flash: Callable[..., None],
    auth: list,
    auth_post: list,
    get_host: Callable[[str], Any],
) -> None:

    def connect_ctx() -> dict[str, Any]:
        try:
            pub = ssh.public_key(settings)
            err = ""
        except Exception as exc:  # sem ssh-keygen: a página diz o que falta em vez de rebentar
            pub, err = "", str(exc)
        return {
            "pubkey": pub,
            "key_error": err,
            "fingerprint": ssh.fingerprint(pub) if pub else "",
            "cmd_check": bootstrap.one_liner(pub, mode="verificar") if pub else "",
            "cmd_patch": bootstrap.one_liner(pub, mode="atualizar") if pub else "",
            "remove_cmd": bootstrap.remove_script(),
        }

    def board_ctx() -> dict[str, Any]:
        return {
            **view.board(store, settings),
            **connect_ctx(),
            "PATCH_MODES": PATCH_MODES,
            "next_runs": {j["id"]: j["next"] for j in engine.next_runs()},
        }

    @app.get("/servers", dependencies=auth)
    async def servers_page(request: Request, partial: str | None = None) -> Response:
        ctx = board_ctx()
        if partial == "board":
            return render(request, "partials/servers_board.html", ctx)
        return render(request, "servers.html", ctx)

    @app.get("/servers/bootstrap.sh", dependencies=auth)
    async def servers_bootstrap(mode: str = "verificar") -> Response:
        if mode not in ("verificar", "atualizar"):
            raise HTTPException(400, "perfil inválido")
        return PlainTextResponse(
            bootstrap.script(ssh.public_key(settings), mode=mode),
            headers={"Content-Disposition": f'inline; filename="vulnflux-ligar-{mode}.sh"'},
        )

    @app.get("/servers/new", dependencies=auth)
    async def server_new(request: Request) -> Response:
        blank = {
            "ssh_enabled": True,
            "wpscan_enabled": False,
            "greenbone_enabled": False,
            "enabled": True,
            "environment": settings.dd_default_product_type,
            "ssh_port": 22,
            "ssh_user": "vulnflux",
            "patch_ring": 2,
            "patch_mode": "verificar",
            "exposure": "interno",
        }
        return render(request, "partials/host_form.html", {"host": None, "values": blank, "errors": {}})

    @app.get("/servers/{host_id}", dependencies=auth)
    async def server_detail(request: Request, host_id: str) -> Response:
        host = get_host(host_id)
        if not host.ssh_enabled:
            flash(request, f"{host.name} ainda não é verificado por SSH: ligue 'Servidor (SSH)' no host.", "warn")
        return render(
            request,
            "server_detail.html",
            {**view.detail(store, settings, host), "PATCH_MODES": PATCH_MODES, "ring_names": dict(cycles.RINGS)},
        )

    @app.post("/servers/{host_id}/check", dependencies=auth_post)
    async def server_check(request: Request, host_id: str) -> Response:
        host = get_host(host_id)
        if not host.source_enabled(Source.SERVER):
            return Response(
                status_code=409, headers=toast_headers(f"{host.name}: verificação por SSH desligada.", "error")
            )
        ids = engine.trigger_servers_check(Trigger.MANUAL, [host.id])
        if not ids:
            return Response(
                status_code=409, headers=toast_headers(f"Já há uma verificação em curso em {host.name}.", "warn")
            )
        return Response(
            status_code=204,
            headers=toast_headers(f"A verificar {host.name}… a página atualiza sozinha.", **{"X-Run-Id": ids[0]}),
        )

    @app.post("/actions/servers/check", dependencies=auth_post)
    async def servers_check_all(request: Request) -> Response:
        ids = engine.trigger_servers_check(Trigger.MANUAL)
        msg = f"{len(ids)} servidores em verificação." if ids else "Nada para verificar (ou já em curso)."
        return Response(status_code=204, headers=toast_headers(msg, "ok" if ids else "warn"))

    @app.post("/servers/{host_id}/accept-key", dependencies=auth_post)
    async def server_accept_key(request: Request, host_id: str) -> Response:
        host = get_host(host_id)
        ssh.forget_host_key(settings, host)
        engine.trigger_servers_check(Trigger.MANUAL, [host.id])
        return Response(
            status_code=204,
            headers=toast_headers(
                f"Chave antiga de {host.name} esquecida: a próxima ligação fixa a nova.",
                "warn",
                **{"HX-Refresh": "true"},
            ),
        )

    @app.post("/servers/{host_id}/ring", dependencies=auth_post)
    async def server_ring(request: Request, host_id: str) -> Response:
        """Mudar de anel / modo diretamente no painel (arrastar ou selecionar)."""
        host = get_host(host_id)
        form = await request.form()
        update: dict[str, Any] = {}
        if "patch_ring" in form:
            try:
                ring = int(str(form["patch_ring"]))
            except ValueError:
                ring = -1
            if ring not in (0, 1, 2, 3):
                raise HTTPException(400, "anel de 0 a 3")
            update["patch_ring"] = ring
        if "patch_mode" in form:
            if form["patch_mode"] not in PATCH_MODES:
                raise HTTPException(400, "modo inválido")
            update["patch_mode"] = str(form["patch_mode"])
        store.save_host(host.model_copy(update=update))
        mode = PATCH_MODES[update.get("patch_mode", host.patch_mode)]
        label = f"anel {update.get('patch_ring', host.patch_ring)} · {mode}"
        return Response(
            status_code=204,
            headers=toast_headers(f"{host.name}: {label}.", **{"HX-Trigger-After-Settle": "refresh-board"}),
        )

    # ---------------------------------------------------------------- ciclos
    @app.post("/patch/cycles", dependencies=auth_post)
    async def cycle_start(request: Request) -> Response:
        user = request.session.get("user", "?")
        cyc = engine.start_patch_cycle(Trigger.MANUAL, user)
        if cyc is None:
            return Response(status_code=409, headers=toast_headers("Já há um ciclo a decorrer.", "warn"))
        msg = cyc.get("note") or "Ciclo iniciado: o anel 0 começa agora."
        return Response(
            status_code=204,
            headers=toast_headers(msg, "ok" if cyc["status"] == "a_decorrer" else "warn", **{"HX-Refresh": "true"}),
        )

    @app.post("/patch/cycles/{cycle_id}/approve/{ring}", dependencies=auth_post)
    async def cycle_approve(request: Request, cycle_id: str, ring: int) -> Response:
        if not 0 <= ring <= 3 or not cycles.approve(store, cycle_id, ring, request.session.get("user", "?")):
            return Response(status_code=409, headers=toast_headers("Este anel já não aguarda aprovação.", "warn"))
        engine.advance_patch()
        return Response(status_code=204, headers=toast_headers(f"Anel {ring} aprovado.", **{"HX-Refresh": "true"}))

    @app.post("/patch/cycles/{cycle_id}/cancel", dependencies=auth_post)
    async def cycle_cancel(request: Request, cycle_id: str) -> Response:
        if not cycles.cancel(store, cycle_id, request.session.get("user", "?")):
            return Response(
                status_code=409, headers=toast_headers("Não é possível cancelar com um anel a atualizar.", "warn")
            )
        return Response(status_code=204, headers=toast_headers("Ciclo cancelado.", "warn", **{"HX-Refresh": "true"}))

    @app.post("/patch/cycles/{cycle_id}/resume", dependencies=auth_post)
    async def cycle_resume(request: Request, cycle_id: str) -> Response:
        if not cycles.resume(store, cycle_id, request.session.get("user", "?")):
            return Response(status_code=409, headers=toast_headers("Não foi possível retomar este ciclo.", "warn"))
        engine.advance_patch()
        return Response(
            status_code=204,
            headers=toast_headers("Ciclo retomado: a repetir o anel que falhou.", **{"HX-Refresh": "true"}),
        )
