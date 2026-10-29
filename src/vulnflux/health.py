"""Verificação das dependências (mostrada no topo do dashboard)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from vulnflux.collectors import wpscan
from vulnflux.config import Settings
from vulnflux.defectdojo import DefectDojo
from vulnflux.errors import ErrorKind, VFError
from vulnflux.greenbone.lifecycle import LifecycleError
from vulnflux.greenbone.readiness import probe
from vulnflux.models import utcnow
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)

OK, WARN, FAIL, OFF = "ok", "warn", "fail", "off"


def _result(status: str, message: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "message": message, "details": details, "checked_at": utcnow().isoformat()}


def _guard(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return fn()
    except VFError as exc:
        status = WARN if exc.kind is ErrorKind.QUOTA else FAIL
        return _result(status, exc.message, kind=exc.kind.value)
    except Exception as exc:
        log.exception("verificação de saúde falhou")
        return _result(FAIL, f"erro interno: {exc.__class__.__name__}")


def check_defectdojo(settings: Settings) -> dict[str, Any]:
    if not settings.dd_configured:
        return _result(FAIL, "VF_DD_URL / VF_DD_TOKEN por definir")
    info = DefectDojo(settings).ping()
    return _result(OK, f"{info['latency_ms']} ms · {info.get('products')} products", **info)


def check_wpscan_api(settings: Settings) -> dict[str, Any]:
    info = wpscan.api_status(settings)
    remaining = info.get("requests_remaining")
    try:
        low = int(remaining) < settings.wpscan_min_quota
    except (TypeError, ValueError):
        low = False
    msg = f"plano {info.get('plan')} · {remaining}/{info.get('requests_limit')} pedidos"
    return _result(WARN if low else OK, msg, **info)


def check_wpscan_cli(settings: Settings) -> dict[str, Any]:
    return _result(OK, wpscan.cli_version(settings))


def check_greenbone(settings: Settings) -> dict[str, Any]:
    from vulnflux.pipeline import lifecycle_host, readiness_config

    if not settings.greenbone_enabled:
        return _result(OFF, "desativado")
    lc = lifecycle_host(settings)
    if lc is not None:
        try:
            result = lc.run("status")
        except LifecycleError as exc:
            return _result(FAIL, f"gb-ctl: {exc}")
        running = sorted(result.running())
        core = {"gvmd", "ospd-openvas", "pg-gvm", "redis-server"}
        if core.issubset(running):
            readiness = probe(readiness_config(settings))
            status = OK if readiness.ready else WARN
            return _result(status, f"ligado · {readiness.status.value}", readiness=readiness.to_dict(), running=running)
        return _result(OK, "parado (on-demand)", running=running)
    readiness = probe(readiness_config(settings))
    status = OK if readiness.ready else (FAIL if readiness.status.value == "failed" else WARN)
    return _result(status, readiness.summary(), readiness=readiness.to_dict())


CHECKS: dict[str, tuple[str, Callable[[Settings], dict[str, Any]]]] = {
    "defectdojo": ("DefectDojo", check_defectdojo),
    "wpscan_api": ("API WPScan", check_wpscan_api),
    "wpscan_cli": ("CLI WPScan", check_wpscan_cli),
    "greenbone": ("Greenbone", check_greenbone),
}


def check_all(settings: Settings, store: JsonStore) -> dict[str, Any]:
    results = {}
    for key, (label, fn) in CHECKS.items():
        res = _guard(lambda fn=fn: fn(settings))
        res["label"] = label
        results[key] = res
    store.set_state("health", results)
    return results
