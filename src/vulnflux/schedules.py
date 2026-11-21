"""Agendas editáveis na interface (Definições → Agenda), sem mexer no .env nem reiniciar.

O valor no .env (VF_*_CRON) é o de partida; uma alteração feita na interface fica guardada no
estado (store "schedules") e prevalece. Vazio desliga a tarefa.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from apscheduler.triggers.cron import CronTrigger

from vulnflux.config import Settings
from vulnflux.store import JsonStore

STATE_KEY = "schedules"


@dataclass(frozen=True)
class Editable:
    job_id: str
    setting: str
    label: str
    help: str
    can_disable: bool = True
    min_minutes: int = 60  # intervalo mínimo entre execuções (scans contra produção não correm a cada minuto)


EDITABLE: tuple[Editable, ...] = (
    Editable("wpscan_batch", "wpscan_cron", "Análise diária dos sites WordPress", "o lote rápido", can_disable=False),
    Editable(
        "wpscan_deep", "wpscan_deep_cron", "Análise completa dos sites WordPress", "procura também os plugins populares"
    ),
    Editable(
        "wp_detect", "wp_detect_cron", "Deteção de quais hosts são WordPress", "convém correr antes da análise diária"
    ),
    Editable("greenbone_batch", "greenbone_cron", "Scan de rede (Greenbone)", "todos os hosts com Greenbone ativo"),
    Editable("risk_daily", "risk_cron", "Prioridades por risco", "descarrega KEV, EPSS e exploits e recalcula"),
    Editable("servers_check", "servers_cron", "Verificação dos servidores", "saúde, hardening e atualizações por SSH"),
    Editable("patch_cycle", "patch_cron", "Ciclo de atualizações por anéis", "instala atualizações, anel a anel"),
)
BY_JOB = {e.job_id: e for e in EDITABLE}

_DAYS = ["domingo", "segunda", "terça", "quarta", "quinta", "sexta", "sábado"]


def min_gap_minutes(expr: str, timezone: str, samples: int = 48) -> float:
    """Menor intervalo, em minutos, entre as próximas execuções de uma expressão cron."""
    trigger = CronTrigger.from_crontab(expr, timezone=timezone)
    now = datetime.now(trigger.timezone)
    prev = trigger.get_next_fire_time(None, now)
    gaps = []
    for _ in range(samples):
        if prev is None:
            break
        nxt = trigger.get_next_fire_time(prev, prev + timedelta(seconds=1))
        if nxt is None:
            break
        gaps.append((nxt - prev).total_seconds() / 60)
        prev = nxt
    return min(gaps) if gaps else float("inf")


def validate(expr: str, timezone: str, min_minutes: int = 0) -> str:
    expr = " ".join(expr.split())
    if expr:
        gap = min_gap_minutes(expr, timezone)  # ValueError se inválida
        if min_minutes and gap < min_minutes:
            raise ValueError(f"corre de {gap:.0f} em {gap:.0f} min; o mínimo para esta tarefa é {min_minutes} min")
    return expr


def apply_overrides(settings: Settings, store: JsonStore) -> None:
    """Põe nas definições em memória o que foi alterado na interface."""
    saved = store.get_state(STATE_KEY, {}) or {}
    for e in EDITABLE:
        if e.setting in saved:
            setattr(settings, e.setting, saved[e.setting])


def save(settings: Settings, store: JsonStore, setting: str, expr: str) -> str:
    edit = next((e for e in EDITABLE if e.setting == setting), None)
    if edit is None:
        raise ValueError("agenda desconhecida")
    expr = validate(expr, settings.timezone, edit.min_minutes)
    if not expr and not edit.can_disable:
        raise ValueError("esta tarefa não pode ficar desligada")
    with store.locked():
        saved = store.get_state(STATE_KEY, {}) or {}
        saved[setting] = expr
        store.set_state(STATE_KEY, saved)
    setattr(settings, setting, expr)
    return expr


def describe(expr: str) -> str:
    """Cron em português simples, para os casos comuns; o resto fica como está."""
    parts = expr.split()
    if not expr:
        return "desligada"
    if len(parts) != 5:
        return expr
    minute, hour, dom, month, dow = parts
    if not (minute.isdigit() and month == "*"):
        return expr
    if hour.startswith("*/") and dom == "*" and dow == "*":
        return f"a cada {hour[2:]} h (ao minuto {int(minute)})"
    if not hour.isdigit():
        return expr
    at = f"às {int(hour):02d}:{int(minute):02d}"
    if dom == "*" and dow == "*":
        return f"todos os dias {at}"
    if dom == "*" and dow == "1-5":
        return f"dias úteis {at}"
    if dom == "*" and dow.isdigit() and 0 <= int(dow) <= 7:
        day = _DAYS[int(dow) % 7]
        return f"todas as semanas, {day}{'-feira' if day not in ('sábado', 'domingo') else ''}, {at}"
    if dom.isdigit() and dow == "*":
        return f"todos os meses, dia {int(dom)}, {at}"
    return expr
