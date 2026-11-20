"""A "maré": o estado de tudo numa frase em português simples, e a lista do que precisa de alguém.

Pensado para quem não é da equipa de segurança: em vez de matrizes e siglas, diz se está tudo bem
e, se não estiver, o que fazer primeiro (cada item leva à página onde se resolve).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from vulnflux.models import utcnow

CALM, CHOPPY, STORM = "calm", "choppy", "storm"
SEA_LABEL = {CALM: "Mar calmo", CHOPPY: "Mar agitado", STORM: "Tempestade"}
_RANK = {CALM: 0, CHOPPY: 1, STORM: 2}


@dataclass
class Todo:
    text: str
    href: str
    action: str
    level: str


@dataclass
class Briefing:
    level: str = CALM
    headline: str = ""
    sub: str = ""
    todo: list[Todo] = field(default_factory=list)

    @property
    def label(self) -> str:
        return SEA_LABEL[self.level]


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def build(
    *,
    kpi: dict[str, Any],
    health: dict[str, Any],
    risk_summary: dict[str, Any] | None,
    watch_events: list[dict[str, Any]],
    servers: list[dict[str, Any]],
    next_scan: Any = None,
) -> Briefing:
    todo: list[Todo] = []

    p1 = ((risk_summary or {}).get("stats") or {}).get("by_priority", {}).get("P1", 0)
    if p1:
        todo.append(
            Todo(
                _plural(p1, "vulnerabilidade para corrigir já", "vulnerabilidades para corrigir já")
                + " (prioridade máxima)",
                "/risk?p=P1",
                "Ver quais",
                STORM,
            )
        )

    week = utcnow() - timedelta(days=7)
    wp_vulns = [
        e
        for e in watch_events
        if e.get("kind") == "vulnerabilidade" and str(e.get("detected_at", "")) >= week.isoformat()
    ]
    if wp_vulns:
        urgent = any(e.get("severity") in ("critical", "high") for e in wp_vulns)
        sites = {s.get("host_id") for e in wp_vulns for s in e.get("sites") or []}
        todo.append(
            Todo(
                f"{_plural(len(wp_vulns), 'falha nova', 'falhas novas')} em plugins WordPress, "
                f"{_plural(len(sites), 'site afetado', 'sites afetados')}",
                "/wordpress?f=vulnerabilidade",
                "Ver sites",
                STORM if urgent else CHOPPY,
            )
        )

    crit_servers = [s for s in servers if s.get("status") == "fail"]
    sec_updates = sum(int(s.get("security_updates") or 0) for s in servers)
    if crit_servers:
        todo.append(
            Todo(
                f"{_plural(len(crit_servers), 'servidor em estado crítico', 'servidores em estado crítico')}",
                "/servers",
                "Abrir servidores",
                STORM,
            )
        )
    elif sec_updates:
        n = sum(1 for s in servers if s.get("security_updates"))
        todo.append(
            Todo(
                _plural(n, "servidor com atualizações de segurança", "servidores com atualizações de segurança")
                + " por instalar",
                "/servers",
                "Abrir servidores",
                CHOPPY,
            )
        )

    down = [h.get("label", k) for k, h in health.items() if h.get("status") == "fail"]
    if down:
        todo.append(
            Todo(
                ("Sem ligação a " + ", ".join(down[:3])) + (" e outros" if len(down) > 3 else ""),
                "/settings",
                "Ver ligações",
                CHOPPY,
            )
        )

    failed = int(kpi.get("failed_24h") or 0)
    if failed:
        todo.append(
            Todo(
                f"{_plural(failed, 'análise falhou', 'análises falharam')} nas últimas 24 horas",
                "/errors?days=1",
                "Ver porquê",
                CHOPPY,
            )
        )

    stale = int(kpi.get("stale") or 0)
    if stale:
        todo.append(
            Todo(
                f"{_plural(stale, 'análise sem resultado recente', 'análises sem resultado recente')}",
                "/hosts",
                "Ver hosts",
                CHOPPY,
            )
        )

    level = max((t.level for t in todo), key=_RANK.__getitem__, default=CALM)
    todo.sort(key=lambda t: -_RANK[t.level])
    b = Briefing(level=level, todo=todo)
    hosts = int(kpi.get("hosts_active") or 0)
    if level == CALM:
        b.headline = "Está tudo em ordem."
        b.sub = (
            f"{_plural(hosts, 'sistema vigiado', 'sistemas vigiados')}, sem falhas nem vulnerabilidades urgentes."
            if hosts
            else "Ainda não há sistemas vigiados. Começa por acrescentar um em Hosts."
        )
    elif level == STORM:
        urgent = sum(1 for t in todo if t.level == STORM)
        b.headline = f"{_plural(urgent, 'assunto urgente', 'assuntos urgentes')} para resolver hoje."
        b.sub = "Começa pelo primeiro da lista: está ordenada pelo que traz mais risco."
    else:
        b.headline = f"{_plural(len(todo), 'coisa precisa', 'coisas precisam')} de atenção."
        b.sub = "Nada urgente, mas convém ver hoje para não se acumular."
    return b


def wave_path(level: str, width: int = 2400, height: int = 84, phase: float = 0.0, line: bool = False) -> str:
    """Caminho SVG do horizonte: quase plano com mar calmo, ondas altas e curtas na tempestade.

    A largura é o dobro do visível e o padrão repete-se, para a deriva em CSS (translateX -50%) não saltar.
    """
    amp = {CALM: 2.5, CHOPPY: 6.0, STORM: 10.0}.get(level, 2.5)
    waves = {CALM: 4, CHOPPY: 6, STORM: 10}.get(level, 4)
    base = height * (0.42 if line else 0.5)
    pts = []
    steps = 160
    for i in range(steps + 1):
        x = width * i / steps
        t = 2 * math.pi * waves * i / steps + phase
        y = base - amp * (math.sin(t) + 0.35 * math.sin(2 * t + 1.3))
        pts.append(f"{x:.1f},{y:.1f}")
    d = "M" + " L".join(pts)
    if line:
        return d
    return f"{d} L{width},{height} L0,{height} Z"
