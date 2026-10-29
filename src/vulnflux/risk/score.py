"""Modelo de prioridade por risco (v1).

    ameaça   = 0,30·(CVSS/10) + 0,30·EPSS_percentil + 0,25·exploit + 0,15·KEV
               exploit: 0 nenhum · 0,4 PoC (ExploitDB não verificado)
                        0,7 ExploitDB verificado ou template Nuclei · 1,0 módulo Metasploit
               KEV: 1 se estiver no catálogo da CISA; uso em ransomware força exploit = 1
    contexto = exposição × criticidade efetiva
               exposição: internet 1,0 · DMZ 0,8 · interno 0,6 · isolado 0,4
               criticidade: crítico 1,0 · alto 0,85 · médio 0,7 · baixo 0,5
    risco    = round(100 × ameaça × contexto)

    Regras: KEV + internet → P1; KEV + DMZ → pelo menos P2.
    P1 ≥ 70 · P2 50–69 · P3 30–49 · P4 < 30

Findings sem CVE (backups expostos, utilizadores enumerados, hardening) usam a
severidade do scanner como ameaça. Findings Info não são priorizados.

Pesos num só sítio e versionados: mudar o modelo é mudar este ficheiro (e MODEL),
para se perceber depois porque é que uma prioridade mudou.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

from vulnflux.risk.context import effective_criticality

MODEL = "v1"

W_CVSS, W_EPSS, W_EXPLOIT, W_KEV = 0.30, 0.30, 0.25, 0.15
EXPOSURE_FACTOR = {"internet": 1.0, "dmz": 0.8, "interno": 0.6, "isolado": 0.4}
CRITICALITY_FACTOR = {"critico": 1.0, "alto": 0.85, "medio": 0.7, "baixo": 0.5}
EXPLOIT_LEVEL = {"metasploit": 1.0, "exploitdb-verified": 0.7, "nuclei": 0.7, "exploitdb": 0.4}
SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
SEVERITY_THREAT = {"critical": 0.85, "high": 0.65, "medium": 0.4, "low": 0.15, "info": 0.0}
THRESHOLDS = ((70, "P1"), (50, "P2"), (30, "P3"))
PRIORITIES = ("P1", "P2", "P3", "P4")


@dataclass(frozen=True)
class Intel:
    """O que se sabe de um CVE nos feeds públicos."""

    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_date: date | None = None
    kev_due: date | None = None
    ransomware: bool = False
    exploits: frozenset[str] = frozenset()


@dataclass
class Assessment:
    score: int
    priority: str
    threat: float
    context: float
    reasons: list[str] = field(default_factory=list)
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_date: date | None = None
    kev_due: date | None = None
    ransomware: bool = False
    exploits: list[str] = field(default_factory=list)

    @property
    def exploit_level(self) -> float:
        if self.ransomware:
            return 1.0
        return max((EXPLOIT_LEVEL.get(e, 0.0) for e in self.exploits), default=0.0)


def _priority(score: int) -> str:
    for threshold, prio in THRESHOLDS:
        if score >= threshold:
            return prio
    return "P4"


def merge_intel(items: list[Intel]) -> Intel:
    """Vários CVE no mesmo finding: conta o pior de cada sinal."""
    if not items:
        return Intel()
    epss = [i.epss for i in items if i.epss is not None]
    pct = [i.epss_percentile for i in items if i.epss_percentile is not None]
    kev_dates = [i.kev_date for i in items if i.kev_date]
    dues = [i.kev_due for i in items if i.kev_due]
    return Intel(
        epss=max(epss) if epss else None,
        epss_percentile=max(pct) if pct else None,
        kev=any(i.kev for i in items),
        kev_date=min(kev_dates) if kev_dates else None,
        kev_due=min(dues) if dues else None,
        ransomware=any(i.ransomware for i in items),
        exploits=frozenset().union(*(i.exploits for i in items)),
    )


def assess(
    *,
    severity: str,
    cvss: float | None,
    has_cve: bool,
    intel: Intel,
    exposure: str,
    criticality: str,
    data_class: str,
) -> Assessment | None:
    sev = (severity or "").lower()
    if sev == "info":
        return None
    crit = effective_criticality(criticality, data_class)
    context = EXPOSURE_FACTOR.get(exposure, 1.0) * CRITICALITY_FACTOR.get(crit, 0.7)
    reasons: list[str] = []
    exploits = sorted(intel.exploits, key=lambda e: -EXPLOIT_LEVEL.get(e, 0))
    a = Assessment(
        score=0,
        priority="P4",
        threat=0.0,
        context=context,
        reasons=reasons,
        epss=intel.epss,
        epss_percentile=intel.epss_percentile,
        kev=intel.kev,
        kev_date=intel.kev_date,
        kev_due=intel.kev_due,
        ransomware=intel.ransomware,
        exploits=exploits,
    )
    if has_cve:
        cvss_value = cvss if cvss is not None else SEVERITY_CVSS.get(sev, 5.0)
        threat = (
            W_CVSS * min(cvss_value, 10.0) / 10
            + W_EPSS * (intel.epss_percentile or 0.0)
            + W_EXPLOIT * a.exploit_level
            + W_KEV * (1.0 if intel.kev else 0.0)
        )
        reasons.append(f"CVSS {cvss_value:.1f}" + ("" if cvss is not None else " (pela severidade)"))
        if intel.epss_percentile is not None:
            reasons.append(f"EPSS percentil {intel.epss_percentile:.2f}")
        if exploits:
            reasons.append("exploit: " + ", ".join(exploits))
        if intel.kev:
            reasons.append("no catálogo KEV" + (" (ransomware)" if intel.ransomware else ""))
    else:
        threat = SEVERITY_THREAT.get(sev, 0.4)
        reasons.append(f"sem CVE: severidade {severity}")
    if crit != criticality:
        reasons.append(f"criticidade elevada a {crit} pelos dados tratados")
    reasons.append(f"contexto {exposure} × {crit} = {context:.2f}")

    a.threat = round(threat, 4)
    a.score = min(100, round(100 * threat * context))
    a.priority = _priority(a.score)
    if intel.kev and exposure == "internet" and a.priority != "P1":
        a.priority = "P1"
        reasons.append("regra: KEV exposto à Internet → P1")
    elif intel.kev and exposure == "dmz" and a.priority in ("P3", "P4"):
        a.priority = "P2"
        reasons.append("regra: KEV na DMZ → pelo menos P2")
    return a


def remediation_date(found: date, priority: str, sla_days: dict[str, int], kev_due: date | None = None) -> date:
    """Data planeada = descoberta + SLA da prioridade; o prazo da CISA ganha se for antes."""
    planned = found + timedelta(days=sla_days[priority])
    if kev_due and found <= kev_due < planned:
        return kev_due
    return planned
