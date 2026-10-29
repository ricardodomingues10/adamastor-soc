"""Escreve no DefectDojo a prioridade por risco de cada finding ativo.

O DefectDojo OSS já tem os campos epss_score, epss_percentile, known_exploited,
ransomware_used, kev_date e planned_remediation_date; o Pro só acrescenta quem os
preenche. Este módulo é esse "quem", pela API v2:

  Product  business_criticality e internet_accessible a partir do inventário
  Finding  campos EPSS/KEV, data planeada de correção pelo SLA da prioridade e as
           tags risk:p1..p4, risk:kev, risk:ransomware, risk:exploit-<fonte>

Regras de convivência com as pessoas que usam o DefectDojo:
  - a severidade do scanner nunca é alterada (a prioridade vive ao lado dela)
  - tags que não começam por "risk:" ficam como estão
  - uma data planeada mudada à mão é respeitada: só reescrevemos a que nós escrevemos
  - só se faz PATCH quando algo muda (correr duas vezes seguidas = zero escritas)
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from vulnflux.config import Settings
from vulnflux.defectdojo import DefectDojo
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import Host, utcnow
from vulnflux.risk.context import DD_BUSINESS_CRITICALITY, effective_criticality
from vulnflux.risk.feeds import CVE_RE, FeedCache
from vulnflux.risk.score import MODEL, PRIORITIES, Assessment, assess, merge_intel, remediation_date

log = logging.getLogger(__name__)

TAG_PREFIX = "risk:"
TOP_LIMIT = 150
MAX_CONSECUTIVE_ERRORS = 20


def finding_cves(finding: dict[str, Any]) -> list[str]:
    raw: list[str] = []
    for item in finding.get("vulnerability_ids") or []:
        raw.append(item.get("vulnerability_id", "") if isinstance(item, dict) else str(item))
    if finding.get("cve"):
        raw.append(str(finding["cve"]))
    out: list[str] = []
    for value in raw:
        m = CVE_RE.fullmatch(value.strip())
        if m and m.group(0).upper() not in out:
            out.append(m.group(0).upper())
    return out


def risk_tags(a: Assessment | None) -> list[str]:
    if a is None:
        return []
    tags = [f"{TAG_PREFIX}{a.priority.lower()}"]
    if a.kev:
        tags.append(f"{TAG_PREFIX}kev")
    if a.ransomware:
        tags.append(f"{TAG_PREFIX}ransomware")
    tags += [f"{TAG_PREFIX}exploit-{e}" for e in a.exploits]
    return tags


def _float_differs(current: Any, new: float | None) -> bool:
    if new is None:
        return False
    try:
        return current is None or abs(float(current) - new) > 1e-6
    except (TypeError, ValueError):
        return True


@dataclass
class EnrichResult:
    model: str = MODEL
    products: int = 0
    products_missing: list[str] = field(default_factory=list)
    products_updated: int = 0
    findings: int = 0
    with_cve: int = 0
    info_skipped: int = 0
    updated: int = 0
    unchanged: int = 0
    manual_sla: int = 0
    kev: int = 0
    errors: int = 0
    error_samples: list[str] = field(default_factory=list)
    by_priority: dict[str, int] = field(default_factory=lambda: dict.fromkeys(PRIORITIES, 0))
    per_host: dict[str, dict[str, int]] = field(default_factory=dict)
    top: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class WrittenDates:
    """Datas planeadas que fomos nós a escrever (finding id → data ISO)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            self.data: dict[str, str] = json.loads(path.read_text())
        except (OSError, ValueError):
            self.data = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, separators=(",", ":")))
        os.replace(tmp, self.path)


def _sync_product(dd: DefectDojo, product: dict[str, Any], host: Host) -> bool:
    crit = effective_criticality(host.criticality, host.data_class)
    desired = {
        "business_criticality": DD_BUSINESS_CRITICALITY[crit],
        "internet_accessible": host.exposure == "internet",
    }
    changes = {k: v for k, v in desired.items() if product.get(k) != v}
    if changes:
        dd.patch(f"/products/{product['id']}/", changes)
    return bool(changes)


def enrich(
    settings: Settings,
    dd: DefectDojo,
    cache: FeedCache,
    hosts: list[Host],
    *,
    progress: Callable[[str], None] | None = None,
) -> EnrichResult:
    result = EnrichResult()
    note = progress or (lambda msg: None)
    sla = settings.sla_days()
    kev_loaded = (cache.dir / "kev.json").exists()

    products = {str(p.get("name", "")).lower(): p for p in dd.paginate("/products/")}
    work: list[tuple[Host, dict[str, Any]]] = []
    for host in hosts:
        product = products.get(host.name.lower())
        if product is None:
            result.products_missing.append(host.name)  # ainda sem nenhum import
            continue
        result.products += 1
        if settings.risk_sync_products:
            try:
                if _sync_product(dd, product, host):
                    result.products_updated += 1
            except VFError as exc:
                if exc.kind is ErrorKind.CONFIG:
                    raise
                result.errors += 1
                if len(result.error_samples) < 5:
                    result.error_samples.append(f"product {host.name}: {exc.message}")
        for f in dd.paginate("/findings/", {"test__engagement__product": product["id"], "active": "true"}):
            work.append((host, f))
        note(f"{result.products} products · {len(work)} findings ativos")

    all_cves = {c for _, f in work for c in finding_cves(f)}
    intel = cache.lookup(all_cves)
    written = WrittenDates(cache.dir / "planned_dates.json")
    consecutive_errors = 0

    for host, f in work:
        result.findings += 1
        cves = finding_cves(f)
        if cves:
            result.with_cve += 1
        cvss = f.get("cvssv3_score") if f.get("cvssv3_score") is not None else f.get("cvssv4_score")
        a = assess(
            severity=str(f.get("severity") or ""),
            cvss=float(cvss) if cvss is not None else None,
            has_cve=bool(cves),
            intel=merge_intel([intel[c] for c in cves if c in intel]),
            exposure=host.exposure,
            criticality=host.criticality,
            data_class=host.data_class,
        )
        current_tags = [str(t) for t in f.get("tags") or []]
        keep = [t for t in current_tags if not t.lower().startswith(TAG_PREFIX)]
        new_tags = keep + risk_tags(a)
        payload: dict[str, Any] = {}
        if sorted(t.lower() for t in current_tags) != sorted(t.lower() for t in new_tags):
            payload["tags"] = new_tags

        fid = str(f["id"])
        if a is None:
            result.info_skipped += 1
        else:
            result.by_priority[a.priority] += 1
            ph = result.per_host.setdefault(host.name, dict.fromkeys(PRIORITIES, 0))
            ph[a.priority] += 1
            if a.kev:
                result.kev += 1
            if _float_differs(f.get("epss_score"), a.epss):
                payload["epss_score"] = a.epss
            if _float_differs(f.get("epss_percentile"), a.epss_percentile):
                payload["epss_percentile"] = a.epss_percentile
            if kev_loaded:
                if bool(f.get("known_exploited")) != a.kev:
                    payload["known_exploited"] = a.kev
                if bool(f.get("ransomware_used")) != a.ransomware:
                    payload["ransomware_used"] = a.ransomware
                kev_date = a.kev_date.isoformat() if a.kev_date else None
                if kev_date and f.get("kev_date") != kev_date:
                    payload["kev_date"] = kev_date

            found = _parse_date(f.get("date")) or utcnow().date()
            planned = remediation_date(found, a.priority, sla, a.kev_due).isoformat()
            current_planned = f.get("planned_remediation_date")
            if current_planned and written.data.get(fid) != current_planned:
                result.manual_sla += 1  # alguém a definiu à mão no DefectDojo
                planned = current_planned
            elif current_planned != planned:
                payload["planned_remediation_date"] = planned

            result.top.append(
                {
                    "finding_id": f["id"],
                    "title": str(f.get("title") or "")[:200],
                    "host": host.name,
                    "severity": f.get("severity"),
                    "priority": a.priority,
                    "score": a.score,
                    "cves": cves[:5],
                    "exploits": a.exploits,
                    "kev": a.kev,
                    "epss_percentile": a.epss_percentile,
                    "planned": planned,
                    "reasons": a.reasons,
                }
            )

        if not payload:
            result.unchanged += 1
            continue
        try:
            dd.patch(f"/findings/{fid}/", payload)
            consecutive_errors = 0
            result.updated += 1
            if "planned_remediation_date" in payload:
                written.data[fid] = payload["planned_remediation_date"]
        except VFError as exc:
            result.errors += 1
            consecutive_errors += 1
            if len(result.error_samples) < 5:
                result.error_samples.append(f"finding {fid}: {exc.message} {(exc.detail or '')[:200]}")
            if exc.kind is ErrorKind.CONFIG or consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                written.save()
                raise VFError(
                    exc.kind,
                    f"a escrita no DefectDojo falhou {consecutive_errors}x seguidas: {exc.message}",
                    detail=exc.detail,
                ) from exc
        if result.updated and result.updated % 200 == 0:
            note(f"{result.updated} findings atualizados")
            written.save()

    written.save()
    result.top.sort(key=lambda t: (-t["score"], t["planned"]))
    result.top = result.top[:TOP_LIMIT]
    return result


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None
