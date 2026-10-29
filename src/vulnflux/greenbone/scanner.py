"""Operações GMP sobre o Greenbone: targets, tasks, scans e reports.

Cada operação abre a sua própria sessão GMP curta. Um lote do Greenbone dura horas e
uma ligação longa ao socket acaba por cair; sessões curtas tornam cada passo
independente e repetível.

Tudo o que o VulnFlux cria no Greenbone tem o prefixo "vulnflux:" no nome, para não
tocar em targets/tasks criados à mão.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError, GvmResponseError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import Host

XML_REPORT_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"
PREFIX = "vulnflux:"

# Estados de task do gvmd
DONE = "Done"
FAILED_STATES = {"Stopped", "Interrupted", "Stop Requested", "Delete Requested", "Ultimate Delete Requested"}
ACTIVE_STATES = {"Requested", "Queued", "Running", "Processing"}


@dataclass
class ReportData:
    xml: bytes
    scan_run_status: str
    results_total: int
    by_threat: dict[str, int]
    hosts_scanned: int


class TaskBusy(VFError):
    """A task do host já está a correr no gvmd (ex.: o VulnFlux reiniciou a meio do scan).

    Traz o report em curso, para a execução nova retomar o acompanhamento em vez de
    lançar um scan novo por cima ou desistir.
    """

    def __init__(self, task_id: str, status: str, report_id: str | None) -> None:
        super().__init__(ErrorKind.TRANSIENT, f"task do Greenbone já está ativa ({status})")
        self.task_id = task_id
        self.status = status
        self.report_id = report_id


def _gmp_filter_value(value: str) -> str:
    # Aspas duplas delimitam o valor no filtro GMP; não podem aparecer dentro.
    return value.replace('"', "")


def target_name(host: Host) -> str:
    digest = hashlib.sha1(host.greenbone_target.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{PREFIX}{host.name}:{digest}"


def task_name(host: Host) -> str:
    return f"{PREFIX}{host.name}"


class GreenboneClient:
    def __init__(self, settings: Settings, gmp_factory: Any = None) -> None:
        self.settings = settings
        self._factory = gmp_factory

    @contextmanager
    def session(self) -> Iterator[Any]:
        s = self.settings
        if not s.greenbone_password.get_secret_value():
            raise VFError(ErrorKind.CONFIG, "VF_GREENBONE_PASSWORD por definir")
        try:
            if self._factory is not None:
                cm = self._factory(s)
            else:
                conn = UnixSocketConnection(path=s.greenbone_socket, timeout=120)
                cm = Gmp(connection=conn, transform=EtreeCheckCommandTransform())
            with cm as gmp:
                try:
                    gmp.authenticate(s.greenbone_user, s.greenbone_password.get_secret_value())
                except GvmResponseError as exc:
                    raise VFError(ErrorKind.CONFIG, f"autenticação no gvmd falhou: {exc}") from exc
                yield gmp
        except VFError:
            raise
        except GvmResponseError as exc:
            raise VFError(ErrorKind.DATA, f"gvmd recusou o pedido: {exc}") from exc
        except (GvmError, OSError) as exc:
            raise VFError(ErrorKind.DEPENDENCY, f"gvmd inacessível: {exc}") from exc

    # ------------------------------------------------------------------ setup
    def ensure_task(self, host: Host) -> str:
        """Garante target + task para o host (idempotente). Devolve o task_id."""
        s = self.settings
        tname, tkname = target_name(host), task_name(host)
        with self.session() as gmp:
            resp = gmp.get_targets(filter_string=f'name="{_gmp_filter_value(tname)}" rows=-1')
            target = resp.find("target")
            if target is not None:
                target_id = target.get("id")
            else:
                created = gmp.create_target(
                    tname,
                    hosts=[host.greenbone_target],
                    port_list_id=s.greenbone_port_list_id,
                    comment="Gerido pelo VulnFlux — não editar",
                )
                target_id = created.get("id")

            resp = gmp.get_tasks(filter_string=f'name="{_gmp_filter_value(tkname)}" rows=-1')
            task = resp.find("task")
            if task is None:
                created = gmp.create_task(
                    tkname,
                    config_id=s.greenbone_scan_config_id,
                    target_id=target_id,
                    scanner_id=s.greenbone_scanner_id,
                    comment="Gerida pelo VulnFlux — não editar",
                )
                return str(created.get("id"))

            task_id = str(task.get("id"))
            status = (task.findtext("status") or "").strip()
            if status in ACTIVE_STATES:
                current = task.find("current_report/report")
                report_id = current.get("id") if current is not None else None
                raise TaskBusy(task_id, status, report_id or None)
            current_target = task.find("target")
            current_config = task.find("config")
            changes: dict[str, str] = {}
            if current_target is None or current_target.get("id") != target_id:
                changes["target_id"] = target_id
            if current_config is None or current_config.get("id") != s.greenbone_scan_config_id:
                changes["config_id"] = s.greenbone_scan_config_id
            if changes:
                gmp.modify_task(task_id, **changes)
            return task_id

    # ------------------------------------------------------------------ execução
    def start(self, task_id: str) -> str:
        with self.session() as gmp:
            resp = gmp.start_task(task_id)
            report_id = (resp.findtext("report_id") or "").strip()
            if not report_id:
                raise VFError(ErrorKind.DATA, "start_task não devolveu report_id")
            return report_id

    def status(self, task_id: str) -> tuple[str, int]:
        with self.session() as gmp:
            task = gmp.get_task(task_id).find("task")
            if task is None:
                raise VFError(ErrorKind.DATA, f"task {task_id} desapareceu do gvmd")
            status = (task.findtext("status") or "").strip()
            try:
                progress = int((task.findtext("progress") or "0").strip())
            except ValueError:
                progress = 0
            return status, progress

    def stop(self, task_id: str) -> None:
        with self.session() as gmp:
            gmp.stop_task(task_id)

    def fetch_report(self, report_id: str) -> ReportData:
        s = self.settings
        flt = f"apply_overrides=0 min_qod={s.greenbone_min_qod} levels={s.greenbone_levels} rows=-1 first=1"
        with self.session() as gmp:
            resp = gmp.get_report(
                report_id,
                report_format_id=XML_REPORT_FORMAT,
                filter_string=flt,
                ignore_pagination=True,
                details=True,
            )
        return parse_report(resp)


def parse_report(resp: Any) -> ReportData:
    """Extrai o <report> exterior (o formato que o parser OpenVAS do DD espera)."""
    outer = resp.find("report")
    if outer is None:
        raise VFError(ErrorKind.DATA, "resposta get_report sem <report>")
    inner = outer.find("report")
    if inner is None:
        raise VFError(ErrorKind.DATA, "report XML sem <report> interior")
    results = inner.findall("results/result")
    threats = Counter((r.findtext("threat") or "Log").strip() for r in results)
    hosts = inner.findtext("hosts/count") or inner.findtext("host_count/full") or "0"
    try:
        host_count = int(hosts.strip())
    except ValueError:
        host_count = 0
    return ReportData(
        xml=etree.tostring(outer, xml_declaration=True, encoding="UTF-8"),
        scan_run_status=(inner.findtext("scan_run_status") or "").strip(),
        results_total=len(results),
        by_threat=dict(threats),
        hosts_scanned=host_count,
    )


def threat_to_severity(by_threat: dict[str, int]) -> dict[str, int]:
    """Contagens no vocabulário do DefectDojo (Log → Info)."""
    mapping = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low", "Log": "Info"}
    out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for threat, count in by_threat.items():
        out[mapping.get(threat, "Info")] += count
    return out
