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
    top: list[dict[str, Any]] | None = None  # resultados mais graves (nome, CVSS, porta)
    ports: list[str] | None = None  # portas que o scanner viu abertas (secção <ports> do report)
    results: list[dict[str, Any]] | None = None  # todos os resultados, do mais grave (diagnóstico)


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


PROFILES = ("rapido", "descoberta", "completo")
FAST_CONFIG_NAME = "VulnFlux · rápido"
# "Global variable settings": desligar o crawling CGI é o que mais encurta scans a sites grandes
# (o WordPress já é analisado pelo WPScan). Os nomes das preferências leem-se do próprio gvmd.
GLOBAL_SETTINGS_OID = "1.3.6.1.4.1.25623.1.0.12288"
FAST_PREFS = {"Enable CGI scanning": "no"}


def profile_of(host: Host, settings: Settings) -> str:
    p = (host.greenbone_profile or settings.greenbone_profile or "rapido").lower()
    return p if p in PROFILES else "rapido"


def target_name(host: Host, profile: str = "completo", ports: str = "") -> str:
    # O perfil (e, na descoberta, as portas) entra no nome: portas diferentes = target diferente
    # (o gvmd não deixa mudar a port list de um target em uso)
    key = host.greenbone_target if profile == "completo" else f"{host.greenbone_target}|{profile}"
    if ports:
        key += "|" + ports
    digest = hashlib.sha1(key.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{PREFIX}{host.name}:{digest}"


def task_name(host: Host) -> str:
    return f"{PREFIX}{host.name}"


class GreenboneClient:
    def __init__(self, settings: Settings, gmp_factory: Any = None) -> None:
        self.settings = settings
        self._factory = gmp_factory
        self.last_profile = ""
        self.notes: list[str] = []

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
    def _fast_port_list(self, gmp: Any) -> str:
        ports = self.settings.greenbone_fast_ports.strip()
        digest = hashlib.sha1(ports.encode(), usedforsecurity=False).hexdigest()[:6]
        name = f"{PREFIX}portas-comuns:{digest}"
        resp = gmp.get_port_lists(filter_string=f'name="{name}" rows=-1')
        found = resp.find("port_list")
        if found is not None:
            return str(found.get("id"))
        created = gmp.create_port_list(name, ports, comment="Portas comuns (perfil rápido do VulnFlux)")
        return str(created.get("id"))

    def _host_port_list(self, gmp: Any, host: Host, spec: str) -> str:
        digest = hashlib.sha1(spec.encode(), usedforsecurity=False).hexdigest()[:6]
        name = f"{PREFIX}descoberta:{host.name}:{digest}"
        resp = gmp.get_port_lists(filter_string=f'name="{_gmp_filter_value(name)}" rows=-1')
        found = resp.find("port_list")
        if found is not None:
            return str(found.get("id"))
        created = gmp.create_port_list(name, spec, comment="Portas abertas encontradas pela sonda (perfil descoberta)")
        return str(created.get("id"))

    def _cleanup(self, gmp: Any, host: Host, keep_target: str) -> None:
        """Apaga targets e port lists antigos deste host que já nada usa (o gvmd recusa apagar os em uso)."""
        try:
            resp = gmp.get_targets(filter_string=f'name~"{_gmp_filter_value(PREFIX + host.name)}:" rows=-1')
            for t in resp.findall("target"):
                if t.get("id") != keep_target and (t.findtext("in_use") or "0").strip() == "0":
                    gmp.delete_target(t.get("id"), ultimate=True)
            resp = gmp.get_port_lists(
                filter_string=f'name~"{_gmp_filter_value(PREFIX + "descoberta:" + host.name)}:" rows=-1'
            )
            for pl in resp.findall("port_list"):
                if (pl.findtext("in_use") or "0").strip() == "0":
                    gmp.delete_port_list(pl.get("id"), ultimate=True)
        except (GvmError, AttributeError, TypeError):
            pass  # limpeza é opcional

    def _fast_config(self, gmp: Any) -> str:
        """Clone do Full and fast sem crawling CGI. Se o gvmd recusar, fica o Full and fast (com aviso)."""
        s = self.settings
        resp = gmp.get_scan_configs(filter_string=f'name="{FAST_CONFIG_NAME}" rows=-1')
        found = resp.find("config")
        if found is not None:
            return str(found.get("id"))
        try:
            created = gmp.create_scan_config(
                s.greenbone_scan_config_id,
                FAST_CONFIG_NAME,
                comment="Gerido pelo VulnFlux: Full and fast sem crawling CGI",
            )
            config_id = str(created.get("id"))
            prefs = gmp.get_preferences(nvt_oid=GLOBAL_SETTINGS_OID, config_id=config_id)
            for pref in prefs.findall("preference"):
                pname = (pref.findtext("name") or "").strip()
                if pname in FAST_PREFS:
                    full = f"{GLOBAL_SETTINGS_OID}:{pref.findtext('id')}:{pref.findtext('type')}:{pname}"
                    gmp.modify_scan_config_set_nvt_preference(
                        config_id, full, GLOBAL_SETTINGS_OID, value=FAST_PREFS[pname]
                    )
            return config_id
        except (GvmError, AttributeError) as exc:
            self.notes.append(f"perfil rápido sem config própria ({exc}): usado o Full and fast")
            return s.greenbone_scan_config_id

    def ensure_task(self, host: Host, port_spec: str | None = None) -> str:
        """Garante target + task para o host (idempotente) no perfil do host. Devolve o task_id.

        No perfil "descoberta", `port_spec` traz as portas encontradas pela sonda; sem ele
        (sonda desligada ou falhou) o host é analisado com o perfil rápido.
        """
        s = self.settings
        profile = profile_of(host, s)
        if profile == "descoberta" and not port_spec:
            profile = "rapido"
        self.last_profile, self.notes = profile, []
        tname = target_name(host, profile, port_spec if profile == "descoberta" else "")
        tkname = task_name(host)
        with self.session() as gmp:
            if profile == "rapido":
                port_list_id, config_id = self._fast_port_list(gmp), self._fast_config(gmp)
            elif profile == "descoberta":
                port_list_id = self._host_port_list(gmp, host, port_spec or "")
                config_id = s.greenbone_scan_config_id
            else:
                port_list_id, config_id = s.greenbone_port_list_id, s.greenbone_scan_config_id
            resp = gmp.get_targets(filter_string=f'name="{_gmp_filter_value(tname)}" rows=-1')
            target = resp.find("target")
            if target is not None:
                target_id = target.get("id")
            else:
                created = gmp.create_target(
                    tname,
                    hosts=[host.greenbone_target],
                    port_list_id=port_list_id,
                    comment=f"Gerido pelo VulnFlux (perfil {profile}) — não editar",
                )
                target_id = created.get("id")

            prefs = {"max_checks": str(max(1, s.greenbone_max_checks))}
            resp = gmp.get_tasks(filter_string=f'name="{_gmp_filter_value(tkname)}" rows=-1')
            task = resp.find("task")
            if task is None:
                created = gmp.create_task(
                    tkname,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=s.greenbone_scanner_id,
                    comment="Gerida pelo VulnFlux — não editar",
                    preferences=prefs,
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
            changes: dict[str, Any] = {}
            if current_target is None or current_target.get("id") != target_id:
                changes["target_id"] = target_id
            if current_config is None or current_config.get("id") != config_id:
                changes["config_id"] = config_id
            current_checks = None
            for pref in task.findall("preferences/preference"):
                if (pref.findtext("scanner_name") or "").strip() == "max_checks":
                    current_checks = (pref.findtext("value") or "").strip()
            if current_checks != prefs["max_checks"]:
                changes["preferences"] = prefs
            if ("target_id" in changes or "config_id" in changes) and status != "New":
                # O gvmd só deixa mudar target/config de uma task que nunca correu: troca-se a task.
                # Os reports antigos já foram importados no DefectDojo.
                gmp.delete_task(task_id, ultimate=True)
                created = gmp.create_task(
                    tkname,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=s.greenbone_scanner_id,
                    comment="Gerida pelo VulnFlux — não editar",
                    preferences=prefs,
                )
                task_id = str(created.get("id"))
                self._cleanup(gmp, host, str(target_id))
                return task_id
            if changes:
                gmp.modify_task(task_id, **changes)
                if "target_id" in changes:
                    self._cleanup(gmp, host, str(target_id))
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
    every = []
    for r in results:
        try:
            sev = float((r.findtext("severity") or "0").strip())
        except ValueError:
            sev = 0.0
        every.append(
            {
                "name": (r.findtext("name") or "").strip()[:160],
                "cvss": sev,
                "port": (r.findtext("port") or "").strip(),
            }
        )
    every.sort(key=lambda x: -x["cvss"])
    scored = [r for r in every if r["cvss"] >= 7.0]
    ports = sorted({(p.text or "").strip() for p in inner.findall("ports/port") if (p.text or "").strip()})
    return ReportData(
        xml=etree.tostring(outer, xml_declaration=True, encoding="UTF-8"),
        top=scored[:25],
        ports=ports[:300],
        results=every[:60],
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
