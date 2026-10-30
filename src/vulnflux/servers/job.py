"""Execuções sobre servidores: verificação (saúde, hardening, atualizações) e aplicação de atualizações.

    Verificar:   Ligar e recolher → Avaliar → Converter → Gate → Importar no DefectDojo → Prioridades
    Atualizar:   Pré-verificação → Atualizar → Reiniciar (se pedido e permitido) → Pós-verificação

As duas são execuções normais do VulnFlux (página Execuções, erros, histórico). Um servidor que não
responde fica marcado como inacessível na página Servidores, sem apagar o último relatório bom.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Callable
from importlib import resources
from typing import Any

from vulnflux.config import Settings
from vulnflux.defectdojo import DefectDojo
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import Host, Run, Source, StepStatus, Trigger, utcnow
from vulnflux.pipeline import RunRecorder, _gate_and_import, _internal, create_run
from vulnflux.servers import checks, findings
from vulnflux.servers.ssh import Runner, SshRunner, host_key
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)

TEST_TITLE = "Servidor (hardening e atualizações)"


def script(name: str) -> str:
    return resources.files("vulnflux.servers").joinpath("scripts", name).read_text("utf-8")


def collect(runner: Runner, settings: Settings, host: Host) -> tuple[dict[str, Any], str, str]:
    """Recolhe e avalia. Devolve (relatório, saída bruta, stderr)."""
    res = runner.run(
        host,
        script("collect.sh"),
        env={"VF_LYNIS": "1" if host.lynis else "0"},
        timeout=settings.servers_command_timeout,
    )
    if not res.out.strip():
        raise VFError(ErrorKind.DATA, f"{host.name}: a recolha não devolveu nada (rc {res.rc})", detail=res.err[:2000])
    report = checks.build_report(res.out, settings.server_thresholds())
    report["checked_at"] = utcnow().isoformat()
    report["host_key"] = host_key(settings, host)
    return report, res.out, res.err


# ---------------------------------------------------------------- verificação
def plan_checks(store: JsonStore, trigger: Trigger, host_ids: list[str] | None = None) -> list[str]:
    ids = []
    for host in store.list_hosts():
        if host_ids is not None and host.id not in host_ids:
            continue
        if host.source_enabled(Source.SERVER):
            run = create_run(store, host, Source.SERVER, trigger)
            if run:
                ids.append(run.id)
    return ids


def execute_check(
    store: JsonStore, settings: Settings, run_id: str, *, runner: Runner | None = None, dd: DefectDojo | None = None
) -> Run | None:
    run = store.get_run(run_id)
    if run is None:
        return None
    rec = RunRecorder(store, run)
    rec.start()
    host = store.get_host(run.host_id)
    try:
        if host is None:
            raise VFError(ErrorKind.PERMANENT, "o servidor foi removido")
        if not host.source_enabled(Source.SERVER):
            raise VFError(ErrorKind.CONFIG, "verificação por SSH desligada neste host")
        runner = runner or SshRunner(settings)
        with rec.step("Ligar e recolher") as st:
            report, out, err = collect(runner, settings, host)
            rec.artifact("recolha.txt", out.encode())
            if err.strip():
                rec.artifact("recolha-stderr.txt", err.encode())
            st.detail = f"{host.ssh_user}@{host.ssh_target}:{host.ssh_port} · {report['os'] or '?'}"
        with rec.step("Avaliar") as st:
            store.save_server_report(host.id, report)
            upd = report["updates"]
            run.stats.update(
                server_status=report["status"],
                score=report["score"],
                security_updates=upd["security"],
                updates=upd["total"],
                reboot=upd["reboot"],
            )
            if not report["complete"]:
                run.warnings.append("recolha incompleta (o script não chegou ao fim)")
            if not report.get("sudo_rules"):
                run.warnings.append("sem sudo do VulnFlux: SSH, firewall e lista de pacotes com menos detalhe")
            st.detail = (
                f"{report['summary']} · hardening {report['score'] if report['score'] is not None else '?'}/100 · "
                f"{upd['security']} atualizações de segurança"
            )
        if settings.servers_import_dd and settings.dd_configured:
            with rec.step("Converter") as st:
                generic = findings.to_generic(host.name, report)
                run.stats["findings_total"] = len(generic["findings"])
                run.stats["by_severity"] = findings.severity_counts(generic)
                rec.artifact("defectdojo-generic.json", json.dumps(generic, indent=2, ensure_ascii=False).encode())
                st.detail = f"{len(generic['findings'])} findings"
            _gate_and_import(
                rec,
                settings,
                dd or DefectDojo(settings),
                host,
                source=Source.SERVER,
                content=json.dumps(generic).encode(),
                filename="vulnflux-server.json",
                scan_type="Generic Findings Import",
                test_title=TEST_TITLE,
            )
        else:
            step = rec.begin_step("Importar no DefectDojo")
            rec.end_step(
                step,
                StepStatus.SKIPPED,
                "DefectDojo não configurado"
                if not settings.dd_configured
                else "desligado (VF_SERVERS_IMPORT_DD=false)",
            )
        rec.finish_ok()
    except VFError as exc:
        if host is not None:
            store.mark_server_unreachable(host.id, exc.message, utcnow())
        rec.fail(exc)
    except Exception as exc:
        log.exception("verificação do servidor falhou")
        rec.fail(_internal(exc))
    return rec.run


# ---------------------------------------------------------------- atualizar
def _markers(out: str) -> dict[str, str]:
    m = {}
    for line in out.splitlines():
        if line.startswith("@@"):
            k, _, v = line[2:].partition(" ")
            m[k.strip()] = v.strip()
    return m


def _wait_back(
    runner: Runner, host: Host, *, since: float, sleep: Callable[[float], None], timeout: float = 600
) -> float:
    """Espera que o servidor volte depois do reinício. Devolve os segundos que demorou."""
    start = time.monotonic()
    sleep(20)
    while time.monotonic() - start < timeout:
        try:
            res = runner.run(host, "cut -d. -f1 /proc/uptime\n", timeout=30)
            up = int(res.out.strip() or "999999")
            if up < time.time() - since + 60:
                return time.monotonic() - start
        except (VFError, ValueError):
            pass
        sleep(15)
    raise VFError(ErrorKind.TRANSIENT, f"{host.name} não voltou depois do reinício ({int(timeout / 60)} min)")


def execute_patch(
    store: JsonStore,
    settings: Settings,
    run_id: str,
    *,
    runner: Runner | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Run | None:
    run = store.get_run(run_id)
    if run is None:
        return None
    rec = RunRecorder(store, run)
    rec.start()
    try:
        host = store.get_host(run.host_id)
        if host is None:
            raise VFError(ErrorKind.PERMANENT, "o servidor foi removido")
        if not host.source_enabled(Source.PATCH):
            raise VFError(ErrorKind.CONFIG, "este servidor está em 'só verificar'")
        runner = runner or SshRunner(settings)
        mode = host.patch_mode

        with rec.step("Pré-verificação") as st:
            before, _, _ = collect(runner, settings, host)
            store.save_server_report(host.id, before)
            low = [
                d
                for d in before["metrics"].get("disks", [])
                if d["mount"] in ("/", "/var") and d["free_gb"] * 1024 < settings.patch_min_free_mb
            ]
            if low:
                raise VFError(
                    ErrorKind.PERMANENT,
                    "pouco espaço livre: " + ", ".join(f"{d['mount']} {d['free_gb']} GiB" for d in low),
                )
            if not before.get("sudo_rules"):
                raise VFError(
                    ErrorKind.CONFIG, "sem sudo do VulnFlux: corra o comando de ligação com o perfil 'atualizar'"
                )
            upd = before["updates"]
            todo = upd["security"] if mode == "seguranca" else upd["total"]
            run.stats.update(before_security=upd["security"], before_total=upd["total"], mode=mode)
            pre_failed = set(before["metrics"].get("failed_units") or [])
            st.detail = f"{upd['security']} de segurança · {upd['total']} no total · modo {mode}"
        if not todo:
            for name in ("Atualizar", "Reiniciar", "Pós-verificação"):
                rec.end_step(rec.begin_step(name), StepStatus.SKIPPED, "nada a atualizar")
            run.stats["nothing_to_do"] = True
            rec.finish_ok()
            return rec.run

        with rec.step("Atualizar") as st:
            sec_pkgs = " ".join(p["name"] for p in upd["packages"] if p["security"])[:8000]
            res = runner.run(
                host, script("patch.sh"), env={"VF_MODE": mode, "VF_SEC_PKGS": sec_pkgs}, timeout=settings.patch_timeout
            )
            rec.artifact(
                "atualizacao.txt", (res.out + ("\n--- stderr ---\n" + res.err if res.err.strip() else "")).encode()
            )
            mk = _markers(res.out)
            if mk.get("error"):
                raise VFError(ErrorKind.CONFIG, mk["error"])
            if mk.get("rc", "1") != "0" or res.rc != 0:
                raise VFError(
                    ErrorKind.PERMANENT,
                    f"o gestor de pacotes terminou com erro (rc {mk.get('rc', res.rc)})",
                    detail=res.err[-2000:] or res.out[-2000:],
                )
            needs_reboot = mk.get("reboot") == "1"
            st.detail = (
                f"{mk.get('pkg', '?')}"
                + (f" · {mk['method']}" if mk.get("method") else "")
                + (" · pede reinício" if needs_reboot else "")
            )

        step = rec.begin_step("Reiniciar")
        if needs_reboot and host.patch_reboot:
            t0 = time.time()
            with contextlib.suppress(VFError):  # a ligação cai com o reinício
                runner.run(host, "sudo -n systemctl reboot\n", timeout=30)
            took = _wait_back(runner, host, since=t0, sleep=sleep)
            run.stats["rebooted"] = True
            rec.end_step(step, StepStatus.OK, f"voltou em {int(took)} s")
        elif needs_reboot:
            run.warnings.append("reinício pendente: reiniciar sozinho está desligado neste servidor")
            rec.end_step(step, StepStatus.SKIPPED, "pedido, mas desligado neste servidor")
        else:
            rec.end_step(step, StepStatus.SKIPPED, "não é preciso")

        with rec.step("Pós-verificação") as st:
            after, _, _ = collect(runner, settings, host)
            store.save_server_report(host.id, after)
            new_failed = sorted(set(after["metrics"].get("failed_units") or []) - pre_failed)
            run.stats.update(after_security=after["updates"]["security"], after_total=after["updates"]["total"])
            if new_failed:
                raise VFError(ErrorKind.DATA, "serviços falharam depois da atualização: " + ", ".join(new_failed[:8]))
            st.detail = (
                f"segurança {upd['security']} → {after['updates']['security']} · "
                f"total {upd['total']} → {after['updates']['total']}"
            )
        rec.finish_ok()
    except VFError as exc:
        rec.fail(exc)
    except Exception as exc:
        log.exception("atualização do servidor falhou")
        rec.fail(_internal(exc))
    return rec.run
