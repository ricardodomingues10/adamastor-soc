"""Servidores: recolha → relatório, bootstrap, verificação, atualização por anéis e páginas."""

from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from tests.test_pipeline import FakeDD
from tests.test_web import auth, client, csrf_of, engine, login  # noqa: F401

from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import Host, RunStatus, Source, StepStatus, Trigger, utcnow
from vulnflux.servers import bootstrap, checks, cycles, findings, job, ssh
from vulnflux.servers.ssh import Result

FIX = Path(__file__).parent / "fixtures" / "servers"
DEBIAN = (FIX / "debian.txt").read_text()
RHEL = (FIX / "rhel.txt").read_text()


@pytest.fixture
def cfg(settings):
    return settings.model_copy(update={"risk_enabled": False, "patch_soak_hours": 24})


class FakeRunner:
    """Responde por script: a recolha devolve a próxima saída da fila, o patch uma saída fixa."""

    def __init__(self, collects=(), patch_out="@@pkg apt\n@@rc 0\n@@reboot 0\n@@end 1\n", fail: VFError | None = None):
        self.collects = list(collects)
        self.patch_out = patch_out
        self.fail = fail
        self.calls: list[tuple[str, dict]] = []

    def run(self, host, script, *, env=None, timeout=600):
        kind = "collect" if "recolha" in script else "patch" if "aplicar atualizações" in script else "cmd"
        self.calls.append((kind, env or {}))
        if self.fail:
            raise self.fail
        if kind == "collect":
            return Result(0, self.collects.pop(0) if len(self.collects) > 1 else self.collects[0], "")
        if kind == "patch":
            return Result(0, self.patch_out, "")
        return Result(0, "30\n", "")


def server(store, name="web01.lab", **kw):
    base = {"ssh_enabled": True, "wpscan_enabled": False, "patch_mode": "seguranca", "patch_ring": 0}
    return store.save_host(Host(name=name, **{**base, **kw}))


# ---------------------------------------------------------------- relatório
def test_relatorio_debian(cfg):
    r = checks.build_report(DEBIAN, cfg.server_thresholds())
    assert r["complete"] and r["os"].startswith("Debian")
    by = {c["id"]: c for c in r["health"]}
    assert by["mem"]["status"] == "warn" and by["mem"]["value"].startswith("87.5%")
    assert by["disk"]["status"] == "fail" and "/ 92.0%" in by["disk"]["value"]
    assert by["units"]["status"] == "warn" and "nginx.service" in by["units"]["value"]
    assert by["oom"]["status"] == "warn"
    hard = {c["id"]: c for c in r["hardening"]}
    assert hard["ssh_root"]["status"] == "fail" and hard["ssh_password"]["status"] == "fail"
    assert hard["ssh_x11"]["status"] == "ok" and hard["ssh_maxauth"]["status"] == "fail"
    assert hard["firewall"]["status"] == "fail" and hard["mac"]["status"] == "ok"
    assert hard["uid0"]["status"] == "fail" and "toor" in hard["uid0"]["value"]
    assert hard["perm_shadow"]["status"] == "fail" and hard["perm_passwd"]["status"] == "ok"
    assert hard["auditd"]["status"] == "fail" and hard["timesync"]["status"] == "ok"
    assert hard["autoupdate"]["status"] == "warn"
    assert hard["sysctl_net_ipv4_conf_all_send_redirects"]["status"] == "fail"
    assert 0 < r["score"] < 60
    u = r["updates"]
    assert (u["total"], u["security"], u["reboot"]) == (4, 2, True)
    assert u["packages"][0] == {
        "name": "libssl3",
        "old": "3.0.11-1~deb12u2",
        "new": "3.0.13-1~deb12u1",
        "security": True,
    }
    assert any(p["name"] == "newpkg" and p["old"] == "" for p in u["packages"])
    assert r["status"] == "fail" and r["lynis"]["index"] == 64


def test_relatorio_rhel(cfg):
    r = checks.build_report(RHEL, cfg.server_thresholds())
    hard = {c["id"]: c for c in r["hardening"]}
    assert (
        hard["mac"]["status"] == "ok" and hard["firewall"]["status"] == "ok" and hard["perm_shadow"]["status"] == "ok"
    )
    assert hard["autoupdate"]["status"] == "ok"
    assert r["updates"]["security"] == 1 and r["updates"]["total"] == 2
    assert r["score"] >= 90
    assert r["status"] == "warn"  # só a atualização de segurança pendente


def test_recolha_incompleta_e_sem_sudo(cfg):
    r = checks.build_report("v\t1\nos.id\tdebian\n", cfg.server_thresholds())
    assert not r["complete"] and r["status"] == "warn"
    assert {c["id"]: c["status"] for c in r["hardening"]}["ssh_root"] == "unknown"


def test_findings_estaveis(cfg):
    r = checks.build_report(DEBIAN, cfg.server_thresholds())
    g = findings.to_generic("web01.lab", r)
    ids = {f["unique_id_from_tool"] for f in g["findings"]}
    assert (
        "vulnflux:server:ssh_root" in ids
        and "vulnflux:server:updates-security" in ids
        and "vulnflux:server:reboot" in ids
    )
    assert "vulnflux:server:mac" not in ids  # o que passa não é finding
    root = next(f for f in g["findings"] if f["vuln_id_from_tool"] == "ssh_root")
    assert root["severity"] == "High" and "PermitRootLogin" in root["mitigation"]


# ---------------------------------------------------------------- bootstrap e scripts
def test_bootstrap_perfis():
    pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemplo vulnflux@soc"
    ro = bootstrap.script(pub)
    assert "no-pty" in ro and "visudo -cf" in ro and "add sshd -T" in ro
    assert "add apt-get ''" not in ro and "perfil verificar: sem comandos de atualização" in ro
    rw = bootstrap.script(pub, mode="atualizar")
    assert "add apt-get ''" in rw and "add systemctl reboot" in rw
    line = bootstrap.one_liner(pub)
    assert line.startswith("echo ") and line.endswith("| base64 -d | sudo sh") and "'" not in line
    with pytest.raises(ValueError):
        bootstrap.script(pub, mode="root")


@pytest.mark.skipif(not shutil.which("sh"), reason="sem sh")
def test_scripts_sintaxe():
    for name in ("collect.sh", "patch.sh"):
        assert subprocess.run(["sh", "-n", "-c", job.script(name)], check=False).returncode == 0
    assert subprocess.run(["sh", "-n", "-c", bootstrap.script("ssh-ed25519 AAAA x")], check=False).returncode == 0


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="sem ssh-keygen")
def test_chave_e_known_hosts(cfg):
    pub = ssh.ensure_key(cfg)
    assert pub.startswith("ssh-ed25519 ") and ssh.ensure_key(cfg) == pub  # gerada uma vez
    assert ssh.fingerprint(pub).startswith("SHA256:")
    h = Host(name="a.lab", ssh_port=2222)
    ssh.known_hosts(cfg).write_text(
        f"[a.lab]:2222 {pub.split()[0]} {pub.split()[1]}\nb.lab {pub.split()[0]} {pub.split()[1]}\n"
    )
    assert ssh.host_key(cfg, h).startswith("ssh-ed25519 SHA256:")
    ssh.forget_host_key(cfg, h)
    assert ssh.host_key(cfg, h) == "" and "b.lab" in ssh.known_hosts(cfg).read_text()


def test_erros_ssh_com_conselho():
    h = Host(name="a.lab")
    assert ssh.ssh_error(h, "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!").kind is ErrorKind.PERMANENT
    assert "comando de ligação" in ssh.ssh_error(h, "Permission denied (publickey).").message
    assert ssh.ssh_error(h, "ssh: connect to host a.lab port 22: Connection timed out").kind is ErrorKind.TRANSIENT


# ---------------------------------------------------------------- verificação
def test_verificar_importa_no_defectdojo(cfg, store):
    h = server(store)
    ids = job.plan_checks(store, Trigger.MANUAL)
    dd = FakeDD()
    run = job.execute_check(store, cfg, ids[0], runner=FakeRunner([DEBIAN]), dd=dd)
    assert run.status is RunStatus.SUCCESS, run.error_message
    assert [s.name for s in run.steps][:3] == ["Ligar e recolher", "Avaliar", "Converter"]
    assert dd.calls[0]["product_name"] == "web01.lab" and dd.calls[0]["test_title"] == job.TEST_TITLE
    assert run.stats["security_updates"] == 2 and run.stats["findings_total"] > 5
    data = store.get_server(h.id)
    assert data["report"]["status"] == "fail" and len(data["history"]) == 1
    assert "recolha.txt" in run.artifacts


def test_verificar_sem_ligacao_guarda_ultimo_bom(cfg, store):
    h = server(store)
    job.execute_check(store, cfg, job.plan_checks(store, Trigger.MANUAL)[0], runner=FakeRunner([RHEL]), dd=FakeDD())
    err = VFError(ErrorKind.TRANSIENT, "web01.lab: sem ligação SSH")
    run = job.execute_check(
        store, cfg, job.plan_checks(store, Trigger.MANUAL)[0], runner=FakeRunner(fail=err), dd=FakeDD()
    )
    assert run.status is RunStatus.FAILED
    data = store.get_server(h.id)
    assert data["report"]["os"].startswith("Rocky") and data["unreachable"]["message"] == err.message


def test_verificar_sem_defectdojo(cfg, store):
    server(store)
    local = cfg.model_copy(update={"dd_url": ""})
    run = job.execute_check(store, local, job.plan_checks(store, Trigger.MANUAL)[0], runner=FakeRunner([RHEL]))
    assert run.status is RunStatus.SUCCESS and run.steps[-1].status is StepStatus.SKIPPED


# ---------------------------------------------------------------- atualizar
AFTER = DEBIAN.replace("aptinst\topenssl", "x\t").replace("aptinst\tlibssl3", "x\t").replace("reboot\t1", "reboot\t0")
DEBIAN_OK_DISK = DEBIAN.replace("disk\t/ 50000000 46000000 4000000", "disk\t/ 50000000 10000000 40000000")
AFTER_OK = AFTER.replace("disk\t/ 50000000 46000000 4000000", "disk\t/ 50000000 10000000 40000000")


def test_atualizar_com_pre_e_pos_verificacao(cfg, store):
    h = server(store)
    from vulnflux.pipeline import create_run

    run = create_run(store, h, Source.PATCH, Trigger.MANUAL)
    runner = FakeRunner([DEBIAN_OK_DISK, AFTER_OK])
    run = job.execute_patch(store, cfg, run.id, runner=runner, sleep=lambda s: None)
    assert run.status is RunStatus.SUCCESS, run.error_message
    kinds = [k for k, _ in runner.calls]
    assert kinds == ["collect", "patch", "collect"]
    env = runner.calls[1][1]
    assert env["VF_MODE"] == "seguranca" and "openssl" in env["VF_SEC_PKGS"] and "tzdata" not in env["VF_SEC_PKGS"]
    assert (run.stats["before_security"], run.stats["after_security"]) == (2, 0)


def test_atualizar_recusa_sem_espaco(cfg, store):
    h = server(store)
    from vulnflux.pipeline import create_run

    run = job.execute_patch(
        store,
        cfg,
        create_run(store, h, Source.PATCH, Trigger.MANUAL).id,
        runner=FakeRunner([DEBIAN.replace("disk\t/ 50000000 46000000 4000000", "disk\t/ 50000000 49900000 100000")]),
    )
    assert run.status is RunStatus.FAILED and "pouco espaço" in run.error_message


def test_atualizar_reinicia_e_espera(cfg, store):
    h = server(store, patch_reboot=True)
    from vulnflux.pipeline import create_run

    runner = FakeRunner([DEBIAN_OK_DISK, AFTER_OK], patch_out="@@pkg apt\n@@rc 0\n@@reboot 1\n@@end 1\n")
    run = job.execute_patch(
        store, cfg, create_run(store, h, Source.PATCH, Trigger.MANUAL).id, runner=runner, sleep=lambda s: None
    )
    assert run.status is RunStatus.SUCCESS and run.stats["rebooted"]
    assert [k for k, _ in runner.calls].count("cmd") >= 2  # reboot + esperar pelo uptime


def test_atualizar_regressao_para(cfg, store):
    h = server(store)
    from vulnflux.pipeline import create_run

    before = DEBIAN_OK_DISK.replace("failed\tnginx.service\n", "")
    runner = FakeRunner([before, AFTER_OK])  # depois: nginx falhou
    run = job.execute_patch(store, cfg, create_run(store, h, Source.PATCH, Trigger.MANUAL).id, runner=runner)
    assert run.status is RunStatus.FAILED and "nginx.service" in run.error_message


def test_atualizar_so_verificar_nunca_toca(cfg, store):
    h = server(store, patch_mode="verificar")
    from vulnflux.pipeline import create_run

    assert create_run(store, h, Source.PATCH, Trigger.MANUAL) is not None
    run = job.execute_patch(store, cfg, store.list_runs(source=Source.PATCH)[0].id, runner=FakeRunner([DEBIAN]))
    assert run.status is RunStatus.FAILED and run.error_kind is ErrorKind.CONFIG


# ---------------------------------------------------------------- anéis
def test_aneis_observacao_aprovacao_e_paragem(cfg, store):
    a = server(store, "a.lab", patch_ring=0)
    server(store, "b.lab", patch_ring=1)
    server(store, "c.lab", patch_ring=3)
    server(store, "d.lab", patch_ring=2, patch_mode="verificar")
    cyc = cycles.new_cycle(store, cfg, Trigger.MANUAL, "ana")
    assert [r["status"] for r in cyc["rings"]] == ["por_iniciar", "por_iniciar", "vazio", "por_iniciar"]
    assert cycles.new_cycle(store, cfg, Trigger.MANUAL) is None  # um de cada vez

    started = []
    cycles.advance(store, cfg, lambda cid, i: started.append(i))
    assert started == [0]

    def ok_run(rid):
        return store.save_run(store.get_run(rid).model_copy(update={"status": RunStatus.SUCCESS}))

    cycles.run_ring(store, cfg, cyc["id"], 0, ok_run)
    assert store.get_cycle(cyc["id"])["rings"][0]["status"] == "ok"

    cycles.advance(store, cfg, lambda cid, i: started.append(i))
    ring1 = store.get_cycle(cyc["id"])["rings"][1]
    assert started == [0] and ring1["status"] == "aguarda_observacao" and ring1["opens_at"]

    later = utcnow() + timedelta(hours=25)
    cycles.advance(store, cfg, lambda cid, i: started.append(i), now=later)
    assert started == [0, 1]
    cycles.run_ring(store, cfg, cyc["id"], 1, ok_run)

    cycles.advance(store, cfg, lambda cid, i: started.append(i), now=later + timedelta(hours=25))
    assert store.get_cycle(cyc["id"])["rings"][3]["status"] == "aguarda_aprovacao" and started == [0, 1]
    assert cycles.approve(store, cyc["id"], 3, "chefe")
    cycles.advance(store, cfg, lambda cid, i: started.append(i), now=later + timedelta(hours=26))
    assert started == [0, 1, 3]

    def fail_run(rid):
        return store.save_run(store.get_run(rid).model_copy(update={"status": RunStatus.FAILED, "error_message": "x"}))

    cycles.run_ring(store, cfg, cyc["id"], 3, fail_run)
    out = cycles.advance(store, cfg, lambda cid, i: started.append(i), now=later + timedelta(hours=27))
    assert out["status"] == "parado" and "anel 3" in out["note"]
    assert cycles.resume(store, cyc["id"], "chefe")
    assert store.get_cycle(cyc["id"])["rings"][3]["status"] == "por_iniciar"
    assert a.id in {s["host_id"] for s in store.get_cycle(cyc["id"])["rings"][0]["servers"]}


def test_ciclo_sem_servidores_a_atualizar(cfg, store):
    server(store, patch_mode="verificar")
    cyc = cycles.new_cycle(store, cfg, Trigger.MANUAL)
    assert cyc["status"] == "concluido" and "só verificar" in cyc["note"]


# ---------------------------------------------------------------- páginas
def test_paginas_servidores(client, auth, store, settings, monkeypatch):  # noqa: F811
    monkeypatch.setattr(ssh, "public_key", lambda s: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemplo vulnflux@soc")
    h = server(store)
    store.save_server_report(
        h.id, {**checks.build_report(DEBIAN, settings.server_thresholds()), "checked_at": utcnow().isoformat()}
    )
    page = client.get("/servers")
    assert page.status_code == 200
    for text in (
        "web01.lab",
        "Anéis de atualização",
        "Canário",
        "base64 -d | sudo sh",
        "Ligar um servidor",
        'stroke-dasharray="',
    ):
        assert text in page.text, text
    assert 'style="' not in page.text  # CSP estrita: nada de estilos inline
    det = client.get(f"/servers/{h.id}")
    assert det.status_code == 200 and "PermitRootLogin no" in det.text and "libssl3" in det.text
    assert (
        client.get("/servers?partial=board").text.startswith('\n<div id="servers-board"')
        or "servers-board" in client.get("/servers?partial=board").text
    )
    assert "visudo" in client.get("/servers/bootstrap.sh?mode=atualizar").text
    r = client.post(f"/servers/{h.id}/ring", data={"patch_ring": "3", "patch_mode": "tudo"}, headers=auth)
    assert r.status_code == 204 and store.get_host(h.id).patch_ring == 3 and store.get_host(h.id).patch_mode == "tudo"
    assert client.post(f"/servers/{h.id}/ring", data={"patch_ring": "9"}, headers=auth).status_code == 400
    assert client.post(f"/servers/{h.id}/check", headers=auth).status_code == 204
    assert client.post("/patch/cycles", headers=auth).status_code == 204
    assert cycles.active_cycle(store) is not None
    assert client.post("/patch/cycles", headers=auth).status_code == 409
    assert "Servidor (SSH)" in client.get("/servers/new").text


def test_formulario_host_com_ssh(store):
    from vulnflux.hosts import HostValidationError, host_from_form

    h = host_from_form(
        {
            "name": "srv.lab",
            "wpscan_enabled": "off",
            "greenbone_enabled": "off",
            "ssh_enabled": "on",
            "ssh_port": "2222",
            "ssh_user": "vulnflux",
            "patch_ring": "1",
            "patch_mode": "tudo",
            "patch_reboot": "on",
        }
    )
    assert h.ssh_enabled and h.ssh_port == 2222 and h.patch_ring == 1 and h.patch_reboot
    with pytest.raises(HostValidationError) as e:
        host_from_form({"name": "srv.lab", "ssh_enabled": "on", "ssh_port": "99999", "patch_mode": "x"})
    assert {"ssh_port", "patch_mode"} <= set(e.value.errors)
    # formulário sem os campos SSH (importação antiga) mantém os valores
    again = host_from_form({"name": "srv.lab", "greenbone_enabled": "on"}, h)
    assert again.ssh_enabled and again.patch_ring == 1
