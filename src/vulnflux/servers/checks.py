"""Da saída da recolha (scripts/collect.sh) ao relatório do servidor: saúde, hardening e atualizações.

Separado da execução SSH para ser testável com saídas reais guardadas. Cada verificação tem um estado
(ok · warn · fail · unknown · info), o valor encontrado, o esperado e como corrigir.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

SEV_WEIGHT = {"alta": 3, "media": 2, "baixa": 1}
STATUS_ORDER = {"fail": 3, "warn": 2, "unknown": 1, "ok": 0, "info": 0}


# ---------------------------------------------------------------- parse
def parse(output: str) -> dict[str, Any]:
    """Linhas "chave<TAB>valor" → dicionário; chaves repetidas viram listas."""
    single: dict[str, str] = {}
    multi: dict[str, list[str]] = defaultdict(list)
    repeated = {"disk", "inode", "failed", "uid0", "perm", "listen", "aptinst", "upd", "updsec"}
    for line in output.splitlines():
        if "\t" not in line:
            continue
        key, _, value = line.partition("\t")
        key, value = key.strip(), value.strip()
        if key in repeated:
            if value:
                multi[key].append(value)
        else:
            single[key] = value
    return {"single": single, "multi": dict(multi), "complete": single.get("end") == "1"}


def _int(v: Any, default: int | None = None) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _float(v: Any, default: float | None = None) -> float | None:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return default


def _check(
    cid: str,
    name: str,
    status: str,
    value: str = "",
    expected: str = "",
    *,
    severity: str = "",
    fix: str = "",
    group: str = "",
) -> dict[str, Any]:
    return {
        "id": cid,
        "name": name,
        "status": status,
        "value": value,
        "expected": expected,
        "severity": severity,
        "fix": fix,
        "group": group,
    }


def _level(value: float, thresholds: tuple[float, float]) -> str:
    warn, crit = thresholds
    return "fail" if value >= crit else "warn" if value >= warn else "ok"


# ---------------------------------------------------------------- saúde
def health(facts: dict[str, Any], th: dict[str, tuple[float, float]]) -> tuple[list[dict], dict[str, Any]]:
    s, m = facts["single"], facts["multi"]
    out: list[dict] = []
    metrics: dict[str, Any] = {}

    total, avail = _int(s.get("mem.MemTotal")), _int(s.get("mem.MemAvailable"))
    if total:
        pct = round(100 * (total - (avail or 0)) / total, 1)
        metrics.update(mem_pct=pct, mem_total_mb=round(total / 1024))
        out.append(
            _check(
                "mem",
                "Memória em uso",
                _level(pct, th["mem"]),
                f"{pct}% de {round(total / 1048576, 1)} GiB",
                f"< {th['mem'][0]:g}%",
                fix="Ver os processos com mais memória: ps aux --sort=-rss | head",
            )
        )
    stotal, sfree = _int(s.get("mem.SwapTotal"), 0), _int(s.get("mem.SwapFree"), 0)
    if stotal:
        pct = round(100 * (stotal - (sfree or 0)) / stotal, 1)
        metrics["swap_pct"] = pct
        out.append(
            _check(
                "swap",
                "Swap em uso",
                _level(pct, th["swap"]),
                f"{pct}% de {round(stotal / 1048576, 1)} GiB",
                f"< {th['swap'][0]:g}%",
            )
        )
    else:
        metrics["swap_pct"] = None

    disks = []
    for line in m.get("disk", []):
        parts = line.rsplit(" ", 3)
        if len(parts) != 4:
            continue
        mount, size, used, free = parts[0], _int(parts[1], 0), _int(parts[2], 0), _int(parts[3], 0)
        if not size or mount.startswith(("/snap", "/run", "/boot/efi")):
            continue
        pct = round(100 * used / (used + free), 1) if (used + free) else 0.0
        disks.append(
            {"mount": mount, "size_gb": round(size / 1048576, 1), "free_gb": round(free / 1048576, 1), "pct": pct}
        )
    inodes = {}
    for line in m.get("inode", []):
        parts = line.rsplit(" ", 2)
        if len(parts) == 3 and _int(parts[1]):
            inodes[parts[0]] = round(100 * (_int(parts[2], 0) or 0) / (_int(parts[1]) or 1), 1)
    for d in disks:
        d["inode_pct"] = inodes.get(d["mount"])
    metrics["disks"] = disks
    if disks:
        worst = max(disks, key=lambda d: d["pct"])
        metrics["disk_max_pct"] = worst["pct"]
        out.append(
            _check(
                "disk",
                "Disco mais cheio",
                _level(worst["pct"], th["disk"]),
                f"{worst['mount']} {worst['pct']}% ({worst['free_gb']} GiB livres)",
                f"< {th['disk'][0]:g}%",
                fix="Ver o que ocupa: sudo du -xh --max-depth=2 " + worst["mount"] + " | sort -h | tail",
            )
        )
        wi = max((d for d in disks if d["inode_pct"] is not None), key=lambda d: d["inode_pct"], default=None)
        if wi:
            out.append(
                _check(
                    "inodes",
                    "Inodes mais usados",
                    _level(wi["inode_pct"], th["disk"]),
                    f"{wi['mount']} {wi['inode_pct']}%",
                    f"< {th['disk'][0]:g}%",
                    fix="Muitos ficheiros pequenos (caches, sessões, logs): find "
                    + wi["mount"]
                    + " -xdev -type f | cut -d/ -f2-3 | sort | uniq -c | sort -n | tail",
                )
            )

    load = (s.get("load") or "").split()
    cpus = _int(s.get("nproc"), 1) or 1
    if len(load) >= 2:
        l5 = _float(load[1], 0.0) or 0.0
        per = round(l5 / cpus, 2)
        metrics.update(load=[_float(x) for x in load], nproc=cpus, load_per_cpu=per)
        out.append(
            _check(
                "load",
                "Carga (5 min por CPU)",
                _level(per, th["load"]),
                f"{load[1]} em {cpus} CPU",
                f"< {th['load'][0]:g} por CPU",
            )
        )

    if s.get("systemd") == "1":
        failed = m.get("failed", [])
        metrics["failed_units"] = failed
        out.append(
            _check(
                "units",
                "Serviços falhados",
                "warn" if failed else "ok",
                ", ".join(failed[:6]) + (" …" if len(failed) > 6 else "") if failed else "nenhum",
                "nenhum",
                fix="systemctl status <serviço> ; journalctl -u <serviço> -n 50",
            )
        )
    oom = _int(s.get("oom"))
    if oom is not None:
        metrics["oom_7d"] = oom
        out.append(
            _check("oom", "Processos mortos por falta de memória (7 dias)", "warn" if oom else "ok", str(oom), "0")
        )
    up = _int(s.get("uptime_s"))
    if up is not None:
        metrics["uptime_days"] = round(up / 86400, 1)
        out.append(_check("uptime", "Ligado há", "info", f"{round(up / 86400, 1)} dias"))
    return out, metrics


# ---------------------------------------------------------------- hardening
def _ssh(s: dict, key: str) -> str:
    return (s.get(f"ssh.{key}") or "").lower()


def hardening(facts: dict[str, Any]) -> list[dict]:
    s, m = facts["single"], facts["multi"]
    out: list[dict] = []

    def add(cid, name, ok: bool | None, value, expected, sev, fix, *, warn: bool = False, group: str = "") -> None:
        status = "unknown" if ok is None else "ok" if ok else ("warn" if warn else "fail")
        out.append(_check(cid, name, status, value or "—", expected, severity=sev, fix=fix, group=group))

    # SSH
    src = s.get("ssh.source", "nenhum")
    known = src != "nenhum"
    v = _ssh(s, "permitrootlogin")
    add(
        "ssh_root",
        "SSH: login direto como root",
        (v in ("no", "prohibit-password", "without-password", "forced-commands-only"))
        if (known and v)
        else (True if known and src == "ficheiro" and not v else None),
        v or ("omissão" if known else ""),
        "no",
        "alta",
        "PermitRootLogin no  (em /etc/ssh/sshd_config.d/50-vulnflux.conf; systemctl reload ssh)",
        group="SSH",
    )
    v = _ssh(s, "passwordauthentication")
    add(
        "ssh_password",
        "SSH: autenticação por palavra-passe",
        (v == "no") if v else None,
        v,
        "no",
        "media",
        "PasswordAuthentication no  (depois de confirmar que todos entram com chave)",
        group="SSH",
    )
    v = _ssh(s, "permitemptypasswords")
    if v:
        add(
            "ssh_empty",
            "SSH: palavras-passe vazias",
            v == "no",
            v,
            "no",
            "alta",
            "PermitEmptyPasswords no",
            group="SSH",
        )
    v = _ssh(s, "x11forwarding")
    if v:
        add("ssh_x11", "SSH: encaminhamento X11", v == "no", v, "no", "baixa", "X11Forwarding no", group="SSH")
    v = _ssh(s, "maxauthtries")
    if v:
        add(
            "ssh_maxauth",
            "SSH: tentativas por ligação",
            (_int(v, 99) or 99) <= 4,
            v,
            "≤ 4",
            "baixa",
            "MaxAuthTries 4",
            group="SSH",
        )

    # Firewall
    ufw = (s.get("fw.ufw") or "").lower()
    firewalld = s.get("fw.firewalld") == "active"
    nft = (_int(s.get("fw.nft_input"), 0) or 0) > 0
    ipt = (s.get("fw.iptables") or "").split()
    ipt_on = bool(ipt) and (ipt[0] in ("DROP", "REJECT") or (_int(ipt[1] if len(ipt) > 1 else 0, 0) or 0) > 0)
    seen = any(k.startswith("fw.") for k in s)
    fw_on = "status: active" in ufw or firewalld or nft or ipt_on
    what = (
        "ufw ativo"
        if "status: active" in ufw
        else "firewalld ativo"
        if firewalld
        else "regras nftables"
        if nft
        else "regras iptables"
        if ipt_on
        else "sem regras de entrada"
    )
    add(
        "firewall",
        "Firewall de entrada",
        fw_on if (seen and (ufw or "fw.firewalld" in s or "fw.nft_input" in s or ipt)) else None,
        what,
        "ativa",
        "alta",
        "ufw default deny incoming && ufw allow OpenSSH && ufw enable   (ou firewalld/nftables)",
        group="Rede",
    )

    # MAC
    se = (s.get("mac.selinux") or "").lower()
    aa = (s.get("mac.apparmor") or "").upper()
    if se or aa:
        ok = se == "enforcing" or aa == "Y"
        add(
            "mac",
            "SELinux / AppArmor",
            ok,
            f"SELinux {se}" if se else f"AppArmor {'ativo' if aa == 'Y' else 'inativo'}",
            "enforcing / ativo",
            "media",
            "SELinux: setenforce 1 e SELINUX=enforcing; AppArmor: systemctl enable --now apparmor",
            warn=se == "permissive",
            group="Sistema",
        )
    else:
        add(
            "mac",
            "SELinux / AppArmor",
            False,
            "nenhum",
            "enforcing / ativo",
            "media",
            "Instalar e ativar o AppArmor (Debian/Ubuntu) ou o SELinux (RHEL)",
            group="Sistema",
        )

    # Serviços de segurança
    if s.get("systemd") == "1":
        add(
            "auditd",
            "Auditoria do kernel (auditd)",
            s.get("unit.auditd") == "active",
            s.get("unit.auditd") or "não instalado",
            "active",
            "media",
            "apt install auditd  /  dnf install audit; systemctl enable --now auditd",
            group="Sistema",
        )
        sync = s.get("ntp") == "yes" or any(
            s.get(f"unit.{u}") == "active" for u in ("chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp")
        )
        add(
            "timesync",
            "Relógio sincronizado (NTP)",
            sync,
            "sincronizado" if sync else "não sincronizado",
            "sim",
            "media",
            "timedatectl set-ntp true  (ou chrony)",
            group="Sistema",
        )
        auto = (
            s.get("auto.apt") == "1"
            or s.get("unit.unattended-upgrades") == "active"
            or s.get("unit.dnf-automatic.timer") == "active"
            or s.get("unit.dnf-automatic-install.timer") == "active"
        )
        add(
            "autoupdate",
            "Atualizações de segurança automáticas",
            auto,
            "ligadas" if auto else "desligadas",
            "ligadas",
            "media",
            "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"
            "  /  dnf install dnf-automatic",
            warn=True,
            group="Atualizações",
        )

    # Contas e permissões
    uid0 = m.get("uid0", [])
    add(
        "uid0",
        "Contas com UID 0",
        uid0 == ["root"],
        ", ".join(uid0) or "—",
        "só root",
        "alta",
        "Remover ou mudar o UID das outras contas com UID 0",
        group="Contas",
    )
    perms = {}
    for line in m.get("perm", []):
        parts = line.split()
        if len(parts) >= 3:
            perms[parts[0]] = (parts[1], parts[2])

    def mode_ok(path: str, max_other: int, max_group: int) -> bool | None:
        if path not in perms:
            return None
        mode = perms[path][0].zfill(3)[-3:]
        try:
            g, o = int(mode[1]), int(mode[2])
        except (ValueError, IndexError):
            return None
        return (o & ~max_other) == 0 and (g & ~max_group) == 0 and perms[path][1] == "root"

    for path, other, group, sev, label in (
        ("/etc/shadow", 0, 4, "alta", "640 root"),
        ("/etc/gshadow", 0, 4, "media", "640 root"),
        ("/etc/passwd", 4, 4, "media", "644 root"),
        ("/etc/ssh/sshd_config", 4, 4, "baixa", "644 root"),
        ("/etc/sudoers", 0, 4, "alta", "440 root"),
    ):
        ok = mode_ok(path, other, group)
        if ok is not None:
            add(
                "perm_" + path.rsplit("/", 1)[1],
                f"Permissões de {path}",
                ok,
                " ".join(perms[path]),
                label,
                sev,
                f"chown root {path} && chmod {label.split()[0]} {path}",
                group="Contas",
            )

    # Kernel
    def sysctl(key: str, want: set[str], sev: str, fix_value: str, label: str) -> None:
        v = s.get(f"sysctl.{key}")
        if v in (None, ""):
            return
        add(
            "sysctl_" + key.replace(".", "_"),
            label,
            v in want,
            f"{key} = {v}",
            " ou ".join(sorted(want)),
            sev,
            f"echo '{key} = {fix_value}' > /etc/sysctl.d/60-vulnflux.conf && sysctl --system",
            group="Kernel",
        )

    sysctl("kernel.randomize_va_space", {"2"}, "media", "2", "ASLR completo")
    sysctl("net.ipv4.tcp_syncookies", {"1"}, "baixa", "1", "Proteção SYN flood")
    sysctl("net.ipv4.conf.all.accept_redirects", {"0"}, "baixa", "0", "Ignorar ICMP redirects")
    sysctl("net.ipv4.conf.all.accept_source_route", {"0"}, "baixa", "0", "Rejeitar source routing")
    if s.get("sysctl.net.ipv4.ip_forward") != "1":  # num router/host de containers os redirects são normais
        sysctl("net.ipv4.conf.all.send_redirects", {"0"}, "baixa", "0", "Não enviar ICMP redirects")
    sysctl("fs.suid_dumpable", {"0"}, "baixa", "0", "Sem core dumps de programas setuid")
    sysctl("kernel.kptr_restrict", {"1", "2"}, "baixa", "1", "Endereços do kernel escondidos")
    sysctl("kernel.dmesg_restrict", {"1"}, "baixa", "1", "dmesg só para root")
    sysctl("fs.protected_symlinks", {"1"}, "baixa", "1", "Proteção de symlinks")
    sysctl("fs.protected_hardlinks", {"1"}, "baixa", "1", "Proteção de hardlinks")
    return out


def score(checks: list[dict]) -> int | None:
    total = got = 0.0
    for c in checks:
        w = SEV_WEIGHT.get(c["severity"], 1)
        if c["status"] == "ok":
            total, got = total + w, got + w
        elif c["status"] == "warn":
            total, got = total + w, got + w / 2
        elif c["status"] == "fail":
            total += w
    return round(100 * got / total) if total else None


# ---------------------------------------------------------------- atualizações
_APT = re.compile(r"^(\S+)(?: \[([^\]]*)\])? \((\S+) ([^\[)]*?)(?: \[[^\]]*\])?\)")


def updates(facts: dict[str, Any]) -> dict[str, Any]:
    s, m = facts["single"], facts["multi"]
    pkgs: list[dict] = []
    for line in m.get("aptinst", []):
        mt = _APT.match(line)
        if mt:
            pkgs.append(
                {
                    "name": mt.group(1),
                    "old": mt.group(2) or "",
                    "new": mt.group(3),
                    "security": "security" in (mt.group(4) or "").lower(),
                }
            )
    sec_nevra = set(m.get("updsec", []))
    for line in m.get("upd", []):
        parts = line.split()
        if len(parts) < 2:
            continue
        name, ver = parts[0], parts[1]
        base, _, arch = name.rpartition(".") if "." in name else (name, "", "")
        nevra = f"{base}-{ver}.{arch}" if arch else f"{name}-{ver}"
        is_sec = nevra in sec_nevra or any(x.startswith(f"{base}-{ver.split(':')[-1]}") for x in sec_nevra)
        pkgs.append(
            {"name": base or name, "old": "", "new": ver, "security": is_sec or (len(parts) > 2 and parts[2] == "sec")}
        )
    sec = sum(1 for p in pkgs if p["security"])
    pkgs.sort(key=lambda p: (not p["security"], p["name"]))
    kernel, latest = s.get("kernel", ""), s.get("kernel_latest", "")
    reboot = s.get("reboot") == "1" or bool(latest and kernel and latest != kernel and s.get("pkg") == "apt")
    refreshed = s.get("pkg.refreshed") == "1"
    age = _int(s.get("pkg.lists_age_s"))
    return {
        "manager": s.get("pkg", "desconhecido"),
        "total": len(pkgs),
        "security": sec,
        "packages": pkgs[:400],
        "reboot": reboot,
        "refreshed": refreshed,
        "lists_age_days": round(age / 86400, 1) if age is not None else None,
    }


def update_checks(u: dict[str, Any]) -> list[dict]:
    out = []
    if u["manager"] in ("desconhecido", ""):
        out.append(_check("upd_mgr", "Gestor de pacotes", "unknown", "não reconhecido", "apt, dnf, yum ou zypper"))
        return out
    out.append(
        _check(
            "upd_sec",
            "Atualizações de segurança pendentes",
            "fail" if u["security"] else "ok",
            str(u["security"]),
            "0",
            severity="alta",
            fix="Anel de atualizações (Servidores → Atualizações) ou: apt-get upgrade / dnf upgrade --security",
        )
    )
    out.append(
        _check(
            "upd_all",
            "Outras atualizações pendentes",
            "warn" if u["total"] - u["security"] > 20 else "ok",
            str(u["total"] - u["security"]),
            "poucas",
            severity="baixa",
        )
    )
    out.append(
        _check(
            "reboot",
            "Reinício pendente",
            "warn" if u["reboot"] else "ok",
            "sim" if u["reboot"] else "não",
            "não",
            severity="media",
            fix="Reiniciar numa janela de manutenção (ou ligar 'reiniciar sozinho' no anel)",
        )
    )
    if not u["refreshed"] and (u["lists_age_days"] or 0) > 7:
        out.append(
            _check(
                "upd_lists",
                "Lista de pacotes atualizada",
                "warn",
                f"há {u['lists_age_days']} dias",
                "< 7 dias",
                fix="Sem sudo para apt-get update: corra de novo o comando de ligação do VulnFlux",
            )
        )
    return out


# ---------------------------------------------------------------- relatório
def build_report(output: str, th: dict[str, tuple[float, float]]) -> dict[str, Any]:
    facts = parse(output)
    s = facts["single"]
    h, metrics = health(facts, th)
    hard = hardening(facts)
    upd = updates(facts)
    uchecks = update_checks(upd)
    sc = score(hard)
    lynis = {"present": s.get("lynis.present") == "1", "index": _int(s.get("lynis.index")), "at": s.get("lynis.at", "")}
    worst_health = max((STATUS_ORDER[c["status"]] for c in h), default=0)
    status = "ok"
    if worst_health >= 3:
        status = "fail"
    elif worst_health == 2 or upd["security"] or (sc is not None and sc < 70) or upd["reboot"]:
        status = "warn"
    if not facts["complete"]:
        status = "warn" if status == "ok" else status
    problems = [c["name"] for c in h if c["status"] in ("fail", "warn")]
    if upd["security"]:
        problems.append(f"{upd['security']} atualizações de segurança")
    summary = "; ".join(problems[:4]) or "tudo em ordem"
    return {
        "schema": 1,
        "complete": facts["complete"],
        "status": status,
        "summary": summary,
        "os": s.get("os.name") or s.get("os.id", ""),
        "os_id": s.get("os.id", ""),
        "os_like": s.get("os.like", ""),
        "kernel": s.get("kernel", ""),
        "arch": s.get("arch", ""),
        "hostname": s.get("hostname", ""),
        "metrics": metrics,
        "health": h,
        "hardening": hard,
        "score": sc,
        "updates": upd,
        "update_checks": uchecks,
        "listen": sorted(set(facts["multi"].get("listen", [])))[:200],
        "lynis": lynis,
        "oscap": s.get("oscap.present") == "1",
        "sudo_rules": _int(s.get("sudo.rules"), 0),
        "ssh_source": s.get("ssh.source", ""),
        "shell_users": _int(s.get("shell_users")),
    }
