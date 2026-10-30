"""Acesso SSH aos servidores: a chave própria do VulnFlux, a confiança nas chaves dos hosts e a execução.

Sem agente: o VulnFlux gera um par ed25519 em data_dir/ssh na primeira utilização e o servidor só
precisa de uma conta com essa chave (o comando de ligação da página Servidores cria-a). A chave do
host é aceite na primeira ligação e fixada em data_dir/ssh/known_hosts (TOFU): se mudar, a ligação
falha até alguém confirmar na interface que a mudança é esperada.
"""

from __future__ import annotations

import base64
import hashlib
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import Host


@dataclass
class Result:
    rc: int
    out: str
    err: str


class Runner(Protocol):
    def run(self, host: Host, script: str, *, env: dict[str, str] | None = None, timeout: int = 600) -> Result: ...


# ---------------------------------------------------------------- chave do VulnFlux
def key_dir(settings: Settings) -> Path:
    return settings.data_dir / "ssh"


def key_path(settings: Settings) -> Path:
    return key_dir(settings) / "id_ed25519"


def known_hosts(settings: Settings) -> Path:
    return key_dir(settings) / "known_hosts"


def ensure_key(settings: Settings) -> str:
    """Gera o par de chaves se ainda não existir. Devolve a chave pública (uma linha)."""
    priv = key_path(settings)
    pub = priv.with_suffix(".pub")
    if not priv.exists():
        priv.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "vulnflux@soc", "-f", str(priv)],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise VFError(ErrorKind.CONFIG, f"não foi possível gerar a chave SSH: {exc}") from exc
    known_hosts(settings).touch(mode=0o600, exist_ok=True)
    return pub.read_text().strip()


def public_key(settings: Settings) -> str:
    return ensure_key(settings)


def fingerprint(pubkey_line: str) -> str:
    """SHA256:… como o ssh-keygen -l mostra."""
    try:
        blob = base64.b64decode(pubkey_line.split()[1])
    except (IndexError, ValueError):
        return "?"
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _kh_name(host: Host) -> str:
    return host.ssh_target if host.ssh_port == 22 else f"[{host.ssh_target}]:{host.ssh_port}"


def host_key(settings: Settings, host: Host) -> str:
    """Impressão digital da chave fixada para este servidor ("" se ainda não houver)."""
    path = known_hosts(settings)
    if not path.exists():
        return ""
    name = _kh_name(host)
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and name in parts[0].split(","):
            return f"{parts[1]} {fingerprint(parts[1] + ' ' + parts[2])}"
    return ""


def forget_host_key(settings: Settings, host: Host) -> None:
    """Esquece a chave fixada (depois de confirmar que a mudança é legítima, ex.: reinstalação)."""
    path = known_hosts(settings)
    if not path.exists():
        return
    name = _kh_name(host)
    keep = [ln for ln in path.read_text().splitlines() if not (ln.split() and name in ln.split()[0].split(","))]
    path.write_text("\n".join(keep) + ("\n" if keep else ""))


# ---------------------------------------------------------------- execução
class SshRunner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def command(self, host: Host, remote: str) -> list[str]:
        return [
            "ssh",
            "-i", str(key_path(self.settings)),
            "-p", str(host.ssh_port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known_hosts(self.settings)}",
            "-o", "HashKnownHosts=no",
            "-o", f"ConnectTimeout={self.settings.servers_ssh_timeout}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4",
            "-o", "LogLevel=ERROR",
            f"{host.ssh_user}@{host.ssh_target}",
            remote,
        ]  # fmt: skip

    def run(self, host: Host, script: str, *, env: dict[str, str] | None = None, timeout: int = 600) -> Result:
        ensure_key(self.settings)
        prefix = " ".join(f"{k}={shlex.quote(v)}" for k, v in (env or {}).items())
        remote = f"{prefix} sh -s" if prefix else "sh -s"
        try:
            proc = subprocess.run(
                self.command(host, remote), input=script, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise VFError(ErrorKind.TRANSIENT, f"{host.name}: sem resposta em {timeout}s") from exc
        except OSError as exc:
            raise VFError(ErrorKind.CONFIG, f"cliente ssh indisponível: {exc}") from exc
        if proc.returncode == 255:
            raise ssh_error(host, proc.stderr)
        return Result(proc.returncode, proc.stdout, proc.stderr)


def ssh_error(host: Host, stderr: str) -> VFError:
    """Traduz a falha de ligação do ssh numa mensagem que diz o que fazer."""
    err = (stderr or "").strip()
    low = err.lower()
    if "remote host identification has changed" in low or "host key verification failed" in low:
        return VFError(
            ErrorKind.PERMANENT,
            f"{host.name}: a chave do servidor mudou desde a primeira ligação. Se foi reinstalado, "
            "confirme em Servidores → Aceitar a nova chave; se não, investigue (possível intercepção).",
            detail=err[:2000],
        )
    if "permission denied" in low:
        return VFError(
            ErrorKind.CONFIG,
            f"{host.name}: acesso recusado a {host.ssh_user}. Corra o comando de ligação no servidor "
            "(Servidores → Ligar um servidor).",
            detail=err[:2000],
        )
    if any(
        x in low for x in ("timed out", "no route", "connection refused", "could not resolve", "network is unreachable")
    ):
        return VFError(
            ErrorKind.TRANSIENT, f"{host.name}: sem ligação SSH ({err.splitlines()[-1][:160]})", detail=err[:2000]
        )
    return VFError(ErrorKind.DEPENDENCY, f"{host.name}: falha SSH: {err[:200] or 'sem detalhe'}", detail=err[:2000])
