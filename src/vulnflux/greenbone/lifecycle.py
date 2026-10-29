"""Controlo do ciclo de vida do Greenbone a partir do orchestrator.

O orchestrator não tem acesso ao Docker. Liga-se por SSH ao host do Greenbone com
uma chave dedicada cujo forced command é /opt/greenbone/gb-ctl.sh, por isso só
consegue pedir um de quatro verbos: start, stop, update, status.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Literal

Verb = Literal["start", "stop", "update", "status"]

# Timeouts do lado do cliente: ligeiramente acima dos do gb-ctl.sh, para que seja
# o script a falhar primeiro com uma mensagem útil.
_TIMEOUTS: dict[str, int] = {"start": 960, "stop": 360, "update": 2760, "status": 60}


class LifecycleError(Exception):
    """Falha ao controlar a stack. `transient` indica se vale a pena repetir."""

    def __init__(self, message: str, *, transient: bool) -> None:
        super().__init__(message)
        self.transient = transient


@dataclass(frozen=True)
class ServiceState:
    service: str
    state: str
    health: str
    exit_code: int
    image: str


@dataclass(frozen=True)
class LifecycleResult:
    action: str
    message: str
    services: list[ServiceState] = field(default_factory=list)

    def running(self) -> set[str]:
        return {s.service for s in self.services if s.state == "running"}


@dataclass(frozen=True)
class GreenboneHost:
    """Destino SSH do gb-ctl. `known_hosts` deve conter só a chave deste host."""

    host: str
    user: str
    identity_file: str
    known_hosts: str
    port: int = 22
    connect_timeout: int = 10

    def _ssh_cmd(self, verb: Verb) -> list[str]:
        return [
            "ssh",
            "-i",
            self.identity_file,
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            f"{self.user}@{self.host}",
            # Com forced command, isto chega ao gb-ctl como SSH_ORIGINAL_COMMAND.
            verb,
        ]

    def run(self, verb: Verb) -> LifecycleResult:
        if verb not in _TIMEOUTS:
            raise ValueError(f"verbo inválido: {verb!r}")
        try:
            proc = subprocess.run(
                self._ssh_cmd(verb),
                capture_output=True,
                text=True,
                timeout=_TIMEOUTS[verb],
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LifecycleError(f"gb-ctl {verb}: sem resposta em {exc.timeout}s", transient=True) from exc

        # ssh devolve 255 quando a falha é da ligação (rede, host key, auth).
        if proc.returncode == 255:
            stderr = proc.stderr.strip()
            permanent = "Permission denied" in stderr or "Host key verification failed" in stderr
            raise LifecycleError(f"gb-ctl {verb}: falha SSH: {stderr}", transient=not permanent)

        return parse_gbctl_output(verb, proc.returncode, proc.stdout)


def parse_gbctl_output(verb: str, returncode: int, stdout: str) -> LifecycleResult:
    """Interpreta a linha JSON do gb-ctl. Separado de `run` para ser testável."""
    lines = [ln for ln in stdout.strip().splitlines() if ln.strip()]
    if not lines:
        raise LifecycleError(f"gb-ctl {verb}: saída vazia (rc={returncode})", transient=True)
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"gb-ctl {verb}: saída não é JSON: {lines[-1][:200]}", transient=False) from exc

    if returncode == 2:
        raise LifecycleError(f"gb-ctl {verb}: {payload.get('message')}", transient=False)
    if returncode != 0 or not payload.get("ok"):
        message = payload.get("message", "erro sem mensagem")
        # Lock ocupado é transitório; o resto (pull falhou, compose falhou) também
        # pode ser, mas o orchestrator limita as tentativas.
        raise LifecycleError(f"gb-ctl {verb}: {message}", transient=True)

    services = [
        ServiceState(
            service=s.get("service", ""),
            state=s.get("state", ""),
            health=s.get("health", "") or "",
            exit_code=int(s.get("exit_code") or 0),
            image=s.get("image", ""),
        )
        for s in (payload.get("data") or [])
    ]
    return LifecycleResult(action=payload.get("action", verb), message=payload.get("message", ""), services=services)
