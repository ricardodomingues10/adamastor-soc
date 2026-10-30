"""Modelos de dados: hosts, execuções e passos."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from vulnflux.errors import ErrorKind


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return secrets.token_hex(6)


class Source(StrEnum):
    WPSCAN = "wpscan"
    GREENBONE = "greenbone"
    RISK = "risk"  # job de prioridades (não é um scanner; corre sobre todos os hosts)
    SERVER = "server"  # saúde, hardening e atualizações pendentes por SSH (vulnflux.servers)
    PATCH = "patch"  # aplicação de atualizações num anel de um ciclo

    @property
    def label(self) -> str:
        return {
            "wpscan": "WPScan",
            "greenbone": "Greenbone",
            "risk": "Prioridades",
            "server": "Servidor",
            "patch": "Atualizações",
        }[self.value]

    @property
    def scanner(self) -> bool:
        return self in (Source.WPSCAN, Source.GREENBONE, Source.SERVER)


class Trigger(StrEnum):
    SCHEDULE = "schedule"
    MANUAL = "manual"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    WARNING = "warning"  # importou, mas com avisos (ex.: queda abrupta de findings)
    FAILED = "failed"
    SKIPPED = "skipped"  # não correu (quota, dependência em baixo antes de começar)
    INTERRUPTED = "interrupted"  # o processo reiniciou a meio

    @property
    def label(self) -> str:
        return {
            "queued": "Em fila",
            "running": "A correr",
            "success": "Sucesso",
            "warning": "Com avisos",
            "failed": "Falhou",
            "skipped": "Ignorado",
            "interrupted": "Interrompido",
        }[self.value]

    @property
    def finished(self) -> bool:
        return self not in (RunStatus.QUEUED, RunStatus.RUNNING)

    @property
    def good(self) -> bool:
        return self in (RunStatus.SUCCESS, RunStatus.WARNING)


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


class Host(BaseModel):
    id: str = Field(default_factory=new_id)
    # Nome canónico (hostname). É o product_name no DefectDojo: tem de ser igual para
    # o WPScan e o Greenbone, para os findings das duas fontes caírem no mesmo product.
    name: str
    url: str | None = None  # alvo WPScan
    scan_target: str | None = None  # alvo Greenbone (hostname ou IP); vazio = name
    environment: str = ""  # product type no DefectDojo
    wpscan_enabled: bool = True
    greenbone_enabled: bool = False
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    notes: str = ""
    # Contexto de negócio para a prioridade por risco (ver vulnflux.risk.context)
    criticality: str = "medio"
    exposure: str = "internet"
    data_class: str = "interno"
    greenbone_profile: str = ""  # rapido | completo · vazio = VF_GREENBONE_PROFILE
    # Servidor gerido por SSH (vulnflux.servers): saúde, hardening, atualizações
    ssh_enabled: bool = False
    ssh_address: str = ""  # vazio = name
    ssh_port: int = 22
    ssh_user: str = "vulnflux"
    patch_ring: int = 2  # 0 canário · 1 piloto · 2 geral · 3 críticos (com aprovação)
    patch_mode: str = "verificar"  # verificar | seguranca | tudo
    patch_reboot: bool = False  # reiniciar sozinho quando a atualização o pede
    lynis: bool = False  # correr o Lynis (se instalado) em cada verificação
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @property
    def ssh_target(self) -> str:
        return self.ssh_address or self.name

    @property
    def greenbone_target(self) -> str:
        return self.scan_target or self.name

    def source_enabled(self, source: Source) -> bool:
        if not self.enabled:
            return False
        if source is Source.WPSCAN:
            return self.wpscan_enabled and bool(self.url)
        if source is Source.GREENBONE:
            return self.greenbone_enabled
        if source is Source.SERVER:
            return self.ssh_enabled
        if source is Source.PATCH:
            return self.ssh_enabled and self.patch_mode in ("seguranca", "tudo")
        return False


class Step(BaseModel):
    name: str
    status: StepStatus = StepStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    detail: str = ""

    @property
    def duration_s(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


ALL_HOSTS = "*"  # host_id das execuções que abrangem todos os hosts (prioridades)


class Run(BaseModel):
    id: str = Field(default_factory=new_id)
    host_id: str
    host_name: str  # cópia: o histórico sobrevive a renomear/apagar o host
    source: Source
    trigger: Trigger = Trigger.SCHEDULE
    status: RunStatus = RunStatus.QUEUED
    error_kind: ErrorKind | None = None
    error_message: str | None = None
    error_detail: str | None = None  # stderr do scanner, corpo da resposta do DD, etc.
    warnings: list[str] = Field(default_factory=list)
    steps: list[Step] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def duration_s(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def findings_total(self) -> int | None:
        value = self.stats.get("findings_total")
        return int(value) if value is not None else None
