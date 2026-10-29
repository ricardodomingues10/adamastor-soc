"""Registo de serviços (portal.yaml).

Cada serviço é descrito só por URLs e credenciais por referência (ficheiro ou variável
de ambiente, nunca o segredo no YAML). Nada depende de os serviços estarem no mesmo
host ou na mesma rede Docker: quando o DefectDojo ou o MISP passarem para máquinas
dedicadas, muda-se o url e mais nada.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

ProbeType = Literal["http", "tcp", "defectdojo", "soc-status", "soc-component", "misp"]
_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")


class RegistryError(ValueError):
    pass


class ProbeDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ProbeType
    name: str = ""
    url: str | None = None  # http(s)://... ; tcp: host:porta
    # Credenciais por referência. O conteúdo nunca aparece na interface.
    token_file: str | None = None
    token_env: str | None = None
    # http: códigos aceites e texto que tem de aparecer na resposta
    expect_status: list[int] = Field(default_factory=lambda: [200])
    contains: str | None = None
    verify_tls: bool | None = None  # None = valor global (SP_VERIFY_TLS)
    timeout: float | None = None
    # soc-component: estado de um componente reportado por outro serviço
    service: str | None = None
    component: str | None = None

    @model_validator(mode="after")
    def _check(self) -> ProbeDef:
        if self.type == "soc-component":
            if not self.service or not self.component:
                raise ValueError("soc-component precisa de 'service' e 'component'")
        elif not self.url:
            raise ValueError(f"a verificação {self.type} precisa de 'url'")
        if self.type == "tcp" and self.url and not re.match(r"^[^:/\s]+:\d{1,5}$", self.url):
            raise ValueError("tcp: url no formato host:porta")
        if self.type not in ("tcp", "soc-component") and self.url and not self.url.startswith(("http://", "https://")):
            raise ValueError("url tem de começar por http:// ou https://")
        return self

    @property
    def label(self) -> str:
        return self.name or self.type

    def token(self) -> str | None:
        """Lê a credencial no momento da verificação (permite rodar sem reiniciar)."""
        if self.token_file:
            try:
                value = Path(self.token_file).read_text().strip()
            except OSError:
                return None
            return value or None
        if self.token_env:
            return os.environ.get(self.token_env) or None
        return None


class LatestDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    github: str | None = None  # owner/repo: usa a última release (sem pré-releases)

    @field_validator("github")
    @classmethod
    def _repo(cls, v: str | None) -> str | None:
        if v and not re.match(r"^[\w.-]+/[\w.-]+$", v):
            raise ValueError("github no formato owner/repo")
        return v


class ServiceDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    group: str = "Serviços"
    description: str = ""
    link: str | None = None  # interface web (o botão "Abrir")
    location: str = ""  # máquina/VM onde corre (informativo)
    probes: list[ProbeDef] = Field(default_factory=list)
    latest: LatestDef | None = None
    depends_on: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID.match(v):
            raise ValueError(f"id '{v}' inválido (minúsculas, números, - e _)")
        return v

    @field_validator("link")
    @classmethod
    def _link(cls, v: str | None) -> str | None:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("link tem de começar por http:// ou https://")
        return v or None


class PortalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = "Portal SOC"
    services: list[ServiceDef] = Field(default_factory=list)

    @model_validator(mode="after")
    def _refs(self) -> PortalConfig:
        ids = [s.id for s in self.services]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"ids repetidos: {', '.join(dupes)}")
        known = set(ids)
        for s in self.services:
            for dep in s.depends_on:
                if dep not in known:
                    raise ValueError(f"{s.id}: depends_on '{dep}' não existe")
                if dep == s.id:
                    raise ValueError(f"{s.id}: não pode depender de si próprio")
            for p in s.probes:
                if p.type == "soc-component" and p.service not in known:
                    raise ValueError(f"{s.id}: soc-component refere o serviço '{p.service}', que não existe")
        return self

    def get(self, service_id: str) -> ServiceDef | None:
        return next((s for s in self.services if s.id == service_id), None)

    def groups(self) -> list[tuple[str, list[ServiceDef]]]:
        out: dict[str, list[ServiceDef]] = {}
        for s in self.services:
            out.setdefault(s.group, []).append(s)
        return list(out.items())


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def expand_env(text: str) -> str:
    """${VAR} e ${VAR:-omissão}: o mesmo portal.yaml serve vários ambientes."""
    return _VAR.sub(lambda m: os.environ.get(m.group(1)) or (m.group(2) or ""), text)


def parse(text: str) -> PortalConfig:
    try:
        data = yaml.safe_load(expand_env(text)) or {}
    except yaml.YAMLError as exc:
        raise RegistryError(f"YAML inválido: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError("o portal.yaml tem de ser um mapa (title, services)")
    try:
        return PortalConfig.model_validate(data)
    except ValidationError as exc:
        parts = []
        for err in exc.errors():
            loc = ".".join(str(x) for x in err["loc"])
            parts.append(f"{loc}: {err['msg']}" if loc else err["msg"])
        raise RegistryError("; ".join(parts)) from exc


class Registry:
    """Lê o portal.yaml e volta a lê-lo quando o ficheiro muda.

    Um ficheiro inválido não derruba o portal: mantém a última configuração boa e
    mostra o erro no topo da página.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.config = PortalConfig()
        self.error: str | None = None
        self._mtime: float | None = None
        self.reload(force=True)

    def reload(self, force: bool = False) -> bool:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            self.error = f"ficheiro {self.path} não encontrado"
            return False
        if not force and mtime == self._mtime:
            return False
        self._mtime = mtime
        try:
            self.config = parse(self.path.read_text(encoding="utf-8"))
            self.error = None
            return True
        except (RegistryError, OSError) as exc:
            self.error = str(exc)
            return False
