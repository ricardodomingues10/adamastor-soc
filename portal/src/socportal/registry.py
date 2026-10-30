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
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator, model_validator

ProbeType = Literal["http", "tcp", "defectdojo", "soc-status", "soc-component", "misp"]
_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")


class RegistryError(ValueError):
    pass


class ProbeDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ProbeType
    name: str = ""
    # http(s)://... ou um caminho (/api/health) relativo ao api_url/link do serviço; tcp: host:porta
    url: str | None = None
    # Credenciais por referência. O conteúdo nunca aparece na interface.
    token_file: str | None = None
    token_env: str | None = None
    # http: códigos aceites e texto que tem de aparecer na resposta
    expect_status: list[int] = Field(default_factory=lambda: [200])
    contains: str | None = None
    # Autenticação do probe http: cabeçalho e esquema (Basic: token "utilizador:password")
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    # Versão a partir da resposta: caminho no JSON (version.number) ou regex (grupos juntos com ".")
    version_path: str | None = None
    version_regex: str | None = None
    verify_tls: bool | None = None  # None = valor global (SP_VERIFY_TLS)
    timeout: float | None = None
    # soc-component: estado de um componente reportado por outro serviço
    service: str | None = None
    component: str | None = None
    # Credencial escrita no formulário, só para o botão "Testar" (nunca gravada assim)
    _inline_token: str | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _check(self) -> ProbeDef:
        if self.type == "soc-component":
            if not self.service or not self.component:
                raise ValueError("soc-component precisa de 'service' e 'component'")
        elif not self.url:
            raise ValueError(f"a verificação {self.type} precisa de 'url'")
        if self.type == "tcp" and self.url and not re.match(r"^[^:/\s]+:\d{1,5}$", self.url):
            raise ValueError("tcp: url no formato host:porta")
        if (
            self.type not in ("tcp", "soc-component")
            and self.url
            and not self.url.startswith(("http://", "https://", "/"))
        ):
            raise ValueError("url tem de começar por http://, https:// ou / (relativo ao serviço)")
        if self.version_regex:
            try:
                re.compile(self.version_regex)
            except re.error as exc:
                raise ValueError(f"version_regex inválida: {exc}") from exc
        if not re.match(r"^[A-Za-z0-9-]{1,64}$", self.auth_header):
            raise ValueError("auth_header inválido")
        return self

    @property
    def relative(self) -> bool:
        return bool(self.url and self.url.startswith("/"))

    @property
    def label(self) -> str:
        return self.name or self.type

    def token(self) -> str | None:
        """Lê a credencial no momento da verificação (permite rodar sem reiniciar)."""
        if self._inline_token:
            return self._inline_token
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
    # Base dos probes com url relativo, se for diferente do link (ex.: nome interno do container)
    api_url: str | None = None
    location: str = ""  # máquina/VM onde corre (informativo)
    function: str | None = None  # função SOC (catálogo): siem, cti, cases, ...
    template: str | None = None  # modelo do catálogo usado para o criar
    # Onde está definido: "file" (portal.yaml) ou "ui" (criado na interface). Preenchido ao carregar.
    origin: Literal["file", "ui"] = "file"
    probes: list[ProbeDef] = Field(default_factory=list)
    latest: LatestDef | None = None
    depends_on: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID.match(v):
            raise ValueError(f"id '{v}' inválido (minúsculas, números, - e _)")
        return v

    @field_validator("link", "api_url")
    @classmethod
    def _link(cls, v: str | None) -> str | None:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("tem de começar por http:// ou https://")
        return v.rstrip("/") if v else None

    @model_validator(mode="after")
    def _relative(self) -> ServiceDef:
        if any(p.relative for p in self.probes) and not (self.api_url or self.link):
            raise ValueError(f"{self.id}: probes com caminho relativo precisam de api_url ou link")
        return self

    def resolve(self, probe: ProbeDef) -> ProbeDef:
        """Probe com o url absoluto (os caminhos relativos usam api_url, senão o link)."""
        if not probe.relative:
            return probe
        base = (self.api_url or self.link or "").rstrip("/")
        return probe.model_copy(update={"url": base + str(probe.url)})


class PortalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = "Adamastor SOC"
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
        raise RegistryError(_short(exc)) from exc


def _mtime(path: Path | None) -> float | None:
    try:
        return path.stat().st_mtime if path else None
    except OSError:
        return None


class Registry:
    """Serviços do portal.yaml + serviços criados na interface (data_dir/services.json).

    O portal.yaml é a configuração "como código" (só leitura na interface). Os criados na
    interface são editáveis lá. Ambos são relidos quando mudam. Um ficheiro inválido não
    derruba o portal: mantém a última configuração boa e mostra o erro no topo.
    """

    def __init__(self, path: Path, ui_path: Path | None = None) -> None:
        self.path = path
        self.ui_path = ui_path
        self.config = PortalConfig()
        self.error: str | None = None
        self._stamp: tuple[float | None, float | None] | None = None
        self.reload(force=True)

    def ui_services(self) -> list[dict]:
        if not self.ui_path or not self.ui_path.exists():
            return []
        import json

        try:
            data = json.loads(self.ui_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RegistryError(f"{self.ui_path} ilegível: {exc}") from exc
        return data.get("services", []) if isinstance(data, dict) else []

    def reload(self, force: bool = False) -> bool:
        stamp = (_mtime(self.path), _mtime(self.ui_path))
        if not force and stamp == self._stamp:
            return False
        self._stamp = stamp
        if stamp[0] is None and not (self.ui_path and stamp[1]):
            self.error = f"ficheiro {self.path} não encontrado"
            return False
        try:
            text = self.path.read_text(encoding="utf-8") if stamp[0] is not None else "{}"
            file_cfg = parse(text)
        except (RegistryError, OSError) as exc:
            self.error = str(exc)
            return False
        for svc in file_cfg.services:
            svc.origin = "file"
        try:
            ui = [{**item, "origin": "ui"} for item in self.ui_services()]
            combined = PortalConfig.model_validate(
                {"title": file_cfg.title, "services": [s.model_dump() for s in file_cfg.services] + ui}
            )
            self.config, self.error = combined, None
        except (RegistryError, ValidationError, ValueError) as exc:
            # Os serviços da interface não podem estragar os do ficheiro
            self.config = file_cfg
            self.error = f"serviços criados na interface ignorados: {_short(exc)}"
        return True

    def file_ids(self) -> set[str]:
        return {s.id for s in self.config.services if s.origin == "file"}


def _short(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" if e["loc"] else e["msg"] for e in exc.errors()
        )
    return str(exc)
