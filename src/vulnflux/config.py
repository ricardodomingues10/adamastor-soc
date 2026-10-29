"""Configuração do VulnFlux.

Tudo vem de variáveis de ambiente com prefixo VF_ (ver .env.example). Segredos podem
vir de Docker secrets: um ficheiro /run/secrets/vf_dd_token preenche VF_DD_TOKEN.
"""

from __future__ import annotations

import os
import re
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = "/run/secrets"

DEFAULT_ENVIRONMENTS = [
    "Sites_Publicos_PRD",
    "Sites_Publicos_TST",
    "Apps_Publicas_Jogos_TST",
    "Development",
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VF_",
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=_SECRETS_DIR if os.path.isdir(_SECRETS_DIR) else None,
        extra="ignore",
    )

    # --- Geral -------------------------------------------------------------------
    data_dir: Path = Path("/data")
    timezone: str = "Europe/Lisbon"
    base_url: str = ""  # usado em links de alertas; vazio = relativo
    retention_days: int = 180
    # Separados por vírgulas; são sugestões no formulário e o product type no DefectDojo
    environments: str = ",".join(DEFAULT_ENVIRONMENTS)

    # --- Interface web -----------------------------------------------------------
    admin_user: str = "admin"
    admin_password: SecretStr = SecretStr("")
    secret_key: SecretStr = SecretStr("")  # vazio = gerado e guardado em data_dir
    cookie_secure: bool = True  # False só para testes locais sem HTTPS
    session_hours: int = 12
    # Token para /api/status (lido pelo Portal SOC). Vazio = endpoint desligado (404).
    status_token: SecretStr = SecretStr("")

    # --- DefectDojo --------------------------------------------------------------
    dd_url: str = ""
    dd_token: SecretStr = SecretStr("")
    dd_engagement: str = "VulnFlux"
    dd_default_product_type: str = "Sites_Publicos_PRD"
    dd_verify_tls: bool = True
    dd_ca_bundle: str = ""  # caminho para a CA interna, se aplicável
    dd_timeout: int = 120
    dd_import_retries: int = 3

    # --- WPScan --------------------------------------------------------------------
    wpscan_api_token: SecretStr = SecretStr("")
    # Várias chaves para rotação, separadas por vírgulas, espaços ou linhas.
    # Junta-se a VF_WPSCAN_API_TOKEN (que continua a funcionar sozinha).
    wpscan_api_tokens: SecretStr = SecretStr("")
    wpscan_cron: str = "37 2 * * *"
    wpscan_batch_size: int = 4
    wpscan_min_quota: int = 5
    wpscan_timeout: int = 1800
    wpscan_disable_tls_checks: bool = False
    wpscan_include_interesting: bool = False
    # O WPScan 4.x sem -e não enumera plugins, utilizadores nem backups: só versão e tema.
    # vp/vt = plugins/temas vulneráveis, tt = timthumbs, cb = backups de configuração,
    # dbe = exports da BD, bf = pastas de backup, u1-10 = utilizadores com ID 1 a 10
    wpscan_enumerate: str = "vp,vt,tt,cb,dbe,bf,u1-10"
    # passive (só o HTML), mixed (HTML + localizações conhecidas) ou aggressive
    wpscan_plugins_detection: str = "mixed"
    # Utilizadores enumerados viram um finding Low por site (com a lista de usernames)
    wpscan_include_users: bool = True
    wpscan_extra_args: str = ""

    # --- Greenbone -----------------------------------------------------------------
    greenbone_enabled: bool = False
    greenbone_cron: str = "13 1 26 * *"
    greenbone_socket: str = "/run/gvmd/gvmd.sock"
    greenbone_user: str = "orchestrator"
    greenbone_password: SecretStr = SecretStr("")
    greenbone_concurrency: int = 3
    greenbone_scan_timeout_hours: float = 8
    greenbone_poll_seconds: int = 30
    greenbone_min_qod: int = 70
    greenbone_levels: str = "hml"  # h=high m=medium l=low g=log (Info no DD)
    greenbone_scan_config_id: str = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
    greenbone_port_list_id: str = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # All IANA assigned TCP
    greenbone_scanner_id: str = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default
    greenbone_min_nvts: int = 10_000
    greenbone_max_feed_age_days: float = 7
    greenbone_block_on_stale_feed: bool = False
    greenbone_ready_timeout_hours: float = 3
    # Ciclo de vida on-demand (vazio = Greenbone sempre ligado, sem start/stop)
    greenbone_ssh_host: str = ""
    greenbone_ssh_user: str = "gbctl"
    greenbone_ssh_port: int = 22
    greenbone_ssh_key: str = "/run/secrets/vf_gbctl_key"
    greenbone_ssh_known_hosts: str = "/run/secrets/vf_gbctl_known_hosts"
    greenbone_update_before_scan: bool = True
    greenbone_stop_after: bool = True

    # --- Prioridade por risco (KEV, EPSS, exploits + contexto do inventário) ------------
    risk_enabled: bool = True
    risk_cron: str = "17 6 * * *"
    # URL vazio desliga a fonte; file:///caminho lê um espelho local (servidores sem Internet)
    risk_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    risk_epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
    risk_exploitdb_url: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    risk_metasploit_url: str = (
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    )
    risk_nuclei_url: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
    risk_download_timeout: int = 300
    # Dias para corrigir por prioridade: P1, P2, P3, P4
    risk_sla_days: str = "7,30,90,180"
    # Recalcular as prioridades de um host logo a seguir a cada import (com os feeds em cache)
    risk_after_import: bool = True
    # Escrever criticidade e exposição no Product do DefectDojo
    risk_sync_products: bool = True
    # URL do DefectDojo para links no browser (se diferente do VF_DD_URL interno)
    dd_public_url: str = ""

    # --- Gates -----------------------------------------------------------------------
    gate_drop_threshold: float = 0.5  # queda > 50% face à última execução boa
    gate_drop_min_previous: int = 5  # só avalia quedas se antes havia >= N findings

    @field_validator("dd_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")

    # --- Derivados ---------------------------------------------------------------------
    @property
    def environment_list(self) -> list[str]:
        return [x.strip() for x in self.environments.split(",") if x.strip()]

    def sla_days(self) -> dict[str, int]:
        """VF_RISK_SLA_DAYS → {"P1": 7, ...}. Valores em falta ou inválidos usam a omissão."""
        defaults = [7, 30, 90, 180]
        parts = [p.strip() for p in self.risk_sla_days.split(",")]
        out = {}
        for i, prio in enumerate(("P1", "P2", "P3", "P4")):
            try:
                value = int(parts[i])
            except (IndexError, ValueError):
                value = defaults[i]
            out[prio] = value if value > 0 else defaults[i]
        return out

    @property
    def dd_browser_url(self) -> str:
        return (self.dd_public_url or self.dd_url).rstrip("/")

    @property
    def greenbone_lifecycle_enabled(self) -> bool:
        return bool(self.greenbone_ssh_host)

    def wpscan_tokens(self) -> list[str]:
        """Todas as chaves WPScan configuradas, sem duplicados, pela ordem dada."""
        raw = self.wpscan_api_token.get_secret_value() + "," + self.wpscan_api_tokens.get_secret_value()
        tokens: list[str] = []
        for item in re.split(r"[\s,;]+", raw):
            item = item.strip()
            if item and item not in tokens:
                tokens.append(item)
        return tokens

    @property
    def dd_configured(self) -> bool:
        return bool(self.dd_url and self.dd_token.get_secret_value())

    def dd_verify(self) -> bool | str:
        if not self.dd_verify_tls:
            return False
        return self.dd_ca_bundle or True

    def resolved_secret_key(self) -> str:
        """Chave das sessões: a configurada, ou uma gerada e persistida no data_dir."""
        configured = self.secret_key.get_secret_value()
        if configured:
            return configured
        path = self.data_dir / ".secret_key"
        if path.exists():
            return path.read_text().strip()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key = secrets.token_urlsafe(48)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key)
        return key

    def public_view(self) -> dict[str, object]:
        """Configuração efetiva para a página de definições, com segredos mascarados."""
        out: dict[str, object] = {}
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                if name == "secret_key" and not value.get_secret_value():
                    out[name] = "gerado automaticamente"
                elif name == "wpscan_api_tokens" and value.get_secret_value():
                    out[name] = f"definido ({len(self.wpscan_tokens())} chaves no total)"
                else:
                    out[name] = "definido" if value.get_secret_value() else "por definir"
            elif isinstance(value, Path):
                out[name] = str(value)
            else:
                out[name] = value
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
