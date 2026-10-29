"""Configuração do processo (variáveis SP_*). Os serviços monitorizados vêm do portal.yaml.

Separação deliberada:
  - variáveis de ambiente: como o portal corre (login, portas, proxy, alertas)
  - portal.yaml: o que o portal monitoriza (serviços, URLs, dependências)

Assim, mudar o DefectDojo para outra máquina é editar um URL no portal.yaml, sem
reconstruir nem reiniciar nada (o ficheiro é relido quando muda).
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = "/run/secrets"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SP_",
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=_SECRETS_DIR if os.path.isdir(_SECRETS_DIR) else None,
        extra="ignore",
    )

    data_dir: Path = Path("/data")
    config_file: Path = Path("/config/portal.yaml")
    timezone: str = "Europe/Lisbon"

    # --- Interface ---------------------------------------------------------------
    admin_user: str = "admin"
    admin_password: SecretStr = SecretStr("")
    secret_key: SecretStr = SecretStr("")  # vazio = gerada e guardada no data_dir
    cookie_secure: bool = True
    session_hours: int = 12
    # Token opcional para /api/summary (SIEM, scripts). Vazio = só com sessão.
    api_token: SecretStr = SecretStr("")

    # --- Verificações --------------------------------------------------------------
    poll_seconds: int = 60
    http_timeout: float = 10
    slow_ms: int = 3000  # acima disto um serviço que responde fica "lento" (aviso)
    verify_tls: bool = True
    ca_bundle: str = ""  # CA interna, se os serviços usarem certificados internos

    # --- Versões mais recentes --------------------------------------------------------
    versions_hours: float = 12
    github_token: SecretStr = SecretStr("")  # opcional: evita o limite de 60 pedidos/h

    # --- Alertas ------------------------------------------------------------------------
    # POST JSON {"text": ...} (Teams/Slack/Mattermost aceitam). Vazio = sem alertas.
    webhook_url: SecretStr = SecretStr("")
    # fail = só quando um serviço cai/recupera; warn = também avisos
    webhook_level: str = "fail"

    def verify(self) -> bool | str:
        if not self.verify_tls:
            return False
        return self.ca_bundle or True

    def resolved_secret_key(self) -> str:
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
