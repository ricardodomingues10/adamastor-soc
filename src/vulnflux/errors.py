"""Classificação de erros.

Cada falha tem um tipo, porque o tratamento depende dele: um timeout repete-se, uma
dependência em baixo bloqueia o lote sem falhar host a host, dados inválidos nunca
chegam ao DefectDojo, e uma quota esgotada adia para o dia seguinte.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorKind(StrEnum):
    TRANSIENT = "transient"  # timeout, 5xx, lock: repetir
    DEPENDENCY = "dependency"  # DefectDojo / gvmd / WPScan API em baixo
    DATA = "data"  # resultado vazio, scan interrompido, JSON inválido
    QUOTA = "quota"  # token WPScan esgotado
    PERMANENT = "permanent"  # site inexistente, credenciais erradas
    CONFIG = "config"  # falta configuração (token, URL...)

    @property
    def label(self) -> str:
        return ERROR_LABELS[self]

    @property
    def retryable(self) -> bool:
        return self in (ErrorKind.TRANSIENT, ErrorKind.DEPENDENCY)


ERROR_LABELS: dict[ErrorKind, str] = {
    ErrorKind.TRANSIENT: "Transitório",
    ErrorKind.DEPENDENCY: "Dependência em baixo",
    ErrorKind.DATA: "Dados inválidos",
    ErrorKind.QUOTA: "Quota esgotada",
    ErrorKind.PERMANENT: "Permanente",
    ErrorKind.CONFIG: "Configuração",
}


class VFError(Exception):
    """Erro com tipo. `detail` vai para o registo da execução, nunca segredos."""

    def __init__(self, kind: ErrorKind, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.detail = detail

    def __str__(self) -> str:
        return f"[{self.kind.value}] {self.message}"
