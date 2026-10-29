"""Rotação de chaves da API do WPScan.

Cada chave tem a sua quota diária. O pool:
  - consulta o estado de todas as chaves no início de cada lote (o endpoint de status
    não gasta quota);
  - escolhe para cada scan a chave com mais pedidos restantes, o que distribui o
    consumo e deixa margem em todas;
  - atualiza a quota da chave com o valor que o próprio scan devolve;
  - quando uma chave esgota a meio de um scan, marca-a e o scan é repetido com a
    próxima (o resultado parcial nunca é importado).

As chaves nunca são gravadas: o estado guarda só uma impressão digital (SHA-256
truncado) e os últimos 4 caracteres, para as identificar na interface.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from vulnflux.collectors import wpscan
from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError
from vulnflux.models import utcnow
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)

STATE_KEY = "wpscan_tokens"
UNLIMITED = 10**9


def fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def label(token: str) -> str:
    return f"…{token[-4:]}" if len(token) >= 8 else "…"


@dataclass
class TokenState:
    fp: str
    label: str
    plan: str | None = None
    remaining: int | None = None  # None = desconhecido; UNLIMITED = sem limite
    limit: int | None = None
    reset: Any = None
    status: str = "unknown"  # ok | low | exhausted | invalid | error | unknown
    message: str = ""
    checked_at: str | None = None
    scans: int = 0

    @property
    def unlimited(self) -> bool:
        return self.remaining is not None and self.remaining >= UNLIMITED


class TokenPool:
    def __init__(
        self,
        settings: Settings,
        store: JsonStore,
        status_fn: Callable[[str], dict[str, Any]] = wpscan.api_status,
    ) -> None:
        self.settings = settings
        self.store = store
        self.status_fn = status_fn
        self.tokens: dict[str, str] = {fingerprint(t): t for t in settings.wpscan_tokens()}
        saved = store.get_state(STATE_KEY, {}) or {}
        self.states: dict[str, TokenState] = {}
        for fp, token in self.tokens.items():
            data = saved.get(fp)
            self.states[fp] = TokenState(**data) if data else TokenState(fp=fp, label=label(token))

    # ------------------------------------------------------------------ estado
    def _save(self) -> None:
        # Só as chaves configuradas: as removidas do .env desaparecem da interface.
        self.store.set_state(STATE_KEY, {fp: asdict(st) for fp, st in self.states.items()})

    def _classify(self, st: TokenState) -> None:
        if st.status in ("invalid", "error"):
            return
        if st.remaining is None:
            st.status = "unknown"
        elif st.remaining <= 0:
            st.status = "exhausted"
        elif st.remaining < self.settings.wpscan_min_quota:
            st.status = "low"
        else:
            st.status = "ok"

    def __len__(self) -> int:
        return len(self.tokens)

    def summary(self) -> list[TokenState]:
        return list(self.states.values())

    def total_remaining(self) -> int | None:
        known = [s.remaining for s in self.states.values() if s.remaining is not None and s.status != "invalid"]
        if not known:
            return None
        return min(sum(known), UNLIMITED)

    # ------------------------------------------------------------------ consulta
    def refresh(self) -> list[TokenState]:
        """Consulta todas as chaves. Uma chave com erro não impede as outras."""
        for fp, token in self.tokens.items():
            st = self.states[fp]
            st.checked_at = utcnow().isoformat()
            try:
                info = self.status_fn(token)
            except VFError as exc:
                if exc.kind is ErrorKind.CONFIG:
                    st.status, st.remaining = "invalid", None
                elif exc.kind is ErrorKind.QUOTA:
                    st.status, st.remaining = "exhausted", 0
                else:
                    st.status = "error"
                st.message = exc.message
                continue
            raw_remaining = info.get("requests_remaining")
            if raw_remaining == "Unlimited" or raw_remaining == -1:
                st.remaining = UNLIMITED
            else:
                try:
                    st.remaining = int(raw_remaining)
                except (TypeError, ValueError):
                    st.remaining = None
            st.plan = info.get("plan")
            st.limit = info.get("requests_limit")
            st.reset = info.get("requests_reset")
            st.status, st.message = "", ""
            self._classify(st)
        self._save()
        return self.summary()

    # ------------------------------------------------------------------ escolha
    def choose(self, exclude: set[str] | None = None) -> tuple[str, str] | None:
        """(fingerprint, chave) com mais pedidos restantes, ou None se nenhuma servir.

        Chaves com quota desconhecida (status falhou por rede) ficam para o fim: são
        tentadas, e o próprio scan diz se havia quota.
        """
        exclude = exclude or set()
        candidates = []
        for fp, st in self.states.items():
            if fp in exclude or st.status in ("invalid", "exhausted", "low"):
                continue
            score = st.remaining if st.remaining is not None else -1
            candidates.append((score, -st.scans, fp))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        fp = candidates[0][2]
        return fp, self.tokens[fp]

    def usable(self) -> bool:
        return self.choose() is not None

    def all_unreachable(self) -> bool:
        return bool(self.states) and all(s.status == "error" for s in self.states.values())

    # ------------------------------------------------------------------ resultados
    def record(self, fp: str, remaining: int | None) -> None:
        st = self.states[fp]
        st.scans += 1
        if remaining is not None:
            st.remaining = remaining
        elif st.remaining is not None and not st.unlimited:
            st.remaining = max(0, st.remaining - 1)
        st.checked_at = utcnow().isoformat()
        self._classify(st)
        self._save()

    def mark_exhausted(self, fp: str, reason: str) -> None:
        st = self.states[fp]
        st.remaining, st.status, st.message = 0, "exhausted", reason
        st.checked_at = utcnow().isoformat()
        self._save()
        log.info("chave WPScan %s marcada como esgotada: %s", st.label, reason)

    def label_of(self, fp: str) -> str:
        return self.states[fp].label
