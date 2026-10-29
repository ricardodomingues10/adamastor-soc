"""Cliente DefectDojo (API v2): reimport com criação automática de contexto.

Modelo no DefectDojo:
    Product type = ambiente do host
    Product      = nome canónico do host (igual para WPScan e Greenbone)
    Engagement   = VF_DD_ENGAGEMENT (um por product)
    Test         = um por fonte ("WPScan", "Greenbone")

Um test por fonte é o que torna seguro o close_old_findings: o reimport diário do
WPScan só fecha findings do test WPScan, nunca os do Greenbone (mensal).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import date
from typing import Any

import requests

from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError


@dataclass
class ImportResult:
    test_id: int | None
    statistics: dict[str, Any]
    raw: dict[str, Any]

    def delta(self) -> dict[str, int]:
        """created/closed/reactivated/untouched, quando o DD devolve estatísticas."""
        delta = (self.statistics or {}).get("delta") or {}
        out: dict[str, int] = {}
        for key in ("created", "closed", "reactivated", "untouched"):
            value = delta.get(key)
            if isinstance(value, dict):
                value = value.get("total")
            if isinstance(value, int):
                out[key] = value
        return out


class DefectDojo:
    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        if not settings.dd_configured:
            raise VFError(ErrorKind.CONFIG, "DefectDojo por configurar (VF_DD_URL / VF_DD_TOKEN)")
        self.settings = settings
        self.base = settings.dd_url + "/api/v2"
        self.session = session or requests.Session()
        self.session.headers["Authorization"] = f"Token {settings.dd_token.get_secret_value()}"
        self.session.headers["Accept"] = "application/json"
        self.session.verify = settings.dd_verify()

    # ---------------------------------------------------------------- saúde
    def ping(self) -> dict[str, Any]:
        started = time.monotonic()
        try:
            resp = self.session.get(f"{self.base}/products/", params={"limit": 1}, timeout=15)
        except requests.exceptions.SSLError as exc:
            raise VFError(ErrorKind.CONFIG, "erro TLS ao ligar ao DefectDojo (CA? VF_DD_CA_BUNDLE)") from exc
        except requests.RequestException as exc:
            raise VFError(ErrorKind.DEPENDENCY, f"DefectDojo inacessível: {exc.__class__.__name__}") from exc
        if resp.status_code in (401, 403):
            raise VFError(ErrorKind.CONFIG, f"token DefectDojo rejeitado ({resp.status_code})")
        if resp.status_code != 200:
            raise VFError(ErrorKind.DEPENDENCY, f"DefectDojo respondeu {resp.status_code}")
        return {"latency_ms": round((time.monotonic() - started) * 1000), "products": resp.json().get("count")}

    # ---------------------------------------------------------------- reimport
    def reimport(
        self,
        *,
        content: bytes,
        filename: str,
        scan_type: str,
        test_title: str,
        product_name: str,
        product_type_name: str,
        close_old_findings: bool,
        scan_date: date | None = None,
    ) -> ImportResult:
        data = {
            "scan_type": scan_type,
            "test_title": test_title,
            "product_name": product_name,
            "product_type_name": product_type_name,
            "engagement_name": self.settings.dd_engagement,
            "auto_create_context": "true",
            "minimum_severity": "Info",
            "active": "true",
            "verified": "false",
            "close_old_findings": "true" if close_old_findings else "false",
            # Fechar só dentro deste test: nunca tocar nos findings da outra fonte
            "close_old_findings_product_scope": "false",
            # Um finding que volta a aparecer tem de ser reaberto (lição do do_not_reactivate)
            "do_not_reactivate": "false",
            "deduplication_on_engagement": "true",
        }
        if scan_date:
            data["scan_date"] = scan_date.isoformat()

        attempts = max(1, self.settings.dd_import_retries)
        last_error: VFError | None = None
        for attempt in range(1, attempts + 1):
            try:
                return self._post_reimport(data, content, filename)
            except VFError as exc:
                last_error = exc
                if not exc.kind.retryable or attempt == attempts:
                    raise
                time.sleep(min(60, 5 * 2 ** (attempt - 1)))
        raise last_error or VFError(ErrorKind.TRANSIENT, "reimport falhou")

    def _post_reimport(self, data: dict[str, str], content: bytes, filename: str) -> ImportResult:
        try:
            resp = self.session.post(
                f"{self.base}/reimport-scan/",
                data=data,
                files={"file": (filename, content)},
                timeout=self.settings.dd_timeout,
            )
        except requests.Timeout as exc:
            raise VFError(ErrorKind.TRANSIENT, f"reimport sem resposta em {self.settings.dd_timeout}s") from exc
        except requests.exceptions.SSLError as exc:
            raise VFError(ErrorKind.CONFIG, "erro TLS ao ligar ao DefectDojo") from exc
        except requests.RequestException as exc:
            raise VFError(ErrorKind.DEPENDENCY, f"DefectDojo inacessível: {exc.__class__.__name__}") from exc

        body_text = resp.text[:3000]
        if resp.status_code in (401, 403):
            raise VFError(ErrorKind.CONFIG, f"DefectDojo recusou o token ({resp.status_code})", detail=body_text)
        if resp.status_code == 400:
            raise VFError(ErrorKind.DATA, "DefectDojo rejeitou o ficheiro (400)", detail=body_text)
        if resp.status_code in (502, 503, 504) or resp.status_code == 429:
            raise VFError(ErrorKind.TRANSIENT, f"DefectDojo respondeu {resp.status_code}", detail=body_text)
        if resp.status_code >= 500:
            # 500 no parser costuma ser do conteúdo, não da disponibilidade
            raise VFError(
                ErrorKind.DATA, f"DefectDojo respondeu {resp.status_code} (erro do parser?)", detail=body_text
            )
        if resp.status_code not in (200, 201):
            raise VFError(ErrorKind.DEPENDENCY, f"DefectDojo respondeu {resp.status_code}", detail=body_text)
        try:
            payload = resp.json()
        except ValueError as exc:
            raise VFError(ErrorKind.DATA, "resposta do DefectDojo não é JSON", detail=body_text) from exc
        return ImportResult(
            test_id=payload.get("test_id") or payload.get("test"),
            statistics=payload.get("statistics") or {},
            raw=payload,
        )
