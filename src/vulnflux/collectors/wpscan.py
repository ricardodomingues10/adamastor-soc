"""Coletor WPScan: executa a CLI, valida o resultado e consulta a quota da API.

Compatível com o WPScan 3.8 e 4.x (validado contra o código do 4.2.0):
  - o token vai na variável WPSCAN_API_TOKEN do processo (nunca na linha de comandos);
  - a BD de metadados vive em ~/.wpscan/db (legado) ou ~/.cache/wpscan/db (4.x);
  - quando a API devolve 429 (quota), o WPScan engole o erro e o scan parece limpo:
    a validação apanha esse caso pelo bloco vuln_api.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError

# Códigos de saída do WPScan (CMSScanner::ExitCode + WPScan::ExitCode::VULNERABLE)
EXIT_OK = 0
EXIT_CLI_OPTION_ERROR = 1
EXIT_INTERRUPTED = 2
EXIT_EXCEPTION = 3
EXIT_ERROR = 4
EXIT_VULNERABLE = 5
COMPLETE_EXIT_CODES = {EXIT_OK, EXIT_VULNERABLE}

STATUS_URL = "https://wpscan.com/api/v4/status"
NO_TOKEN_MARKER = "no wpscan api token given"  # noqa: S105 - texto da mensagem do WPScan


@dataclass
class ScanOutput:
    exit_code: int
    raw: dict[str, Any] | None
    stderr: str


def wpscan_home(settings: Settings) -> Path:
    """HOME privado do WPScan (BD de metadados e cache), dentro do data_dir persistente."""
    home = settings.data_dir / "wpscan-home"
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    return home


def db_dirs(settings: Settings) -> list[Path]:
    home = wpscan_home(settings)
    return [home / ".wpscan" / "db", home / ".cache" / "wpscan" / "db"]


def _env(settings: Settings, token: str | None = None) -> dict[str, str]:
    # Nada de VF_* (segredos do VulnFlux) no ambiente do scanner; só a chave escolhida.
    # As variáveis de proxy (HTTP_PROXY, https_proxy, NO_PROXY...) passam.
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VF_", "DD_", "GB_")) and k != "WPSCAN_API_TOKEN"}
    home = wpscan_home(settings)
    env["HOME"] = str(home)
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    if token:
        env["WPSCAN_API_TOKEN"] = token
    return env


def ensure_cli() -> str:
    path = shutil.which("wpscan")
    if not path:
        raise VFError(ErrorKind.CONFIG, "CLI do WPScan não encontrada no PATH")
    return path


def update_database(settings: Settings, timeout: int = 600) -> str:
    """Atualiza a BD de metadados uma vez por lote (os scans correm com --no-update)."""
    ensure_cli()
    try:
        proc = subprocess.run(
            ["wpscan", "--update", "--no-banner"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env(settings),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VFError(ErrorKind.TRANSIENT, f"atualização da BD do WPScan sem resposta em {timeout}s") from exc
    if proc.returncode != 0:
        raise VFError(
            ErrorKind.DEPENDENCY, "falha a atualizar a BD do WPScan", detail=(proc.stderr or proc.stdout)[-2000:]
        )
    return (proc.stdout or "").strip()[-500:]


def ensure_database(settings: Settings, max_age_hours: float = 24) -> str:
    """Atualiza a BD de metadados se não existir ou tiver mais de `max_age_hours`."""
    for db in db_dirs(settings):
        for marker in (db / ".last_update", db / "metadata.json"):
            if marker.exists() and (time.time() - marker.stat().st_mtime) < max_age_hours * 3600:
                return "BD de metadados atual"
    update_database(settings)
    return "BD de metadados atualizada"


def enumerate_option(settings: Settings) -> str:
    """Valor do -e. Sem utilizadores incluídos, nem os enumeramos (poupa pedidos)."""
    items = [i.strip() for i in settings.wpscan_enumerate.split(",") if i.strip()]
    if not settings.wpscan_include_users:
        items = [i for i in items if not i.startswith("u")]
    return ",".join(items)


def build_command(url: str, output: Path, settings: Settings) -> list[str]:
    cmd = [
        "wpscan",
        "--url",
        url,
        "--format",
        "json",
        "--output",
        str(output),
        "--no-banner",
        "--no-update",
    ]
    enum = enumerate_option(settings)
    if enum:
        cmd += ["--enumerate", enum]
    if settings.wpscan_plugins_detection:
        if settings.wpscan_plugins_detection not in ("passive", "mixed", "aggressive"):
            raise VFError(ErrorKind.CONFIG, "VF_WPSCAN_PLUGINS_DETECTION tem de ser passive, mixed ou aggressive")
        cmd += ["--plugins-detection", settings.wpscan_plugins_detection]
    if settings.wpscan_disable_tls_checks:
        cmd.append("--disable-tls-checks")
    if settings.wpscan_extra_args.strip():
        extra = shlex.split(settings.wpscan_extra_args)
        forbidden = {
            "--url",
            "--format",
            "-f",
            "--output",
            "-o",
            "--api-token",
            "-e",
            "--enumerate",
            "--plugins-detection",  # usar VF_WPSCAN_ENUMERATE / _PLUGINS_DETECTION
        }
        clash = forbidden.intersection(extra)
        if clash:
            raise VFError(ErrorKind.CONFIG, f"VF_WPSCAN_EXTRA_ARGS não pode conter {sorted(clash)}")
        cmd.extend(extra)
    return cmd


def run_scan(url: str, output: Path, settings: Settings, token: str | None = None) -> ScanOutput:
    ensure_cli()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)  # nunca reaproveitar um resultado antigo
    try:
        proc = subprocess.run(
            build_command(url, output, settings),
            capture_output=True,
            text=True,
            timeout=settings.wpscan_timeout,
            env=_env(settings, token),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VFError(ErrorKind.TRANSIENT, f"WPScan excedeu {settings.wpscan_timeout}s") from exc

    raw: dict[str, Any] | None = None
    if output.exists() and output.stat().st_size > 0:
        try:
            raw = json.loads(output.read_text("utf-8"))
        except json.JSONDecodeError:
            raw = None
    return ScanOutput(exit_code=proc.returncode, raw=raw, stderr=(proc.stderr or "")[-4000:])


def validate(scan: ScanOutput, *, token_configured: bool) -> dict[str, Any]:
    """Gates do resultado. Devolve o JSON validado ou levanta VFError."""
    raw = scan.raw
    if raw is None:
        kind = ErrorKind.TRANSIENT if scan.exit_code in (EXIT_INTERRUPTED, EXIT_EXCEPTION) else ErrorKind.DATA
        raise VFError(kind, f"WPScan não produziu JSON válido (exit {scan.exit_code})", detail=scan.stderr)

    aborted = raw.get("scan_aborted")
    if aborted:
        text = str(aborted)
        lowered = text.lower()
        if "not seem to be running wordpress" in lowered or "seems to be down" in lowered:
            raise VFError(ErrorKind.PERMANENT, f"scan abortado: {text}")
        if "redirect" in lowered:
            raise VFError(ErrorKind.PERMANENT, f"scan abortado (redirecionamento): {text}")
        raise VFError(ErrorKind.DATA, f"scan abortado: {text}")

    if scan.exit_code not in COMPLETE_EXIT_CODES:
        raise VFError(ErrorKind.DATA, f"WPScan terminou com exit {scan.exit_code}", detail=scan.stderr)

    if not raw.get("target_url"):
        raise VFError(ErrorKind.DATA, "JSON sem target_url")

    if token_configured:
        # Sem dados da API, o scan parece limpo mas não tem vulnerabilidades:
        # importar fecharia findings reais. Qualquer sinal de problema bloqueia o import.
        api = raw.get("vuln_api")
        if not isinstance(api, dict):
            raise VFError(ErrorKind.DATA, "JSON sem vuln_api: dados de vulnerabilidades em falta")
        if api.get("http_error"):
            raise VFError(ErrorKind.DEPENDENCY, f"API do WPScan com erro HTTP: {api['http_error']}")
        if api.get("parse_error"):
            raise VFError(ErrorKind.DEPENDENCY, "API do WPScan devolveu uma resposta inválida")
        if api.get("error"):
            error = str(api["error"])
            lowered = error.lower()
            if NO_TOKEN_MARKER in lowered:
                # O token foi passado: a API não respondeu ao status (o WPScan trata 429 como vazio)
                raise VFError(
                    ErrorKind.QUOTA, "API do WPScan sem resposta com token definido (quota esgotada? HTTP 429)"
                )
            kind = ErrorKind.QUOTA if "limit" in lowered or "quota" in lowered else ErrorKind.DEPENDENCY
            raise VFError(kind, f"API do WPScan: {error.splitlines()[0]}")
        remaining = quota_from_raw(raw)
        if remaining is not None and remaining <= 0:
            # Os pedidos depois de esgotar a quota devolvem vazio: dados possivelmente incompletos.
            raise VFError(ErrorKind.QUOTA, "quota do WPScan esgotou durante o scan: dados possivelmente incompletos")
    return raw


def quota_from_raw(raw: dict[str, Any]) -> int | None:
    api = raw.get("vuln_api")
    if isinstance(api, dict) and api.get("requests_remaining") is not None:
        try:
            value = int(api["requests_remaining"])
        except (TypeError, ValueError):
            return None  # "Unlimited"
        return None if value < 0 else value
    return None


def api_status(token: str, timeout: int = 15) -> dict[str, Any]:
    """Consulta o estado de uma chave na API (não gasta quota)."""
    if not token:
        raise VFError(ErrorKind.CONFIG, "chave WPScan vazia")
    try:
        resp = requests.get(STATUS_URL, headers={"Authorization": f"Token token={token}"}, timeout=timeout)
    except requests.RequestException as exc:
        raise VFError(ErrorKind.DEPENDENCY, f"API do WPScan inacessível: {exc.__class__.__name__}") from exc
    if resp.status_code in (401, 403):
        raise VFError(ErrorKind.CONFIG, "chave WPScan inválida")
    if resp.status_code == 429:
        raise VFError(ErrorKind.QUOTA, "chave WPScan sem quota (HTTP 429)")
    if resp.status_code >= 500:
        raise VFError(ErrorKind.DEPENDENCY, f"API do WPScan respondeu {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise VFError(ErrorKind.DEPENDENCY, "API do WPScan devolveu uma resposta inválida") from exc
    if resp.status_code != 200:
        raise VFError(ErrorKind.DEPENDENCY, f"API do WPScan respondeu {resp.status_code}: {data}")
    remaining = data.get("requests_remaining")
    return {
        "plan": data.get("plan"),
        "requests_remaining": "Unlimited" if remaining == -1 else remaining,
        "requests_limit": data.get("requests_limit"),
        "requests_reset": data.get("requests_reset"),
    }


def cli_version(settings: Settings) -> str:
    ensure_cli()
    proc = subprocess.run(
        ["wpscan", "--version", "--no-banner"],
        capture_output=True,
        text=True,
        timeout=60,
        env=_env(settings),
        check=False,
    )
    out = (proc.stdout or proc.stderr or "").strip()
    for line in out.splitlines():
        if "version" in line.lower():
            return line.strip()
    return out.splitlines()[0] if out else "desconhecida"
