"""Autenticação, CSRF e cabeçalhos de segurança da interface web."""

from __future__ import annotations

import hmac
import logging
import secrets
import threading
import time
from collections import deque
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from socportal.config import Settings

CSRF_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"

log = logging.getLogger(__name__)


def safe_equal(a: str, b: str) -> bool:
    """Comparação em tempo constante que aceita qualquer texto (o hmac recusa str com não-ASCII)."""
    return hmac.compare_digest(a.encode("utf-8", "surrogateescape"), b.encode("utf-8", "surrogateescape"))


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


async def verify_csrf(request: Request) -> None:
    """Exigido em todos os POST: campo do formulário ou cabeçalho (HTMX)."""
    expected = request.session.get("csrf")
    supplied = request.headers.get(CSRF_HEADER)
    if not supplied:
        form = await request.form()
        value = form.get(CSRF_FIELD)
        supplied = value if isinstance(value, str) else None
    if not expected or not supplied or not safe_equal(expected, supplied):
        raise HTTPException(status_code=403, detail="Pedido inválido (CSRF). Recarrega a página.")


class LoginRequired(Exception):
    def __init__(self, next_url: str) -> None:
        self.next_url = next_url


async def require_user(request: Request) -> str:
    user = request.session.get("user")
    expires = request.session.get("expires", 0)
    if not user or time.time() > expires:
        request.session.pop("user", None)
        raise LoginRequired(request.url.path)
    return str(user)


def login_redirect(request: Request, next_url: str) -> Response:
    target = f"/login?next={quote(next_url)}" if next_url not in ("/", "") else "/login"
    if request.headers.get("hx-request"):
        return Response(status_code=401, headers={"HX-Redirect": target})
    return RedirectResponse(target, status_code=303)


def check_credentials(settings: Settings, username: str, password: str) -> bool:
    expected = settings.admin_password.get_secret_value()
    if not expected:
        return False
    user_ok = safe_equal(username, settings.admin_user)
    pass_ok = safe_equal(password, expected)
    return user_ok and pass_ok


def safe_next(value: str | None) -> str:
    """Só caminhos locais (evita open redirect)."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    return value


class ProxyCheck:
    """Avisa (uma vez) quando o pedido chega por um proxy em que a aplicação não confia.

    Sem isso, todos os pedidos parecem vir do IP do proxy: o limite de tentativas de login passa a
    ser partilhado por toda a gente e os logs perdem o IP real.
    """

    def __init__(self, variable: str) -> None:
        self.variable = variable
        self.warned = False

    def __call__(self, request: Request) -> None:
        if self.warned:
            return
        forwarded = request.headers.get("x-forwarded-for", "")
        client = request.client.host if request.client else ""
        if forwarded and client and client not in [x.strip() for x in forwarded.split(",")]:
            self.warned = True
            log.warning(
                "pedido com X-Forwarded-For vindo de %s, que não é um proxy de confiança: define %s=%s "
                "(senão o limite de tentativas de login é partilhado por todos os utilizadores)",
                client,
                self.variable,
                client,
            )


class LoginThrottle:
    """Bloqueio simples por IP: N falhas numa janela de tempo."""

    def __init__(self, max_failures: int = 8, window_s: int = 900) -> None:
        self.max_failures = max_failures
        self.window_s = window_s
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._failures.setdefault(key, deque())
        while q and now - q[0] > self.window_s:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self.max_failures

    def fail(self, key: str) -> None:
        with self._lock:
            self._prune(key, time.monotonic()).append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class SecurityHeaders(BaseHTTPMiddleware):
    CSP = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", self.CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "public, max-age=3600")
        else:
            response.headers.setdefault("Cache-Control", "no-store")
        return response
