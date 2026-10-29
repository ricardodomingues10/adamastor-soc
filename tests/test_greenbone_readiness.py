"""Testes do gate de prontidão e do cliente gb-ctl.

As respostas GMP passam pelo EtreeCheckCommandTransform real do python-gvm, por isso
os erros (status 4xx/5xx) são levantados exatamente como em produção.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from gvm.transforms import EtreeCheckCommandTransform

from vulnflux.greenbone.lifecycle import LifecycleError, parse_gbctl_output
from vulnflux.greenbone.readiness import (
    FULL_AND_FAST_CONFIG,
    ReadinessConfig,
    Status,
    evaluate,
    parse_feed_timestamp,
    probe,
    wait_until_ready,
)

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
CFG = ReadinessConfig(socket_path="/nope", username="orch", password="x")
_transform = EtreeCheckCommandTransform()


def T(xml: str):
    # python-gvm 27 entrega as respostas como bytes ao transform
    return _transform(xml.encode())


def feed(ftype: str, version: str = "202610290400", extra: str = "") -> str:
    return f"<feed><type>{ftype}</type><name>Community</name><version>{version}</version>{extra}</feed>"


def feeds_xml(*feeds: str, owner: str = "1") -> str:
    return f'<get_feeds_response status="200" status_text="OK"><feed_owner_set>{owner}</feed_owner_set>{"".join(feeds)}</get_feeds_response>'


ALL_FEEDS_OK = feeds_xml(feed("NVT"), feed("SCAP"), feed("CERT"), feed("GVMD_DATA"))
CONFIG_OK = (
    f'<get_configs_response status="200" status_text="OK"><config id="{FULL_AND_FAST_CONFIG}"><name>Full and fast</name>'
    "<nvt_count>98765<growing>1</growing></nvt_count></config></get_configs_response>"
)
CONFIG_404 = '<get_configs_response status="404" status_text="Failed to find config"/>'
SCANNER_OK = (
    '<verify_scanner_response status="200" status_text="OK"><version>OSP 22.4</version></verify_scanner_response>'
)
SCANNER_FAIL = '<verify_scanner_response status="503" status_text="Service temporarily down"/>'
VERSION = '<get_version_response status="200" status_text="OK"><version>22.6</version></get_version_response>'
AUTH_FAIL = '<authenticate_response status="400" status_text="Authentication failed"/>'
AUTH_OK = '<authenticate_response status="200" status_text="OK"><role>Admin</role></authenticate_response>'


class FakeGmp:
    def __init__(self, feeds=ALL_FEEDS_OK, config=CONFIG_OK, scanner=SCANNER_OK, auth=AUTH_OK):
        self.r = {"feeds": feeds, "config": config, "scanner": scanner, "auth": auth}

    def authenticate(self, u, p):
        return T(self.r["auth"])

    def get_version(self):
        return T(VERSION)

    def get_feeds(self):
        return T(self.r["feeds"])

    def get_scan_config(self, config_id):
        return T(self.r["config"])

    def verify_scanner(self, scanner_id):
        return T(self.r["scanner"])


def factory(gmp):
    @contextmanager
    def _f(cfg):
        yield gmp

    return _f


# --- evaluate -----------------------------------------------------------------


def test_tudo_ok_fica_ready():
    r = evaluate(FakeGmp(), CFG, NOW)
    assert r.status is Status.READY, r.summary()
    assert r.gmp_version == "22.6"
    assert r.feed_versions["NVT"] == "202610290400"
    assert not r.warnings


def test_feed_a_sincronizar_bloqueia_sem_ser_permanente():
    feeds = feeds_xml(
        feed("NVT", extra="<currently_syncing><timestamp>x</timestamp></currently_syncing>"),
        feed("SCAP"),
        feed("CERT"),
        feed("GVMD_DATA"),
    )
    # Enquanto sincroniza, a config pode não existir: não é falha permanente.
    r = evaluate(FakeGmp(feeds=feeds, config=CONFIG_404), CFG, NOW)
    assert r.status is Status.NOT_READY
    assert any(c.name == "feed:NVT" and "sincronizar" in c.detail for c in r.checks)


def test_vts_ainda_a_carregar_bloqueia():
    low = CONFIG_OK.replace("98765", "312")
    r = evaluate(FakeGmp(config=low), CFG, NOW)
    assert r.status is Status.NOT_READY
    assert "312 NVTs" in r.summary()


def test_config_inexistente_com_feeds_estaveis_e_permanente():
    r = evaluate(FakeGmp(config=CONFIG_404), CFG, NOW)
    assert r.status is Status.FAILED


def test_feed_owner_por_definir_e_permanente():
    r = evaluate(FakeGmp(feeds=ALL_FEEDS_OK.replace("<feed_owner_set>1", "<feed_owner_set>0")), CFG, NOW)
    assert r.status is Status.FAILED
    assert "feed import owner" in r.summary()


def test_scanner_em_baixo_bloqueia():
    r = evaluate(FakeGmp(scanner=SCANNER_FAIL), CFG, NOW)
    assert r.status is Status.NOT_READY
    assert any(c.name == "scanner" and not c.ok for c in r.checks)


def test_feed_velho_e_aviso_por_omissao_e_bloqueio_se_configurado():
    old = feeds_xml(feed("NVT", "202609010000"), feed("SCAP"), feed("CERT"), feed("GVMD_DATA"))
    r = evaluate(FakeGmp(feeds=old), CFG, NOW)
    assert r.status is Status.READY and any("NVT" in w for w in r.warnings)

    strict = ReadinessConfig(socket_path="/nope", username="o", password="x", block_on_stale_feed=True)
    r = evaluate(FakeGmp(feeds=old), strict, NOW)
    assert r.status is Status.NOT_READY


def test_feed_em_falta_bloqueia():
    r = evaluate(FakeGmp(feeds=feeds_xml(feed("NVT"), feed("SCAP"), feed("CERT"))), CFG, NOW)
    assert r.status is Status.NOT_READY
    assert any(c.name == "feed:GVMD_DATA" for c in r.checks)


def test_parse_feed_timestamp():
    assert parse_feed_timestamp("202610290512") == datetime(2026, 10, 29, 5, 12, tzinfo=UTC)
    assert parse_feed_timestamp("20261029") == datetime(2026, 10, 29, tzinfo=UTC)
    assert parse_feed_timestamp("abc") is None


# --- probe ----------------------------------------------------------------------


def test_probe_auth_falhada_e_permanente():
    r = probe(CFG, NOW, gmp_factory=factory(FakeGmp(auth=AUTH_FAIL)))
    assert r.status is Status.FAILED and r.checks[0].name == "auth"


def test_probe_socket_inexistente_e_not_ready():
    # Ligação real ao socket que não existe: exercita UnixSocketConnection + Gmp.
    r = probe(CFG, NOW)
    assert r.status is Status.NOT_READY and r.checks[0].name == "gvmd"


# --- wait_until_ready -----------------------------------------------------------


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _seq(*statuses):
    from vulnflux.greenbone.readiness import Check, Readiness

    it = iter(statuses)

    def _probe(cfg):
        st, name = next(it)
        return Readiness(st, [] if st is Status.READY else [Check(name, False, "x", permanent=st is Status.FAILED)])

    return _probe


def test_wait_espera_ate_ready():
    c = Clock()
    r = wait_until_ready(
        CFG,
        3600,
        60,
        probe_fn=_seq((Status.NOT_READY, "gvmd"), (Status.NOT_READY, "feed:NVT"), (Status.READY, "")),
        sleep=c.sleep,
        clock=c,
    )
    assert r.ready and c.t == 120


def test_wait_ignora_failed_durante_a_janela_de_graca():
    c = Clock()
    r = wait_until_ready(
        CFG,
        3600,
        300,
        probe_fn=_seq((Status.FAILED, "scan_config"), (Status.READY, "")),
        sleep=c.sleep,
        clock=c,
        failed_grace_s=900,
    )
    assert r.ready


def test_wait_failed_depois_da_graca_termina():
    c = Clock()
    seq = [(Status.FAILED, "scan_config")] * 10
    r = wait_until_ready(CFG, 7200, 300, probe_fn=_seq(*seq), sleep=c.sleep, clock=c, failed_grace_s=900)
    assert r.status is Status.FAILED and c.t == 900


def test_wait_auth_termina_logo():
    c = Clock()
    r = wait_until_ready(CFG, 3600, 60, probe_fn=_seq((Status.FAILED, "auth")), sleep=c.sleep, clock=c)
    assert r.status is Status.FAILED and c.t == 0


def test_wait_timeout_devolve_not_ready():
    c = Clock()
    r = wait_until_ready(CFG, 300, 60, probe_fn=_seq(*[(Status.NOT_READY, "gvmd")] * 20), sleep=c.sleep, clock=c)
    assert r.status is Status.NOT_READY and any(x.name == "timeout" for x in r.checks)


# --- gb-ctl -----------------------------------------------------------------------

OK_LINE = (
    '{"action":"start","ok":true,"message":"stack arrancada","ts":"t","data":'
    '[{"service":"gvmd","state":"running","health":"","exit_code":0,"image":"gvmd:stable"}]}'
)


def test_gbctl_ok():
    r = parse_gbctl_output("start", 0, OK_LINE + "\n")
    assert r.running() == {"gvmd"}


def test_gbctl_verbo_invalido_nao_e_transitorio():
    with pytest.raises(LifecycleError) as e:
        parse_gbctl_output("start", 2, '{"action":"invalid","ok":false,"message":"verbo inválido","data":null}')
    assert e.value.transient is False


def test_gbctl_lock_e_transitorio():
    with pytest.raises(LifecycleError) as e:
        parse_gbctl_output(
            "start", 1, '{"action":"start","ok":false,"message":"outra operação gb-ctl em curso","data":null}'
        )
    assert e.value.transient is True


def test_gbctl_saida_vazia():
    with pytest.raises(LifecycleError):
        parse_gbctl_output("status", 0, "")


def test_probe_auth_5xx_nao_e_permanente():
    # gvmd a arrancar pode responder 503 ao authenticate: esperar, não falhar.
    r = probe(
        CFG,
        NOW,
        gmp_factory=factory(FakeGmp(auth='<authenticate_response status="503" status_text="Service unavailable"/>')),
    )
    assert r.status is Status.NOT_READY
