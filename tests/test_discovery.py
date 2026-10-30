from __future__ import annotations

import pytest
import requests

from vulnflux.errors import ErrorKind, VFError
from vulnflux.greenbone import discovery


class Resp:
    def __init__(self, code, body):
        self.status_code, self._body = code, body

    def json(self):
        if self._body is None:
            raise ValueError("sem json")
        return self._body


class Sess:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def post(self, url, **kw):
        self.calls.append((url, kw))
        if self.exc:
            raise self.exc
        return self.resp


def s_with(settings, **kw):
    return settings.model_copy(update={"greenbone_discovery_url": "http://sonda:8000/", **kw})


def test_descoberta_devolve_portas_e_port_list(settings):
    sess = Sess(Resp(200, {"tcp": [6667, 21, 22, 21], "hosts_up": 1, "seconds": 41.2, "nmap": "Nmap 7.95"}))
    d = discovery.discover(s_with(settings), "alvo", session=sess)
    assert d.tcp == [21, 22, 6667] and d.seconds == 41.2
    assert sess.calls[0][0] == "http://sonda:8000/scan" and sess.calls[0][1]["json"] == {"target": "alvo"}
    assert d.port_spec("53, 161,x") == "T:21,22,6667,U:53,161"
    assert discovery.Discovery("a").port_spec("") == ""


@pytest.mark.parametrize(
    ("sess", "kind"),
    [
        (Sess(exc=requests.ConnectionError("recusado")), ErrorKind.DEPENDENCY),
        (Sess(Resp(401, {"error": "token"})), ErrorKind.CONFIG),
        (Sess(Resp(502, {"error": "nmap falhou"})), ErrorKind.DEPENDENCY),
        (Sess(Resp(500, None)), ErrorKind.DEPENDENCY),
    ],
)
def test_descoberta_erros(settings, sess, kind):
    with pytest.raises(VFError) as exc:
        discovery.discover(s_with(settings), "alvo", session=sess)
    assert exc.value.kind is kind


def test_descoberta_ligada_so_com_url(settings):
    assert not discovery.enabled(settings)
    assert discovery.enabled(s_with(settings))
