from __future__ import annotations

import responses

from vulnflux.labtools import dd_token

URL = "http://dd-nginx:8080/api/v2/api-token-auth/"


@responses.activate
def test_espera_pelo_defectdojo_e_grava_token(tmp_path, monkeypatch):
    monkeypatch.setattr("vulnflux.labtools.time.sleep", lambda s: None)
    responses.post(URL, status=502)
    responses.post(URL, status=400, json={"non_field_errors": ["Unable to log in"]})
    responses.post(URL, json={"token": "abc123"})
    out = tmp_path / "secrets" / "vf_dd_token"
    assert dd_token("http://dd-nginx:8080", "admin", "pw", out, timeout_s=60, interval_s=0) == 0
    assert out.read_text() == "abc123"
    assert oct(out.stat().st_mode & 0o777) == "0o644"
    body = responses.calls[-1].request.body
    assert "username=admin" in (body.decode() if isinstance(body, bytes) else body)


@responses.activate
def test_desiste_ao_fim_do_tempo(tmp_path, monkeypatch):
    monkeypatch.setattr("vulnflux.labtools.time.sleep", lambda s: None)
    clock = iter(range(0, 1000, 10))
    monkeypatch.setattr("vulnflux.labtools.time.monotonic", lambda: next(clock))
    responses.post(URL, status=503)
    assert dd_token("http://dd-nginx:8080", "admin", "pw", tmp_path / "t", timeout_s=30, interval_s=0) == 1
    assert not (tmp_path / "t").exists()
