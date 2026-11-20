"""Deteção de quais hosts são WordPress, e o lote WPScan a saltar os que não são."""

from __future__ import annotations

import responses

from vulnflux import pipeline
from vulnflux.models import Host, Trigger
from vulnflux.wordpress import detect

WP_HOME = '<html><head><meta name="generator" content="WordPress 6.6.2"><link href="/wp-content/themes/x/s.css"></head></html>'


@responses.activate
def test_classifica_pela_pagina_e_pelos_enderecos_proprios(settings):
    responses.get("https://wp.exemplo.pt/", body=WP_HOME)
    r = detect.detect("https://wp.exemplo.pt/", settings)
    assert r["is_wp"] is True and r["version"] == "6.6.2" and len(r["evidence"]) == 2

    # Página inicial sem rasto (cache/CDN), mas /wp-json/ confirma
    responses.get("https://cdn.exemplo.pt/", body="<html>ola</html>")
    responses.get("https://cdn.exemplo.pt/wp-json/", json={"namespaces": ["oembed/1.0", "wp/v2"]})
    r = detect.detect("https://cdn.exemplo.pt/", settings)
    assert r["is_wp"] is True and any("wp/v2" in e for e in r["evidence"])

    # Nada
    responses.get("https://app.exemplo.pt/", body="<html>app</html>")
    responses.get("https://app.exemplo.pt/wp-json/", status=404)
    responses.get("https://app.exemplo.pt/wp-login.php", status=404)
    assert detect.detect("https://app.exemplo.pt/", settings)["is_wp"] is False

    # Cabeçalho Link basta
    responses.get(
        "https://h.exemplo.pt/",
        body="<html></html>",
        headers={"Link": '<https://h.exemplo.pt/wp-json/>; rel="https://api.w.org/"'},
    )
    assert detect.detect("https://h.exemplo.pt/", settings)["is_wp"] is True


def test_url_alvo():
    assert (
        detect.target_url(Host(name="x.exemplo.pt", url="https://x.exemplo.pt/blog/")) == "https://x.exemplo.pt/blog/"
    )
    assert detect.target_url(Host(name="loja.exemplo.pt")) == "https://loja.exemplo.pt/"
    assert detect.target_url(Host(name="10.0.0.5")) is None
    assert detect.target_url(Host(name="srv01")) is None


@responses.activate
def test_lote_salta_os_que_nao_sao_wordpress(store, settings):
    wp = store.save_host(Host(name="wp.exemplo.pt", url="https://wp.exemplo.pt/"))
    app = store.save_host(Host(name="app.exemplo.pt", url="https://app.exemplo.pt/"))
    responses.get("https://wp.exemplo.pt/", body=WP_HOME)
    responses.get("https://app.exemplo.pt/", body="<html>app</html>")
    responses.get("https://app.exemplo.pt/wp-json/", status=404)
    responses.get("https://app.exemplo.pt/wp-login.php", status=404)
    summary = detect.run(store, settings)
    assert summary["wordpress"] == 1 and summary["not_wordpress"] == 1
    ids = pipeline.plan_wpscan_batch(store, settings, Trigger.MANUAL)
    hosts = {store.get_run(i).host_id for i in ids}
    assert hosts == {wp.id} and app.id not in hosts


@responses.activate
def test_sem_resposta_nao_exclui(store, settings):
    import requests

    h = store.save_host(Host(name="down.exemplo.pt", url="https://down.exemplo.pt/"))
    responses.get("https://down.exemplo.pt/", body=requests.ConnectionError())
    detect.run(store, settings)
    assert store.get_state(detect.STATE_KEY)[h.id]["is_wp"] is None
    assert not detect.is_known_not_wp(store, h.id)  # sem resposta não tira o host do lote
