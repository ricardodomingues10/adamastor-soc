from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses

from vulnflux.collectors import wpscan
from vulnflux.collectors.wpscan import ScanOutput, build_command, validate
from vulnflux.converters.wpscan_generic import convert, severity_counts, severity_from_cvss
from vulnflux.defectdojo import DefectDojo
from vulnflux.errors import ErrorKind, VFError
from vulnflux.gates import decide_close_old

# Campos aceites pelo parser Generic Findings Import do DefectDojo (dojo/tools/generic/json_parser.py)
DD_ALLOWED = {
    "title",
    "severity",
    "description",
    "date",
    "cwe",
    "cve",
    "epss_score",
    "epss_percentile",
    "cvssv3",
    "cvssv3_score",
    "cvssv4",
    "cvssv4_score",
    "mitigation",
    "impact",
    "steps_to_reproduce",
    "severity_justification",
    "references",
    "active",
    "verified",
    "false_p",
    "out_of_scope",
    "risk_accepted",
    "under_review",
    "is_mitigated",
    "thread_id",
    "mitigated",
    "numerical_severity",
    "param",
    "payload",
    "line",
    "file_path",
    "component_name",
    "component_version",
    "static_finding",
    "dynamic_finding",
    "scanner_confidence",
    "unique_id_from_tool",
    "vuln_id_from_tool",
    "sast_source_object",
    "sast_sink_object",
    "sast_source_line",
    "sast_source_file_path",
    "nb_occurences",
    "publish_date",
    "service",
    "planned_remediation_date",
    "planned_remediation_version",
    "effort_for_fixing",
    "tags",
    "kev_date",
    "known_exploited",
    "ransomware_used",
    "fix_available",
    "fix_version",
    # retirados pelo parser antes da validação
    "endpoints",
    "files",
    "vulnerability_ids",
    "cwes",
}


# ------------------------------------------------------------------ conversor


def test_convert_core_temas_plugins_e_dedup(wpscan_raw):
    out = convert(wpscan_raw)
    findings = out["findings"]
    vulns = [f for f in findings if f["tags"][1] in ("core", "plugin", "theme")]
    assert len(vulns) == 3  # core + tema + plugin (duplicado removido)
    by_comp = {f["component_name"]: f for f in vulns}
    assert set(by_comp) == {"wordpress", "avada", "contact-form-7"}

    core = by_comp["wordpress"]
    assert core["severity"] == "High"  # cvss 8.1
    assert core["vulnerability_ids"] == ["CVE-2023-6553"]
    assert core["component_version"] == "6.4.1"
    assert core["fix_version"] == "6.4.2" and core["fix_available"] is True
    assert core["cvssv3"].startswith("CVSS:3.1")
    assert core["unique_id_from_tool"] == "wpscan:core:wordpress:aaaa-1111"
    assert core["date"] == "2025-10-29"

    assert by_comp["avada"]["vulnerability_ids"] == ["CVE-2023-39312"]  # já com prefixo
    assert by_comp["avada"]["severity"] == "Medium"  # sem cvss
    assert by_comp["contact-form-7"]["severity"] == "Critical"
    for f in findings:
        assert set(f) <= DD_ALLOWED, set(f) - DD_ALLOWED
        assert len(f["title"]) <= 500 and f["severity"] in ("Critical", "High", "Medium", "Low", "Info")
    # core, tema, plugin, timthumb, config backup, db export, backup folder, utilizadores
    assert len(findings) == 8
    assert severity_counts(out) == {"Critical": 1, "High": 4, "Medium": 2, "Low": 1, "Info": 0}


def test_convert_ficheiros_expostos(wpscan_raw):
    by_tag = {f["tags"][1]: f for f in convert(wpscan_raw)["findings"]}
    cfg = by_tag["config_backup"]
    assert cfg["severity"] == "High" and cfg["cwe"] == 530
    assert cfg["endpoints"] == ["https://www.exemplo.pt/wp-config.php.bak"]
    assert "credenciais" in cfg["description"] and "rodar as credenciais" in cfg["mitigation"]
    assert by_tag["db_export"]["severity"] == "High"
    folder = by_tag["backup_folder"]
    assert folder["severity"] == "High"  # o WPScan marcou high (tem conteúdo)
    assert "site-2026-10.zip" in folder["description"]


def test_convert_timthumb_vulneravel_wpscan4(wpscan_raw):
    tt = next(f for f in convert(wpscan_raw)["findings"] if f["tags"][1] == "timthumb")
    url = "https://www.exemplo.pt/wp-content/themes/velho/timthumb.php"
    assert tt["component_name"] == url and tt["component_version"] == "1.33"
    assert tt["vulnerability_ids"] == ["CVE-2014-4663"]
    # WPScan 4.x: o id vem em "uuid" e gera a referência wpscan.com
    assert tt["unique_id_from_tool"].endswith("6fc6f6b2-9a4c-4d33-9f2d-4c1d3c1a3b11")
    assert "wpscan.com/vulnerability/6fc6f6b2" in tt["references"]


def test_convert_utilizadores(wpscan_raw):
    users = next(f for f in convert(wpscan_raw)["findings"] if f["tags"][1] == "users")
    assert users["severity"] == "Low" and "(2 encontrados)" in users["title"]
    assert "`admin` (ID 1)" in users["description"] and "`editora` (ID 3)" in users["description"]
    assert users["unique_id_from_tool"] == "wpscan:users:https://www.exemplo.pt/"
    without = convert(wpscan_raw, include_users=False)["findings"]
    assert not [f for f in without if f["tags"][1] == "users"]


def test_backup_folder_severidade_desconhecida_vira_medium():
    raw = {"target_url": "https://a.pt/", "backup_folders": {"https://a.pt/bk/": {"severity": "weird"}}}
    assert convert(raw)["findings"][0]["severity"] == "Medium"


def test_convert_interesting_opcional(wpscan_raw):
    out = convert(wpscan_raw, include_interesting=True)
    infos = [f for f in out["findings"] if f["severity"] == "Info"]
    assert len(infos) == 1 and "readme" in infos[0]["title"].lower()
    assert len(out["findings"]) == 9
    assert set(infos[0]) <= DD_ALLOWED


def test_convert_resultado_limpo():
    assert convert({"target_url": "https://a.pt/", "version": {"number": "6.6", "vulnerabilities": []}}) == {
        "findings": []
    }


@pytest.mark.parametrize(
    "cvss,sev",
    [
        (None, "Medium"),
        ({"score": "9.1"}, "Critical"),
        (7.0, "High"),
        (4, "Medium"),
        (0.1, "Low"),
        (0, "Info"),
        ("abc", "Medium"),
    ],
)
def test_severity_from_cvss(cvss, sev):
    assert severity_from_cvss(cvss) == sev


# ------------------------------------------------------------------ validação WPScan


def _scan(raw, code=0):
    return ScanOutput(exit_code=code, raw=raw, stderr="boom")


def test_validate_ok_e_vulneravel(wpscan_raw):
    assert validate(_scan(wpscan_raw, 0), token_configured=True) is wpscan_raw
    assert validate(_scan(wpscan_raw, 5), token_configured=True) is wpscan_raw
    assert wpscan.quota_from_raw(wpscan_raw) == 21


@pytest.mark.parametrize(
    "raw,code,kind",
    [
        (None, 4, ErrorKind.DATA),
        (None, 2, ErrorKind.TRANSIENT),
        (
            {"scan_aborted": "The remote website is up, but does not seem to be running WordPress.", "target_url": "x"},
            4,
            ErrorKind.PERMANENT,
        ),
        ({"scan_aborted": "The URL supplied redirects to https://b.pt/", "target_url": "x"}, 4, ErrorKind.PERMANENT),
        ({"scan_aborted": "Unknown failure", "target_url": "x"}, 4, ErrorKind.DATA),
        ({"target_url": "x", "vuln_api": {"plan": "free"}}, 1, ErrorKind.DATA),
        ({"vuln_api": {}}, 0, ErrorKind.DATA),
        ({"target_url": "x"}, 0, ErrorKind.DATA),
        ({"target_url": "x", "vuln_api": {"error": "You have reached your API limit"}}, 0, ErrorKind.QUOTA),
        ({"target_url": "x", "vuln_api": {"error": "HTTP Error 500"}}, 0, ErrorKind.DEPENDENCY),
    ],
)
def test_validate_falhas(raw, code, kind):
    with pytest.raises(VFError) as exc:
        validate(_scan(raw, code), token_configured=True)
    assert exc.value.kind is kind


def test_build_command_nao_aceita_override_de_output(settings):
    cmd = build_command("https://a.pt/", Path("/tmp/x.json"), settings)
    assert "--no-update" in cmd and "--api-token" not in cmd
    # sem -e o WPScan 4.x não enumera plugins nem utilizadores
    assert cmd[cmd.index("--enumerate") + 1] == "vp,vt,tt,cb,dbe,bf,u1-10"
    assert cmd[cmd.index("--plugins-detection") + 1] == "mixed"
    no_users = settings.model_copy(update={"wpscan_include_users": False})
    assert (
        build_command("https://a.pt/", Path("/tmp/x.json"), no_users)[cmd.index("--enumerate") + 1]
        == "vp,vt,tt,cb,dbe,bf"
    )
    for extra in ("-e ap", "--enumerate u", "--plugins-detection aggressive"):
        with pytest.raises(VFError):
            build_command(
                "https://a.pt/", Path("/tmp/x.json"), settings.model_copy(update={"wpscan_extra_args": extra})
            )
    with pytest.raises(VFError):
        build_command(
            "https://a.pt/", Path("/tmp/x.json"), settings.model_copy(update={"wpscan_plugins_detection": "x"})
        )
    bad = settings.model_copy(update={"wpscan_extra_args": "--output /etc/passwd"})
    with pytest.raises(VFError):
        build_command("https://a.pt/", Path("/tmp/x.json"), bad)


def test_token_vai_no_ambiente_e_nao_vaza_segredos(settings, monkeypatch):
    monkeypatch.setenv("VF_DD_TOKEN", "nao-pode-passar")
    env = wpscan._env(settings, "chave-escolhida")
    assert env["WPSCAN_API_TOKEN"] == "chave-escolhida"
    assert "WPSCAN_API_TOKEN" not in wpscan._env(settings)
    assert "VF_DD_TOKEN" not in env
    assert env["XDG_CACHE_HOME"].endswith(".cache")
    cmd = build_command("https://a.pt/", Path("/tmp/x.json"), settings)
    assert "wp-token" not in " ".join(cmd)


def test_ensure_database_usa_bd_recente(settings, monkeypatch):
    called = []
    monkeypatch.setattr(wpscan, "update_database", lambda s: called.append(1))
    assert wpscan.ensure_database(settings) == "BD de metadados atualizada" and called
    db = wpscan.db_dirs(settings)[1]  # caminho XDG do WPScan 4.x
    db.mkdir(parents=True)
    (db / ".last_update").write_text("2026-10-29")
    called.clear()
    assert wpscan.ensure_database(settings) == "BD de metadados atual" and not called


@pytest.mark.parametrize(
    "api,kind",
    [
        ({"error": "No WPScan API Token given, as a result vulnerability data has not been output."}, ErrorKind.QUOTA),
        ({"http_error": "HTTP Error: 503"}, ErrorKind.DEPENDENCY),
        ({"parse_error": "invalid"}, ErrorKind.DEPENDENCY),
        ({"plan": "free", "requests_done_during_scan": 25, "requests_remaining": 0}, ErrorKind.QUOTA),
    ],
)
def test_validate_api_v4(api, kind):
    with pytest.raises(VFError) as exc:
        validate(_scan({"target_url": "x", "vuln_api": api}), token_configured=True)
    assert exc.value.kind is kind


def test_quota_ilimitada():
    assert wpscan.quota_from_raw({"vuln_api": {"requests_remaining": "Unlimited"}}) is None
    assert wpscan.quota_from_raw({"vuln_api": {"requests_remaining": -1}}) is None


# ------------------------------------------------------------------ gates


def test_gate():
    assert decide_close_old(current_total=2, previous_total=None, threshold=0.5, min_previous=5).close_old_findings
    assert decide_close_old(current_total=0, previous_total=3, threshold=0.5, min_previous=5).close_old_findings
    d = decide_close_old(current_total=2, previous_total=40, threshold=0.5, min_previous=5)
    assert not d.close_old_findings and "95%" in d.warnings[0]
    assert decide_close_old(current_total=25, previous_total=40, threshold=0.5, min_previous=5).close_old_findings


# ------------------------------------------------------------------ DefectDojo


@responses.activate
def test_reimport_parametros_e_estatisticas(settings):
    responses.post(
        "https://dd.test/api/v2/reimport-scan/",
        json={
            "test_id": 42,
            "statistics": {
                "delta": {
                    "created": {"total": 3},
                    "closed": {"total": 1},
                    "reactivated": {"total": 0},
                    "untouched": {"total": 9},
                }
            },
        },
    )
    res = DefectDojo(settings).reimport(
        content=b"{}",
        filename="x.json",
        scan_type="Generic Findings Import",
        test_title="WPScan",
        product_name="a.pt",
        product_type_name="PRD",
        close_old_findings=True,
    )
    assert res.test_id == 42
    assert res.delta() == {"created": 3, "closed": 1, "reactivated": 0, "untouched": 9}
    body = responses.calls[0].request.body.decode("latin-1")
    for field, value in [
        ("close_old_findings_product_scope", "false"),
        ("do_not_reactivate", "false"),
        ("auto_create_context", "true"),
        ("product_name", "a.pt"),
        ("engagement_name", "VulnFlux"),
        ("test_title", "WPScan"),
        ("close_old_findings", "true"),
    ]:
        assert f'name="{field}"\r\n\r\n{value}\r\n' in body, field
    assert responses.calls[0].request.headers["Authorization"] == "Token dd-token"


@responses.activate
def test_reimport_repete_503_e_falha_400(settings, monkeypatch):
    monkeypatch.setattr("vulnflux.defectdojo.time.sleep", lambda s: None)
    url = "https://dd.test/api/v2/reimport-scan/"
    responses.post(url, status=503)
    responses.post(url, json={"test_id": 1})
    dd = DefectDojo(settings)
    kwargs = dict(
        content=b"{}",
        filename="x.json",
        scan_type="s",
        test_title="t",
        product_name="p",
        product_type_name="pt",
        close_old_findings=False,
    )
    assert dd.reimport(**kwargs).test_id == 1
    assert len(responses.calls) == 2

    responses.replace(responses.POST, url, status=400, json={"file": ["Not allowed fields are present: ['x']"]})
    with pytest.raises(VFError) as exc:
        dd.reimport(**kwargs)
    assert exc.value.kind is ErrorKind.DATA and "Not allowed" in exc.value.detail


@responses.activate
def test_ping_token_errado(settings):
    responses.get("https://dd.test/api/v2/products/", status=401)
    with pytest.raises(VFError) as exc:
        DefectDojo(settings).ping()
    assert exc.value.kind is ErrorKind.CONFIG


def test_dd_por_configurar(settings):
    with pytest.raises(VFError) as exc:
        DefectDojo(settings.model_copy(update={"dd_url": ""}))
    assert exc.value.kind is ErrorKind.CONFIG


def test_generic_json_e_serializavel(wpscan_raw):
    json.dumps(convert(wpscan_raw, include_interesting=True))
