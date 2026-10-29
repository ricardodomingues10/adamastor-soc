from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from socportal.config import Settings

CONFIG = """
title: Portal de teste
services:
  - id: vulnflux
    name: VulnFlux
    group: Vulnerabilidades
    link: http://localhost:8080
    probes:
      - type: soc-status
        url: http://vulnflux:8080/api/status
        token_env: TEST_VF_TOKEN
    latest: {github: ricardodomingues10/vuln-flux}
    depends_on: [defectdojo, greenbone]
  - id: greenbone
    name: Greenbone
    group: Vulnerabilidades
    probes:
      - type: soc-component
        service: vulnflux
        component: greenbone
  - id: defectdojo
    name: DefectDojo
    group: Vulnerabilidades
    link: http://localhost:8081
    probes:
      - type: defectdojo
        url: http://dd:8080
        token_file: {token_file}
    latest: {github: DefectDojo/django-DefectDojo}
"""


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    path = tmp_path / "dd_token"
    path.write_text("dd-secret\n")
    return path


@pytest.fixture
def config_file(tmp_path: Path, token_file: Path) -> Path:
    path = tmp_path / "portal.yaml"
    path.write_text(textwrap.dedent(CONFIG).replace("{token_file}", str(token_file)))
    return path


@pytest.fixture
def settings(tmp_path: Path, config_file: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("TEST_VF_TOKEN", "vf-status-token")
    return Settings(
        data_dir=tmp_path / "data",
        config_file=config_file,
        admin_password="pw-teste",
        cookie_secure=False,
        secret_key="k" * 40,
        slow_ms=3000,
        _env_file=None,
    )


def soc_status(**over):
    data = {
        "schema": "soc-status/1",
        "service": "vulnflux",
        "version": "0.2.0",
        "status": "ok",
        "message": "tudo bem",
        "checks": [{"id": "defectdojo", "name": "DefectDojo", "status": "ok", "message": "12 ms"}],
        "dependencies": {"defectdojo": "ok", "greenbone": "off"},
        "freshness": [
            {
                "id": "wpscan_db",
                "name": "BD WPScan",
                "updated_at": "2026-10-29T02:31:00+00:00",
                "max_age_hours": 36,
                "status": "ok",
            }
        ],
        "components": {
            "greenbone": {
                "name": "Greenbone",
                "status": "off",
                "message": "parado (on-demand)",
                "freshness": [
                    {
                        "id": "NVT",
                        "name": "Feed NVT",
                        "updated_at": "2026-10-20T05:00:00+00:00",
                        "max_age_hours": 168,
                        "status": "off",
                    }
                ],
            }
        },
        "jobs": [
            {
                "id": "wpscan_batch",
                "name": "Lote WPScan",
                "next_run": "2026-10-30T02:37:00+00:00",
                "last_status": "success",
            }
        ],
    }
    data.update(over)
    return data
