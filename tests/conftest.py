from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import SecretStr

from vulnflux.config import Settings
from vulnflux.store import JsonStore

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        admin_user="admin",
        admin_password=SecretStr("segredo-de-teste"),
        secret_key=SecretStr("chave-de-teste-" * 4),
        cookie_secure=False,
        dd_url="https://dd.test",
        dd_token=SecretStr("dd-token"),
        dd_import_retries=2,
        wpscan_api_token=SecretStr("wp-token"),
        greenbone_enabled=True,
        greenbone_password=SecretStr("gb-pass"),
        greenbone_poll_seconds=1,
    )


@pytest.fixture
def store(settings: Settings) -> JsonStore:
    return JsonStore(settings.data_dir)


@pytest.fixture
def wpscan_raw() -> dict:
    return json.loads((FIXTURES / "wpscan_sample.json").read_text())
