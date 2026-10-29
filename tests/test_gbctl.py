"""Testes do deploy/greenbone/gb-ctl.sh com um `docker` falso no PATH."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from vulnflux.greenbone.lifecycle import LifecycleError, parse_gbctl_output

SCRIPT = Path(__file__).parents[1] / "deploy" / "greenbone" / "gb-ctl.sh"

pytestmark = pytest.mark.skipif(
    not (shutil.which("jq") and shutil.which("flock") and shutil.which("bash")), reason="precisa de bash, jq e flock"
)

FAKE_DOCKER = """#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
case "$*" in
  *" ps -a --format json"*)
    printf '%s\\n' '{"Service":"gvmd","State":"running","Health":"","ExitCode":0,"Image":"gvmd:stable"}' \
                   '{"Service":"ospd-openvas","State":"exited","Health":"","ExitCode":0,"Image":"ospd:stable"}';;
esac
if [ -n "$FAKE_FAIL" ]; then case "$*" in *"$FAKE_FAIL"*) exit 7;; esac; fi
exit 0
"""


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    return {
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_LOG": str(tmp_path / "calls.log"),
        "GB_COMPOSE_DIR": str(tmp_path),
        "GB_LOG_FILE": str(tmp_path / "ctl.log"),
        "GB_LOCK_FILE": str(tmp_path / "lock"),
    }


def run(env: dict[str, str], *args: str, **extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPT), *args], env={**env, **extra}, capture_output=True, text=True, check=False
    )


@pytest.mark.parametrize("verb", ["status", "start", "stop", "update"])
def test_verbos(env, verb):
    proc = run(env, verb)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = parse_gbctl_output(verb, proc.returncode, proc.stdout)
    assert result.running() == {"gvmd"}


def test_update_faz_pull_e_up(env):
    run(env, "update")
    calls = Path(env["FAKE_LOG"]).read_text()
    assert " pull --quiet" in calls and " up -d --remove-orphans" in calls and "image prune -f" in calls


def test_forced_command_rejeita_injecao(env):
    proc = run(env, SSH_ORIGINAL_COMMAND="start; rm -rf /")
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["ok"] is False
    assert not Path(env["FAKE_LOG"]).exists()  # o docker nunca foi chamado
    with pytest.raises(LifecycleError) as exc:
        parse_gbctl_output("start", proc.returncode, proc.stdout)
    assert exc.value.transient is False


def test_falha_no_pull(env):
    proc = run(env, "update", FAKE_FAIL="pull")
    assert proc.returncode == 1 and "pull" in json.loads(proc.stdout)["message"]


def test_lock_ocupado(env):
    # Outro processo segura o lock, como um update ainda em curso
    holder = subprocess.Popen(["flock", env["GB_LOCK_FILE"], "sleep", "5"])
    try:
        time.sleep(0.3)
        proc = run(env, "start")
    finally:
        holder.kill()
    assert proc.returncode == 1 and "em curso" in json.loads(proc.stdout)["message"]
