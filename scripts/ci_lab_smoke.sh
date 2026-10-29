#!/usr/bin/env bash
# Teste de integração do laboratório (CI): DefectDojo real + VulnFlux.
#
# Valida, contra o DefectDojo verdadeiro (não simulado):
#   1. o token da API é obtido automaticamente pelo serviço dd-token
#   2. o VulnFlux arranca e liga-se ao DefectDojo com esse token
#   3. o JSON Generic Findings do conversor WPScan é aceite pelo parser do DefectDojo
#   4. um segundo reimport do mesmo ficheiro não cria duplicados
#   5. mudar a password do admin no .env.lab depois do 1.º arranque continua a funcionar
#
# O Greenbone fica de fora (os feeds demoram horas a carregar).

set -Eeuo pipefail
cd "$(dirname "$0")/.."

cp lab.env.example .env.lab
sed -i 's/=GERAR$/=ci-segredo-123456789/' .env.lab
C=(docker compose -f compose.lab.yaml --env-file .env.lab)

echo "::group::build"
"${C[@]}" build vulnflux
echo "::endgroup::"

echo "::group::DefectDojo"
"${C[@]}" up -d dd-nginx
echo "::endgroup::"

echo "::group::dd-token"
timeout 1200 "${C[@]}" run --rm --no-deps dd-token
echo "::endgroup::"

echo "::group::VulnFlux"
"${C[@]}" up -d --no-deps vulnflux
for _ in $(seq 1 60); do
  curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS http://127.0.0.1:8080/healthz
echo "::endgroup::"

echo "::group::conversor WPScan"
python - <<'PY'
import json
from vulnflux.converters.wpscan_generic import convert
raw = json.load(open("tests/fixtures/wpscan_sample.json"))
generic = convert(raw, include_interesting=True)
json.dump(generic, open("/tmp/vf-generic.json", "w"))
open("/tmp/vf-expected", "w").write(str(len(generic["findings"])))
print("findings gerados:", len(generic["findings"]))
PY
"${C[@]}" cp /tmp/vf-generic.json vulnflux:/tmp/vf-generic.json
"${C[@]}" cp /tmp/vf-expected vulnflux:/tmp/vf-expected
echo "::endgroup::"

echo "::group::reimport real no DefectDojo"
"${C[@]}" exec -T vulnflux python - <<'PY'
from pathlib import Path
from vulnflux.config import get_settings
from vulnflux.defectdojo import DefectDojo

s = get_settings()
assert s.dd_token.get_secret_value(), "token do DefectDojo não chegou ao VulnFlux"
dd = DefectDojo(s)
print("ping:", dd.ping())
content = Path("/tmp/vf-generic.json").read_bytes()
kw = dict(content=content, filename="wpscan-generic.json", scan_type="Generic Findings Import",
          test_title="WPScan", product_name="ci.exemplo.pt", product_type_name="Lab", close_old_findings=True)
first = dd.reimport(**kw)
print("1.º reimport:", first.test_id, first.delta(), first.statistics)
assert first.test_id, first.raw
second = dd.reimport(**kw)
print("2.º reimport:", second.test_id, second.delta())
assert second.test_id == first.test_id, "o reimport devia reutilizar o mesmo test"
d = second.delta()
if d:
    assert d.get("created", 0) == 0, f"duplicados criados no 2.º reimport: {d}"
findings = dd.session.get(f"{dd.base}/findings/", params={"test": first.test_id, "limit": 100}, timeout=30).json()
expected = int(Path("/tmp/vf-expected").read_text())
print("findings no test:", findings["count"], "esperados:", expected)
# core, tema, plugin, timthumb, config backup, db export, backup folder, utilizadores, interesting
assert findings["count"] == expected, (findings["count"], expected)
sev = {}
for f in findings["results"]:
    sev[f["severity"]] = sev.get(f["severity"], 0) + 1
print("por severidade no DefectDojo:", sev)
PY
echo "::endgroup::"

echo "::group::password do admin alterada no .env.lab depois do 1.º arranque"
sed -i 's/^DD_ADMIN_PASSWORD=.*/DD_ADMIN_PASSWORD=nova-password-987654/' .env.lab
"${C[@]}" up --no-deps --exit-code-from dd-initializer dd-initializer
timeout 300 "${C[@]}" run --rm --no-deps dd-token
echo "::endgroup::"

echo "OK: laboratório validado contra o DefectDojo real"
