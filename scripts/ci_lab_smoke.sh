#!/usr/bin/env bash
# Teste de integração do laboratório (CI): DefectDojo real + VulnFlux.
#
# Valida, contra o DefectDojo verdadeiro (não simulado):
#   1. o token da API é obtido automaticamente pelo serviço dd-token
#   2. o VulnFlux arranca e liga-se ao DefectDojo com esse token
#   3. o JSON Generic Findings do conversor WPScan é aceite pelo parser do DefectDojo
#   4. um segundo reimport do mesmo ficheiro não cria duplicados
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
json.dump(convert(raw, include_interesting=True), open("/tmp/vf-generic.json", "w"))
PY
"${C[@]}" cp /tmp/vf-generic.json vulnflux:/tmp/vf-generic.json
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
print("findings no test:", findings["count"])
assert findings["count"] == 4, findings["count"]  # core + tema + plugin + interesting
PY
echo "::endgroup::"

echo "OK: laboratório validado contra o DefectDojo real"
