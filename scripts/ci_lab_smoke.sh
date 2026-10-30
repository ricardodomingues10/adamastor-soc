#!/usr/bin/env bash
# Teste de integração do laboratório (CI): DefectDojo real + VulnFlux.
#
# Valida, contra o DefectDojo verdadeiro (não simulado):
#   1. o token da API é obtido automaticamente pelo serviço dd-token
#   2. o VulnFlux arranca e liga-se ao DefectDojo com esse token
#   3. o JSON Generic Findings do conversor WPScan é aceite pelo parser do DefectDojo
#   4. um segundo reimport do mesmo ficheiro não cria duplicados
#   5. mudar a password do admin no .env.lab depois do 1.º arranque continua a funcionar
#   6. motor de risco: KEV/EPSS/exploits (fixtures locais) escritos nos findings reais
#      (tags risk:*, campos EPSS/KEV, data planeada, product) e 2.ª passagem sem escritas
#   7. Portal SOC: lê a versão do DefectDojo e o contrato soc-status/1 do VulnFlux
#   9. Atalaia Cert: clonado do repositório certs-watch, construído e arrancado pelo lab.sh, visto ativo no portal
#  10. eventos (P1/KEV) e /api/exposure para o SIEM; segmentação de rede; backup e restauro verdadeiro
#   8. Servidores: servidor de demonstração ligado com o comando de bootstrap, verificação real por SSH
#      (sudo limitado, sshd -T), hardening e atualizações importados no DefectDojo, componente no portal
#
# O Greenbone fica de fora (os feeds demoram horas a carregar).

set -Eeuo pipefail
cd "$(dirname "$0")/.."

cp lab.env.example .env.lab
sed -i 's/=GERAR$/=ci-segredo-123456789/' .env.lab
# Feeds de ameaça a partir de fixtures (determinístico e sem depender da Internet)
for f in kev:kev.json epss:epss.csv.gz exploitdb:exploitdb.csv metasploit:metasploit.json nuclei:nuclei.json; do
  key="$(echo "${f%%:*}" | tr '[:lower:]' '[:upper:]')"
  echo "VF_RISK_${key}_URL=file:///data/risk-fixtures/${f#*:}" >>.env.lab
done
C=(docker compose -f compose.lab.yaml --env-file .env.lab)
BACKUP_UID="$(id -u)"
BACKUP_GID="$(id -g)"
export BACKUP_UID BACKUP_GID
mkdir -p .lab/backups .lab/atalaia/secrets

echo "::group::build"
"${C[@]}" build vulnflux portal
echo "::endgroup::"

echo "::group::DefectDojo"
"${C[@]}" up -d dd-nginx
echo "::endgroup::"

echo "::group::dd-token"
timeout 1200 "${C[@]}" run --rm --no-deps dd-token
echo "::endgroup::"

echo "::group::VulnFlux"
# host do inventário com contexto de risco (antes do arranque: o VulnFlux é de processo único)
"${C[@]}" run --rm --no-deps --entrypoint python vulnflux -c "
from pathlib import Path
from vulnflux.models import Host
from vulnflux.store import JsonStore
JsonStore(Path('/data')).save_host(Host(name='ci.exemplo.pt', url='https://ci.exemplo.pt/', environment='Lab',
    criticality='medio', exposure='internet', data_class='pessoais'))
print('host ci.exemplo.pt criado')
"
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

echo "::group::motor de risco contra o DefectDojo real"
"${C[@]}" exec -T vulnflux mkdir -p /data/risk-fixtures
for f in tests/fixtures/risk/*; do
  "${C[@]}" cp "$f" "vulnflux:/data/risk-fixtures/$(basename "$f")"
done
"${C[@]}" exec -T vulnflux python -m vulnflux.labtools risk | tee /tmp/vf-risk1.txt
"${C[@]}" exec -T vulnflux python - <<'PY'
from vulnflux.config import get_settings
from vulnflux.defectdojo import DefectDojo

dd = DefectDojo(get_settings())
prod = [p for p in dd.paginate("/products/") if p["name"] == "ci.exemplo.pt"][0]
print("product:", prod["business_criticality"], prod["internet_accessible"])
assert prod["business_criticality"] == "high", prod["business_criticality"]  # médio + dados pessoais
assert prod["internet_accessible"] is True
findings = list(dd.paginate("/findings/", {"test__engagement__product": prod["id"], "active": "true"}))
tagged = [f for f in findings if any(t.lower().startswith("risk:") for t in f["tags"])]
print(f"findings: {len(findings)} · com prioridade: {len(tagged)}")
for f in findings:
    print(f"  {f['severity']:8} {f['tags']} epss={f['epss_score']} kev={f['known_exploited']} sla={f['planned_remediation_date']}")
kev = [f for f in findings if "CVE-2023-39312" in str(f.get("vulnerability_ids"))]
assert kev, "finding com CVE-2023-39312 não encontrado"
f = kev[0]
tags = {t.lower() for t in f["tags"]}
assert {"risk:p1", "risk:kev", "risk:exploit-metasploit"} <= tags, tags
assert "wpscan" in tags, "as tags do scanner têm de ficar"
assert f["known_exploited"] is True and f["kev_date"] == "2024-01-10", (f["known_exploited"], f["kev_date"])
assert abs(f["epss_score"] - 0.9) < 1e-6 and abs(f["epss_percentile"] - 0.97) < 1e-6
assert f["planned_remediation_date"], "sem data planeada"
non_info = [x for x in findings if x["severity"] != "Info"]
assert all(any(t.lower().startswith("risk:p") for t in x["tags"]) for x in non_info), "finding sem prioridade"
PY
"${C[@]}" exec -T vulnflux python -m vulnflux.labtools risk --no-download | tee /tmp/vf-risk2.txt
python - <<'PY'
import json
last = json.loads(open("/tmp/vf-risk2.txt").read().strip().splitlines()[-1])
print("2.ª passagem:", last)
assert last["status"] == "success", last
assert last["updated"] == 0, f"a 2.ª passagem não devia escrever nada: {last}"
PY
echo "::endgroup::"

echo "::group::eventos e exposição para o SIEM"
VFT="$(grep '^VF_STATUS_TOKEN=' .env.lab | cut -d= -f2-)"
curl -fsS -H "Authorization: Bearer $VFT" http://127.0.0.1:8080/api/exposure >/tmp/exposure.json
curl -fsS -H "Authorization: Bearer $VFT" "http://127.0.0.1:8080/api/exposure?formato=csv" | head -3
"${C[@]}" exec -T vulnflux cat /data/eventos/eventos.jsonl >/tmp/eventos.jsonl
python - <<'PY'
import json
rows = json.load(open("/tmp/exposure.json"))["rows"]
print("exposição:", [(r["host"], r["cve"], r["prioridade"], r["kev"]) for r in rows])
assert any(r["cve"] == "CVE-2023-39312" and r["kev"] for r in rows), rows
evs = [json.loads(x) for x in open("/tmp/eventos.jsonl")]
print("eventos:", [e["message"] for e in evs])
assert any(e["event"]["type"] == ["vulnerabilidade"] and e["vulnflux"].get("kev") for e in evs), evs
# a 2.ª passagem não repete alertas
assert len([e for e in evs if e["event"]["type"] == ["vulnerabilidade"]]) == len({e["event"]["id"] for e in evs}), "alertas repetidos"
PY
echo "::endgroup::"

echo "::group::segmentação de rede"
probe() { # serviço host porta → "sim" se liga
  "${C[@]}" exec -T "$1" python -c "import socket,sys
try: socket.create_connection(('$2', $3), timeout=4); print('sim')
except OSError: print('nao')" 2>/dev/null || echo "erro: $1 parado"
}
"${C[@]}" up -d --no-deps portal sonda backup
sleep 5
seg_fail=0
check() { # descrição esperado serviço host porta
  got="$(probe "$3" "$4" "$5")"
  printf '  %-55s %s\n' "$1" "$got"
  [ "$got" = "$2" ] || { echo "::error title=segmentação::$1 (esperado $2, obtido $got)"; seg_fail=1; }
}
check "vulnflux → dd-nginx:8080 (integração)" sim vulnflux dd-nginx 8080
check "vulnflux → dd-postgres:5432 (BD do DefectDojo)" nao vulnflux dd-postgres 5432
check "vulnflux → dd-valkey:6379" nao vulnflux dd-valkey 6379
check "portal → dd-uwsgi:3031" nao portal dd-uwsgi 3031
check "portal → vulnflux:8080" sim portal vulnflux 8080
check "vulnflux → sonda:8000" sim vulnflux sonda 8000
check "portal → sonda:8000" nao portal sonda 8000
[ "$seg_fail" = 0 ] || exit 1
echo "::endgroup::"

echo "::group::backup e restauro"
mkdir -p .lab/backups
if ! ./scripts/lab.sh backup agora >/tmp/backup.txt 2>&1; then cat /tmp/backup.txt; echo "::error title=backup::$(tail -c 1500 /tmp/backup.txt | tr '\n' ' ')"; exit 1; fi
cat /tmp/backup.txt
B="$(find .lab/backups -maxdepth 1 -type d -name '20*' | sort | tail -n1)"
ls -la "$B"
for f in defectdojo.dump vulnflux.tar.gz portal.tar.gz segredos.tar.gz MANIFESTO.txt; do
  [ -s "$B/$f" ] || { echo "::error title=backup::falta $f em $B"; exit 1; }
done
grep -q '"estado":"ok"' .lab/backups/ultimo.json
# restauro verdadeiro: apaga um host, restaura, o host volta
"${C[@]}" exec -T vulnflux python -c "
from pathlib import Path
from vulnflux.store import JsonStore
s = JsonStore(Path('/data')); h = s.get_host_by_name('ci.exemplo.pt'); s.delete_host(h.id); print('host apagado')"
./scripts/lab.sh backup restaurar "$(basename "$B")" --sim >/tmp/restore.txt 2>&1 || { cat /tmp/restore.txt; echo "::error title=restauro::$(tail -c 1500 /tmp/restore.txt | tr '\n' ' ')"; exit 1; }
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 2; done
"${C[@]}" exec -T vulnflux python -c "
from pathlib import Path
from vulnflux.store import JsonStore
assert JsonStore(Path('/data')).get_host_by_name('ci.exemplo.pt'), 'o host não voltou'; print('host restaurado')"
echo "::notice title=backup::$(du -sh "$B" | cut -f1) em $(basename "$B"), restauro verificado"
echo "::endgroup::"

echo "::group::Portal SOC"
"${C[@]}" up -d --no-deps portal
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8090/healthz >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS http://127.0.0.1:8090/healthz
"${C[@]}" exec -T portal soc-portal check
"${C[@]}" exec -T portal soc-portal check --json >/tmp/portal.json
python - <<'PY'
import json
d = json.load(open("/tmp/portal.json"))
s = d["services"]
print({k: (v["status"], v["version"]) for k, v in s.items()})
assert s["defectdojo"]["status"] == "ok", s["defectdojo"]
assert s["defectdojo"]["version"], "versão do DefectDojo não lida"
assert s["vulnflux"]["status"] in ("ok", "warn"), s["vulnflux"]
assert s["vulnflux"]["version"] == "0.2.0"
edges = {(e["from"], e["to"]): e["status"] for e in d["edges"]}
assert edges[("vulnflux", "defectdojo")] == "ok", edges
fresh = {f["id"]: f["status"] for f in d["freshness"]}
print("listas:", fresh)
assert fresh.get("risk_kev") in ("ok", "warn") and "greenbone_nvt" in fresh
PY
echo "::endgroup::"

echo "::group::Servidores (SSH real ao servidor de demonstração)"
CS=("${C[@]}" --profile servers)
"${CS[@]}" up -d --build --no-deps lab-server
"${C[@]}" exec -T vulnflux python -m vulnflux.labtools bootstrap verificar | "${CS[@]}" exec -T lab-server sh
"${CS[@]}" exec -T lab-server sh -c 'test -f /etc/sudoers.d/vulnflux && grep -q "sshd -T" /etc/sudoers.d/vulnflux'
if ! "${C[@]}" exec -T vulnflux python -m vulnflux.labtools add-server lab-server.lab lab-server 0 verificar \
  >/tmp/add-server.txt 2>&1; then
  cat /tmp/add-server.txt
  echo "::error title=servidores::$(tr '\n' ' ' </tmp/add-server.txt | cut -c1-900)"
  exit 1
fi
cat /tmp/add-server.txt
annotate() { # título, ficheiro: mostra a saída e cria uma anotação legível pela API
  cat "$2"
  echo "::error title=$1::$(tr '\n' ' ' <"$2" | tail -c 1500)"
}
if ! "${C[@]}" exec -T vulnflux python - >/tmp/servers-check.txt 2>&1 <<'PY'; then
import json
from pathlib import Path
from vulnflux.config import get_settings
from vulnflux.defectdojo import DefectDojo
from vulnflux.store import JsonStore

s = get_settings()
store = JsonStore(Path("/data"))
h = next(h for h in store.list_hosts() if h.name == "lab-server.lab")
rep = store.get_server(h.id)["report"]
assert rep and rep["complete"], "relatório do servidor em falta ou incompleto"
assert rep["os_id"] == "debian" and rep["ssh_source"] == "sshd-T", (rep["os_id"], rep["ssh_source"])
assert rep["sudo_rules"] >= 1 and rep["score"] is not None
hard = {c["id"]: c["status"] for c in rep["hardening"]}
assert hard["ssh_password"] == "fail", hard  # Debian por omissão: palavra-passe ligada
print("servidor:", rep["status"], "hardening", rep["score"], "atualizações", rep["updates"]["total"])
dd = DefectDojo(s)
prod = next(p for p in dd.paginate("/products/") if p["name"] == "lab-server.lab")
titles = [f["title"] for f in dd.paginate("/findings/", {"test__engagement__product": prod["id"], "active": "true"})]
print("findings no DefectDojo:", len(titles))
# o DefectDojo põe os títulos em Title Case: comparar sem maiúsculas
assert any(t.lower().startswith("hardening: ssh: autenticação por palavra-passe") for t in titles), titles
PY
  annotate servidores-verificacao /tmp/servers-check.txt
  exit 1
fi
cat /tmp/servers-check.txt
"${C[@]}" exec -T portal soc-portal check --json >/tmp/portal2.json
if ! python - >/tmp/portal2.txt 2>&1 <<'PY'; then
import json
s = json.load(open("/tmp/portal2.json"))["services"]
print("portal servidores:", s["servidores"]["status"], s["servidores"].get("message", ""))
assert s["servidores"]["status"] in ("ok", "warn", "fail") and "servidores" in s["servidores"].get("message", "")
PY
  annotate servidores-portal /tmp/portal2.txt
  exit 1
fi
cat /tmp/portal2.txt
echo "::endgroup::"

echo "::group::Atalaia Cert (lab.sh atalaia up, com o certs-watch verdadeiro)"
if ! ./scripts/lab.sh atalaia up >/tmp/atalaia-up.txt 2>&1; then
  annotate atalaia-up /tmp/atalaia-up.txt
  exit 1
fi
tail -20 /tmp/atalaia-up.txt
CA=("${C[@]}" --profile atalaia)
ok=0
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8088/healthz >/dev/null 2>&1; then ok=1; break; fi
  sleep 3
done
if [ "$ok" != 1 ]; then
  "${CA[@]}" logs --no-color --tail=80 atalaia-web atalaia-worker atalaia-db >/tmp/atalaia-logs.txt 2>&1 || true
  annotate atalaia-healthz /tmp/atalaia-logs.txt
  exit 1
fi
TOKEN="$(grep '^ATALAIA_STATUS_TOKEN=' .env.lab | cut -d= -f2-)"
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8088/api/status >/tmp/atalaia-status.json
"${CA[@]}" exec -T portal soc-portal check --json >/tmp/portal3.json
if ! python - >/tmp/atalaia-check.txt 2>&1 <<'PY'; then
import json
st = json.load(open("/tmp/atalaia-status.json"))
assert st["schema"] == "soc-status/1" and st["service"] == "atalaia-cert", st
s = json.load(open("/tmp/portal3.json"))["services"]
print("Atalaia no portal:", s["atalaia-cert"]["status"], s["atalaia-cert"].get("version"), s["atalaia-cert"].get("message"))
assert s["atalaia-cert"]["status"] in ("ok", "warn"), s["atalaia-cert"]
PY
  annotate atalaia-portal /tmp/atalaia-check.txt
  exit 1
fi
cat /tmp/atalaia-check.txt
echo "::endgroup::"

echo "::group::password do admin alterada no .env.lab depois do 1.º arranque"
sed -i 's/^DD_ADMIN_PASSWORD=.*/DD_ADMIN_PASSWORD=nova-password-987654/' .env.lab
"${C[@]}" up --no-deps --exit-code-from dd-initializer dd-initializer
timeout 300 "${C[@]}" run --rm --no-deps dd-token
echo "::endgroup::"

echo "OK: laboratório validado contra o DefectDojo real"
