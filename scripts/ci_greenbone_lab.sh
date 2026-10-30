#!/usr/bin/env bash
# Greenbone real contra um alvo vulnerável (CI, manual): mede quanto demora um scan e o que encontra.
#
#   1. laboratório completo (Greenbone + DefectDojo + VulnFlux) e o alvo Metasploitable 2
#   2. o VulnFlux espera que os feeds estejam carregados (gate de prontidão)
#   3. scan com o perfil rápido; depois, se houver tempo, com o completo
#   4. resultados (duração, achados por gravidade, CVSS >= 9) em anotações do workflow
#
# PERFIS="rapido completo" escolhe quais correr.

set -Eeuo pipefail
cd "$(dirname "$0")/.."
START=$SECONDS
BUDGET_MIN=${BUDGET_MIN:-330}

cp lab.env.example .env.lab
sed -i 's/=GERAR$/=ci-segredo-123456789/' .env.lab
{
  echo "VF_GREENBONE_READY_TIMEOUT_HOURS=3.5"
  echo "VF_GREENBONE_SCAN_TIMEOUT_HOURS=4"
  echo "VF_WPSCAN_CRON=0 0 1 1 *"
  echo "VF_SERVERS_CRON=0 0 1 1 *"
} >>.env.lab
C=(docker compose -f compose.lab.yaml --env-file .env.lab --profile alvos)

note() { # título, texto
  echo "::notice title=$1::$(printf '%s' "$2" | tr '\n' ' ' | cut -c1-3500)"
}

echo "::group::build e arranque"
"${C[@]}" build vulnflux portal
"${C[@]}" up -d dd-nginx
timeout 1200 "${C[@]}" run --rm --no-deps dd-token
"${C[@]}" up -d
for _ in $(seq 1 90); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8080/healthz
echo "::endgroup::"

for profile in ${PERFIS:-rapido completo}; do
  left=$((BUDGET_MIN - (SECONDS - START) / 60))
  if [ "$left" -lt 40 ]; then
    note "greenbone-$profile" "não corrido: só restavam $left min"
    continue
  fi
  echo "::group::scan $profile (restam $left min)"
  if "${C[@]}" exec -T vulnflux python -m vulnflux.labtools gb-scan alvo-vulneravel.lab alvo-vulneravel "$profile" "$((left - 10))" \
    >"/tmp/gb-$profile.txt" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  cat "/tmp/gb-$profile.txt"
  note "greenbone-$profile" "rc=$rc $(tail -n 1 "/tmp/gb-$profile.txt")"
  note "greenbone-$profile-passos" "$(grep -E '^\s+\[' "/tmp/gb-$profile.txt" | tail -n 12)"
  echo "::endgroup::"
done

"${C[@]}" exec -T vulnflux python - <<'PY' >/tmp/feeds.txt 2>&1 || true
from vulnflux.config import get_settings
from vulnflux.pipeline import readiness_config
from vulnflux.greenbone.readiness import probe
r = probe(readiness_config(get_settings()))
print(r.summary(), "|", " ".join(f"{c.name}={c.detail}" for c in r.checks))
PY
note "greenbone-feeds" "$(cat /tmp/feeds.txt) · total $(((SECONDS - START) / 60)) min"
