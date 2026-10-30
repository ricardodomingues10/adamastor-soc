#!/usr/bin/env bash
# Greenbone real contra um alvo vulnerável (CI, manual): mede quanto demora um scan e o que encontra.
#
#   1. laboratório completo (Greenbone + DefectDojo + VulnFlux) e os alvos (Apache 2.4.49 e Metasploitable 2)
#   2. o VulnFlux espera que os feeds estejam carregados (gate de prontidão)
#   3. o mesmo alvo com cada perfil: descoberta (nmap → portas abertas), rápido e completo
#   4. resultados (duração, portas vistas, achados por gravidade, CVSS >= 9) em anotações do workflow
#
# PERFIS="descoberta rapido completo" escolhe quais correr (pela ordem).

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
BACKUP_UID="$(id -u)"
BACKUP_GID="$(id -g)"
export BACKUP_UID BACKUP_GID
mkdir -p .lab/backups .lab/atalaia/secrets

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

# Isolamento: os alvos só são alcançáveis a partir do scanner e da sonda (rede "alvos", internal).
# "Ligação recusada" é alcançável (a rede chegou lá); isolado é não resolver o nome ou não haver resposta.
census='import socket,sys
for host, ports in (("alvo-web", (80,)), ("alvo-vulneravel", (21, 22, 23, 25, 80, 139, 445, 3306, 5432, 6667, 8180))):
    seen = []
    for p in ports:
        try:
            socket.create_connection((host, p), timeout=4).close(); seen.append(f"{p}:aberta")
        except ConnectionRefusedError:
            seen.append(f"{p}:fechada")
        except OSError as e:
            seen.append(f"{p}:inalcançável({e.__class__.__name__})")
    print(host, " ".join(seen))'
reach() { # serviço → linhas do censo
  "${C[@]}" exec -T "$1" "$2" -c "$census" 2>&1 || true
}
for _ in $(seq 1 12); do
  iso_scanner=$(reach ospd-openvas python3)
  case "$iso_scanner" in *"80:aberta"*) break ;; esac
  sleep 10
done
iso_sonda=$(reach sonda python3)
iso_vulnflux=$(reach vulnflux python)
note "greenbone-alvos" "ospd-openvas vê: $iso_scanner"
note "greenbone-isolamento" "sonda: $iso_sonda || vulnflux: $iso_vulnflux"
case "$iso_scanner" in *"alvo-web 80:aberta"*) ;; *) echo "::error title=isolamento::o scanner não chega ao alvo-web"; exit 1 ;; esac
case "$iso_sonda" in *"alvo-web 80:aberta"*) ;; *) echo "::error title=isolamento::a sonda não chega ao alvo-web"; exit 1 ;; esac
case "$iso_vulnflux" in *aberta* | *fechada*) echo "::error title=isolamento::o VulnFlux chega aos alvos"; exit 1 ;; esac

failed=0
for profile in ${PERFIS:-descoberta rapido completo}; do
  left=$((BUDGET_MIN - (SECONDS - START) / 60))
  if [ "$left" -lt 40 ]; then
    note "greenbone-$profile" "não corrido: só restavam $left min"
    continue
  fi
  echo "::group::scan $profile (restam $left min)"
  if "${C[@]}" exec -T vulnflux python -m vulnflux.labtools gb-scan alvo-web.lab alvo-web "$profile" "$((left - 10))" \
    >"/tmp/gb-$profile.txt" 2>&1; then
    rc=0
  else
    rc=$?
    failed=1
  fi
  cat "/tmp/gb-$profile.txt"
  note "greenbone-$profile" "rc=$rc $(grep -v '^\s*<' "/tmp/gb-$profile.txt" | tail -n 3)"
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
# Metasploitable no fim, se houver tempo (perfil descoberta: mostra o que está mesmo a correr)
left=$((BUDGET_MIN - (SECONDS - START) / 60))
if [ "$left" -ge 40 ]; then
  "${C[@]}" exec -T vulnflux python -m vulnflux.labtools gb-scan alvo-vulneravel.lab alvo-vulneravel descoberta "$((left - 10))" \
    >/tmp/gb-msf.txt 2>&1 || true
  note "greenbone-metasploitable" "$(grep -v '^\s*<' /tmp/gb-msf.txt | tail -n 3)"
fi
note "greenbone-feeds" "$(cat /tmp/feeds.txt) · total $(((SECONDS - START) / 60)) min"
exit "$failed"
