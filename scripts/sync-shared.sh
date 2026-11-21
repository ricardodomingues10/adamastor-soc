#!/usr/bin/env bash
# Copia a camada visual comum do Vigia para o Portal SOC (as duas imagens são construídas de
# contextos diferentes, por isso os ficheiros existem nos dois sítios; o CI verifica que são iguais).
set -euo pipefail
cd "$(dirname "$0")/.."
src=src/vulnflux/web/static
dst=portal/src/socportal/web/static
cp "$src/css/theme.css" "$dst/css/theme.css"
mkdir -p "$dst/fonts"
cp "$src"/fonts/* "$dst/fonts/"
echo "camada comum copiada para o portal"
