# Mapa da infraestrutura

- `adamastor-infra.drawio`: laboratório e produção, abre em diagrams.net (e daí exporta para .vsdx/Visio).
- `build.py` + `template.html`: geram o mapa interativo e o .drawio a partir do compose resolvido.

```bash
cp lab.env.example .env.lab && sed -i 's/=GERAR/=x/' .env.lab
docker compose -f compose.lab.yaml --env-file .env.lab --profile alvos --profile servers --profile atalaia config --format json > /tmp/cfg.json
python3 docs/infra/build.py /tmp/cfg.json
```

O `build.py` falha se aparecer um contentor no compose que não esteja no mapa.
