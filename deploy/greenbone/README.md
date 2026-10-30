# Greenbone on-demand

O Greenbone deixa de ser um serviço sempre ligado. O VulnFlux liga-o, espera que fique
pronto, corre os scans, recolhe os resultados e desliga-o. Não há interface web, não
há `gvm-cli` e não há scripts bash com lógica.

| Ficheiro | Onde vive | Papel |
|---|---|---|
| `compose.yaml` | host do Greenbone, em `/opt/greenbone/` | Stack mínima, sem gsa/gsad/nginx/gvm-tools |
| `gb-ctl.sh` | host do Greenbone, em `/opt/greenbone/` | Aceita só `start`/`stop`/`update`/`status`; não tem lógica |

O `compose.yaml` foi derivado do compose oficial da Community Edition (feed release 24.10).

## Ciclo de um lote

1. `gb-ctl update`, ou `start` se `VF_GREENBONE_UPDATE_BEFORE_SCAN=false`.
2. **Gate de prontidão** via GMP. O lote só avança quando:
   - o gvmd responde e a autenticação passa;
   - nenhum feed (NVT, SCAP, CERT, GVMD_DATA) está a sincronizar;
   - o feed import owner está definido;
   - a scan config *Full and fast* existe e tem pelo menos `VF_GREENBONE_MIN_NVTS` NVTs;
   - o `verify_scanner` confirma que o OpenVAS responde.
3. Cria ou atualiza os targets e as tasks `vulnflux:<host>` a partir dos hosts da interface web.
4. Corre os scans, no máximo `VF_GREENBONE_CONCURRENCY` em simultâneo.
5. Recolhe e valida os reports, e importa-os no DefectDojo (test "Greenbone", parser OpenVAS).
6. `gb-ctl stop`.

Se o gate falhar, nenhum scan é lançado. As execuções ficam como *Ignorado*, com o motivo
visível no painel, e a stack volta a ser desligada.

## Instalação no host do Greenbone

```bash
sudo useradd --system --create-home --shell /bin/sh --groups docker gbctl
sudo install -d -m 0755 /opt/greenbone
sudo install -d -m 0750 -o gbctl -g gbctl /var/log/greenbone
sudo install -m 0644 compose.yaml /opt/greenbone/compose.yaml
sudo install -m 0755 gb-ctl.sh /opt/greenbone/gb-ctl.sh
sudo apt-get install -y jq
```

O nome do projeto é o mesmo do compose oficial (`greenbone-community-edition`), por isso
os volumes atuais (feeds, BD do gvmd, tasks) são reutilizados. Na primeira vez, corre:

```bash
cd /opt/greenbone
docker compose up -d --remove-orphans   # remove gsa, gsad, nginx e gvm-tools antigos
```

### Utilizador dedicado no gvmd

```bash
docker compose -f /opt/greenbone/compose.yaml exec -u gvmd gvmd \
  gvmd --create-user=orchestrator --role=Admin
docker compose -f /opt/greenbone/compose.yaml exec -u gvmd gvmd \
  gvmd --user=orchestrator --new-password='<password-forte>'
```

A password vai para `VF_GREENBONE_PASSWORD` no `.env` do VulnFlux.

### Chave SSH restrita para o gb-ctl

No servidor do VulnFlux:

```bash
mkdir -p secrets
ssh-keygen -t ed25519 -N '' -C vulnflux-gbctl -f secrets/gbctl_key
ssh-keyscan -H <host-do-greenbone> > secrets/known_hosts   # ou 127.0.0.1 se for a mesma máquina
sudo chown 10001:10001 secrets/gbctl_key secrets/known_hosts && chmod 600 secrets/gbctl_key
```

No host do Greenbone, em `~gbctl/.ssh/authorized_keys`, coloca uma única linha:

```
restrict,command="/opt/greenbone/gb-ctl.sh" ssh-ed25519 AAAA... vulnflux-gbctl
```

Como funciona:
- `restrict` desliga o port forwarding, o PTY, o agent e o X11.
- `command=` força a execução do gb-ctl. O verbo pedido chega em `SSH_ORIGINAL_COMMAND` e é validado contra a lista fixa.
- O container do VulnFlux nunca tem acesso ao `docker.sock`.

> Pertencer ao grupo `docker` equivale a ser root no host. Aqui é aceitável, porque esse
> utilizador só é alcançável através do forced command.

Se o Greenbone estiver na mesma máquina, usa `ssh-keyscan -H host.docker.internal`.
Em alternativa, gera o known_hosts a partir de `/etc/ssh/ssh_host_ed25519_key.pub`,
com o nome `host.docker.internal`.

## Ligação do VulnFlux ao gvmd

Com o Greenbone na mesma máquina, o `docker-compose.greenbone.yml` na raiz do repositório
monta o socket (volume `gb_gvmd_socket`) e configura o SSH. Para arrancar:

```bash
docker compose -f docker-compose.yml -f docker-compose.greenbone.yml up -d --build
```

Confirma as permissões do socket com `docker compose -f /opt/greenbone/compose.yaml exec gvmd ls -ln /run/gvmd/`.
O VulnFlux corre com o uid `10001`. Se o socket não for acessível a esse utilizador, acrescenta
ao serviço `vulnflux`, no override, `group_add: ["<gid do socket>"]`.

## Restart policy

Os serviços core usam `on-failure` em vez do `any` do compose oficial. Com `any`
(equivalente a `always`), um reboot do host voltaria a arrancar a stack inteira mesmo depois de um
`stop`. Com `on-failure`, um reboot respeita o estado parado e só o VulnFlux a volta a ligar.

## Fixar versões

As imagens core estão fixadas por digest no `compose.yaml` (o Dependabot abre um PR quando sai
uma versão nova; o CI valida-a antes de entrar). Os data containers (feeds)
ficam sem tag fixa, porque convém ter sempre o feed mais recente.
