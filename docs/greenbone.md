# Greenbone: scans que demoram ou não terminam

No laboratório, cada scan demora 4 a 7 minutos. Quando um scan real passa das horas, a causa está
quase sempre no alvo e não no VulnFlux. Estes são os multiplicadores conhecidos e o que o VulnFlux
faz com cada um.

| Causa | Efeito | O que o VulnFlux faz | Definição |
| --- | --- | --- | --- |
| Vários vhosts no mesmo IP (nomes no certificado, DNS reverso) | O OpenVAS repete todos os testes em cada vhost: 20 vhosts são 20 vezes mais tempo | Desliga a expansão de vhosts nas configs que gere | `VF_GREENBONE_EXPAND_VHOSTS=false` |
| WAF ou IPS a bloquear o scanner | Cada teste bloqueado espera até ao limite (o OpenVAS usa 320 s) | Limita cada teste a 120 s | `VF_GREENBONE_PLUGINS_TIMEOUT=120` |
| Firewall que descarta pacotes | O varrimento de portas fica muito lento | Recomenda o perfil `descoberta` (portas pela sonda nmap) ou `rapido` | `VF_GREENBONE_PROFILE` |
| Host que não responde a ping | É dado como morto e o scan termina sem resultados | Permite outro teste de host vivo | `VF_GREENBONE_ALIVE_TEST` |
| Scan preso num teste | Fica parado em 98-99% durante horas | Deteta a falta de progresso e para o scan | `VF_GREENBONE_STALL_HOURS=3` |

## O que acontece quando um scan passa do prazo

O prazo (`VF_GREENBONE_SCAN_TIMEOUT_HOURS`, 8 h) conta só enquanto o gvmd está a correr o scan; o
tempo em fila não conta. Quando o prazo se esgota, ou o scan fica `VF_GREENBONE_STALL_HOURS` sem
avançar, o VulnFlux:

1. para a task no gvmd;
2. recolhe o report com o que já foi encontrado;
3. importa-o no DefectDojo **sem fechar findings antigos** (o que não apareceu pode ainda existir);
4. marca a execução como "com avisos", com o motivo, o progresso ao longo do tempo e uma dica.

Com `VF_GREENBONE_IMPORT_PARTIAL=false`, o scan parado é dado como falhado e nada é importado.

## Onde parou diz quase sempre porquê

- **Acima de 90%:** os últimos testes são normalmente os testes web. Um WAF a bloquear o scanner ou
  muitos vhosts. Põe o IP do scanner na lista de exceções do WAF ou usa o perfil rápido.
- **Abaixo de 10%:** ainda no varrimento de portas. Uma firewall que descarta pacotes. Usa o perfil
  descoberta ou o rápido.
- **No meio:** tudo avança devagar. Reduz `VF_GREENBONE_CONCURRENCY` (scans em paralelo) ou
  `VF_GREENBONE_MAX_CHECKS` (testes em paralelo por host).

## Teste de host vivo

Valores aceites em `VF_GREENBONE_ALIVE_TEST` (vazio usa o da scan config):
`ICMP Ping`, `TCP-ACK Service Ping`, `TCP-SYN Service Ping`, `ARP Ping`,
`ICMP & TCP-ACK Service Ping`, `ICMP & ARP Ping`, `TCP-ACK Service & ARP Ping`,
`ICMP, TCP-ACK Service & ARP Ping`, `Consider Alive`, `Scan Config Default`.

`Consider Alive` analisa o host mesmo que não responda: útil atrás de firewalls, mas um IP sem
nada por trás fica a ser analisado até ao prazo.

## Configs geridas

O VulnFlux cria clones do Full and fast com o nome `VulnFlux · <perfil> · <resumo>`. O resumo muda
quando mudam as preferências, e a task passa para a config nova (o gvmd não deixa alterar uma
config em uso nem as predefinidas). As configs antigas podem ser apagadas no GSA.
