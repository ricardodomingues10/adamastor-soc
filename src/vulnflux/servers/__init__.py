"""Servidores: saúde, hardening e atualizações por SSH, sem agente.

ssh.py        chave própria do VulnFlux, confiança nas chaves dos hosts (TOFU) e execução
bootstrap.py  comando de ligação (conta + chave + sudo limitado), perfis verificar e atualizar
scripts/      collect.sh (só leitura) e patch.sh (aplicar atualizações)
checks.py     da saída da recolha ao relatório (saúde, hardening com pontuação, atualizações)
findings.py   relatório → findings do DefectDojo (hardening falhado e atualizações de segurança)
job.py        execuções Verificar e Atualizar (aparecem em Execuções como as outras)
cycles.py     ciclos de atualização por anéis 0 → 3, com observação entre anéis e aprovação no 3
"""
