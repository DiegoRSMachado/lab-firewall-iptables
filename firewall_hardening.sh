#!/bin/bash
# Script de Hardening de Rede - Projeto SOC
# Autor: Diego Machado

echo "Iniciando configuracao do Firewall..."

# 1. Limpar regras antigas
iptables -F
iptables -X

# 2. Politica Padrao: BLOQUEAR TUDO na entrada (Seguranca Positiva)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Aceitar trafego local (Loopback)
iptables -A INPUT -i lo -j ACCEPT

# 4. Aceitar conexoes ja estabelecidas (Para nao derrubar o SSH atual)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 5. Liberar SSH (Porta 22) - Gestao
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# 6. Liberar Servidor Web (80/443) - Se houver servico rodando
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 7. Liberar Monitoramento Nagios (NRPE - 5666)
iptables -A INPUT -p tcp --dport 5666 -j ACCEPT

# 8. REGRA DE OURO DO SOC: Logar o que for bloqueado antes de descartar
# Isso gera evidencias para analise de incidentes
iptables -A INPUT -j LOG --log-prefix "FIREWALL_DROP: " --log-level 6

echo "Firewall configurado com sucesso."
