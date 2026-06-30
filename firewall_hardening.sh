#!/bin/bash
# ==============================================================================
# hardening_firewall.sh — Hardening de borda do host (iptables)
# Projeto SOC / Lab SENAC-DF · Autor: Diego Machado
#
# Política positiva (default DROP), defesa em profundidade, log com rate limit,
# cobertura IPv4 + IPv6 e persistência. Idempotente: pode rodar várias vezes.
#
# MITRE D3FEND: D3-ITF (Inbound Traffic Filtering), D3-NTF (Network Traffic Filtering)
# Mitiga: T1110 (Brute Force), T1046 (Network Service Scanning), T1190, T1090
# ==============================================================================
set -euo pipefail

# ----------------------------- PARÂMETROS -------------------------------------
# Ajuste estas variáveis ao seu lab. Deixe MGMT_NET vazio ("") para liberar SSH
# de qualquer origem (NÃO recomendado fora de lab isolado).
MGMT_NET="192.168.56.0/24"      # rede de gerência autorizada a falar SSH
NAGIOS_SERVER="192.168.56.10"   # único IP que pode acessar o NRPE (5666)
ALLOW_WEB="true"                # "true" libera 80/443; "false" fecha
ALLOW_PING="true"               # "true" responde ping (rate-limited)
SSH_PORT="22"

LOG_PREFIX4="FIREWALL_DROP: "
LOG_PREFIX6="FIREWALL6_DROP: "

# ----------------------------- PRÉ-CHECKS -------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "[ERRO] Rode como root."; exit 1; }
command -v iptables >/dev/null  || { echo "[ERRO] iptables ausente."; exit 1; }

echo "[*] Iniciando hardening de firewall..."

# ==============================================================================
# IPv4
# ==============================================================================
echo "[*] Limpando regras IPv4 antigas..."
# IMPORTANTE: NÃO setar policy DROP agora. Primeiro liberamos o essencial,
# e só ao final fechamos. Isso evita lockout de sessão SSH remota.
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X

# --- Cadeia dedicada: loga (com teto) e descarta -----------------------------
# Sem -m limit, um scan/flood encheria /var/log e travaria o I/O (HDD).
iptables -N LOGDROP
iptables -A LOGDROP -m limit --limit 5/min --limit-burst 10 \
  -j LOG --log-prefix "$LOG_PREFIX4" --log-level 6
iptables -A LOGDROP -j DROP

echo "[*] Regras de estado e anti-spoof..."
# Descarta pacotes em estado inválido (malformados / fora de fluxo)
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
# Loopback liberado; bloqueia spoof de loopback vindo de outra interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j LOGDROP
# Conexões já estabelecidas (mantém SSH atual vivo)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- ICMP (ping) controlado --------------------------------------------------
if [ "$ALLOW_PING" = "true" ]; then
  echo "[*] Liberando ICMP echo (rate-limited)..."
  iptables -A INPUT -p icmp --icmp-type echo-request \
    -m limit --limit 1/s --limit-burst 4 -j ACCEPT
fi

# --- SSH: escopo de rede + proteção brute force ------------------------------
echo "[*] Configurando SSH (porta $SSH_PORT) com proteção brute force..."
SSH_SRC=()
[ -n "$MGMT_NET" ] && SSH_SRC=(-s "$MGMT_NET")
# Marca novas conexões e bloqueia >3 tentativas/60s da mesma origem
iptables -A INPUT "${SSH_SRC[@]}" -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
  -m recent --set --name SSHPROBE
iptables -A INPUT "${SSH_SRC[@]}" -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSHPROBE -j LOGDROP
iptables -A INPUT "${SSH_SRC[@]}" -p tcp --dport "$SSH_PORT" -j ACCEPT

# --- Serviço Web -------------------------------------------------------------
if [ "$ALLOW_WEB" = "true" ]; then
  echo "[*] Liberando 80/443..."
  iptables -A INPUT -p tcp --dport 80  -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
fi

# --- NRPE (Nagios) restrito ao servidor de monitoramento ---------------------
if [ -n "$NAGIOS_SERVER" ]; then
  echo "[*] Liberando NRPE 5666 apenas para $NAGIOS_SERVER..."
  iptables -A INPUT -p tcp -s "$NAGIOS_SERVER" --dport 5666 -j ACCEPT
fi

# --- Tudo que sobrou: loga e descarta ----------------------------------------
iptables -A INPUT -j LOGDROP

echo "[*] Aplicando política restritiva final (default DROP)..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT   # egress liberado neste estágio (ver [PRÓXIMO] no README)

# ==============================================================================
# IPv6 — sem isto, o firewall IPv4 pode ser contornado via IPv6
# ==============================================================================
if command -v ip6tables >/dev/null; then
  echo "[*] Endurecendo IPv6..."
  ip6tables -P INPUT ACCEPT; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT
  ip6tables -F; ip6tables -X
  ip6tables -N LOGDROP6
  ip6tables -A LOGDROP6 -m limit --limit 5/min --limit-burst 10 \
    -j LOG --log-prefix "$LOG_PREFIX6" --log-level 6
  ip6tables -A LOGDROP6 -j DROP
  ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  # ICMPv6 é OBRIGATÓRIO (NDP/descoberta de vizinho). Bloquear quebra o IPv6.
  ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
  ip6tables -A INPUT -j LOGDROP6
  ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT ACCEPT
fi

# ==============================================================================
# PERSISTÊNCIA — sem isto, tudo some no reboot
# ==============================================================================
echo "[*] Salvando regras para sobreviver a reboot..."
if command -v netfilter-persistent >/dev/null; then
  netfilter-persistent save
elif [ -d /etc/iptables ]; then
  iptables-save  > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
else
  echo "[AVISO] iptables-persistent não instalado. Instale com:"
  echo "        sudo apt install iptables-persistent netfilter-persistent"
  iptables-save  > /etc/iptables.rules.v4
  ip6tables-save > /etc/iptables.rules.v6 2>/dev/null || true
fi

echo "[OK] Firewall endurecido e persistido."
echo "[i] Verifique com: sudo iptables -L -n -v --line-numbers"
