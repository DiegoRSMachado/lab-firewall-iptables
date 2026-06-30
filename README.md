# Lab — Hardening de Firewall + Detecção SOC (iptables → Wazuh)

Endurecimento de borda de host com `iptables` (política positiva, IPv4 + IPv6,
proteção brute force, logging controlado e persistência) **integrado a detecção**
no Wazuh, com correlação de port scan e brute force SSH mapeada ao MITRE ATT&CK.

Lab acadêmico/supervisionado (SENAC-DF). Defensivo — Blue Team.

## Arquivos

| Arquivo | Função | Destino |
|---|---|---|
| `hardening_firewall.sh` | Aplica e persiste as regras de firewall | host alvo |
| `local_decoder.xml` | Parseia o log `FIREWALL_DROP` (srcip, dstport…) | `/var/ossec/etc/decoders/` |
| `local_rules.xml` | Regras de correlação (scan / brute force) | `/var/ossec/etc/rules/` |
| `sigma_iptables_portscan.yml` | Regra Sigma portável (T1046) | repositório de detecções |

## Arquitetura de defesa

Política **default DROP** na entrada; só o estritamente necessário é liberado, na ordem:
estado inválido descartado → loopback → conexões estabelecidas → ICMP controlado →
SSH (com escopo de rede + rate limit) → web → NRPE restrito → o resto é logado e descartado.

| Vetor | ATT&CK | Controle aplicado | D3FEND |
|---|---|---|---|
| Brute force SSH | T1110 | `recent`: >3 conexões NEW/60s da mesma origem → LOGDROP; escopo `MGMT_NET` | D3-ITF |
| Port/Service scan | T1046 | default DROP + correlação de drops por origem | D3-NTF |
| Exploit de serviço exposto | T1190 | NRPE 5666 só do IP do Nagios; web opcional | D3-ITF |
| Spoofing / evasão | T1090 | drop `INVALID`; anti-spoof de loopback | D3-NTF |
| Bypass por IPv6 | — | `ip6tables` espelhado (ICMPv6/NDP preservado) | D3-ITF |

## Como usar

### 1. Ajustar parâmetros
Edite o topo do `hardening_firewall.sh` com os IPs do seu lab:
```bash
MGMT_NET="192.168.56.0/24"      # rede autorizada a falar SSH
NAGIOS_SERVER="192.168.56.10"   # único IP liberado no NRPE
ALLOW_WEB="true"                # 80/443
ALLOW_PING="true"               # ICMP echo rate-limited
```

### 2. (Pré-requisito) persistência
```bash
sudo apt update && sudo apt install -y iptables-persistent netfilter-persistent
```

### 3. Rede de segurança contra lockout (execução remota)
Antes de aplicar via SSH, agende um resgate que limpa o firewall se você se trancar:
```bash
echo "iptables -P INPUT ACCEPT; iptables -F" | sudo at now + 5 minutes
# se continuar conectado depois de validar, cancele o resgate:
sudo atq          # veja o ID do job
sudo atrm <ID>
```

### 4. Aplicar
```bash
sudo bash hardening_firewall.sh
sudo iptables -L -n -v --line-numbers     # conferir
```

### 5. Plugar a detecção no Wazuh
```bash
sudo cp local_decoder.xml /var/ossec/etc/decoders/
sudo cp local_rules.xml   /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```
Garanta que o agente coleta o kernel log (onde o iptables grava). No `ossec.conf` do agente:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>
```

## Validação (provar que funciona)

```bash
# 1. De outra máquina do lab (ex.: Kali), bater numa porta fechada gera FIREWALL_DROP:
nmap -sS -p 1-1000 <IP_DO_HOST>

# 2. No host, ver o log sendo gerado:
sudo grep "FIREWALL_DROP" /var/log/kern.log | tail

# 3. No Wazuh, testar o parse e a regra com um evento de exemplo:
sudo /var/ossec/bin/wazuh-logtest
# cole uma linha real de kern.log com "FIREWALL_DROP:" e verifique se cai na regra 100100/100101
```

Resultado esperado: o scan dispara a regra **100101** (port scan, nível 10) por excesso
de drops da mesma origem; tentativas repetidas na porta 22 disparam a **100102** (brute force, nível 12).

## Triagem (reduzir falso-positivo)

Antes de tratar como incidente, descarte causas legítimas:
- A origem é o **scanner autorizado** (Nessus/OpenVAS) numa janela de teste agendada? → falso-positivo.
- É **health check / monitoração** batendo em porta fechada? → ajuste o monitor ou crie exceção por IP.
- Origem é o próprio `NAGIOS_SERVER`? Não deveria gerar drop — se gerar, revise a regra do NRPE.
Caso contrário (origem desconhecida, varredura ampla): trate como **recon (T1046)** e
verifique se houve conexão subsequente bem-sucedida em alguma porta aberta.

## Custo no hardware (i5 2013 / 16GB / HDD)

`iptables` é stateless em CPU/RAM para esse volume — custo desprezível. O ponto sensível é
**I/O de disco do logging**: por isso o `LOGDROP` usa `-m limit --limit 5/min`, evitando que
um flood encha `/var/log` e trave o HDD. Sem esse teto, um scan agressivo geraria milhares de
linhas/segundo. Viável e leve no seu hardware.

## Próximos passos

1. **Egress filtering (D3-OTF, anti-C2 / T1571):** trocar `OUTPUT ACCEPT` por default DROP na
   saída, liberando só DNS, NTP, HTTP/S e os destinos necessários. Reduz exfiltração e C2.
2. **fail2ban ou CrowdSec** sobre o SSH, complementando o rate limit do kernel com ban dinâmico.
3. **Migração para nftables** (`nft`), padrão atual do kernel — mesmas políticas, sintaxe unificada.
4. **Dashboard Wazuh** com as regras 1001xx para evidência visual de tentativas bloqueadas.

---
**Autor:** Diego Machado · Lab SENAC-DF · Blue Team / SOC
