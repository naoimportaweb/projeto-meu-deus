#!/usr/bin/env bash
# ============================================================
#  sysnet.sh   ->  RODAR NA VM: sys-net
#  Rodar como root:   sudo bash sysnet.sh
# ------------------------------------------------------------
#  Faz TUDO que a sys-net precisa, de uma vez:
#   - libera kali <-> exploitable (comunicacao do lab)
#   - da Internet ao alvo (inclui DNS)
#   - BLOQUEIA a sua LAN real e os outros qubes (contencao)
#   - persiste pra sobreviver a reboot
#  Idempotente: pode rodar de novo sem medo (faz flush antes).
# ============================================================
set -euo pipefail

# ---- IPs (edite se os seus diferirem) ----
KALI_IP="${KALI_IP:-10.137.0.21}"   # kali (atacante)
ALVO_IP="${ALVO_IP:-10.137.0.24}"   # exploitable (alvo)

[ "$(id -u)" -eq 0 ] || { echo "rode como root:  sudo bash $0"; exit 1; }

echo "== checando se kali e alvo estao atras desta sys-net =="
for ip in "$KALI_IP" "$ALVO_IP"; do
  if ip -4 route show | grep -qE "(^|[[:space:]])$ip([[:space:]]|/)"; then
    echo "  [ok]    $ip"
  else
    echo "  [AVISO] $ip nao aparece nas rotas — confira a netvm dele antes de confiar"
  fi
done
echo

# ---- aplica ao vivo ----
nft flush chain ip qubes custom-forward 2>/dev/null || true
# comunicacao: kali <-> exploitable  (ANTES dos drops; kali esta em 10/8)
nft add rule ip qubes custom-forward ip saddr "$KALI_IP" ip daddr "$ALVO_IP" accept
nft add rule ip qubes custom-forward ip saddr "$ALVO_IP" ip daddr "$KALI_IP" accept
# DNS do alvo (senao apt nao resolve nomes; DNS do Qubes em 10.139.1.x)
nft add rule ip qubes custom-forward ip saddr "$ALVO_IP" udp dport 53 accept
nft add rule ip qubes custom-forward ip saddr "$ALVO_IP" tcp dport 53 accept
# bloqueia faixas privadas: sua LAN real + outros qubes
nft add rule ip qubes custom-forward ip saddr "$ALVO_IP" ip daddr 10.0.0.0/8     drop
nft add rule ip qubes custom-forward ip saddr "$ALVO_IP" ip daddr 172.16.0.0/12  drop
nft add rule ip qubes custom-forward ip saddr "$ALVO_IP" ip daddr 192.168.0.0/16 drop
# (sem drop final) -> IP publico cai no forward normal do Qubes -> Internet OK
echo "[+] regras aplicadas ao vivo."

# ---- persiste ----
tee /rw/config/qubes-firewall-user-script >/dev/null <<EOF
#!/bin/sh
nft flush chain ip qubes custom-forward 2>/dev/null
nft add rule ip qubes custom-forward ip saddr ${KALI_IP} ip daddr ${ALVO_IP} accept
nft add rule ip qubes custom-forward ip saddr ${ALVO_IP} ip daddr ${KALI_IP} accept
nft add rule ip qubes custom-forward ip saddr ${ALVO_IP} udp dport 53 accept
nft add rule ip qubes custom-forward ip saddr ${ALVO_IP} tcp dport 53 accept
nft add rule ip qubes custom-forward ip saddr ${ALVO_IP} ip daddr 10.0.0.0/8     drop
nft add rule ip qubes custom-forward ip saddr ${ALVO_IP} ip daddr 172.16.0.0/12  drop
nft add rule ip qubes custom-forward ip saddr ${ALVO_IP} ip daddr 192.168.0.0/16 drop
EOF
chmod +x /rw/config/qubes-firewall-user-script
echo "[+] persistido em /rw/config/qubes-firewall-user-script"
echo
echo "== custom-forward final (confira a ordem: accepts, DNS, depois os drops) =="
nft list chain ip qubes custom-forward
