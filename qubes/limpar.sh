#!/usr/bin/env bash
# ============================================================
#  limpar.sh   ->  DESFAZ a config de rede do lab no Qubes
#  Auto-detecta a VM (dom0 / sys-net / exploitable) ou receba
#  o papel explicito:   sudo bash limpar.sh [sysnet|exploitable|dom0]
# ------------------------------------------------------------
#  Reverte o que sysnet.sh / exploitable.sh (e o qvm-firewall
#  do QUBES.md) aplicaram, restaurando o Qubes ao padrao:
#    - sys-net:      esvazia a chain custom-forward + remove
#                    /rw/config/qubes-firewall-user-script
#    - exploitable:  esvazia a chain custom-input     + remove
#                    /rw/config/rc.local
#    - dom0:         qvm-firewall <alvo> reset
#  Idempotente: rodar de novo, ou sem nada pra limpar, e' seguro.
#  Os arquivos de persistencia sao salvos em .bak antes de sair.
#
#  NAO apaga a VM nem mexe em qvm-prefs (netvm etc). Pra remover
#  o qube inteiro:  qvm-remove <alvo>   (no dom0, irreversivel).
# ============================================================
set -euo pipefail

# ---- nome do qube alvo (so usado no papel dom0) ----
ALVO_VM="${ALVO_VM:-exploitable}"

# ---- saida padronizada (mesmo estilo dos outros scripts) ----
log()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "rode como root:  sudo bash $0 $ROLE"; }

# Remove um arquivo de persistencia com cuidado:
#  - ausente -> nada a fazer
#  - contem SO linhas do lab (shebang/comentario/nft custom-*) -> backup + remove
#  - contem linhas estranhas -> backup + AVISA e mantem (nao apaga config alheia)
limpar_arquivo() {
  local f="$1"
  [ -f "$f" ] || { log "$f: ja nao existe."; return; }
  cp -a "$f" "${f}.bak"
  if grep -qvE '^\s*(#|$)|custom-forward|custom-input|nft ' "$f"; then
    warn "$f tem linhas que nao sao do lab — backup em ${f}.bak, arquivo MANTIDO."
    warn "    revise e remova a mao se quiser."
  else
    rm -f "$f"
    log "$f removido (backup em ${f}.bak)."
  fi
}

# ---- limpezas por papel ----
clean_sysnet() {
  need_root
  log "sys-net: esvaziando a chain custom-forward (regras do lab)..."
  nft flush chain ip qubes custom-forward 2>/dev/null \
    || warn "chain custom-forward ausente (nada a esvaziar)."
  limpar_arquivo /rw/config/qubes-firewall-user-script
  echo
  log "custom-forward agora (deve estar vazia):"
  nft list chain ip qubes custom-forward 2>/dev/null || true
  echo
  log "Feito. A internet/vizinhos do alvo voltam ao padrao do Qubes."
}

clean_exploitable() {
  need_root
  log "exploitable: esvaziando a chain custom-input (regra do lab)..."
  nft flush chain ip qubes custom-input 2>/dev/null \
    || warn "chain custom-input ausente (nada a esvaziar)."
  limpar_arquivo /rw/config/rc.local
  echo
  log "custom-input agora (deve estar vazia):"
  nft list chain ip qubes custom-input 2>/dev/null || true
  echo
  warn "Lembrete: com input no padrao (policy drop), a kali PARA de alcancar o alvo."
  log  "Feito."
}

clean_dom0() {
  command -v qvm-firewall >/dev/null 2>&1 || die "qvm-firewall ausente — isto nao parece o dom0."
  log "dom0: qvm-firewall $ALVO_VM reset (volta ao padrao: aceita tudo)..."
  qvm-firewall "$ALVO_VM" reset || die "falhou o reset — confira o nome do qube (ALVO_VM=$ALVO_VM)."
  echo
  log "Regras de $ALVO_VM agora:"
  qvm-firewall "$ALVO_VM" || true
  echo
  log "Feito. (A contencao de LAN via qvm-firewall foi removida.)"
}

# ---- deteccao de papel ----
detectar_papel() {
  command -v qvm-firewall >/dev/null 2>&1 && { echo dom0; return; }
  if [ -f /rw/config/qubes-firewall-user-script ] \
     && grep -q custom-forward /rw/config/qubes-firewall-user-script; then
    echo sysnet; return
  fi
  if [ -f /rw/config/rc.local ] && grep -q custom-input /rw/config/rc.local; then
    echo exploitable; return
  fi
  # fallback: olha as chains ao vivo
  if nft list chain ip qubes custom-forward 2>/dev/null | grep -q 'ip daddr'; then
    echo sysnet; return
  fi
  if nft list chain ip qubes custom-input 2>/dev/null | grep -q 'ip saddr'; then
    echo exploitable; return
  fi
  echo desconhecido
}

# ---- despacho ----
ROLE="${1:-auto}"
case "$ROLE" in
  auto)
    ROLE="$(detectar_papel)"
    [ "$ROLE" = desconhecido ] && die "nao consegui detectar a VM. Rode com o papel:  sudo bash $0 [sysnet|exploitable|dom0]"
    log "papel detectado: $ROLE"
    ;;
  sysnet|exploitable|dom0) ;;
  -h|--help)
    echo "Uso: sudo bash $0 [sysnet|exploitable|dom0]   (sem argumento = auto-detecta)"
    echo "     ALVO_VM=<nome> ...   (nome do qube no papel dom0; padrao: exploitable)"
    exit 0 ;;
  *) die "papel invalido: '$ROLE' (use sysnet|exploitable|dom0, ou nada p/ auto)";;
esac

case "$ROLE" in
  sysnet)      clean_sysnet ;;
  exploitable) clean_exploitable ;;
  dom0)        clean_dom0 ;;
esac
