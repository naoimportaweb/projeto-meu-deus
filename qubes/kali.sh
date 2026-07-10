#!/usr/bin/env bash
# ============================================================
#  kali.sh   ->  RODAR NA VM: kali (o atacante)
#  Rodar:   bash kali.sh      (nao precisa de root)
# ------------------------------------------------------------
#  Prova que a kali alcanca o alvo e valida as vulns/flags.
# ============================================================
set -uo pipefail

# ---- IP do alvo (edite se o seu diferir) ----
ALVO_IP="${ALVO_IP:-10.137.0.24}"   # exploitable (alvo)

echo "== kali -> alvo ($ALVO_IP) : deve funcionar =="
ping -c2 -W2 "$ALVO_IP" && echo "[ping OK]" || echo "[ping FALHOU - checar sysnet.sh/exploitable.sh]"
echo
echo "-- curl na porta 80 --"
curl -s -m5 "http://$ALVO_IP/" | head -n 5 || echo "(sem resposta em :80)"
echo
if [ -x ./test-lab.sh ]; then
  echo "== rodando ./test-lab.sh $ALVO_IP =="
  ./test-lab.sh "$ALVO_IP"
else
  echo "(test-lab.sh nao esta aqui; copie-o pra kali e rode:  ./test-lab.sh $ALVO_IP)"
fi
