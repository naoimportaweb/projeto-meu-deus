# Montando o lab no Qubes OS — guia completo

Como rodar o alvo (`provision.sh`) e um atacante (Kali) **isolados** no Qubes, e
fazer os dois se enxergarem. Documenta a saga de rede que resolvemos, para não
repetir o sofrimento. **Leia isto antes de mexer na rede do Qubes.**

Setup de referência (ajuste os IPs aos seus — pegue com `qvm-ls --fields name,ip`):

| Qube | Papel | IP |
|------|-------|-----|
| `exploitable` | alvo (StandaloneVM Debian, roda `provision.sh`) | `10.137.0.24` |
| `kali` | atacante (HVM, roda `test-lab.sh`) | `10.137.0.21` |
| `sys-net` | netvm dos dois | gateway `10.137.0.x` |

> No Qubes o **IP é fixo por qube** (não muda ao trocar de netvm). Por isso as
> regras abaixo usam IP e sobrevivem a reboot sem ajuste.

---

## 1. Criar e provisionar o alvo

```bash
# no dom0
qvm-create --class StandaloneVM --template debian-13 --label red exploitable
qvm-prefs exploitable memory 2048 ; qvm-prefs exploitable maxmem 2048
qvm-prefs exploitable netvm sys-net        # precisa de internet para o apt
```
Levar o script (qube→qube via qrexec, **nunca** pelo dom0):
```bash
# do qube onde está o repo
qvm-copy-to-vm exploitable /caminho/provision.sh
```
Na `exploitable`: `sudo ./provision.sh` (menu) → gera flags.
Provisione **com internet**; depois é seguro isolar.

---

## 2. Modelo de rede do Qubes (o que você PRECISA saber)

Fonte: doc.qubes-os.org/en/latest/developer/system/networking.html

- **Roteado, não bridge.** Cada qube tem IP **/32** ponto-a-ponto; **NAT em cada
  hop**. Não há L2/broadcast entre qubes.
- IP/gateway vêm via **QubesDB** no boot — mas só para qubes **nativas** (com
  `qubes-core-agent`). Uma **HVM não-nativa (Kali)** NÃO recebe isso sozinha.
- **Qubes isola qube-de-qube por padrão**, em QUALQUER netvm (sys-net, sys-firewall,
  netvm isolada). Internet funciona; vizinho não. Isso é proposital (segurança).

---

## 3. Os três bloqueios (e como cada um se manifesta)

Resolvemos nesta ordem. Sintoma → causa → fix.

### Bloqueio A — atacante não-nativo sem rede (Kali HVM)
**Sintoma:** Kali com IP/gateway errados (ex.: `10.138.31.x`, `nexthop invalid
gateway`, "host unreachable").
**Causa:** sem `qubes-core-agent`, a Kali não pega a config ponto-a-ponto do Qubes.
**Fix (rápido):** usar o DHCP que o Qubes serve para HVMs —
```bash
# na kali
sudo ip addr flush dev eth0
sudo dhclient -v eth0        # pega o 10.137.0.21 + gateway certos
```
Remova rotas estáticas velhas que sobrarem (`ip -4 route`; `ip route del default via <ip-velho>`).
**Fix definitivo:** instalar `qubes-core-agent-networking` na Kali (vira nativa).

### Bloqueio B — sys-net não encaminha entre qubes
**Sintoma:** Kali pinga `8.8.8.8` mas **não** pinga o alvo (e vice-versa).
**Causa:** a chain `forward` da sys-net dropa tráfego para vif de qube:
```
chain forward {
    policy accept;
    jump custom-forward                 # <- roda PRIMEIRO (accept aqui é terminal)
    ct state established,related accept
    oifgroup 2 ... drop                 # <- dropa tudo que sai para um vif (qube vizinho)
}
```
(internet passa porque sai pela eth0, não é `oifgroup 2`.)
**Fix — na `sys-net`, como root:**
```bash
nft add rule ip qubes custom-forward ip saddr 10.137.0.21 ip daddr 10.137.0.24 accept
nft add rule ip qubes custom-forward ip saddr 10.137.0.24 ip daddr 10.137.0.21 accept
```
> Nesta versão do Qubes o mecanismo é `oifgroup 2 drop` + `custom-forward` (NÃO um
> set `allowed { vif . ip }`, que aparece em outras versões/threads). Como o
> `jump custom-forward` vem antes do drop e `accept` é terminal, a regra por IP resolve.

### Bloqueio C — o alvo recusa conexões de entrada
**Sintoma:** depois do B, o alvo pinga a Kali, mas Kali→alvo dá ping sem resposta e
`curl` com **"Connection refused"**.
**Causa:** todo qube tem `input` com `policy drop`; só aceita `established,related`.
Conexão nova de entrada (os serviços!) é barrada:
```
chain input {
    policy drop;
    jump custom-input                   # <- roda PRIMEIRO
    ct state established,related accept
    ...
    <resto cai no drop implícito>        # os pacotes da Kali morrem aqui
}
```
**Fix — na `exploitable`, como root (é alvo proposital, aceita tudo):**
```bash
nft add rule ip qubes custom-input accept
```
> Seguro: a sys-net continua barrando entrada **da internet** para o alvo (ninguém
> liberou forward internet→alvo), então só a Kali/lab alcança.

---

## 4. Persistir as regras (senão somem no reboot/reload)

Lugares **diferentes** porque os papéis são diferentes:

**sys-net (netvm)** → `/rw/config/qubes-firewall-user-script` (roda a cada reload):
```bash
sudo tee /rw/config/qubes-firewall-user-script >/dev/null <<'EOF'
#!/bin/sh
nft flush chain ip qubes custom-forward 2>/dev/null      # idempotente
nft add rule ip qubes custom-forward ip saddr 10.137.0.21 ip daddr 10.137.0.24 accept
nft add rule ip qubes custom-forward ip saddr 10.137.0.24 ip daddr 10.137.0.21 accept
EOF
sudo chmod +x /rw/config/qubes-firewall-user-script
```

**exploitable (qube folha)** → `/rw/config/rc.local` (roda no boot; qube folha NÃO
roda o qubes-firewall-user-script):
```bash
sudo tee -a /rw/config/rc.local >/dev/null <<'EOF'
#!/bin/sh
nft add rule ip qubes custom-input accept
EOF
sudo chmod +x /rw/config/rc.local
```

---

## 4b. Conter o alvo: só fala com a Kali + Internet, nunca com a LAN real

O alvo é vulnerável de propósito — se comprometido, não pode virar trampolim para
atacar a sua rede local. Restrinja a **saída** dele com `qvm-firewall` (aplicado na
netvm, à prova de bypass, e **persiste sozinho** no dom0 — não precisa de rc.local).

**No dom0:**
```bash
qvm-firewall exploitable reset
qvm-firewall exploitable add accept specialtarget=dns       # DNS
qvm-firewall exploitable add accept dst4=10.137.0.21/32     # KALI (único LAN liberado)
qvm-firewall exploitable add drop   dst4=10.0.0.0/8         # bloqueia LAN 10.x
qvm-firewall exploitable add drop   dst4=172.16.0.0/12      # bloqueia LAN 172.x
qvm-firewall exploitable add drop   dst4=192.168.0.0/16     # bloqueia LAN 192.x
qvm-firewall exploitable add accept                         # resto = Internet
```
Regras top-down, primeira que casa vence: Kali aceita antes dos drops de LAN;
públicos caem no `accept` final (Internet). Respostas à Kali são established/related
(sempre ok). Confira com `qvm-firewall exploitable`.

## 5. Testar

```bash
# na kali
ping -c2 10.137.0.24
curl -s http://10.137.0.24/ | head
./test-lab.sh 10.137.0.24         # bateria completa: PASS/FAIL por vuln
```
Ferramentas úteis na Kali: já vêm `curl`, `dig`, `smbclient`, `nc`; confira
`redis-tools` e `nfs-common` (senão esses checks viram `[SKIP]`).

---

## Diagnóstico (cola destes quando algo não anda)

```bash
# no atacante:  tem rota? pinga internet? pinga o vizinho?
ip -4 route ; ping -c2 8.8.8.8 ; ping -c2 <ip-alvo>
# curl -v <alvo>  → "Connection refused" = input do alvo (Bloqueio C)
#                  timeout                = forward da netvm (Bloqueio B)

# na netvm (sys-net):
sudo nft list chain ip qubes forward
sudo nft list chain ip qubes custom-forward

# no alvo:
sudo nft list chain ip qubes input
sudo nft list chain ip qubes custom-input
```

**Regra de ouro:** internet OK + vizinho não = firewall do Qubes, não a sua config.
Beco sem saída: testar de um qube em netvm **diferente** do alvo — o NAT por hop
reescreve a origem e a regra por IP não casa. Ataque sempre da **mesma netvm** do alvo.
