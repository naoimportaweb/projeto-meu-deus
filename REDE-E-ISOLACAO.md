# Rede e isolação do lab no Qubes (sem dom0)

Guia completo de como fazer a **kali** (atacante) e a **exploitable** (alvo do
`provision.sh`) se comunicarem no Qubes **e** conter o alvo, tocando **apenas** em
`sys-net`, `kali` e `exploitable` — **sem mexer no dom0** (sem `qvm-firewall`).

> Complementa o `QUBES.md` (que documenta a via `qvm-firewall`, no dom0). Aqui a
> contenção é feita com `nft` na `sys-net`.

## Topologia de referência

| Qube | Papel | IP (fixo por qube) |
|------|-------|--------------------|
| `kali` | atacante | `10.137.0.21` |
| `exploitable` | alvo (`provision.sh`) | `10.137.0.24` |
| `sys-net` | netvm dos dois | gateway `10.137.0.x` |
| roteador real | sua LAN física | `192.168.100.1` |

Ambos os qubes ficam **na mesma netvm** (`sys-net`). Isso é obrigatório: se
estiverem atrás de netvms diferentes, o **NAT por hop** reescreve o IP de origem e
as regras por IP não casam.

---

## Política escolhida: "Internet sim, LAN não"

O alvo é **propositalmente vulnerável**. Se comprometido, não pode virar trampolim
para a sua rede física. Mas também queremos **Internet no alvo** para o `apt`/
`provision.sh` funcionarem sem religar nada toda hora.

A política aplicada:

| Do alvo para… | Ação |
|---------------|------|
| `kali` | **ACEITA** (é o ataque do lab) |
| Internet (IP público) | **ACEITA** (`apt`, updates) |
| sua LAN real (`192.168.x`, `10.x`, `172.16.x`) | **BLOQUEIA** |
| outros qubes | **BLOQUEIA** |

Resultado: protege a sua rede sem te obrigar a alternar Internet.

> **Alternativa mais rígida (isolação total):** trocar os `drop` de faixa por um
> único `drop` de tudo que não seja a kali. O alvo passa a falar **só com a kali**
> (nem Internet). Mais seguro, mas exige liberar a Internet temporariamente sempre
> que for instalar algo. Não é a política deste guia.

---

## Modelo de rede do Qubes (o que você precisa saber)

- **Roteado, não bridge.** Cada qube tem IP `/32`; **NAT em cada hop**. Sem L2 entre
  qubes.
- **Qubes isola qube-de-qube por padrão**, em qualquer netvm. Internet funciona;
  vizinho, não. É proposital.
- IP/rota vêm via **QubesDB** no boot, mas só para qubes **nativas**
  (`qubes-core-agent`). HVM não-nativa (Kali sem o agent) não recebe isso sozinha.

### Os três planos (não confundir)

A comunicação + contenção envolve **três controles diferentes**, cada um num lugar:

| Plano | O que controla | Onde a regra vive | Persiste em |
|-------|----------------|-------------------|-------------|
| **Forward** | `sys-net` deixa (ou não) um qube falar com outro / Internet | `sys-net`, chain `custom-forward` | `/rw/config/qubes-firewall-user-script` |
| **Input** | o alvo aceita (ou não) conexão nova de entrada | `exploitable`, chain `custom-input` | `/rw/config/rc.local` |
| **Egress do alvo** | para onde o alvo pode iniciar conexão | **também no `custom-forward` da `sys-net`** | mesmo arquivo do forward |

**Ponto-chave de segurança:** a contenção do egress fica na **`sys-net`**, *fora* do
alvo. Um atacante que tome root no alvo **não consegue** desfazer uma regra que está
na netvm — ele não a alcança. Por isso não filtramos no próprio alvo.

---

## As regras (o coração de tudo)

Na `sys-net`, chain `custom-forward`, **nesta ordem** (a ordem é crítica):

```
accept  kali(10.137.0.21) -> alvo(10.137.0.24)     # kali ataca o alvo
accept  alvo(10.137.0.24) -> kali(10.137.0.21)     # alvo responde à kali
accept  alvo -> udp/tcp dport 53                    # DNS (senão apt não resolve nomes)
drop    alvo -> 10.0.0.0/8                          # LAN + outros qubes
drop    alvo -> 172.16.0.0/12
drop    alvo -> 192.168.0.0/16                      # seu roteador 192.168.100.1 cai aqui
        (resto = IP público -> cai no forward normal do Qubes -> Internet OK)
```

Por que a ordem importa:

- **`accept` da kali vem antes do `drop` de `10.0.0.0/8`** — a kali é `10.137.0.21`,
  que está dentro de `10/8`. Se o drop viesse antes, mataria a comunicação com a kali.
- **`accept` de DNS vem antes dos drops** — o DNS do Qubes é `10.139.1.x` (dentro de
  `10/8`). Sem essa regra, o alvo teria Internet por IP mas **não resolveria nomes**,
  e o `apt` quebraria.
- **Sem `drop` final** — o que não casou nenhuma regra (IP público) “cai” no forward
  normal do Qubes, que já permite qube→Internet. É assim que o alvo mantém Internet.

No alvo (`exploitable`), chain `custom-input`:

```
accept  saddr kali(10.137.0.21)     # aceita entrada só da kali
```

(É escopado à kali de propósito — defense-in-depth. Como só a kali tem forward
liberado, é redundante, mas mais limpo.)

---

## Scripts (pasta `qubes/`, parametrizados por IP)

São **3 scripts, e o nome é o destino** — cada um faz tudo que aquela VM precisa
(aplica + persiste + mostra o resultado). Edite os IPs no topo se os seus diferirem.

| Script | Mande pra | Rode com | Função |
|--------|-----------|----------|--------|
| `qubes/sysnet.sh` | **sys-net** | `sudo bash sysnet.sh` | libera kali↔alvo, dá Internet ao alvo, **bloqueia sua LAN** e outros qubes, persiste |
| `qubes/exploitable.sh` | **exploitable** | `sudo bash exploitable.sh` | alvo aceita entrada só da kali, persiste, e **prova a proteção** |
| `qubes/kali.sh` | **kali** | `bash kali.sh` | confirma o acesso ao alvo (ping/curl/test-lab) |

`sysnet.sh` e `exploitable.sh` são **idempotentes** (`flush` + reconstroem): rodar de
novo é seguro e substitui qualquer regra anterior.

### Ordem de execução

```
1. sys-net:      sudo bash sysnet.sh        # libera + contém + persiste
2. exploitable:  sudo bash exploitable.sh   # entrada da kali + persiste + prova
3. kali:         bash kali.sh               # prova comunicação
```

### Como levar os scripts pra cada VM

- Individual: `qvm-copy qubes/sysnet.sh` (e os outros dois) — qube→qube via qrexec;
  **nunca** pelo dom0.
- Chegam em `~/QubesIncoming/<origem>/` na VM destino; rode de lá.

---

## Verificação esperada

**No alvo (`exploitable.sh`):**

```
kali       (10.137.0.21)  -> ok      (esperado ok)
internet   (8.8.8.8)      -> ok      (esperado ok)
lan-real   (192.168.100.1)-> fail    (esperado fail)
```

**Na kali (`kali.sh`):** `ping` responde, `curl :80` retorna HTML, e `test-lab.sh`
mostra as flags em PASS.

---

## Persistência (senão some no reboot)

Foi exatamente o que nos mordeu: depois de um reboot, o `custom-forward` estava
**vazio** porque as regras nunca tinham sido gravadas. A persistência resolve:

- **sys-net** → `/rw/config/qubes-firewall-user-script` (o serviço `qubes-firewall`
  roda no boot e a cada reload). Gravado pelo `passo2`.
- **exploitable** → `/rw/config/rc.local` (roda no fim do boot). Gravado pelo `passo5`.

Ambos ficam em `/rw`, que é o volume **persistente**. As mudanças do `provision.sh`
(serviços, configs, usuários) persistem porque a exploitable é **StandaloneVM**.

### Prova real (recomendado)

“Gravado” só vira “provado” após reiniciar:

```
# reinicie sys-net e exploitable, depois:
sys-net:      sudo bash sysnet.sh                 # regras reaparecem / reaplicadas
exploitable:  sudo nft list chain ip qubes custom-input   # mostra o accept da kali?
exploitable:  sudo bash exploitable.sh            # kali=ok internet=ok lan=fail
kali:         bash kali.sh                        # volta a pingar / test-lab
```

Se tudo reaparecer sem tocar em nada → persistência OK. Aí tire um **snapshot** do
alvo (pós-provisionamento + pós-configuração) para restaurar entre turmas.

---

## Instalar mais pacotes no alvo (depois)

Com esta política o alvo **já tem Internet**, então é direto:

```
# na exploitable
sudo apt-get update
sudo ./provision.sh --only <modulo>     # ou o apt install que precisar
```

Sem toggles: a Internet está sempre liberada; só a sua LAN fica bloqueada.

---

## Diagnóstico rápido

Regra de ouro: **internet OK + vizinho não = firewall do Qubes**, não a sua config.

```
# no atacante (kali): tem rota? pinga internet? pinga o alvo?
ip -4 route ; ping -c2 8.8.8.8 ; ping -c2 10.137.0.24
#   curl -v 10.137.0.24  -> "Connection refused" = falta custom-input no alvo (passo5)
#                        -> timeout               = falta custom-forward na sys-net (passo1)

# na sys-net:
sudo nft list chain ip qubes custom-forward

# no alvo:
sudo nft list chain ip qubes custom-input
```

Beco sem saída: atacar de um qube em netvm **diferente** do alvo (o NAT por hop
reescreve a origem e a regra por IP não casa). Ataque sempre da **mesma netvm**.

Se a Kali for **HVM não-nativa** e ficar sem rede (IP/gw errados): `sudo dhclient -v
eth0` como paliativo, ou instale `qubes-core-agent-networking` para torná-la nativa.
