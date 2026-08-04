# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## O que é este repositório

`projeto-meu-deus` é o **espelho público e sanitizado** do lab `meudeus` (repo GitHub
`naoimportaweb/projeto-meu-deus`). Monta um alvo Debian **propositalmente vulnerável**,
nível iniciante, para aulas de pentest. Todo o alvo cabe num **único script**:
`provision.sh` transforma um Debian limpo no alvo.

**Sanitização:** este espelho é público e **sem gabarito**. O bloco
`# gabarito (só para o instrutor)` em `provision.sh:176` está intencionalmente vazio, e
o `test-lab.sh` (bateria de verificação PASS/FAIL das flags, citado no `README.md` e nos
docs de rede) **não existe aqui** — é parte do `meudeus` privado. Ao mexer, **não**
adicione gabarito, dump de flags em disco/log, nem o `test-lab.sh` a este repo.

> ⚠️ O produto deste script é uma máquina gravemente insegura de propósito. Nunca rode
> `provision.sh` nesta estação — só numa VM descartável. Não há o que "testar" localmente.

## Comandos

Não há build/lint/suíte de testes — é bash puro sobre Debian.

```bash
sudo ./provision.sh                 # MENU interativo (marca tudo por padrão)
sudo ./provision.sh --all           # instala tudo, sem menu
sudo ./provision.sh --only dns,web  # só esses módulos
sudo ./provision.sh --list          # lista módulos (não precisa de root)
sudo ./provision.sh --all --yes     # tudo, sem confirmação
bash -n provision.sh                # checagem de sintaxe (o mais perto de "lint")
```

O modo `curl | bash` (ver `README.md`) exige `--all --yes`: o `read` do menu disputa o
stdin com o pipe.

## Arquitetura do `provision.sh` (o coração)

Tudo — apps web, configs de serviço, backdoors — está **embutido como heredocs** dentro do
único script. Não há arquivos de app separados; copiar só o `provision.sh` para a VM basta
(exceto pelos assets do módulo `wordpress`, ver abaixo).

**Registro de módulos** (três lugares que precisam andar juntos):
1. `MODS=(...)` (`provision.sh:63`) — ordem de exibição **e** de execução.
2. `TITLE[<mod>]="..."` — texto no menu/`--list`.
3. `mod_<nome>()` — a função que instala aquela vuln.
4. `PORT[<mod>]="porta/serv"` (perto do fim, no resumo) — o que o sumário final anuncia.

O dispatch é um loop no fim: `for m in "${MODS[@]}"; do [ "${SEL[$m]}" = 1 ] && "mod_$m"; done`.
**Para adicionar um módulo**, edite os quatro pontos acima. A ordem em `MODS` importa
(dependências e conflitos de porta são implícitos na ordem).

**Helpers (use-os em vez de reinventar):**
- `log/info/warn/die` — saída padronizada e colorida; `die` aborta.
- `set_kv arquivo chave valor` — edita config idempotentemente (substitui ou anexa).
- `add_user usuário senha [shell]` — cria/reseta usuário.
- `svc nome` — enable + restart tolerante a ausência de systemd.
- `apt_install …` — **fatal** (aborta o script se falhar); faz `apt-get update` uma vez.
- `apt_try …` — **best-effort**; use quando o módulo pode falhar sem derrubar o resto
  (padrão: `apt_try foo || { warn "…pulado"; return; }`).
- `rnd` — 4 bytes hex aleatórios, base das flags.

**Convenções de design:**
- **Idempotência** é regra: rodar de novo não deve quebrar. Siga o padrão dos módulos
  existentes (`set_kv`, `id … || useradd`, `IF NOT EXISTS` no SQL).
- **Flags** são `FLAG_*` geradas por `rnd` a cada execução (`provision.sh:158`+). Cada
  módulo escreve sua flag no lugar que o exercício pede (arquivo, coluna de DB, post).
- **Dependências:** `ssh`, `ftp` e `privesc` forçam `SEL[base]=1` (usuários vêm do `base`).
- **Guardas** (início): exige root, exige `apt-get`, aborta se hostname parece `prod`.
- Comentários, logs e docs em **pt-BR**.

## Módulos que baixam da rede

Alguns módulos puxam artefatos externos em tempo de provisionamento — o alvo precisa de
Internet nessa hora:
- `wordpress` e `log4j` são **pesados** (wp-cli.phar, JDK 8).
- `wordpress` baixa os plugins vulneráveis do **próprio repo público** via
  `raw.githubusercontent.com/naoimportaweb/projeto-meu-deus/main/assets/wordpress/…`
  (o wordpress.org remove versões antigas com CVE). **Consequência:** mudanças em
  `assets/wordpress/` só têm efeito no lab depois de **commitadas e enviadas ao GitHub**.
- O que é de fato perigoso (LFI/webshell, ex. `mail-masta`) **não** é hospedado em
  `assets/`: é reproduzido por um PHP mínimo plantado pelo próprio script. Mantenha essa
  separação — `assets/` guarda só plugins/core GPL legítimos (ver `assets/wordpress/README.md`
  e `SHA256SUMS`). O `.6.0.zip` do wp-file-manager tem um **zip aninhado**; o módulo
  extrai o interno (comentários em `mod_wordpress`).

## Rede e isolação (Qubes)

O alvo precisa de Internet para provisionar, mas **depois** deve ser contido para não
alcançar sua LAN real. Toda a receita está em `REDE-E-ISOLACAO.md` (contenção via `nft`
na `sys-net`, sem tocar no dom0) e `QUBES.md` (via `qvm-firewall`, no dom0). Os scripts
parametrizados por IP ficam em `qubes/` — **o nome do script diz a VM destino**:
`sysnet.sh` → sys-net, `exploitable.sh` → alvo, `kali.sh` → atacante (ordem 1→2→3).
`sysnet.sh`/`exploitable.sh` são idempotentes (flush + reconstroem).

Regra de ouro de diagnóstico: **internet OK + vizinho não = firewall do Qubes**, não a
config do lab. Ataque sempre da **mesma netvm** do alvo (NAT por hop quebra regras por IP).

## Reset entre turmas

Provisione com Internet → contenha → tire um **snapshot** da VM e restaure entre aulas.
As flags são aleatórias a cada execução do script. Use **StandaloneVM** no Qubes (num
AppVM, mudanças em `/etc` e pacotes somem no reboot).
