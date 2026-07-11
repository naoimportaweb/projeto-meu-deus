# meudeus

Monta um ambiente lotado de erros e falhas de segurança — um alvo
propositalmente vulnerável, nível **iniciante**, para aulas de pentest.
É um **único script** (`provision.sh`) que transforma um Debian limpo no alvo.

> ⚠️ **Isto deixa a máquina gravemente insegura de propósito.** Rode apenas numa
> **VM descartável**. Ela precisa de Internet para provisionar (o `curl` e o `apt`);
> **logo depois, contenha-a** para que não alcance a sua rede local — receita em
> [`REDE-E-ISOLACAO.md`](REDE-E-ISOLACAO.md).

## Instalação rápida (curl)

Na VM-alvo (Debian limpo, com Internet):

```bash
# baixar e rodar com o MENU de seleção
curl -fsSL https://raw.githubusercontent.com/naoimportaweb/projeto-meu-deus/refs/heads/main/provision.sh -o provision.sh
chmod +x provision.sh
sudo ./provision.sh

# ou tudo de uma vez, sem menu:
curl -fsSL https://raw.githubusercontent.com/naoimportaweb/projeto-meu-deus/refs/heads/main/provision.sh | sudo bash -s -- --all --yes
```

O modo `curl | bash` exige `--all --yes`: o menu interativo precisa do arquivo em
disco (o `read` disputa o stdin com o pipe).

**Ordem certa:** provisione **com Internet** (o `curl` e o `apt` precisam dela) e
**só então** contenha o alvo, bloqueando o acesso à sua LAN — receita em
[`REDE-E-ISOLACAO.md`](REDE-E-ISOLACAO.md) (scripts em `qubes/`).

## Como usar

1. Crie uma VM Debian limpa (Debian 12/13).
2. Copie **só o `provision.sh`** para dentro dela — o app web está embutido no script.
3. Dentro da VM:
   ```bash
   sudo ./provision.sh                 # abre o MENU de seleção
   sudo ./provision.sh --all           # instala tudo, sem menu
   sudo ./provision.sh --only dns,web  # instala só esses módulos
   sudo ./provision.sh --list          # lista os módulos (não precisa de root)
   sudo ./provision.sh --all --yes     # tudo, sem confirmação
   ```
4. No fim ele mostra IP, portas e serviços.

### Menu (`read`, bash puro — sem dependências)

Digite o número para **marcar/desmarcar** cada módulo (aceita vários: `3 5 7`),
`a` marca todos, `n` desmarca todos, `ENTER` confirma:

```
   1) [x] base    Usuários e senhas fracas (+ flag de foothold)
   2) [x] ssh     SSH com senha fraca / login de root
   ...
   11) [x] redis  Redis sem senha, exposto na rede (RCE)
   12) [x] privesc Escalação de privilégio (SUID, sudo, cron)
```

## Módulos disponíveis

| Módulo | Vulnerabilidades | Portas |
|--------|------------------|--------|
| `base` | usuários/senhas fracas, credenciais vazadas em backup, flag de foothold | — |
| `ssh` | SSH com senha fraca / login de root habilitado | 22 |
| `ftp` | FTP anônimo (vsftpd) com upload + arquivo que vaza credenciais | 21 |
| `samba` | Samba/NetBIOS aberto a convidado (`enum4linux`, `smbclient`) | 137/139/445 |
| `dns` | **transferência de zona (AXFR)** — `dig axfr empresa.local @IP` despeja hosts escondidos + flag TXT | 53 |
| `web` | SQLi, XSS refletido, LFI, upload/RCE, command injection, backup de config vazado | 80 |
| `apache` | Apache mal configurado: `server-status`, UserDir, listagem de diretório, `.htpasswd` exposto | 80 |
| `nginx` | path traversal por `alias` (off-by-slash) e `.git` exposto | 8080 |
| `nfs` | export com `no_root_squash` + RPC/rpcbind (`rpcinfo`, `showmount`) | 111/2049 |
| `smtp` | Postfix open relay + `VRFY` para enumeração | 25 |
| `redis` | Redis sem senha, exposto na rede (RCE) | 6379 |
| `privesc` | SUID em `find`, `sudo NOPASSWD` em `vim`, cron de root `world-writable` | — |

`ssh`, `ftp` e `privesc` dependem do `base` (usuários), ligado automaticamente.
Cada módulo deixa **pistas de recon** (credenciais default, banners, `robots.txt`,
arquivos "esquecidos"). Objetivo dos alunos: capturar as flags.

## Qubes OS — notas

- Use uma **StandaloneVM** (não AppVM). Num AppVM, mudanças em `/etc` e pacotes
  **somem no reboot** (só `/home`, `/usr/local` e `/rw` persistem).
- **Não** copie nada para o **dom0**. Use `qvm-copy` (qube→qube, via qrexec) para
  levar os scripts pra VM.
- Provisione **com internet** (o `apt` precisa baixar pacotes); **depois** isole a rede.
- **Rede atacante↔alvo:** no Qubes, dois qubes atrás da mesma netvm **não se
  enxergam por padrão** (o netvm bloqueia o forward). Libere o par na netvm:
  ```bash
  # no terminal da netvm (ex.: sys-net ou uma netvm isolada), como root:
  nft add rule ip qubes custom-forward ip saddr <ip-atacante> ip daddr <ip-alvo> accept
  nft add rule ip qubes custom-forward ip saddr <ip-alvo> ip daddr <ip-atacante> accept
  ```
  Persista em `/rw/config/qubes-firewall-user-script` (com `#!/bin/sh`, `chmod +x`,
  e um `nft flush chain ip qubes custom-forward` no início para ser idempotente).
- **Atacante não-nativo (ex.: Kali HVM sem qubes-agent):** ele não recebe a config
  ponto-a-ponto do Qubes automaticamente — configure IP `/32` + rota on-link pro
  gateway na mão, ou instale o qubes-agent para torná-lo nativo.

## Reset entre turmas

Tire um **snapshot** da VM depois de provisionar e restaure entre as aulas.
As flags são aleatórias a cada execução do script.
