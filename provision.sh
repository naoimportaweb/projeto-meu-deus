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

# ---------------------------------------------------------- registro de módulos
MODS=(base ssh ftp vsftpd234 ftpdos samba dns web apache nginx nfs smtp redis log4j snmp mysql postgres tomcat wordpress phpmyadmin privesc)
declare -A TITLE
TITLE[base]="Usuários e senhas fracas (+ flag de foothold)"
TITLE[ssh]="SSH com senha fraca / login de root"
TITLE[ftp]="FTP anônimo com upload (vsftpd, porta 2121) + creds vazadas"
TITLE[vsftpd234]="Backdoor vsftpd 2.3.4 na porta 21 (CVE-2011-2523) -> shell root"
TITLE[ftpdos]="FTP legado 2.3.2 na porta 2100: DoS por glob (CVE-2011-0762)"
TITLE[samba]="Samba/NetBIOS aberto a convidado (enum4linux)"
TITLE[dns]="DNS com transferência de zona liberada (AXFR)"
TITLE[web]="App web: SQLi, XSS, LFI, upload/RCE, cmd injection"
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
TITLE[privesc]="Escalação de privilégio (SUID, sudo, cron)"

usage() {
  echo "Uso: sudo ./provision.sh [--all | --only m1,m2,...] [--yes] [--list]"
  echo "Módulos:"; for m in "${MODS[@]}"; do printf "  %-9s %s\n" "$m" "${TITLE[$m]}"; done
}

# --------------------------------------------------------------- args + seleção
declare -A SEL; for m in "${MODS[@]}"; do SEL[$m]=0; done
INTERACTIVE=1; ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all)  INTERACTIVE=0; for m in "${MODS[@]}"; do SEL[$m]=1; done;;
    --only) INTERACTIVE=0; IFS=, read -ra P <<<"${2:-}"; shift
            for p in "${P[@]}"; do
              [ -n "${TITLE[$p]:-}" ] || die "módulo desconhecido: '$p' (veja --list)"
              SEL[$p]=1
            done;;
    --yes)  ASSUME_YES=1;;
    --list) usage; exit 0;;
    -h|--help) usage; exit 0;;
    *) die "opção desconhecida: '$1' (veja --help)";;
  esac; shift
done

# ------------------------------------------------------------------- guardas --
[ "$(id -u)" -eq 0 ] || die "rode como root:  sudo ./provision.sh"
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

# gabarito (só para o instrutor)

log "Provisionando: ${CHOSEN[*]}"

# ============================================================ MÓDULOS
mod_base() {
  info "== base: usuários e credenciais fracas =="
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
  mkdir -p /srv/samba/publico /srv/samba/privado
  echo "Dica: a app web esta na porta 80; o FTP na 21." > /srv/samba/publico/notas.txt
  echo "Credenciais do banco: webapp / webapp123" > /srv/samba/privado/segredo.txt
  chmod -R 0777 /srv/samba/publico
  chmod -R 0770 /srv/samba/privado
  # define a senha samba de msfadmin (se o usuário existir)
  if id msfadmin >/dev/null 2>&1; then
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
  cat > /etc/bind/db.empresa.local <<EOF
\$TTL 604800
@   IN  SOA ns1.empresa.local. admin.empresa.local. (
        2024010101 604800 86400 2419200 604800 )
@       IN  NS      ns1.empresa.local.
@       IN  MX  10  mail.empresa.local.
ns1     IN  A       127.0.0.1
www     IN  A       127.0.0.1
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
sysLocation Sala de servidores - ${FLAG_SNMP}
sysContact admin@empresa.local
extend whoami /usr/bin/id
EOF
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
  local IPADDR; IPADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
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
PORT[ftp]="2121/ftp"; PORT[vsftpd234]="21/ftp,6200/shell"; PORT[ftpdos]="2100/ftp"; PORT[ssh]="22/ssh"; PORT[dns]="53/dns"; PORT[web]="80/http"
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
