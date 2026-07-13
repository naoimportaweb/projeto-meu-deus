# assets/wordpress — componentes vulneráveis do lab (espelho estável)

Cópias **preservadas** das versões vulneráveis usadas pelo módulo `wordpress` do `provision.sh`.
São softwares **GPL legítimos**, apenas em versões antigas com CVE conhecida — mantidos aqui porque o
`wordpress.org` **remove versões antigas** com o tempo (o `mail-masta 1.0` e o `revslider` já
retornam `404`). O `provision.sh` baixa destes arquivos (raw GitHub) em vez do wordpress.org, para o
lab continuar reproduzível.

> Nota: o que é *de fato* perigoso (LFI/webshell) **não** é hospedado aqui — é reproduzido por arquivo
> PHP mínimo plantado pelo `provision.sh` (ex.: `mail-masta`). Estes zips são só os plugins/core GPL.

| Arquivo | Componente | Versão | CVE |
|---|---|---|---|
| `wordpress-4.7.1.zip` | WordPress core | 4.7.1 | CVE-2017-1001000 (REST API content injection) |
| `wp-file-manager.6.0.zip` | wp-file-manager | 6.0 | CVE-2020-25213 (upload não-auth → RCE) |
| `social-warfare.3.5.2.zip` | Social Warfare | 3.5.2 | CVE-2019-9978 |
| `reflex-gallery.3.1.3.zip` | Reflex Gallery | 3.1.3 | CVE-2015-4133 |

Integridade: `sha256sum -c SHA256SUMS`.
