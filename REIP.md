# Reassociar o alvo a um novo IP (`--reip`)

## O sintoma

Depois de provisionar, a VM-alvo troca de IP (snapshot restaurado entre turmas,
DHCP diferente, mudança de netvm) e **alguns serviços param de responder no IP novo**:

- **Tomcat (8082)** some da rede — a porta nem escuta.
- **DNS (53)** ainda sobe, mas `ns1`/`www` resolvem para o IP **antigo**.
- **WordPress (80)** redireciona para o IP antigo e "quebra" (loop/erro).

Os demais módulos (SSH, FTP, SMB, Redis, SMTP, MySQL, Apache) **não** são afetados:
escutam em `0.0.0.0` e não gravam o IP em lugar nenhum.

## A causa-raiz

O `provision.sh` detecta o IP **uma única vez**, no momento do provision
(`hostname -I | awk '{print $1}'`), e **grava esse valor em disco** em três lugares.
Se a VM mudar de IP depois, esses três pontos continuam apontando para o IP velho:

| Módulo | Onde o IP fica gravado | Por que precisa do IP real |
|--------|------------------------|----------------------------|
| `dns` | `/etc/bind/db.empresa.local` — registros A de `ns1` e `www` | AXFR realista: `dnsrecon`/`dnsenum`/`fierce` resolvem o NS pelo resolvedor do sistema; com `127.0.0.1` o AXFR volta vazio. |
| `tomcat` | `/etc/tomcat10/server.xml` — `address="…"` no connector 8082 | Bind no IP externo (em Qubes o `qubes-updates-proxy` já ocupa `127.0.0.1:8082`). Se o IP não existe mais na máquina, o connector **falha o bind em silêncio** e a porta morre. |
| `wordpress` | banco (`wp_options.siteurl`/`home`, e refs em posts/guid/user_url) | O WP redireciona toda requisição para o host de `siteurl`. |

> Diagnóstico rápido do connector do Tomcat: o `systemctl status tomcat10` diz
> `active` (o processo Java sobe), mas `ss -ltn | grep :8082` não mostra nada —
> o bind do connector falhou porque o `address` aponta para um IP inexistente.

## A solução: `sudo ./provision.sh --reip`

Subcomando idempotente que **re-detecta o IP atual** e reescreve **apenas** esses três
pontos, reiniciando os serviços afetados. **Não regenera as flags** e **não usa Internet**
(ao contrário de reprovisionar) — pode rodar quantas vezes quiser.

```bash
sudo ./provision.sh --reip
```

Saída esperada:

```
[*] == reip: reassociando servicos ao IP atual (10.137.0.24) ==
[+] dns: ns1/www -> 10.137.0.24
[+] tomcat: connector 8082 -> address=10.137.0.24
[+] wordpress: siteurl/home -> http://10.137.0.24/wordpress
[+] reip concluido.
```

### O que ele faz, por dentro

- **DNS:** reescreve as linhas `ns1`/`www` `IN A` para o IP atual, sobe o serial do
  SOA, valida com `named-checkzone` (só recarrega se passar) e reinicia `named`/`bind9`.
- **Tomcat:** troca (ou insere) o `address="…"` **somente** nas linhas do connector
  `port="8082"`. Os templates AJP/SSL (comentados, com `address="::1"`) ficam intactos.
- **WordPress:** atualiza `siteurl`/`home` e faz `wp search-replace` do host antigo
  para o novo em todas as tabelas.

Cada bloco é guardado por `[ -f … ]` / `[ -d … ]`, então rodar `--reip` numa VM que
não tem aquele módulo instalado simplesmente pula o passo.

### Fonte única do IP

A detecção foi centralizada no helper `lab_ip()` (`hostname -I | awk '{print $1}'`),
usado tanto pelos três módulos no provision quanto pelo `--reip` — um lugar só para
mudar caso a regra de "qual IP usar" evolua.

## Quando usar

- **Entre turmas:** depois de restaurar o snapshot, se o IP mudou, rode `--reip`
  antes da aula (mais rápido que reprovisionar e **preserva as flags** da turma).
- **Trocou de netvm / rede:** mesma coisa.
- **Não** substitui o provision inicial — só conserta o IP de um alvo já montado.

## Correção manual (sem o script)

Se precisar consertar na unha, o IP antigo aparece em:

```bash
grep -rIl "IP_ANTIGO" /etc/bind /etc/tomcat10           # dns + tomcat
sudo -u www-data wp --path=/var/www/html/wordpress option get siteurl   # wordpress
```

Troque pelo IP novo, `named-checkzone empresa.local /etc/bind/db.empresa.local`,
e reinicie `named` e `tomcat10`. No WP use `wp option update` + `wp search-replace`.
