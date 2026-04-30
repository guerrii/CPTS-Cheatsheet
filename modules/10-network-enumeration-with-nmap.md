# 10 — Network Enumeration with Nmap

Network mapper. Host discovery, port scanning, service/version detection, OS fingerprinting, and scripting via NSE.

## Quick reference

| Goal | Command |
|---|---|
| Default TCP scan, top 1000 ports | `nmap <TARGET>` |
| All TCP ports, fast | `nmap -p- --min-rate 5000 <TARGET>` |
| Service + version + default scripts + OS | `nmap -sCV -O <TARGET>` |
| UDP top 100 | `nmap -sU --top-ports 100 <TARGET>` |
| Discover hosts in /24 (no port scan) | `nmap -sn 10.10.10.0/24` |
| Skip host discovery (assume up) | `nmap -Pn <TARGET>` |

## Target specification

```bash
nmap 10.10.10.5                 # single host
nmap 10.10.10.0/24              # CIDR
nmap 10.10.10.1-50              # range
nmap target.tld                  # DNS
nmap -iL targets.txt             # from file (one per line)
nmap --exclude 10.10.10.5 ...
nmap --excludefile skip.txt ...
```

## Host discovery (`-s*`)

| Flag | Meaning |
|---|---|
| `-sn` | Ping scan only — no port scan |
| `-Pn` | Skip discovery, treat all hosts as up |
| `-PE` | ICMP echo |
| `-PP` | ICMP timestamp |
| `-PM` | ICMP netmask |
| `-PS<ports>` | TCP SYN ping (e.g. `-PS22,80,443`) |
| `-PA<ports>` | TCP ACK ping |
| `-PU<ports>` | UDP ping |
| `-PR` | ARP ping (default on local LAN) |
| `-n` | No DNS resolution |
| `-R` | Always resolve DNS |
| `--dns-servers 1.1.1.1` | Custom resolvers |

```bash
# Sweep a /24 quickly with multiple probe types
nmap -sn -PE -PS80,443 -PA3389 -PU161 10.10.10.0/24
```

## Port scanning techniques

| Flag | Technique | Notes |
|---|---|---|
| `-sS` | TCP SYN ("half-open") | Default when run as root; stealthier |
| `-sT` | TCP connect() | Default unprivileged; full handshake |
| `-sU` | UDP | Slow; pair with `-sV` and small port set |
| `-sA` | TCP ACK | Maps firewall rules (filtered vs unfiltered) |
| `-sN`/`-sF`/`-sX` | Null / FIN / Xmas | Bypasses some stateless filters |
| `-sY` | SCTP INIT | Rare |
| `-sO` | IP protocol scan | Lists supported IP protocols |
| `-b <ftp>` | FTP bounce | Legacy |

### Port selection

```bash
-p 22,80,443           # specific
-p 1-1024              # range
-p-                    # all 65535
--top-ports 100        # most common
-p U:53,T:80           # UDP and TCP mix (needs -sU -sS)
-F                     # fast (top 100)
-r                     # scan in order, do not randomize
```

### Port states

`open`, `closed`, `filtered`, `unfiltered`, `open|filtered`, `closed|filtered`.

## Service & version detection

```bash
nmap -sV <TARGET>                       # banner/version probes
nmap -sV --version-intensity 9 <TARGET> # 0=light, 9=all probes
nmap -sV --version-all <TARGET>         # equivalent to intensity 9
nmap --version-light <TARGET>           # intensity 2
```

## OS detection

```bash
nmap -O <TARGET>
nmap -O --osscan-guess <TARGET>     # aggressive guess
nmap -O --osscan-limit <TARGET>     # only when conditions are good
```

## NSE — Nmap Scripting Engine

```bash
nmap -sC <TARGET>                          # default scripts (~"safe"+"discovery")
nmap --script vuln <TARGET>                # category
nmap --script "http-*" <TARGET>            # glob
nmap --script "not intrusive" <TARGET>
nmap --script "default and safe" <TARGET>
nmap --script <name> --script-args key=val <TARGET>
nmap --script-help <name>
```

Useful categories: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`.

Common one-shot scripts:

```bash
# SMB
nmap -p445 --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-protocols,smb2-security-mode <TARGET>
nmap -p445 --script smb-vuln-* <TARGET>

# SMB null session shares
nmap -p445 --script smb-enum-shares.nse --script-args smbuser=,smbpass= <TARGET>

# HTTP recon
nmap -p80,443 --script http-title,http-headers,http-methods,http-enum,http-robots.txt <TARGET>

# SSL/TLS
nmap -p443 --script ssl-cert,ssl-enum-ciphers <TARGET>

# DNS
nmap -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=<DOMAIN> <DNS-SERVER>

# SNMP
nmap -sU -p161 --script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr <TARGET>

# FTP anon + version
nmap -p21 --script ftp-anon,ftp-syst <TARGET>

# Vuln check
nmap --script vuln <TARGET>
```

Update script DB after install: `sudo nmap --script-updatedb`

## Output formats

```bash
-oN file.nmap     # normal
-oG file.gnmap    # greppable
-oX file.xml      # XML (feed to other tools)
-oA basename      # all three at once
-v / -vv / -vvv   # verbosity
-d / -dd          # debug
--reason          # why each port is in its state
--open            # only show open ports
--packet-trace    # raw packet log
--append-output   # don't overwrite
```

Convert to HTML: `xsltproc file.xml -o file.html`
Greppable extract open ports: `grep "/open/" file.gnmap | awk '{print $2}'`

## Timing & performance

```bash
-T0  # paranoid (IDS evasion)
-T1  # sneaky
-T2  # polite
-T3  # normal (default)
-T4  # aggressive (fast LAN)
-T5  # insane (assume excellent network, lossy)

--min-rate 1000
--max-rate 5000
--min-parallelism 100
--max-retries 2
--host-timeout 30s
--scan-delay 100ms
```

Aggressive shortcut: `-A` = `-sV -sC -O --traceroute`

## Firewall / IDS evasion

```bash
-f                          # fragment packets
--mtu 24                    # custom MTU (multiple of 8)
-D RND:10                   # 10 random decoys
-D 10.0.0.5,ME,10.0.0.7
-S <SRC-IP>                 # spoof source
-e <iface>                  # specify interface
--source-port 53            # spoof source port (or -g 53)
--data-length 50            # pad packets
--ttl 65
--randomize-hosts
--badsum                    # invalid checksum (filter detection)
--proxies http://proxy:8080,...
```

## Workflow patterns

### Two-stage scan (fast wide → deep targeted)

```bash
# Stage 1: find open TCP ports across all 65535
nmap -p- --min-rate 5000 -oA stage1 <TARGET>

# Stage 2: deep probe only the open ports
ports=$(grep "^[0-9].*open" stage1.gnmap | awk -F'/' '{print $1}' | tr '\n' ',')
# easier:
ports=$(awk -F'[ /]' '/Ports:/ {for (i=1;i<=NF;i++) if ($i~/open/) print $(i-3)}' stage1.gnmap | sort -un | paste -sd,)

nmap -sCV -O -p$ports -oA stage2 <TARGET>
```

### UDP top + version

```bash
sudo nmap -sU --top-ports 100 -sV --version-intensity 0 -oA udp <TARGET>
```

### Subnet sweep with output

```bash
nmap -sn -oA hosts 10.10.10.0/24
grep "Up$" hosts.gnmap | awk '{print $2}' > live.txt
```

### Resume an interrupted scan

```bash
nmap --resume basename.gnmap
```

## Cheatsheet of cheatsheets

- Run as root for raw-socket scans (`-sS`, `-sU`, `-O`, ARP).
- `-Pn` is mandatory for hosts that drop ICMP/probes.
- For UDP, scope tightly — full UDP scans take hours.
- Always save output (`-oA`) — feeds the next steps and the report.
- NSE is your force multiplier; learn the script names for SMB, HTTP, SMTP, LDAP, RDP, DNS.

## Sources

- Official documentation: https://nmap.org/book/man.html
- NSE script DB: https://nmap.org/nsedoc/
- `man nmap`
