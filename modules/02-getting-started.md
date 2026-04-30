# 02 — Getting Started

Baseline tooling, lab connectivity, and a default workflow to drop into when starting any engagement or box.

## Lab connectivity

```bash
# Connect to a VPN profile (OpenVPN)
sudo openvpn --config profile.ovpn

# Verify the tunnel
ip a show tun0
ping -c 2 <gateway>
```

Keep the VPN session in a dedicated `tmux` window so it survives a closed terminal.

## Default attacker host layout

```
~/engagements/<client>/<date>/
├── recon/        # nmap, sub-domains, DNS dumps
├── creds/        # found / cracked / spray candidates
├── loot/         # files exfiltrated for evidence
├── notes.md      # running log (timestamped)
├── scope.txt     # in-scope IPs/domains
└── report/       # screenshots, final write-up
```

## Default workflow when faced with an unknown host

1. Add to `/etc/hosts` if a hostname is known.
2. Full TCP port sweep (`nmap -p- --min-rate 5000`).
3. Targeted scan on open ports (`nmap -sCV -p<ports>`).
4. UDP top-100.
5. Per-service enumeration (see [11 Footprinting](11-footprinting.md)).
6. Web: directory and vhost fuzzing, source review, Burp.
7. Identify weak credentials / known CVEs / misconfigurations.
8. Exploit → foothold.
9. Local enum → privesc.
10. If AD environment: BloodHound/NetExec → lateral.

## Common ports — quick reference

| Port | Proto | Service |
|---|---|---|
| 21 | TCP | FTP |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67/68 | UDP | DHCP |
| 69 | UDP | TFTP |
| 80 | TCP | HTTP |
| 88 | TCP | Kerberos |
| 110 | TCP | POP3 |
| 111 | TCP/UDP | RPCbind |
| 119 | TCP | NNTP |
| 123 | UDP | NTP |
| 135 | TCP | MS RPC |
| 137-139 | TCP/UDP | NetBIOS |
| 143 | TCP | IMAP |
| 161/162 | UDP | SNMP |
| 389 | TCP | LDAP |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB |
| 464 | TCP/UDP | Kerberos pwd change |
| 500 | UDP | IKE / IPsec |
| 514 | UDP | Syslog |
| 587 | TCP | SMTP submission |
| 593 | TCP | RPC over HTTP |
| 623 | UDP | IPMI |
| 636 | TCP | LDAPS |
| 873 | TCP | rsync |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 1080 | TCP | SOCKS |
| 1433 | TCP | MSSQL |
| 1521 | TCP | Oracle TNS |
| 2049 | TCP | NFS |
| 2375/2376 | TCP | Docker API |
| 3128 | TCP | HTTP proxy |
| 3268/3269 | TCP | Global Catalog (LDAP) |
| 3306 | TCP | MySQL/MariaDB |
| 3389 | TCP | RDP |
| 4369 | TCP | Erlang epmd |
| 5040 | TCP | WinRM (legacy) |
| 5060/5061 | TCP/UDP | SIP |
| 5432 | TCP | PostgreSQL |
| 5601 | TCP | Kibana |
| 5666 | TCP | NRPE |
| 5672 | TCP | RabbitMQ AMQP |
| 5800/5900 | TCP | VNC |
| 5985/5986 | TCP | WinRM (HTTP/HTTPS) |
| 6379 | TCP | Redis |
| 7001 | TCP | WebLogic |
| 8000-8999 | TCP | Various web admin |
| 8080/8443 | TCP | HTTP alt / HTTPS alt |
| 8089 | TCP | Splunk |
| 9000 | TCP | PHP-FPM |
| 9090 | TCP | Cockpit |
| 9100 | TCP | Printer (JetDirect) |
| 9200/9300 | TCP | Elasticsearch |
| 11211 | TCP/UDP | Memcached |
| 27017 | TCP | MongoDB |

## Note-taking discipline

- Timestamp every action (`date -Iseconds` in the prompt).
- Save raw command output to disk (`tee` / `script`), not just terminal scrollback.
- Capture screenshots immediately when you see something report-worthy.
- One file per host or per finding makes report assembly trivial.

## Toolbox (assumes Kali / Parrot)

| Category | Tools |
|---|---|
| Recon | `nmap`, `masscan`, `rustscan`, `amass`, `subfinder`, `httpx`, `dnsx`, `whois` |
| Web | Burp Suite, ZAP, `ffuf`, `feroxbuster`, `gobuster`, `wfuzz`, `nikto`, `whatweb` |
| Exploitation | Metasploit, `searchsploit`, `sqlmap` |
| AD | `netexec` (was crackmapexec), Impacket suite, BloodHound, `kerbrute`, `ldapsearch` |
| Cred attacks | `hydra`, `hashcat`, `john`, `cewl`, `crunch` |
| Tunneling | `chisel`, `ligolo-ng`, `sshuttle`, `socat`, `proxychains` |
| Privesc | `linpeas`, `winPEAS`, `pspy`, GTFOBins, LOLBAS |
| Listeners | `nc` / `ncat` / `pwncat`, `rlwrap`, `socat` |

## Sources

- Service/port assignments (IANA): https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
- Kali tools index: https://www.kali.org/tools/
