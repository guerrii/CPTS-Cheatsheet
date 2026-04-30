# 03 — Introduction to Networking

Reference for the network concepts that come up constantly during enumeration and exploitation.

## OSI vs TCP/IP

| OSI Layer | TCP/IP Layer | Examples |
|---|---|---|
| 7 Application | Application | HTTP, DNS, SMTP, SSH, SMB |
| 6 Presentation | Application | TLS, MIME, ASCII |
| 5 Session | Application | NetBIOS, RPC |
| 4 Transport | Transport | TCP, UDP, SCTP |
| 3 Network | Internet | IP, ICMP, ARP, IPsec |
| 2 Data Link | Link | Ethernet, Wi-Fi, MAC |
| 1 Physical | Link | Cables, radio |

## IPv4 addressing

- 32-bit, written in dotted decimal: `10.0.0.1`.
- Private ranges (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- Loopback: `127.0.0.0/8`.
- Link-local: `169.254.0.0/16`.

### CIDR & subnetting cheat

| Prefix | Mask | Hosts |
|---|---|---|
| /30 | 255.255.255.252 | 2 |
| /29 | 255.255.255.248 | 6 |
| /28 | 255.255.255.240 | 14 |
| /27 | 255.255.255.224 | 30 |
| /26 | 255.255.255.192 | 62 |
| /25 | 255.255.255.128 | 126 |
| /24 | 255.255.255.0 | 254 |
| /23 | 255.255.254.0 | 510 |
| /22 | 255.255.252.0 | 1022 |
| /16 | 255.255.0.0 | 65534 |
| /8 | 255.0.0.0 | 16777214 |

```bash
# Quick math via ipcalc
ipcalc 10.10.10.0/24
# Network/broadcast/usable range
sipcalc 10.10.10.0/24
```

## IPv6 addressing

- 128-bit, hex groups separated by `:`.
- Loopback: `::1`. Link-local: `fe80::/10`. ULA: `fc00::/7`.
- Discovery uses ICMPv6 (NDP) instead of ARP.

## TCP vs UDP

| | TCP | UDP |
|---|---|---|
| Connection | 3-way handshake (SYN, SYN/ACK, ACK) | Connectionless |
| Reliability | Yes (seq/ack, retransmit) | No |
| Order | Yes | No |
| Use cases | HTTP, SSH, SMB | DNS, SNMP, NTP, VoIP |

### TCP flags

`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`. Combinations matter for scan techniques (see [10 Nmap](10-network-enumeration-with-nmap.md)).

## ARP

```bash
arp -a                       # cached entries
ip neigh show
sudo arp-scan -l             # local broadcast scan
sudo netdiscover -r 10.0.0.0/24
```

ARP is layer-2; it does not cross routers. ARP spoofing only affects the local broadcast domain.

## DNS

| Record | Purpose |
|---|---|
| `A` | IPv4 |
| `AAAA` | IPv6 |
| `CNAME` | Alias |
| `MX` | Mail server |
| `NS` | Name server |
| `TXT` | Free text (SPF, DKIM, DMARC, verifications) |
| `SRV` | Service (used heavily by AD: `_ldap._tcp.dc._msdcs.<domain>`) |
| `PTR` | Reverse DNS |
| `SOA` | Authority |

```bash
dig <domain>                       # default A
dig +short <domain>
dig <domain> ANY
dig @1.1.1.1 <domain>              # custom resolver
dig -x 8.8.8.8                     # reverse
dig AXFR <domain> @<ns>            # zone transfer (rarely allowed; report if it works)
host <domain>
nslookup <domain>
```

## Routing & ICMP

```bash
ip r
ip r get 1.1.1.1
traceroute <host>
mtr <host>                  # interactive
```

ICMP types worth knowing: `0` echo reply, `3` destination unreachable, `8` echo request, `11` time exceeded, `13/14` timestamp.

## Common protocol ports

See [02 Getting Started](02-getting-started.md) for the full table.

## Network tooling on Linux

```bash
ip a                                  # interfaces (replaces ifconfig)
ip r                                  # routes
ss -tlnp                              # listening TCP ports + process
ss -unp                               # UDP sockets
ss -tnp state established
sudo lsof -i :80                       # what owns port 80
sudo tcpdump -i eth0 -nn -A 'port 80'  # capture
sudo tcpdump -i any -w cap.pcap         # save for Wireshark
```

## Network tooling on Windows

```powershell
ipconfig /all
route print
arp -a
netstat -anob              # processes per port (admin)
Get-NetTCPConnection
Test-NetConnection <host> -Port 445
Resolve-DnsName <host>
```

## VLANs / 802.1Q

- Tagged frames carry a 4-byte VLAN tag.
- Trunk ports carry multiple VLANs; access ports carry one.
- VLAN hopping: double-tagging or DTP abuse — relevant to internal pentests.

## Sources

- IANA registry: https://www.iana.org/protocols
- RFC 791 (IPv4), RFC 793 (TCP), RFC 768 (UDP), RFC 1918 (private addr), RFC 8200 (IPv6).
- `man ip`, `man ss`, `man tcpdump`, `man dig`.
