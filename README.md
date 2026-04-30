# CPTS Cheatsheet

A personal, command-first reference for the **Certified Penetration Testing Specialist** (CPTS) job-role path. Organized by attack phase, written for fast recall during boxes and exam preparation.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Modules](https://img.shields.io/badge/Modules-35-blue)
![Style](https://img.shields.io/badge/Style-Command--first-orange)

> **Use only against systems you have explicit written authorization to test.** This is a study and engagement reference; misuse against unauthorized targets is illegal in most jurisdictions.

## Quick navigation

### By engagement phase

| Phase | Modules |
|---|---|
| **Foundations** | [01](modules/01-penetration-testing-process.md) · [02](modules/02-getting-started.md) · [03](modules/03-introduction-to-networking.md) · [04](modules/04-linux-fundamentals.md) · [05](modules/05-windows-fundamentals.md) · [06](modules/06-introduction-to-windows-cli.md) · [07](modules/07-introduction-to-active-directory.md) · [08](modules/08-introduction-to-web-applications.md) · [09](modules/09-web-requests.md) |
| **Recon & Enumeration** | [10 Nmap](modules/10-network-enumeration-with-nmap.md) · [11 Footprinting](modules/11-footprinting.md) · [12 Web Recon](modules/12-information-gathering-web.md) |
| **Pre-Exploit** | [13 File Transfers](modules/13-file-transfers.md) · [14 Vuln Assessment](modules/14-vulnerability-assessment.md) · [15 Shells & Payloads](modules/15-shells-and-payloads.md) · [16 Metasploit](modules/16-metasploit-framework.md) |
| **Exploitation & Lateral** | [17 Password Attacks](modules/17-password-attacks.md) · [18 Common Services](modules/18-attacking-common-services.md) · [19 Pivoting](modules/19-pivoting-tunneling-port-forwarding.md) · [20 AD Attacks](modules/20-active-directory-attacks.md) |
| **Web Exploitation** | [21 Web Proxies](modules/21-using-web-proxies.md) · [22 FFuF](modules/22-attacking-web-apps-with-ffuf.md) · [23 Login Brute Force](modules/23-login-brute-forcing.md) · [24 SQLi](modules/24-sql-injection-fundamentals.md) · [25 SQLMap](modules/25-sqlmap-essentials.md) · [26 XSS](modules/26-xss.md) · [27 File Inclusion](modules/27-file-inclusion.md) · [28 File Upload](modules/28-file-upload-attacks.md) · [29 Command Injection](modules/29-command-injection.md) · [30 Web Attacks](modules/30-web-attacks.md) · [31 Common Apps](modules/31-attacking-common-applications.md) |
| **Post-Exploit** | [32 Linux Privesc](modules/32-linux-privilege-escalation.md) · [33 Windows Privesc](modules/33-windows-privilege-escalation.md) |
| **Reporting & Capstone** | [34 Reporting](modules/34-documentation-and-reporting.md) · [35 Enterprise Methodology](modules/35-attacking-enterprise-networks.md) |

### Appendices

- [Quick commands](appendices/quick-commands.md) — most-used one-liners across all phases
- [References](appendices/references.md) — canonical external resources

### Common quick lookups

| I want to… | Go to |
|---|---|
| Pick the right reverse shell | [15 Shells & Payloads](modules/15-shells-and-payloads.md) |
| Look up a SUID binary | [GTFOBins](https://gtfobins.github.io/) + [32 Linux Privesc](modules/32-linux-privilege-escalation.md) |
| Look up a Windows abuse path | [LOLBAS](https://lolbas-project.github.io/) + [33 Windows Privesc](modules/33-windows-privilege-escalation.md) |
| Identify a hash | [17 Password Attacks](modules/17-password-attacks.md) |
| Pick an `nmap` invocation | [10 Nmap](modules/10-network-enumeration-with-nmap.md) |
| Build a `msfvenom` payload | [15 Shells & Payloads](modules/15-shells-and-payloads.md) |
| Pivot through a host | [19 Pivoting](modules/19-pivoting-tunneling-port-forwarding.md) |
| Plan an AD attack chain | [20 AD Attacks](modules/20-active-directory-attacks.md) |
| Structure a finding | [34 Reporting](modules/34-documentation-and-reporting.md) |
| Run an end-to-end engagement | [35 Enterprise Methodology](modules/35-attacking-enterprise-networks.md) |

## Conventions

- `$` prefix → unprivileged shell, `#` → root/admin, `PS>` → PowerShell, `mimikatz #` → mimikatz prompt.
- `<TARGET>`, `<RHOST>`, `<LHOST>`, `<USER>`, `<PASS>`, `<DC>`, `<DOMAIN>` are placeholders — substitute before running.
- Code blocks are tagged with the language they should be executed in (`bash`, `cmd`, `powershell`, `sql`, etc.).
- Sources are listed at the bottom of every module file.
- Cross-references between modules are relative links.

## Sourcing & licensing

All content is original prose written from public references. Each module lists its sources. The repo is **MIT-licensed** — see [LICENSE](LICENSE). Use it, fork it, modify it, share it.

External resources cited throughout:

- [HackTricks](https://book.hacktricks.wiki/) — community-curated pentest reference
- [The Hacker Recipes](https://www.thehacker.recipes/) — particularly strong on AD
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — payload library (MIT)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — web vuln theory
- [OWASP](https://owasp.org/) — testing guide, cheat sheets, ASVS
- [GTFOBins](https://gtfobins.github.io/) — Linux privesc lookup
- [LOLBAS](https://lolbas-project.github.io/) — Windows binary abuse lookup
- [WADComs](https://wadcoms.github.io/) — Windows AD/network commands lookup
- Tool docs: nmap.org, sqlmap.org, hashcat.net, openwall.com/john, NetExec wiki, Impacket, BloodHound, Metasploit
- RFCs and Microsoft Learn for protocol-level details

## Contributing

Personal repo, but issues and PRs are welcome:

- Found a typo or broken command? Open a PR.
- Found that a command doesn't work with a newer tool version? Open an issue with the version + corrected syntax.
- Want to add a technique? Open an issue first to discuss scope. Keep it command-first; teaching prose belongs in source course material, not here.
- **Do not** submit content copied from any paid course (HTB Academy, OffSec, Zero-Point Security, etc.).

## Disclaimer

This material is for educational use, authorized penetration testing, and Capture-The-Flag exercises. The author is not responsible for misuse. Always verify scope and authorization before running any command from this cheatsheet against a target.
