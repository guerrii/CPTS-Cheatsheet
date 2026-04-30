# References

Canonical external resources cited throughout the cheatsheet, grouped by topic.

## General methodology & frameworks

- [PTES (Penetration Testing Execution Standard)](http://www.pentest-standard.org/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [NIST SP 800-115 — Technical Guide to Security Testing](https://csrc.nist.gov/pubs/sp/800/115/final)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CVE / NVD](https://nvd.nist.gov/)
- [CISA KEV (Known Exploited Vulnerabilities)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CVSS v3.1 calculator](https://www.first.org/cvss/calculator/3.1)

## Multi-topic curated references

- [HackTricks](https://book.hacktricks.wiki/) — pentest playbook, broadest topic coverage
- [The Hacker Recipes](https://www.thehacker.recipes/) — particularly strong on AD
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — payload library, MIT-licensed
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — web vuln theory + free labs
- [SecLists](https://github.com/danielmiessler/SecLists) — wordlists for everything
- [WADComs](https://wadcoms.github.io/) — Windows AD/network commands, searchable
- [GTFOBins](https://gtfobins.github.io/) — Linux binary abuse lookup
- [LOLBAS](https://lolbas-project.github.io/) — Windows binary abuse lookup
- [LOOBins](https://www.loobins.io/) — macOS binary abuse lookup
- [revshells.com](https://www.revshells.com/) — reverse shell payload generator

## Network / protocols

- [Nmap docs](https://nmap.org/book/man.html) and [NSE script DB](https://nmap.org/nsedoc/)
- [Wireshark display filter reference](https://www.wireshark.org/docs/dfref/)
- IETF RFCs: [791](https://www.rfc-editor.org/rfc/rfc791) IPv4, [793](https://www.rfc-editor.org/rfc/rfc793) TCP, [768](https://www.rfc-editor.org/rfc/rfc768) UDP, [9110](https://www.rfc-editor.org/rfc/rfc9110) HTTP, [4120](https://www.rfc-editor.org/rfc/rfc4120) Kerberos, [4511](https://www.rfc-editor.org/rfc/rfc4511) LDAP, [6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0
- [IANA service-port assignments](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

## Linux

- [Filesystem Hierarchy Standard](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html)
- [PEASS-ng (linpeas)](https://github.com/peass-ng/PEASS-ng)
- [pspy](https://github.com/DominicBreuker/pspy)
- [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- `man capabilities`, `man sudoers`, `man systemd.unit`

## Windows

- [Microsoft Learn — Windows](https://learn.microsoft.com/en-us/windows/)
- [Microsoft Learn — PowerShell](https://learn.microsoft.com/en-us/powershell/)
- [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
- [PowerSploit / PowerUp](https://github.com/PowerShellMafia/PowerSploit)
- [winPEAS (PEASS-ng)](https://github.com/peass-ng/PEASS-ng)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [UACME](https://github.com/hfiref0x/UACME) — UAC bypass catalog
- [The Potato family — JuicyPotato](https://github.com/ohpe/juicy-potato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), [GodPotato](https://github.com/BeichenDream/GodPotato), [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [ired.team](https://www.ired.team/) — offensive security playbooks

## Active Directory

- [The Hacker Recipes — AD](https://www.thehacker.recipes/ad)
- [HackTricks — AD methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/)
- [ADSecurity blog](https://adsecurity.org/) (Sean Metcalf)
- [SpecterOps — Certified Pre-Owned (ADCS)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [BloodHound CE docs](https://bloodhound.specterops.io/)
- [Impacket](https://github.com/fortra/impacket)
- [Certipy](https://github.com/ly4k/Certipy)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [NetExec wiki](https://www.netexec.wiki/)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [kerbrute](https://github.com/ropnop/kerbrute)
- [mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Coercer](https://github.com/p0dalirius/Coercer)

## Web

- [PortSwigger Academy](https://portswigger.net/web-security) (course-by-course)
- [PayloadsAllTheThings — Web sections](https://github.com/swisskyrepo/PayloadsAllTheThings) (XSS, SQLi, CSRF, SSRF, SSTI, etc.)
- [HackTricks — Web pentesting](https://book.hacktricks.wiki/en/pentesting-web/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [GraphQL security](https://graphql.security/)
- [JWT Toolkit (`jwt_tool`)](https://github.com/ticarpi/jwt_tool)
- [SQLMap](https://github.com/sqlmapproject/sqlmap)
- [tplmap (SSTI)](https://github.com/epinna/tplmap)
- [ysoserial (Java deser)](https://github.com/frohoff/ysoserial)
- [phpggc (PHP deser)](https://github.com/ambionics/phpggc)
- [Burp Suite docs](https://portswigger.net/burp/documentation)
- [OWASP ZAP docs](https://www.zaproxy.org/docs/)

## Crypto / passwords

- [Hashcat wiki](https://hashcat.net/wiki/) and [examples](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [John the Ripper docs](https://www.openwall.com/john/doc/)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [crackstation.net](https://crackstation.net/) — online lookup for unsalted hashes

## Pivoting / C2

- [chisel](https://github.com/jpillora/chisel)
- [ligolo-ng](https://github.com/nicocha30/ligolo-ng)
- [sshuttle](https://github.com/sshuttle/sshuttle)
- [proxychains-ng](https://github.com/rofl0r/proxychains-ng)
- [socat docs](http://www.dest-unreach.org/socat/doc/socat.html)

## Reporting

- [PTES Reporting](http://www.pentest-standard.org/index.php/Reporting)
- [SysReptor](https://docs.sysreptor.com/)
- [GhostWriter (SpecterOps)](https://github.com/GhostManager/Ghostwriter)
- [Pwndoc](https://github.com/pwndoc/pwndoc)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

## Reverse engineering / binary (out of CPTS scope, useful adjacent)

- [Compiler Explorer](https://godbolt.org/)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [radare2 / rizin / Cutter](https://rizin.re/)

## Cloud (adjacent)

- [HackTricks Cloud](https://cloud.hacktricks.wiki/)
- [PayloadsAllTheThings — Cloud](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md)

## OSINT

- [crt.sh](https://crt.sh/)
- [Shodan](https://www.shodan.io/)
- [Censys](https://search.censys.io/)
- [theHarvester](https://github.com/laramies/theHarvester)
- [Amass](https://github.com/owasp-amass/amass)
- [Subfinder](https://github.com/projectdiscovery/subfinder)

## Practice (legal)

- [HackTheBox](https://www.hackthebox.com/) — main lab platform
- [TryHackMe](https://tryhackme.com/) — beginner-friendly rooms and paths
- [PortSwigger Academy](https://portswigger.net/web-security) — free, browser-based web labs
- [VulnHub](https://www.vulnhub.com/) — downloadable lab VMs
- [PicoCTF](https://picoctf.org/) — beginner CTFs

## Reading (long-form, exam-relevant)

- "The Web Application Hacker's Handbook" (Stuttard & Pinto) — older but timeless web theory
- "Red Team Field Manual" (Clark, RTFM v2) — pocket reference
- "The Hacker Playbook 3" (Kim) — methodology
- "Real-World Bug Hunting" (Yaworski) — bug-bounty case studies
- "Practical IoT Hacking" (Chantzis et al.) — adjacent
