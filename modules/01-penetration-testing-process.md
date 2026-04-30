# 01 — Penetration Testing Process

High-level methodology, engagement types, and the phase model that the rest of the cheatsheet hangs off.

## Engagement types

| Type | What the tester knows |
|---|---|
| Black box | Nothing beyond scope (target IP / domain). Simulates an external attacker. |
| Gray box | Limited info (low-priv credentials, partial network diagram). Most realistic. |
| White box | Full access (source code, architecture, admin creds). Maximum coverage. |
| Red team | Goal-based, stealth-focused, simulates a specific threat actor. |
| Purple team | Red team + Blue team collaborating in real time. |

## Common phase models

The exact wording varies between PTES, OSSTMM, NIST SP 800-115, and OWASP WSTG, but the practical pipeline is:

```
Pre-engagement → Recon → Enumeration → Vulnerability Analysis →
Exploitation → Post-Exploitation → Lateral Movement → Reporting → Re-test
```

### 1. Pre-engagement
- Statement of Work (SoW), Rules of Engagement (RoE), scope, in/out-of-scope assets.
- Authorization letter ("get out of jail" card) — keep it on you during on-site work.
- Emergency contacts, working hours, allowed techniques, data handling rules.

### 2. Reconnaissance (passive)
- OSINT: WHOIS, DNS, certificate transparency, social media, leaks, GitHub.
- No packets to the target. Build target profile, asset list, and people list.

### 3. Enumeration (active)
- Port scanning (`nmap`), service fingerprinting, banner grabbing.
- Web crawling, subdomain enum, virtual host discovery, directory busting.
- Active Directory enumeration if internal.

### 4. Vulnerability Analysis
- Map services/versions to known CVEs, misconfigurations, and weak credentials.
- Manual review — automated scanners miss logic flaws.
- Prioritize by exploitability + business impact.

### 5. Exploitation
- Get initial foothold. Verify findings; PoC, not damage.
- Avoid DoS unless explicitly authorized.

### 6. Post-Exploitation
- Local enumeration, situational awareness, persistence (if in scope).
- Privilege escalation.
- Sensitive data discovery (PII, credentials, secrets).

### 7. Lateral Movement
- Credential harvesting, pivoting, tunneling.
- Domain dominance in AD environments (e.g., reach Domain Admin or equivalent).

### 8. Reporting
- Executive summary (non-technical).
- Technical findings (per-issue: description, impact, evidence, remediation, CVSS).
- Attack narrative (chained findings).
- Appendices (raw output, scripts, IOCs).

### 9. Re-test
- Validate that remediations actually fix the issues.

## Standards and frameworks

| Framework | Focus |
|---|---|
| PTES (Penetration Testing Execution Standard) | End-to-end methodology |
| OSSTMM | Security testing, metrics-driven |
| NIST SP 800-115 | Technical guide to security testing |
| OWASP WSTG | Web app testing |
| OWASP MASTG | Mobile app testing |
| MITRE ATT&CK | Adversary TTP knowledge base |
| PCI DSS / ISO 27001 | Compliance drivers that often trigger pentests |

## Scoping checklist

- [ ] In-scope IPs, domains, applications, source code repos.
- [ ] Out-of-scope assets (third-party SaaS, prod DB, etc.).
- [ ] Allowed techniques (DoS, social engineering, physical, password spraying).
- [ ] Test window (timezone, blackout dates).
- [ ] Credentials provided (gray/white box).
- [ ] Logging / detection expectations (do you want them to detect you?).
- [ ] Data handling: where does evidence live, encryption-at-rest, retention.
- [ ] Communication channels (Slack/Signal), incident escalation contact.
- [ ] Re-test included? Timeline.

## Severity & CVSS

Use CVSS v3.1 / v4.0 base score for technical severity. Adjust with environmental score for the client's context.

| Score | Rating |
|---|---|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.1 – 3.9 | Low |
| 0.0 | Informational |

Calculator: https://www.first.org/cvss/calculator/3.1

## Sources

- PTES: http://www.pentest-standard.org/
- NIST SP 800-115: https://csrc.nist.gov/pubs/sp/800/115/final
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- MITRE ATT&CK: https://attack.mitre.org/
- CVSS: https://www.first.org/cvss/
