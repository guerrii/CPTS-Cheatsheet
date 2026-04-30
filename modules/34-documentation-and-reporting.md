# 34 — Documentation & Reporting

The deliverable is the report, not the shells. This module is the structure and discipline that turns engagement notes into a defensible document.

## Note-taking during the engagement

Adopt **one** system and stick to it. Common picks: Obsidian, CherryTree, Joplin, plain Markdown in a directory tree, or Notion if the client policy allows.

Minimum schema:

```
~/engagements/<client>/<date>/
├── scope.txt
├── notes.md                ← timestamped running log
├── recon/
│   ├── nmap-stage1.gnmap
│   ├── nmap-stage2.nmap
│   └── subdomains.txt
├── creds/
│   ├── valid.txt           ← <user>:<pass>:<source>
│   └── hashes/
├── loot/                    ← exfiltrated files (encrypted at rest)
├── findings/
│   ├── F001-<title>/
│   │   ├── description.md
│   │   ├── evidence/
│   │   │   ├── 01-request.png
│   │   │   ├── 02-response.png
│   │   │   └── raw.har
│   │   └── remediation.md
│   └── F002-<title>/
└── report/                  ← final assembly
```

### What each note must include

- Timestamp (`date -Iseconds` or `date /T` on Windows).
- Source IP / VPN tunnel name.
- Target IP / hostname / URL.
- Exact command run (copy-paste, never reconstruct).
- Output excerpt that proves the finding.
- Screenshot when GUI is involved.

`script` records a whole terminal session including escape codes:

```bash
script -t 2> session.tim session.log
# ...do stuff...
exit
# Replay later:
scriptreplay session.tim session.log
```

## Severity scoring

Default to **CVSS v3.1 base score** with a vector string in every finding. Override with environmental score when the asset's context changes the impact (e.g., a 7.5 vuln on a workstation might be 9.0 on a domain controller).

Severity bands (CVSS 3.1):

| Band | Score |
|---|---|
| Critical | 9.0–10.0 |
| High | 7.0–8.9 |
| Medium | 4.0–6.9 |
| Low | 0.1–3.9 |
| Informational | 0.0 |

Calculator: https://www.first.org/cvss/calculator/3.1

For chained findings, score each individually and add an "Attack Path" finding that scores the chain — usually higher than any single component.

## Report structure

Industry standard, used in some form by every consultancy:

1. **Title page** — engagement name, dates, version, classification.
2. **Document control** — author, reviewer, distribution list, revision history.
3. **Confidentiality notice** — handling caveats.
4. **Executive summary** — 1–2 pages, plain English.
5. **Scope and methodology** — what was tested, what was not, framework used.
6. **Findings overview** — count by severity, summary table.
7. **Detailed findings** — one section per finding.
8. **Attack narrative** — chained-findings story (pure attacker prose).
9. **Recommendations** — strategic, beyond per-finding fixes.
10. **Appendices** — tools used, raw output, scripts, IOCs, evidence index.

### Executive summary — what it must contain

Audience: CTO/CISO who never opens the rest of the document.

- One paragraph: what was tested and how.
- One paragraph: highest-risk findings in plain English (no acronyms).
- A small chart or table with severity counts.
- A single overall risk statement (e.g., "internal compromise was achieved within X hours").
- One paragraph of strategic recommendations.

Two pages maximum. No CVSS strings, no tool names, no payloads.

### Per-finding template

Every finding should have:

```
F-XXX  <Short, descriptive title>

Severity:   <Critical/High/Medium/Low/Info>
CVSS:       <vector string>  (score)
Affected:   <hostnames/IPs/URLs>
Discovered: <date>

Description
-----------
What is wrong, in 2-4 sentences. Plain English first, technical second.

Impact
------
What an attacker can actually do with this. Tied to the customer's business
where possible (data theft, lateral movement, regulatory exposure).

Evidence
--------
- Screenshot 1: ...
- Command + output excerpt:

    $ nmap -p445 --script smb2-security-mode 10.0.0.5
    | smb2-security-mode:
    |   message_signing: disabled (dangerous, but default)

- Reproduction steps (numbered, runnable verbatim).

Remediation
-----------
Concrete actions: vendor patch number, configuration line, code change.
Pointer to vendor docs / CIS benchmark / NIST guidance.

References
----------
CVE, vendor advisory, public PoC, MITRE ATT&CK technique IDs.
```

Keep titles consistent in style ("SMB Signing Not Enforced on Domain Controllers", not a paragraph).

### Attack narrative

A short, chronological prose section that walks the reader through the chain you actually used to get to the goal:

```
1. We discovered that the corporate web application leaked
   employee email addresses through the password-reset page.
2. Using the harvested email list, we performed a Kerberos
   password spray against the domain controllers and obtained
   credentials for user `m.smith`.
3. Bloodhound analysis revealed that `m.smith` had GenericWrite
   over the `helpdesk` group...
```

This is the section management actually reads. Tie each step to a finding ID so each numbered point links to its detailed entry.

## Evidence handling

- Capture **request and response** for every web finding (Burp item → Save selected items).
- Capture full terminal output, not just the success line — context proves the vulnerability is reachable.
- Screenshots: include the URL bar, timestamp, and your IP if relevant.
- Redact secrets in the report (passwords, tokens, customer PII) and keep the unredacted copy under engagement-store encryption.
- Hash-and-store binaries you used (`sha256sum`) so the customer can verify what ran on their assets.

## Tooling

| Tool | Use |
|---|---|
| Obsidian / Joplin / CherryTree | Field notes |
| Burp project file | Web evidence persistence |
| `script` | Terminal session capture |
| Flameshot, ShareX, macOS native | Screenshots with annotations |
| `pandoc` | Markdown → DOCX/PDF |
| Word / LibreOffice templates | Final assembly |
| **PlexTrac**, **Dradis**, **SysReptor**, **Faraday**, **Hexway** | Reporting platforms |
| **GhostWriter** (SpecterOps) | Engagement & reporting platform |
| Pwndoc | OSS report generator |

A pandoc-based pipeline (no licenses):

```bash
pandoc -s --reference-doc=template.docx \
  -o final.docx \
  cover.md exec-summary.md scope.md findings/*.md narrative.md appendices.md
```

## Reproducibility checklist

Before submitting:

- [ ] Every finding has a CVSS vector and score.
- [ ] Every finding has at least one screenshot or copy-pasteable command output.
- [ ] Reproduction steps run end-to-end on a clean shell.
- [ ] All credentials / tokens / customer PII redacted in the deliverable.
- [ ] Severity totals on the summary page match the count of detail sections.
- [ ] Attack narrative cross-references finding IDs.
- [ ] Tooling and methodology section lists what you actually ran.
- [ ] Out-of-scope items explicitly listed in scope section.
- [ ] Recommendations exist for every finding, with vendor / CWE references.
- [ ] Spell-check pass.
- [ ] Customer name and dates correct on every page (footer).
- [ ] Document classification banner on every page if required.
- [ ] Encrypted PDF if delivery is by email; secure link otherwise.

## Re-test report

When the customer says they fixed things, redo the relevant tests and produce a short addendum:

- Original finding ID + severity.
- Test method used to validate.
- Outcome: Closed / Partially Closed / Open.
- New CVSS (if reduced).
- Evidence of resolution.

## Common report mistakes

- Copy-pasting Nessus / nmap output as "findings" without validation.
- One screenshot for ten findings ("here's BloodHound").
- Same wording for every remediation ("apply vendor patch").
- Missing impact language — saying *what* was found but not *what it lets an attacker do*.
- CVSS scores that disagree with the vector string. Use the calculator.
- Mixing voices ("we", "I", passive) within a single finding.
- Including raw client passwords / tokens in the deliverable.
- "Critical" findings without a clear exploitation path.

## Sources

- PTES Reporting: http://www.pentest-standard.org/index.php/Reporting
- NIST SP 800-115 (Section 7): https://csrc.nist.gov/pubs/sp/800/115/final
- OWASP Web Security Testing Guide — Reporting: https://owasp.org/www-project-web-security-testing-guide/
- FIRST CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
- MITRE ATT&CK: https://attack.mitre.org/
- CIS Benchmarks (remediation reference): https://www.cisecurity.org/cis-benchmarks
- SysReptor / GhostWriter / Pwndoc / Dradis (open-source reporting platforms).
