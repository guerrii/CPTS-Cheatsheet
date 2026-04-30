# 07 — Introduction to Active Directory

Concepts and vocabulary you need before doing AD enumeration or attacks. Hands-on AD attack syntax lives in [20 Active Directory Enumeration & Attacks](20-active-directory-attacks.md).

## What AD is

Microsoft's directory service. Stores objects (users, computers, groups, GPOs) in a hierarchical database (`NTDS.dit`) on Domain Controllers, accessible primarily via LDAP and authenticated via Kerberos and NTLM.

## Core terminology

| Term | Meaning |
|---|---|
| Forest | Top-level container; one or more domain trees sharing schema/global catalog. |
| Tree | Domains sharing a contiguous DNS namespace. |
| Domain | Administrative boundary. Stored on DCs. |
| Domain Controller (DC) | Server holding a writable copy of the directory. |
| RODC | Read-Only DC; cached subset of credentials. |
| OU | Organizational Unit — folder for delegating admin and applying GPOs. |
| Object | User, computer, group, OU, GPO, etc. Each has a SID and a DN. |
| GPO | Group Policy Object — config applied to OUs / sites / domains. |
| Trust | Relationship between domains/forests for authentication. |
| Site | Network-topology grouping for replication and DC selection. |
| Global Catalog | Forest-wide partial replica (queried on TCP 3268/3269). |
| FSMO | Five flexible-single-master roles (Schema, Domain Naming, RID, PDC, Infrastructure). |

## Object naming

- **DN (Distinguished Name)**: `CN=Alice,OU=Sales,DC=corp,DC=local`
- **CN**: Common Name (object's name)
- **OU**: container path
- **DC**: domain components (split DNS name)
- **UPN (User Principal Name)**: `alice@corp.local`
- **sAMAccountName**: pre-Windows-2000 logon name (`alice`); machine accounts end with `$` (e.g. `WS01$`).
- **objectSID**: security identifier; well-known RIDs: 500 Administrator, 502 krbtgt, 512 Domain Admins, 513 Domain Users, 516 DCs, 519 Enterprise Admins.

## Authentication: NTLM (legacy)

Challenge/response over the wire. The user's password is hashed with MD4 to form an `NT hash`; that hash is the secret used in the challenge. NTLM still works on most networks because of legacy clients.

NTLM message flow:

```
Client → Server: NEGOTIATE
Server → Client: CHALLENGE (server nonce)
Client → Server: AUTHENTICATE (HMAC of nonce keyed with NT hash)
```

The hash is the credential — see "pass-the-hash" in [20 AD Attacks](20-active-directory-attacks.md).

NTLMv1 and v2 differ in the response algorithm; v1 is broken (NetNTLMv1 → NT hash via crack.sh).

## Authentication: Kerberos

Default in AD when DNS is healthy. Symmetric tickets, no plaintext on the wire.

### Tickets

- **TGT (Ticket Granting Ticket)**: proves identity; issued by the KDC's AS (Authentication Service). Encrypted with the `krbtgt` account's key.
- **TGS (Ticket Granting Service ticket)**: per-service ticket; encrypted with the target service account's key.

### Flow (simplified)

1. **AS-REQ** — client → KDC: "I am Alice." Includes a timestamp encrypted with Alice's key (preauth).
2. **AS-REP** — KDC → client: TGT (encrypted with `krbtgt` key) + a session key.
3. **TGS-REQ** — client → KDC: "I want a ticket for `cifs/server`." Presents TGT.
4. **TGS-REP** — KDC → client: TGS encrypted with the service account's key.
5. **AP-REQ** — client → service: presents TGS.

### SPNs

A Service Principal Name links a service to the account that runs it: `MSSQLSvc/db01.corp.local:1433` → SQL service account. SPNs make Kerberoasting possible (see [20](20-active-directory-attacks.md)).

### Special accounts

- `krbtgt` — domain account whose password hash signs every TGT. Compromising it enables Golden Tickets.
- Computer accounts (`HOST$`) — every domain-joined machine has one; their NT hash signs TGS for the machine's services.

## LDAP basics

LDAP is the query protocol for the directory. Ports: 389 (LDAP), 636 (LDAPS), 3268/3269 (Global Catalog, GC over TLS).

```bash
# Anonymous bind (often blocked but try anyway)
ldapsearch -x -H ldap://dc.corp.local -b "DC=corp,DC=local"

# Authenticated bind
ldapsearch -x -H ldap://dc.corp.local -D "alice@corp.local" -w 'Password1' \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName memberOf

# RootDSE (no creds needed)
ldapsearch -x -H ldap://dc.corp.local -s base -b "" "(objectClass=*)"
```

Common filters:

| Filter | Selects |
|---|---|
| `(objectClass=user)` | All user/computer objects |
| `(&(objectCategory=person)(objectClass=user))` | Real user accounts |
| `(objectCategory=computer)` | Computers |
| `(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)` | DA group members |
| `(servicePrincipalName=*)` | Accounts with SPNs (Kerberoast targets) |
| `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` | DONT_REQ_PREAUTH (AS-REP roast targets) |
| `(adminCount=1)` | Members of protected groups (now or historically) |

## Group Policy (GPO)

- Applied at site / domain / OU level (precedence: Local → Site → Domain → OU; later wins, unless enforced).
- Stored as files under `\\<domain>\SYSVOL\<domain>\Policies\{GUID}`.
- Linked to objects via `gPLink` attribute.
- Edit rights → code execution on every box the GPO applies to.

## Trusts

| Trust | Direction | Use |
|---|---|---|
| Parent-child | Two-way, transitive | Within a tree |
| Tree-root | Two-way, transitive | Between trees in a forest |
| Forest | Configurable | Between forests |
| External | Configurable, non-transitive | To NT domains or other forests |
| Realm | Configurable | To non-Windows Kerberos realms |
| Shortcut | One/two-way, transitive | Optimize within a forest |

Trust direction is the *trust* arrow, not the access arrow — A trusts B means principals in B can access resources in A.

## Useful built-in groups

| Group | What they can do |
|---|---|
| Domain Admins | Full control of the domain. |
| Enterprise Admins | Full control of the forest. |
| Schema Admins | Modify the schema. |
| Account Operators | Manage non-admin accounts. |
| Server Operators | Local admin on DCs (effectively domain-level). |
| Backup Operators | Read SAM/SYSTEM/NTDS via SeBackupPrivilege. |
| Print Operators | Load drivers (Print Spooler abuse). |
| DnsAdmins | Load DLLs into the DNS service (potential RCE on DC). |
| Remote Management Users | Connect via WinRM. |
| Remote Desktop Users | RDP in. |
| Protected Users | Restricts NTLM/Kerberos behavior to mitigate credential theft. |

## Sources

- Microsoft Learn (Active Directory): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services
- RFC 4120 (Kerberos), RFC 4511 (LDAP).
- The Hacker Recipes (AD): https://www.thehacker.recipes/ad
