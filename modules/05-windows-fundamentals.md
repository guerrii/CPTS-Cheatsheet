# 05 — Windows Fundamentals

Windows architecture, filesystem, registry, accounts, and services — enough context to recognize what you are looking at on a target Windows host.

## Filesystem

| Path | Contents |
|---|---|
| `C:\Windows\System32` | Core system binaries (despite the name, 64-bit on x64) |
| `C:\Windows\SysWOW64` | 32-bit binaries on x64 systems |
| `C:\Windows\Temp` | World-writable temp |
| `C:\Users\<user>` | User profile |
| `C:\Users\<user>\AppData\{Local,LocalLow,Roaming}` | App data |
| `C:\ProgramData` | Machine-wide app data (often loose ACLs) |
| `C:\Program Files`, `C:\Program Files (x86)` | Installed software |
| `C:\Windows\System32\config\` | SAM, SECURITY, SYSTEM hives |
| `C:\Windows\NTDS\NTDS.dit` | AD database (DC only) |
| `C:\Windows\Panther\Unattend.xml` | Possible plaintext creds (post-install leftover) |
| `C:\inetpub\wwwroot` | IIS default web root |

NTFS streams (`file:stream`) hide data inside files; `dir /r` reveals them.

## Accounts & SIDs

- Local accounts live in the SAM database.
- Domain accounts live in NTDS.dit on Domain Controllers.
- Each principal has a SID like `S-1-5-21-<domain>-<RID>`.
- Well-known RIDs: `500` Administrator, `501` Guest, `512` Domain Admins, `513` Domain Users, `516` Domain Controllers.
- Built-in groups: `Administrators`, `Users`, `Backup Operators`, `Remote Desktop Users`, `Remote Management Users` (WinRM), `Hyper-V Administrators`, `DnsAdmins`.

## Authentication packages

- `MSV1_0` — local NTLM authentication.
- `Kerberos` — domain authentication (preferred when a DNS-resolvable DC is reachable).
- `Negotiate` (SPNEGO) — picks Kerberos or NTLM.
- `WDigest` — legacy; if enabled (`UseLogonCredential = 1`) plaintext passwords end up in LSASS memory.

LSASS (`lsass.exe`) holds credential material in memory — this is what mimikatz, `pypykatz`, and `lsassy` dump.

## Registry

Hierarchical, hive-based config store. Common hives:

| Hive | Contents |
|---|---|
| `HKLM` (HKEY_LOCAL_MACHINE) | Machine-wide settings (Software, System, Security, SAM) |
| `HKCU` (HKEY_CURRENT_USER) | Current user |
| `HKCR` (HKEY_CLASSES_ROOT) | File associations / COM |
| `HKU` (HKEY_USERS) | All loaded user profiles |
| `HKCC` (HKEY_CURRENT_CONFIG) | Hardware profile |

Useful keys for offense:

| Key | Why |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services` | Services configuration (binPath, start type) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Autoruns |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `DefaultUserName`, `DefaultPassword` (autologon) |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | LSA config (RunAsPPL, RestrictedAdmin) |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` → `AlwaysInstallElevated` | Privesc opportunity |
| `HKLM\SOFTWARE\RealVNC`, `\TightVNC`, `\PuTTY\Sessions` | Stored creds |

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg add HKCU\Software\... /v Name /t REG_SZ /d Value /f
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```

## Services

A Windows service runs in the background under a configurable identity (`LocalSystem`, `LocalService`, `NetworkService`, or a domain account). Misconfiguration → privesc.

```cmd
sc query
sc qc <service>                       # config, including binPath
sc config <service> binPath= "C:\path\evil.exe"
sc start <service>
```

Risky misconfigurations:
- Writable service binary path.
- Unquoted service paths with spaces (`C:\Program Files\X Y\service.exe`).
- Weak ACLs on the service itself (`SERVICE_CHANGE_CONFIG`).
- Privileged user runs the service (`Get-Service | ... StartName`).

## Permissions (NTFS / share)

```cmd
icacls C:\path
icacls C:\path /grant user:F
icacls C:\path /remove user
```

`accesschk` (Sysinternals) is more readable for offensive enumeration:

```cmd
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uws "Everyone" "C:\Program Files"
```

## Important processes

| Process | Role |
|---|---|
| `System` (PID 4) | Kernel + drivers |
| `smss.exe` | Session Manager |
| `csrss.exe` | Client/Server runtime (one per session) |
| `wininit.exe` | Initializes session 0 services |
| `services.exe` | Service Control Manager |
| `lsass.exe` | Local Security Authority — credential material |
| `winlogon.exe` | Logon UI |
| `explorer.exe` | Shell |
| `svchost.exe` | Hosts services (multiple instances) |

## UAC (User Account Control)

- Splits an admin token into a filtered medium-IL token and a full high-IL token.
- Spawn a high-IL process by accepting an elevation prompt or an auto-elevate path.
- Bypass categories (research/internal use): COM hijacks, `fodhelper`, `eventvwr`, `sdclt`, environment-variable abuse — see [33 Windows Privesc](33-windows-privilege-escalation.md).

## Useful enumeration commands (cmd / PowerShell)

```cmd
systeminfo
hostname
whoami /all
net user
net localgroup
net localgroup administrators
wmic qfe list brief                    # patches
tasklist /v
ipconfig /all
route print
arp -a
netstat -ano
```

```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
Get-Service | Where-Object Status -eq Running
Get-CimInstance Win32_OperatingSystem | select Caption, Version, BuildNumber
Get-HotFix
Get-Process
```

## Sources

- Microsoft Learn: https://learn.microsoft.com/en-us/windows/
- Sysinternals: https://learn.microsoft.com/en-us/sysinternals/
- LOLBAS: https://lolbas-project.github.io/
