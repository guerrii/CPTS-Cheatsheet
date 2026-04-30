# 04 — Linux Fundamentals

Reference for the Linux concepts and commands that come up during exploitation, lateral movement, and privesc.

## Filesystem layout

| Path | Contents |
|---|---|
| `/` | Root |
| `/bin`, `/sbin` | Essential binaries (often symlinks to `/usr/bin`) |
| `/etc` | System configuration |
| `/home/<user>` | User home directories |
| `/root` | Root's home |
| `/var` | Variable data (logs, mail, spool) |
| `/var/log` | Log files |
| `/tmp`, `/var/tmp`, `/dev/shm` | World-writable scratch space |
| `/opt` | Third-party software |
| `/usr` | User binaries, libraries, docs |
| `/proc` | Kernel & process info (virtual fs) |
| `/sys` | Kernel objects (virtual fs) |
| `/dev` | Device nodes |
| `/mnt`, `/media` | Mount points |
| `/boot` | Kernel + bootloader |

## Users, groups, permissions

### Files

```bash
ls -la           # long listing
stat file
file file
```

Permission triplets: `owner / group / other`, each with `r`, `w`, `x`.

```
-rwxr-xr-- 1 alice devs 4096 Jan 1 file
 ↑ ↑↑↑ ↑↑↑ ↑↑↑
 │ │   │   └─ other: r--
 │ │   └───── group: r-x
 │ └───────── owner: rwx
 └─────────── type:  - file, d dir, l symlink, b/c device, s socket, p fifo
```

```bash
chmod 750 file              # rwx r-x ---
chmod u+x,g-w file
chown alice:devs file
chgrp devs file
umask                       # default mask (subtract from 666/777)
```

### Special bits

| Bit | Octal | Meaning |
|---|---|---|
| SUID | 4xxx | Run as file's owner (e.g. `passwd`). Critical for privesc. |
| SGID | 2xxx | Run as file's group; on dirs, new files inherit group. |
| Sticky | 1xxx | On dirs, only owner can delete files (e.g. `/tmp`). |

```bash
chmod u+s file              # set SUID
chmod g+s dir               # set SGID
chmod +t /tmp               # sticky
```

### Find SUID / SGID / capabilities

```bash
find / -perm -4000 -type f 2>/dev/null      # SUID
find / -perm -2000 -type f 2>/dev/null      # SGID
find / -perm -u=s -o -perm -g=s 2>/dev/null
getcap -r / 2>/dev/null                      # file capabilities
```

Cross-reference results against [GTFOBins](https://gtfobins.github.io/) for exploitable binaries.

### Users & accounts

```bash
id
whoami
groups
who
last
cat /etc/passwd
sudo cat /etc/shadow
getent passwd
```

`/etc/passwd` format:
```
user:x:UID:GID:GECOS:home:shell
```

`/etc/shadow` format (root-only):
```
user:$<algo>$<salt>$<hash>:lstchg:min:max:warn:inactive:expire:reserved
```

Common hash IDs: `$1$` MD5crypt, `$2y$` bcrypt, `$5$` SHA-256, `$6$` SHA-512, `$y$` yescrypt.

## Common commands by purpose

### Navigation & files

```bash
pwd                                       # current dir
ls -lah                                   # listing with hidden, human sizes
cd -                                      # previous dir
tree -L 2 .                               # 2-level tree
find / -name "id_rsa" 2>/dev/null
find / -type f -size +100M 2>/dev/null
find / -mtime -1 2>/dev/null              # modified in last 24h
```

### Reading & editing

```bash
cat / less / more
head -n 50 file
tail -f /var/log/syslog
nano / vim / vi                           # interactive
sed -i 's/old/new/g' file
awk '{print $1, $7}' file
grep -RIn "password" /etc 2>/dev/null
```

### Process & service management

```bash
ps -ef
ps auxf
top / htop
pgrep -a sshd
kill -9 <pid>
systemctl status <unit>
systemctl list-units --type=service --state=running
journalctl -u sshd -e
```

### Networking (already covered in 03)

```bash
ip a; ip r
ss -tlnp
curl -I https://example
wget <url>
```

### Package management

```bash
# Debian/Ubuntu/Kali
apt update; apt install <pkg>; apt list --installed; dpkg -l | grep <pkg>
# RHEL/CentOS/Rocky
dnf install <pkg>; rpm -qa | grep <pkg>
# Arch
pacman -S <pkg>; pacman -Q
# Source/manual
make && sudo make install
```

### Compression & archives

```bash
tar -czf out.tgz dir/
tar -xzf out.tgz
tar -xJf x.tar.xz
zip -r out.zip dir/; unzip out.zip
gzip / gunzip
```

### Text & data manipulation

```bash
sort -u
uniq -c
cut -d: -f1 /etc/passwd
tr 'A-Z' 'a-z' < file
wc -l file
column -t -s,
xargs -n1 -I{} echo {}
diff -u a.txt b.txt
```

### Redirection & pipes

```bash
cmd > out 2> err
cmd &> all
cmd 2>&1 | tee log
cmd1 | cmd2
cmd1 < input
<(cmd)                  # process substitution
```

## Scheduled jobs

```bash
crontab -l
crontab -e
ls /etc/cron.{hourly,daily,weekly,monthly}
cat /etc/crontab
systemctl list-timers
```

Cron format:
```
m h dom mon dow command
```

## Bash quick reference

```bash
# Variables
VAR="value"
echo "$VAR"
export VAR

# Conditionals
if [[ -f file ]]; then ... ; fi
if [[ "$a" == "$b" ]]; then ... ; fi
[[ -z "$VAR" ]]   # empty
[[ -n "$VAR" ]]   # non-empty

# Loops
for i in {1..10}; do echo $i; done
while read line; do echo $line; done < file

# Functions
fn() { local x=$1; echo "hi $x"; }

# History / shortcuts
!!         # last command
!$         # last arg of last command
^old^new   # replace in last command
Ctrl-R     # reverse search
```

## Useful files for post-exploitation

| File | Why |
|---|---|
| `/etc/passwd` | User list |
| `/etc/shadow` | Hashes (root only) |
| `/etc/group`, `/etc/gshadow` | Group membership |
| `/etc/sudoers`, `/etc/sudoers.d/*` | Privilege rules |
| `/home/*/.ssh/` | Keys, `authorized_keys`, `known_hosts` |
| `/home/*/.bash_history`, `.zsh_history` | Command history |
| `/etc/crontab`, `/etc/cron.*/*` | Scheduled execution |
| `/etc/fstab` | Mounts (NFS, credentials) |
| `/etc/network/interfaces`, `/etc/netplan/*` | Network config |
| `/var/log/auth.log`, `/var/log/secure` | Auth events |
| `/var/log/apache2/*`, `/var/log/nginx/*` | Web logs (LFI fodder) |
| `/proc/version`, `/etc/os-release` | Kernel & distro version |
| `/var/mail/*` | Mailspool |

## Sources

- Filesystem Hierarchy Standard: https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html
- `man hier`, `man bash`, `man find`, `man chmod`
- GTFOBins: https://gtfobins.github.io/
