# 09 — Web Requests

HTTP request/response anatomy, methods, headers, status codes, and command-line clients (`curl`, `wget`, `Invoke-WebRequest`).

## Anatomy of a request / response

```
GET /path?key=val HTTP/1.1            ← request line: METHOD SP TARGET SP VERSION
Host: example.com                     ← headers
User-Agent: curl/8.0
Accept: */*
Cookie: SID=abc

(empty line)
(optional body, on POST/PUT/PATCH)
```

```
HTTP/1.1 200 OK                       ← status line
Content-Type: text/html
Content-Length: 1234
Set-Cookie: SID=abc; HttpOnly

<body>
```

## Methods

| Method | Idempotent | Body | Use |
|---|---|---|---|
| GET | yes | no | Read |
| HEAD | yes | no | Read headers only |
| POST | no | yes | Create / arbitrary action |
| PUT | yes | yes | Replace |
| PATCH | no | yes | Partial update |
| DELETE | yes | no | Delete |
| OPTIONS | yes | no | Capabilities (CORS preflight) |
| TRACE | yes | no | Echo request — should be disabled |
| CONNECT | – | no | Tunnel (used by proxies) |

## Status codes (most useful)

| Code | Meaning |
|---|---|
| 200 | OK |
| 201 | Created |
| 204 | No Content |
| 301 / 308 | Permanent redirect |
| 302 / 303 / 307 | Temporary redirect |
| 304 | Not Modified |
| 400 | Bad Request |
| 401 | Unauthorized (no/invalid creds) |
| 403 | Forbidden (auth'd but not allowed) |
| 404 | Not Found |
| 405 | Method Not Allowed |
| 408 | Request Timeout |
| 409 | Conflict |
| 413 | Payload Too Large |
| 415 | Unsupported Media Type |
| 418 | I'm a teapot |
| 422 | Unprocessable Entity (validation) |
| 429 | Too Many Requests |
| 500 | Internal Server Error |
| 501 | Not Implemented |
| 502 | Bad Gateway |
| 503 | Service Unavailable |
| 504 | Gateway Timeout |

`401` vs `403` matters: `401` says "log in", `403` says "you can't go here even logged in".

## Headers cheat-sheet

| Header | Direction | Notes |
|---|---|---|
| `Host` | req | Required in HTTP/1.1; used for vhost routing. |
| `User-Agent` | req | Often filtered/logged. |
| `Accept`, `Accept-Encoding`, `Accept-Language` | req | Content negotiation. |
| `Authorization` | req | `Basic`, `Bearer`, `Digest`, custom. |
| `Cookie` | req | Session/state. |
| `Content-Type` | both | `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `text/xml`. |
| `Content-Length` | both | Bytes in body. |
| `Referer` | req | Sometimes used for CSRF/origin checks. |
| `Origin` | req | Used in CORS. |
| `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto` | req | Set by proxies — and frequently trusted incorrectly. |
| `Set-Cookie` | resp | Cookie attributes (Secure, HttpOnly, SameSite). |
| `Location` | resp | Redirect target. |
| `WWW-Authenticate` | resp | Auth challenge. |
| `Cache-Control`, `ETag`, `Last-Modified` | resp | Caching. |
| `Strict-Transport-Security` | resp | HSTS. |
| `Content-Security-Policy` | resp | CSP. |
| `X-Frame-Options` | resp | Clickjacking. |
| `X-Content-Type-Options: nosniff` | resp | MIME-sniffing block. |

## curl — daily driver

```bash
# Basic GET
curl https://example.com

# Show only response headers
curl -I https://example.com

# Verbose (request + response headers)
curl -v https://example.com

# Trace everything to file
curl --trace-ascii trace.txt https://example.com

# Follow redirects
curl -L https://example.com

# Custom method + headers + body
curl -X POST https://api/x \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer eyJ...' \
  -d '{"name":"alice"}'

# URL-encoded form
curl -X POST -d 'user=alice&pass=Pass1' https://target/login

# Multipart upload
curl -X POST -F 'file=@./shell.php' -F 'desc=test' https://target/upload

# Save body / discard body
curl -o out.html https://example.com
curl -s -o /dev/null -w '%{http_code}\n' https://example.com

# Cookie jar
curl -c jar.txt -b jar.txt https://target/login -d ...
curl -b 'SID=abc' https://target/dash

# Authentication
curl -u user:pass https://target            # Basic
curl --digest -u user:pass https://target   # Digest

# Proxy (Burp on 8080)
curl -x http://127.0.0.1:8080 -k https://target

# Don't verify TLS / use specific cert
curl -k https://self-signed
curl --cacert ca.pem https://target

# Specify HTTP version
curl --http1.1 / --http2 / --http3

# Resolve a host to a specific IP (vhost testing)
curl --resolve target.tld:443:10.10.10.5 https://target.tld/

# Send a raw Host header (vhost fuzzing)
curl -H 'Host: admin.target.tld' https://10.10.10.5/

# Repeat N times (timing / rate)
for i in {1..50}; do curl -s -o /dev/null -w '%{http_code}\n' https://t/; done
```

## wget

```bash
wget https://example.com/file.zip
wget -r -np -nH --cut-dirs=1 -R "index.html*" https://target/files/    # mirror
wget --user=alice --password=Pass1 https://target/private
wget --header='Cookie: SID=abc' https://target/dash
```

## PowerShell

```powershell
Invoke-WebRequest https://example.com -OutFile out.html
$r = Invoke-WebRequest https://target -SessionVariable s
Invoke-WebRequest https://target/dash -WebSession $s

# REST
Invoke-RestMethod https://api/x -Method POST -Body (@{name='alice'} | ConvertTo-Json) `
  -ContentType 'application/json' -Headers @{Authorization='Bearer eyJ...'}

# Skip cert validation (PS 6+)
Invoke-WebRequest -SkipCertificateCheck https://self-signed
```

## Crafting raw HTTP via netcat / openssl

```bash
# Plain HTTP
printf 'GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n' | nc target 80

# HTTPS
printf 'GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n' | \
  openssl s_client -connect target:443 -quiet -servername target
```

## Encoding quick reference

| Encoding | Example |
|---|---|
| URL | `space` → `%20`, `=` → `%3D` |
| HTML entity | `<` → `&lt;`, `&` → `&amp;` |
| Base64 | `echo -n 'admin:pass' | base64` |
| Hex | `echo -n 'abc' | xxd -p` |
| Unicode | `<`, full-width `＜` (sometimes bypasses filters) |

## HTTP/1.1 vs HTTP/2 vs HTTP/3

- HTTP/1.1: text framing, persistent connections, head-of-line blocking.
- HTTP/2: binary frames, multiplexing, header compression (HPACK). Smuggling/desync angles.
- HTTP/3: HTTP over QUIC (UDP).

For testing, force a version with `curl --http1.1` / `--http2` / `--http3`.

## Sources

- MDN HTTP: https://developer.mozilla.org/en-US/docs/Web/HTTP
- RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1), RFC 9113 (HTTP/2), RFC 9114 (HTTP/3), RFC 6265 (Cookies).
- `man curl`, `man wget`.
