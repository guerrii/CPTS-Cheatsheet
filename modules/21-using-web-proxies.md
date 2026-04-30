# 21 — Using Web Proxies

Burp Suite and OWASP ZAP — interception, replay, fuzzing, and the workflow that connects every web module that follows.

## Setup

### Browser configuration

Best path: launch a browser through the proxy's helper.

- Burp: **Proxy → Intercept → Open browser** (uses Burp's bundled Chromium with the CA pre-installed).
- ZAP: **Tools → Manual Explore → Launch Browser**.

If using a system browser, set the HTTP proxy to `127.0.0.1:8080` (Burp default) or `127.0.0.1:8081` (ZAP default).

### Install the CA certificate

Without it you cannot intercept HTTPS — the browser will refuse the proxy's cert.

```
Burp:  http://burpsuite — download "CA Certificate" → import as trusted.
ZAP:   Options → Network → Server Certificates → Save / Import.
```

System-wide on Linux:

```bash
sudo cp burp.crt /usr/local/share/ca-certificates/burp.crt
sudo update-ca-certificates
```

For tools that ignore the system store: `curl --cacert burp.crt`, `requests verify=path-to-pem`, `JAVA -Djavax.net.ssl.trustStore=...`.

### Mobile / native apps

- Android emulator + `adb` + Burp's CA in the system store (Android 7+ requires system-store install or Frida bypass).
- iOS: install profile + Charles or Burp.
- Use `mitmproxy` for headless / scripted interception (`mitmweb`).

## Burp Suite — daily workflow

### Map the application (Target / Site map)

1. Open the in-Burp browser.
2. Click around manually for the "happy path".
3. **Site map** populates automatically.
4. Right-click the host → **Add to scope**.
5. **Proxy → HTTP history** then filter by scope.

### Repeater (manual probing)

`Ctrl+R` from any request → modify → `Ctrl+Space` to send. Use it for:
- Testing parameters.
- Tampering headers / methods.
- Manual SQLi / SSTI / IDOR confirmation.

Useful Repeater keys (default): `Ctrl+R` send to Repeater, `Ctrl+I` send to Intruder, `Ctrl+U` URL-encode, `Ctrl+Shift+U` URL-decode, `Ctrl+B` Base64.

### Intruder (fuzzing)

Send to Intruder, mark insertion points (`§`), pick attack type:

| Type | Behavior |
|---|---|
| Sniper | One payload set, cycles through each insertion point one at a time. |
| Battering ram | Same payload simultaneously into all insertion points. |
| Pitchfork | One payload set per insertion point, advances together. |
| Cluster bomb | Cartesian product of all payload sets. |

Match-and-replace, response grep-extract, and grep-match are essential for spotting hits in noisy results.

Free edition rate-limits Intruder. For heavy fuzzing, use `ffuf` or `feroxbuster` with Burp as the upstream proxy (`-x http://127.0.0.1:8080`) so traffic still flows into the site map.

### Decoder

URL/HTML/Base64/Hex/ASCII-hex/Octal/Binary, plus hashes (MD5, SHA1, SHA256). Right-click → Smart decode handles unknown encodings.

### Comparer

Diff two responses (handy for boolean blind SQLi: legitimate vs payloaded response).

### Logger

Records every request through Burp regardless of source. Use it to verify what your other tools (`curl`, `ffuf`, scripts) actually sent.

### Useful extensions (BApp Store)

| Extension | Use |
|---|---|
| Logger++ | Better request log + filtering |
| Autorize | Authorization / IDOR comparison between two sessions |
| Param Miner | Hidden parameter / header / cookie discovery |
| Active Scan++ | Adds checks to Burp's scanner |
| JSON Web Token Editor | Modify/sign JWTs in-line |
| Hackvertor | Inline conversions in requests |
| Turbo Intruder | Fast Python-driven attack engine |
| Backslash Powered Scanner | SQL/NoSQL/SSI/SSTI fuzzing |
| Reflected Parameters | Highlights reflections automatically |
| Collaborator Everywhere | Auto-injects Burp Collaborator payloads |
| HTTP Request Smuggler | Desync detection |

### Match-and-replace tricks

`Proxy → Match and replace` — global rewrite rules that fire for every request through Burp:

- Add `X-Forwarded-For: 127.0.0.1` to every request.
- Replace a `Cookie: SESSION=...` value.
- Strip `Origin` / `Referer` headers.
- Force-downgrade `Accept-Encoding` to `identity` so payloads aren't gzipped in responses.

### Collaborator (out-of-band)

Use for blind SSRF/XSS/RCE/XXE detection — anything that can phone home but does not produce visible output.

`Burp Collaborator client → Copy to clipboard` → paste into payload. Poll for callbacks.

## OWASP ZAP — daily workflow

ZAP works as a Burp alternative; comparable feature set, fully open-source.

### Modes

- **Standard** — passive scanning everywhere.
- **Protected** — only scan in scope.
- **ATTACK** — auto-scan as you browse (only for lab / explicit scope).
- **Safe** — read-only.

### Key tools

| ZAP | Burp equivalent |
|---|---|
| Manual Explore / HUD | Proxy + browser |
| Spider / AJAX Spider | Site map + crawl |
| Active Scan | Scanner |
| Fuzzer | Intruder |
| Forced Browse | Discover |
| Scripts (JS/Groovy/Python) | Extensions / Bambdas |
| Sites tree | Target → Site map |

CLI / headless:

```bash
zap.sh -daemon -host 0.0.0.0 -port 8090
zap-cli quick-scan --self-contained https://target
```

### ZAP API

Full REST API (default key required) for automation, baseline scans, and CI.

```bash
zap-baseline.py -t https://target -r baseline.html
```

## mitmproxy — terminal workflow

```bash
mitmproxy -p 8080
mitmweb -p 8080                          # browser UI
mitmdump -p 8080 -w cap.mitm             # capture only
mitmdump -nr cap.mitm -s script.py        # replay through a script
```

Scriptable in Python — easy for one-off transforms (auto-set headers, capture creds, rewrite responses).

## Connecting CLI tools through Burp/ZAP

```bash
# curl
curl -x http://127.0.0.1:8080 -k https://target

# ffuf
ffuf -u https://target/FUZZ -w wordlist -replay-proxy http://127.0.0.1:8080

# sqlmap
sqlmap -u 'https://target/page?id=1' --proxy=http://127.0.0.1:8080

# wget
https_proxy=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080 wget --no-check-certificate https://target

# Python requests
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
requests.get(url, verify=False, proxies=proxies)
```

Routing every tool through the proxy keeps the site map authoritative and gives you a single audit trail.

## Saving evidence

- **Burp**: File → Save project → `.burp` (full state). For specific items: right-click → Save selected.
- **ZAP**: File → Persist Session.
- **mitmproxy**: `-w cap.mitm`.
- For reports: copy the request/response from Repeater, paste into the finding.

## Troubleshooting

- "SSL Handshake Error" — CA not trusted; reinstall.
- HTTP/2 oddities in older Burp — set Repeater to HTTP/1 explicitly when needed.
- Native app pinning — patch the app, use Frida-Gadget, or downgrade with mitmproxy + `--ssl-insecure`.
- Proxy chain (Burp → ZAP, or both → upstream corporate proxy): set "Upstream Proxy Servers" in Burp options.

## Sources

- PortSwigger Web Security Academy: https://portswigger.net/web-security
- Burp Suite docs: https://portswigger.net/burp/documentation
- OWASP ZAP docs: https://www.zaproxy.org/docs/
- mitmproxy docs: https://docs.mitmproxy.org/
