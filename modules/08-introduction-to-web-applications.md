# 08 — Introduction to Web Applications

Vocabulary, stack overview, and the attack-surface map you keep in your head when assessing a web app.

## Stack components

```
Client (browser, CLI, mobile)
   │  HTTP(S)
   ▼
Reverse proxy / WAF / CDN  ─── Cloudflare, nginx, F5, AWS ALB
   │
   ▼
Web server                 ─── Apache, nginx, IIS, Tomcat
   │  CGI/FCGI/WSGI/AJP
   ▼
Application server         ─── Node, PHP-FPM, Gunicorn, Tomcat, .NET, Java EE
   │  business logic
   ▼
Database / cache / queue   ─── MySQL, Postgres, MSSQL, Mongo, Redis, RabbitMQ
```

Knowing where a request actually executes determines what payloads make sense (e.g., SSTI vs SQLi vs SSRF).

## Front-end vs back-end

- **Front-end** is whatever runs in the browser: HTML, CSS, JavaScript (often via React/Vue/Angular). Anything sent here is attacker-visible.
- **Back-end** is whatever runs on the server: PHP, Python, Node, Java, .NET, Go, Ruby. The user only sees its outputs.
- Modern apps push more logic to the front end (SPAs); the API surface is the real attack surface.

## URL anatomy

```
https://user:pass@example.com:8443/path/to/resource?key=value&k2=v2#frag
└─┬─┘   └────┬────┘ └────┬────┘ └─┬─┘ └─────┬─────┘ └─────┬─────┘ └─┬─┘
scheme    userinfo      host    port      path          query     fragment
```

Encoding rules and URL parsing differences cause real bugs (e.g., parser confusion in SSRF).

## Common technologies / fingerprints

| Hint | Likely tech |
|---|---|
| `PHPSESSID` cookie, `.php` URLs | PHP |
| `JSESSIONID`, `;jsessionid=` in URL | Java (Tomcat / JBoss / WildFly) |
| `ASP.NET_SessionId`, `__VIEWSTATE` | ASP.NET (classic / Web Forms) |
| `.aspx`, `.ashx` | ASP.NET |
| `connect.sid` | Express / Node |
| `csrftoken`, `sessionid` | Django |
| `_session_id`, `_<app>_session` | Rails |
| `laravel_session` | Laravel |
| `x-powered-by`, `server` headers | Anything |
| Wappalyzer / `whatweb` | Automated guess |

```bash
whatweb https://target
curl -sI https://target | egrep -i 'server|x-powered-by|set-cookie'
```

## HTTP basics

- Stateless protocol; state is faked with cookies, tokens, or sessions.
- Methods used in modern apps: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`. Less common: `TRACE`, `CONNECT`.
- Status code families: 1xx info, 2xx success, 3xx redirect, 4xx client error, 5xx server error.

Detail in [09 Web Requests](09-web-requests.md).

## Sessions, cookies, tokens

| Mechanism | Where it lives | Notes |
|---|---|---|
| Server-side session | Server memory / store; ID in cookie | Classic; revocation easy. |
| JWT | Token in `Authorization: Bearer` or cookie | Self-contained; check `alg`/key handling. |
| OAuth 2 / OIDC | Bearer tokens with scopes | Many flows; check `redirect_uri`, `state`. |
| SAML | XML assertions | Sig wrapping, XXE in IdP. |
| API keys | Header / query param | Should be per-user, scoped. |

Cookie attributes that matter for security:
- `Secure` — sent only over HTTPS.
- `HttpOnly` — not accessible to JS (mitigates XSS theft).
- `SameSite=Lax|Strict|None` — CSRF defense.
- `Domain`, `Path` — scope.
- `Expires` / `Max-Age` — lifetime.

## Same-Origin Policy & CORS

- An origin is `(scheme, host, port)`. SOP isolates scripts across origins.
- CORS relaxes SOP via `Access-Control-Allow-Origin` and friends.
- Look for `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true` or origin reflection — almost always exploitable.

## Attack surface map (what to look at, in order)

1. **Authentication** — login, registration, password reset, MFA, SSO, account lockout.
2. **Authorization** — vertical (admin vs user) and horizontal (user A vs user B) access checks. IDOR territory.
3. **Session management** — token strength, rotation on auth, fixation, logout.
4. **Input handling** — every parameter (URL, body, headers, cookies, JSON keys, file names). SQLi, XSS, command injection, SSRF, SSTI, deserialization.
5. **File handling** — uploads, downloads, includes, archive extraction (ZipSlip), path handling.
6. **Business logic** — race conditions, multi-step flows, rate-limit bypass, price/cart tampering.
7. **Integrations** — webhooks, OAuth, SAML, third-party APIs, redirects.
8. **Out-of-band** — DNS, SMTP from the app, scheduled jobs.
9. **Static assets** — leaked `.git/`, `.env`, backup files, source maps.

## Common pitfalls (defender's checklist, attacker's wishlist)

- Trusting client-side validation only.
- Stable, sequential IDs (IDOR fodder).
- Verbose error messages (stack traces, SQL errors).
- Mixed authentication: API endpoints not protected the same as UI.
- Old endpoints left in routing (`/admin.bak`, `/api/v1/` after `v2` is live).
- Mass assignment in framework binders.
- Permissive CORS, weak CSRF protection, missing security headers.

## Headers worth checking

```http
Strict-Transport-Security
Content-Security-Policy
X-Frame-Options / CSP frame-ancestors
X-Content-Type-Options: nosniff
Referrer-Policy
Permissions-Policy
Set-Cookie attributes (above)
```

## Sources

- MDN Web Docs: https://developer.mozilla.org/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- RFC 9110 (HTTP Semantics), RFC 6265 (Cookies), RFC 6749 (OAuth 2.0).
