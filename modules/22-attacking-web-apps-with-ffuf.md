# 22 — Attacking Web Applications with FFuF

`ffuf` is a fast HTTP fuzzer. It replaces the keyword `FUZZ` (or any custom keyword) in URL/header/body with each line of a wordlist and reports back. Same primitive used for directory busting, vhost discovery, parameter mining, login brute forcing, and value enumeration.

## Install

```bash
go install github.com/ffuf/ffuf/v2@latest
# Or:
sudo apt install ffuf
```

## Mental model

Every fuzz boils down to: **what is changing**, **what wordlist**, **what is a hit**.

```bash
ffuf -u <URL with FUZZ> -w <wordlist> -mc <match-codes> -fs <filter-size> ...
```

Filters drop noise; match flags keep only what looks interesting. Almost all real ffuf usage is tuning these two.

## Filtering & matching

| Flag | Meaning |
|---|---|
| `-mc` | Match HTTP status codes (`-mc 200,301`) |
| `-ms` | Match response size |
| `-ml` | Match line count |
| `-mw` | Match word count |
| `-mr` | Match a regex in body |
| `-fc` | Filter (drop) on status |
| `-fs` | Filter on size |
| `-fl` | Filter on line count |
| `-fw` | Filter on word count |
| `-fr` | Filter on regex |
| `-mc all` | Show every status (use with `-fc` to subtract) |

Tactic: send a known-bogus value, note the baseline size/line count, then `-fs`/`-fl` it out.

## Directory & file fuzzing

```bash
# Directories
ffuf -u https://target/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc all -fc 404

# Files with extension permutations
ffuf -u https://target/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.html,.txt,.bak,.zip,.tar.gz \
  -mc 200,204,301,302,307,401,403

# Recursion (crawl into discovered directories)
ffuf -u https://target/FUZZ -w wordlist -recursion -recursion-depth 2 \
  -mc 200,301,302,401,403

# Save results
ffuf ... -of json -o out.json
ffuf ... -of csv  -o out.csv
ffuf ... -of html -o out.html
```

Wordlists worth remembering:

```
/usr/share/seclists/Discovery/Web-Content/
  raft-{small,medium,large}-{words,directories,files}.txt
  directory-list-2.3-{small,medium,big}.txt
  common.txt
  api/objects.txt, api/api-endpoints.txt
  burp-parameter-names.txt
```

## Virtual host fuzzing

When several apps share an IP, the web server picks the app by `Host:`.

```bash
# 1. Get baseline (default vhost) size
curl -sk -o /dev/null -w '%{size_download}\n' -H 'Host: nope.example.tld' https://<IP>/

# 2. Filter that size out while fuzzing the Host header
ffuf -u https://<IP>/ -H "Host: FUZZ.example.tld" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -fs <baseline-size>
```

Or filter by status if the default vhost returns a 404/redirect:

```bash
ffuf -u https://<IP>/ -H "Host: FUZZ.example.tld" -w subs.txt -fc 404,301
```

`gobuster vhost --append-domain ...` does the same thing if you prefer.

## Subdomain DNS fuzzing

```bash
ffuf -u https://FUZZ.example.tld -w subs.txt -mc all -fs 0
```

Hits show up where DNS resolves and the server answers. A `0`-byte reply means DNS resolved but the host returned nothing — still a finding.

## Parameter discovery

### GET parameter names

```bash
ffuf -u 'https://target/page.php?FUZZ=test' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <baseline>            # filter the no-effect response size
```

### POST parameter names

```bash
ffuf -u https://target/api/x -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'FUZZ=test' \
  -w params.txt -fs <baseline>
```

### JSON keys

```bash
ffuf -u https://target/api/x -X POST \
  -H 'Content-Type: application/json' \
  -d '{"FUZZ":"test"}' \
  -w params.txt -mc all -fc 400,404
```

### Hidden headers

```bash
ffuf -u https://target/ -H 'FUZZ: test' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404
```

## Parameter value fuzzing

Once you know the parameter name, fuzz its values to find LFI / SQLi / IDOR / SSRF.

```bash
# IDOR-style numeric ID enumeration
ffuf -u 'https://target/profile?id=FUZZ' -w <(seq 1 1000) -mc 200 -fs <baseline>

# LFI candidates
ffuf -u 'https://target/page?file=FUZZ' \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mr 'root:x:0'
```

## Multi-keyword fuzzing (custom keywords)

Use `:KEY` aliases when `FUZZ` is overloaded:

```bash
ffuf -u 'https://target/USER/PASS' \
  -w users.txt:USER -w passwords.txt:PASS \
  -mode clusterbomb -mc 200
```

`-mode` options: `clusterbomb` (cartesian), `pitchfork` (parallel), `sniper` (one at a time, default with one wordlist).

## Login brute force with FFuF

```bash
ffuf -u https://target/login -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=FUZZ' \
  -w passwords.txt \
  -fr 'Invalid|Wrong|Login failed'
```

Tactics:
- `-fr` filters on body regex of the failure message — anything else is a candidate hit.
- `-mc 302` if successful login redirects.
- `-fc 401,403` filters fixed-failure status codes.
- For CSRF-protected forms, see [23 Login Brute Forcing](23-login-brute-forcing.md).

## Cookie / session-bound testing

```bash
ffuf -u https://target/admin/FUZZ -w wordlist \
  -b 'SESSION=abc123; token=xyz' \
  -H 'Cookie: SESSION=abc123' \
  -H 'X-CSRF-Token: ...' \
  -mc all -fc 401,403,404
```

`-b` is shorthand for `-H 'Cookie: ...'`.

## Performance & politeness

```
-t 40            # threads (default 40)
-rate 50         # requests per second cap
-p 0.1-1         # random delay 100ms-1s between requests
-timeout 10      # per-request timeout (sec)
-maxtime 600     # cap whole run
-maxtime-job 60  # cap per recursion job
```

For aggressive scans drop `-rate` for max throughput; for prod / IDS-aware engagements add `-p` and tighten `-rate`.

## Routing through Burp

```bash
ffuf ... -replay-proxy http://127.0.0.1:8080
```

Only sends "interesting" hits to Burp (matched, not filtered) — so your site map stays clean and Burp Repeater is one click away.

## Useful helpers

```
-recursion                  # follow into found directories
-recursion-depth N
-recursion-strategy default # or greedy
-ac                         # "auto-calibrate" - learns baseline + filters automatically
-acc 'random/value'         # provide a calibration value
-input-cmd 'seq 1 100'      # use stdout of a command as input
-input-num 1000             # synthetic number range as input
-D                          # debug
-v                          # verbose (per-result)
-of all                     # write all output formats
```

`-ac` is great when you do not know the baseline; ffuf sends decoy requests, learns the noise, and filters automatically.

## Common pitfalls

- HTTPS with HTTP/2 — some servers behave differently; force HTTP/1.1 with `-http2=false` (default) or test both.
- Web app behind a CDN — `-rate` low to avoid getting banned (Cloudflare especially).
- Soft 404s — site returns 200 with a "Not Found" body. Filter by content size or regex (`-fs` / `-fr`) instead of `-mc`.
- Param case sensitivity — fuzz lower- and upper-case if needed.
- Some apps treat unknown params as 200 with the same body — `-fs` solves it; `-ac` automates it.

## Sources

- ffuf docs: https://github.com/ffuf/ffuf
- ffuf wiki: https://github.com/ffuf/ffuf/wiki
- SecLists: https://github.com/danielmiessler/SecLists
