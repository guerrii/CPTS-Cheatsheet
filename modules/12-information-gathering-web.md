# 12 — Information Gathering: Web Edition

Passive and active recon for web targets. Goal: build a complete map of hosts, subdomains, virtual hosts, technologies, endpoints, and parameters before attacking anything.

## Contents

- [Passive recon (no traffic to the target)](#passive-recon-no-traffic-to-the-target)
- [Active recon (traffic to the target)](#active-recon-traffic-to-the-target)
- [Wordlists worth knowing](#wordlists-worth-knowing)
- [Putting it together (a starter recon pipeline)](#putting-it-together-a-starter-recon-pipeline)
- [Sources](#sources)

## Passive recon (no traffic to the target)

### WHOIS / RDAP

```bash
whois example.com
whois 1.2.3.4
```

Useful for: registrar, registration date, abuse contact, sometimes tech contact e-mails.

### DNS

```bash
dig example.com ANY
dig +short example.com
dig example.com MX
dig example.com TXT                 # SPF/DKIM/DMARC, verifications
dig example.com NS
dig SOA example.com
host -a example.com
```

### Certificate transparency

Enumerate every cert ever issued for the domain — leaks subdomains.

```bash
# crt.sh
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u

# Chaos / Censys / Subfinder use these sources internally:
subfinder -d example.com -all -recursive
amass enum -passive -d example.com
```

### Web archives & search engines

```bash
# Wayback URLs
curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" | sort -u
waybackurls example.com
gau example.com                  # GetAllUrls (waybackurls + commoncrawl + URLScan)
```

Google dorking starting points:

```
site:example.com
site:example.com -www
site:example.com filetype:pdf
site:example.com inurl:admin
site:example.com intitle:"index of"
site:*.example.com
"@example.com"                   # email harvesting
```

### Public code & paste sites

```bash
# Search GitHub for leaks
trufflehog github --org=<org>
gitleaks detect --source <repo>
github-search.py / gitGraber
```

Also: GitLab, Bitbucket, Pastebin, Trello boards, S3 buckets (`<name>.s3.amazonaws.com`, `<name>.s3.<region>.amazonaws.com`).

### Threat-intel & metadata

- Shodan: `org:"Example"`, `hostname:example.com`, `ssl:"Example"`.
- Censys: `services.tls.certificates.leaf_data.subject.common_name: example.com`.
- Hunter.io / phonebook.cz / dehashed (creds leaks).

## Active recon (traffic to the target)

### Subdomain enumeration

```bash
# Brute-force
gobuster dns -d example.com -w wordlist.txt -t 50
puredns bruteforce wordlist.txt example.com -r resolvers.txt
ffuf -u https://FUZZ.example.com -w wordlist.txt -mc all -fs 0   # via DNS resolution

# Active probing (HTTP)
httpx -l subs.txt -title -tech-detect -status-code -follow-redirects -o live.txt
```

### Virtual host discovery

When subdomains share an IP, the web server picks the app by `Host:` header. Resolve all known names to the same IP, then fuzz `Host`.

```bash
ffuf -u http://<TARGET-IP>/ -H "Host: FUZZ.example.com" -w vhosts.txt \
  -fs <baseline-size>                    # filter the default-vhost size

# Or by status / words
ffuf -u http://<TARGET-IP>/ -H "Host: FUZZ.example.com" -w vhosts.txt -fc 404
```

`gobuster vhost -u http://<T> -w list.txt --append-domain` does the same.

### Technology fingerprinting

```bash
whatweb -a 3 https://target
wappalyzer https://target              # browser ext or CLI
httpx -tech-detect -title -server -l urls.txt
nuclei -u https://target -t http/technologies/
```

Also:
- `curl -sI` for headers (Server, X-Powered-By).
- `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/security.txt`.
- HTML comments (`curl -s ... | grep -E '<!--'`).
- JS files for clues (frameworks, API URLs).

### Crawling

```bash
# katana (recursive crawler)
katana -u https://target -d 5 -kf all -o urls.txt

# hakrawler
echo https://target | hakrawler -d 3

# gau / waybackurls feed historic URLs into crawl seed
gau target | uniq > seeds.txt
```

Pull every JS file and inspect for endpoints/secrets:

```bash
katana -u https://target -d 3 -jc -o js.txt
# Or:
subjs -i live.txt | tee js.txt
# Extract endpoints/strings
xnLinkFinder -i js.txt -o endpoints.txt
```

### Directory / file fuzzing

See [22 Attacking Web Apps with FFuF](22-attacking-web-apps-with-ffuf.md) for the full reference. Quick:

```bash
ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -mc all -fc 404
feroxbuster -u https://target -w wordlist -x php,html,txt
gobuster dir -u https://target -w wordlist
```

### Parameter discovery

```bash
arjun -u 'https://target/page' --get -m GET
arjun -u 'https://target/api/x' -m POST --headers 'Cookie: a=b'

# ParamMiner (Burp ext) is excellent for hidden headers and params
```

Common interesting params: `id`, `user`, `file`, `page`, `path`, `redirect`, `next`, `url`, `callback`, `template`, `cmd`, `debug`, `admin`.

## Wordlists worth knowing

```
/usr/share/seclists/Discovery/Web-Content/
  raft-{small,medium,large}-{words,directories,files}.txt
  directory-list-2.3-{small,medium,big}.txt
  common.txt
  api/objects.txt, api/api-endpoints.txt
  CMS/wp-plugins.txt
  burp-parameter-names.txt
/usr/share/seclists/Discovery/DNS/
  subdomains-top1million-110000.txt
  bitquark-subdomains-top100000.txt
  fierce-hostlist.txt
/usr/share/wordlists/dirb/, dirbuster/
```

### Subdomain takeover

Dangling DNS records pointing at de-provisioned cloud resources let an attacker re-claim the resource and serve content from the victim's hostname.

```bash
# Resolve and probe at HTTP layer for fingerprints
subjack -w subs.txt -t 50 -o takeovers.txt -ssl
nuclei -l live-http.txt -t http/takeovers/

# Manual: look at the CNAME and the HTTP body
dig +short cdn.example.com
curl -sI https://cdn.example.com
```

Common signatures:

| Service | Fingerprint string in 404 body |
|---|---|
| AWS S3 | `NoSuchBucket` |
| GitHub Pages | "There isn't a GitHub Pages site here" |
| Heroku | "No such app" |
| Azure | `404 Web Site Not Found` |
| Fastly | `Fastly error: unknown domain` |
| Shopify | "Sorry, this shop is currently unavailable" |
| Tumblr | "There's nothing here" |
| Zendesk | "Help Center Closed" |

Full list maintained at [`EdOverflow/can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz).

### API discovery

Modern apps expose their backend at JSON / REST / GraphQL / SOAP endpoints worth listing separately:

```bash
# Common API roots
ffuf -u https://target/FUZZ -w api-paths.txt -mc all -fc 404
# api, api/v1, api/v2, graphql, rest, internal/api, _api, services, soap

# Swagger / OpenAPI / API docs
for p in /swagger /swagger-ui /swagger-ui.html /api-docs /v2/api-docs /v3/api-docs \
         /openapi.json /openapi.yaml /docs /redoc /api/swagger.json /api/explorer ; do
  curl -sk -o /dev/null -w "%{http_code} $p\n" "https://target$p"
done

# Postman / Insomnia exports occasionally appear in the repo or static dir
curl -sI https://target/postman.json
curl -sI https://target/api/postman_collection.json
```

JS files often hard-code API paths — extract and feed to fuzzing:

```bash
katana -u https://target -d 3 -jc | grep -oE '"/[a-zA-Z0-9_/.-]+"' | sort -u
```

For testing endpoints, see [22 FFuF](22-attacking-web-apps-with-ffuf.md), [30 Web Attacks — GraphQL](30-web-attacks.md).

## Putting it together (a starter recon pipeline)

```bash
DOMAIN=example.com

# 1. Subdomains (passive + active)
subfinder -d $DOMAIN -all -recursive -o subs.txt
amass enum -passive -d $DOMAIN -silent | sort -u >> subs.txt
puredns resolve subs.txt -r resolvers.txt -w live-dns.txt

# 2. Live HTTP
httpx -l live-dns.txt -title -tech-detect -status-code -follow-redirects \
  -o live-http.txt

# 3. Crawl + historic URLs
katana -list live-http.txt -d 3 -kf all -o urls.txt
gau --subs $DOMAIN >> urls.txt
sort -u urls.txt -o urls.txt

# 4. Directory fuzz on each live host
while read u; do
  ffuf -u "$u/FUZZ" -w raft-medium-words.txt -mc all -fc 404 -of json \
    -o "ffuf-$(echo $u | sed 's,[/:],_,g').json"
done < live-http.txt
```

## Sources

- OWASP WSTG (Information Gathering): https://owasp.org/www-project-web-security-testing-guide/
- ProjectDiscovery tools: https://projectdiscovery.io/
- SecLists: https://github.com/danielmiessler/SecLists
- crt.sh: https://crt.sh/
