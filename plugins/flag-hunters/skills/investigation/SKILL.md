---
name: investigation
description: >-
  The finals meta-workflow for a "digital murder mystery": systematically investigate a provided
  victim's computer / system, work a visual-novel storyline, and hunt flags hidden across files,
  accounts, messages, browser data and pages. Use WHENEVER the task is to explore a whole machine
  or environment rather than one isolated file, when there's a story/characters/dialogue to follow,
  when there are multiple flags to find, or when the user mentions the "victim's computer", a case,
  side quests, or a visual novel. Coordinates the ctf-* specialists per artifact it uncovers.
---

# Investigation — working a victim's machine & the murder-mystery

The Flag Hunters finals is a **digital murder mystery**: your team gets a **victim's computer**
plus in-game resources, a **visual novel** (dialogue + choose-your-own-adventure) that tracks the
story and your progress, and **side quests / minigames** hidden throughout. **More flags = more
story.** Flags hide in files, accounts, messages and pages you must discover yourself.

This skill is the connective tissue: enumerate thoroughly, keep a case board, tie narrative clues
to technical flags, and dispatch each concrete artifact to the right specialist (`ctf-crypto`,
`ctf-web`, `ctf-forensics`, `ctf-stego`, `ctf-rev`, `ctf-binary`, `ctf-misc`). **Scope:** only the
organisers' provided systems — never touch the university network or anything else (instant DQ).

---

## Keep a case board (do this from minute one)

Open one shared notes file the whole team edits. Track:
- **Flags found** (text + where) and **flags expected** (story beats that imply a missing flag).
- **Characters / names / dates / places** from the story — these become passwords, filenames,
  search terms, and OSINT pivots.
- **Leads**: things seen but not yet chased (a locked archive, a logged-out account, a URL).
- **Ruled out**: so a later hint snaps into place instead of restarting.

Teams are 3–5: **divide the surface** (one on the filesystem, one on browser/accounts, one on
the story/visual novel, one running specialist scripts) and sync to the board.

---

## Enumerate the machine (breadth first, then depth)

Sweep in roughly this order — cheap and high-yield first. Read filenames and folder names as
clues (the author chose them).

**First, identify what the "victim's computer" actually is.** The commands below assume a
unix-like shell, but the finals environment may not be one — adapt before typing:
- **Linux / macOS shell** → use the commands below as-is.
- **Windows** → `dir /a` (incl. hidden), `%USERPROFILE%\Desktop|Documents|Downloads`, Recycle
  Bin, browser profiles under `%LOCALAPPDATA%`, `%APPDATA%` app data, PowerShell
  `Get-ChildItem -Force -Recurse`, `Get-Content (Get-PSReadlineOption).HistorySavePath`,
  Event Viewer, registry Run keys. The *goals* (history, accounts, hidden/misdirected files) are
  identical; only the paths/commands change.
- **A simulated in-game OS or a pure web app (no terminal)** → "enumerate" means click every
  menu, file/icon, app, inbox, note and settings pane; read the in-game UI's page source and
  `localStorage`/cookies; use any in-world search. The forensic *instinct* transfers even when
  no shell exists — don't assume you'll get one.

**Home & obvious surfaces (unix-like; translate per the above)**
```bash
ls -la ~ ~/Desktop ~/Documents ~/Downloads ~/Pictures ~/Music ~/Videos 2>/dev/null
ls -la ~/.* 2>/dev/null                       # dotfiles / hidden config
cat ~/.bash_history ~/.zsh_history 2>/dev/null # what the victim actually did
```
**Hidden, misdirected & deleted** (misdirection = signpost — see clue-first):
```bash
find ~ -iname '*dontlook*' -o -iname '*private*' -o -iname '*secret*' -o -iname '*do_not*' 2>/dev/null
ls -la ~/.local/share/Trash ~/.Trash 2>/dev/null   # trash often holds the answer
find ~ -type f -newermt 'yesterday' 2>/dev/null     # recently touched
find ~ -size +5M 2>/dev/null                         # big files hiding payloads
```
**Flag sweep across everything**
```bash
grep -rIaE 'flag\{[A-Za-z0-9_]+\}' ~ 2>/dev/null
python3 -I <ctf-triage>/scripts/flag_grep.py ~    # raw bytes + encodings + leet + ligatures
```
**Accounts, browser & messages** (where "accounts/messages/pages" flags live):
- Browser **history, bookmarks, autofill, saved logins, cookies, localStorage** (profiles under
  `~/.config/google-chrome`, `~/.mozilla/firefox`, `~/Library/Application Support/...`). History
  points at in-scope pages to visit; saved logins/cookies unlock accounts.
- **Email / chat / notes apps**: Mail, Slack/Discord/Telegram data, Notes, sticky notes, a
  password manager, the clipboard. Read the latest threads — the story lives there.
- **Recently opened** lists, office "recent documents", IDE recent projects.

### Browser artifacts (SQLite queries + the two weird timestamp epochs)

Browser DBs are plain SQLite with **non-standard timestamps**:
- **Chrome/Chromium (WebKit epoch):** microseconds since **1601-01-01**.
  SQLite: `datetime(ts/1000000 - 11644473600, 'unixepoch')`.
- **Firefox:** microseconds since **1970-01-01** (Unix).
  SQLite: `datetime(ts/1000000, 'unixepoch')`.
  (Caveat: `moz_cookies.expiry` is in **seconds**, while `last_visit_date` / cookie
  `lastAccessed` / `creationTime` are in **microseconds**.)

Copy the DB first (`cp` — the browser may hold a lock), then query a *copy*.

**Chrome / Chromium / Edge** — profile `Default/`:
- macOS: `~/Library/Application Support/Google/Chrome/Default/`
- Linux: `~/.config/google-chrome/Default/`  · Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
```bash
# History (urls + downloads)
sqlite3 History "SELECT url,title,datetime(last_visit_time/1000000-11644473600,'unixepoch') \
  FROM urls ORDER BY last_visit_time DESC LIMIT 50;"
sqlite3 History "SELECT target_path,tab_url,datetime(start_time/1000000-11644473600,'unixepoch') \
  FROM downloads;"
# Cookies (values encrypted on modern Chrome — need keychain/DPAPI key)
sqlite3 Cookies "SELECT host_key,name,datetime(expires_utc/1000000-11644473600,'unixepoch') FROM cookies;"
# Saved logins (passwords encrypted; usernames/urls are clear)
sqlite3 "Login Data" "SELECT origin_url,username_value FROM logins;"
# Bookmarks (JSON) + Local Storage / IndexedDB (LevelDB, not SQLite)
cat Bookmarks | python3 -m json.tool | grep -A2 '"url"'
strings "Local Storage/leveldb/"*.ldb | grep -i flag
```
Chrome password decryption (when the master key is provided, as in CTFs): `password_value`
is `v10/v11` AES-GCM — `nonce=blob[3:15]`, `ct=blob[15:-16]`, `tag=blob[-16:]`; master key from
`Local State` → `os_crypt.encrypted_key` (base64, drop 5-byte `DPAPI` prefix). Route the actual
decrypt to **ctf-crypto**.

**Firefox** — profile `*.default-release/`:
- macOS: `~/Library/Application Support/Firefox/Profiles/*.default-release/`
- Linux: `~/.mozilla/firefox/*.default-release/`
```bash
# History + bookmarks
sqlite3 places.sqlite "SELECT url,title,datetime(last_visit_date/1000000,'unixepoch') \
  FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 50;"
sqlite3 formhistory.sqlite "SELECT fieldname,value FROM moz_formhistory;"   # autofill
sqlite3 cookies.sqlite "SELECT host,name,value FROM moz_cookies;"
# Saved passwords: logins.json + key4.db -> python3 firefox_decrypt.py <PROFILE>/  (route to ctf-crypto)
# Previously open tabs (lz4-framed JSON)
python3 -c "import json,lz4.block;f=open('sessionstore-backups/recovery.jsonlz4','rb');f.read(8);\
d=json.loads(lz4.block.decompress(f.read()));print('\n'.join(t['entries'][-1]['url'] \
for w in d['windows'] for t in w['tabs']))"
# Quick-and-dirty: just grep the raw DB
strings places.sqlite | grep -iE 'flag|http'
```
**Instinct:** history/bookmarks point at in-scope pages to visit; `moz_formhistory` + saved
logins unlock accounts; `sessionstore` shows what the victim had open. Always `strings | grep`
the DB too — the flag is often sitting in a URL.

**System traces**
```bash
history; crontab -l 2>/dev/null; ls -la /var/log 2>/dev/null
env | grep -iE 'flag|key|token'
```

---

## Tie the story to the flags

The visual novel is not decoration — it's the clue channel:
- **Dialogue names a file, date, place, or password** → go use it (a character's birthday as an
  archive password; a mentioned folder; a place to OSINT).
- **A choose-your-own-adventure branch gates content** → different choices reveal different leads;
  if progress tracks, explore branches deliberately and note what each unlocks.
- **"More flags = more story"** → finding a technical flag often advances the narrative, which
  exposes the next lead. Alternate between *investigating* and *progressing the story*.
- **Side quests / minigames** are hidden and count — poke at unusual UI, odd files, and "take a
  break" prompts. Rule no. 1 is literally "have fun" — the playful corners hide points.

---

## Dispatch each artifact to a specialist

As you uncover concrete things, route them (run specialists in parallel across different leads):

| Uncovered | Route to |
|---|---|
| A URL / web app / login the victim used | `ctf-web` |
| An archive (esp. nested/password-protected) | `ctf-forensics` (`nested_archive_peel.py`) |
| A `.pcap`, disk/memory image, or log | `ctf-forensics` |
| An image/audio that "looks off" | `ctf-stego` |
| Encrypted text / keys / a seed or timestamp | `ctf-crypto` |
| An executable / crackme | `ctf-rev`; if it's a network service, `ctf-binary` |
| A mystery encoded blob / QR | `ctf-misc` |
| A photo/place/person to identify | `ctf-osint` |
| Invisible/zero-width text in a note | `ctf-forensics` (`zerowidth_decode.py`) |

Always first run the **universal opening** on any file (`file`, `exiftool`, `strings|grep flag`,
`flag_grep.py`) and read its name — see `ctf-triage` and `clue-first.md`.

---

## Rhythm under the clock (4–6 hrs, many flags)

- **Breadth pass first** (~20–30 min): enumerate everything, fill the board with leads and easy
  plain-sight flags, before going deep on any one.
- **Bank easy flags**, then take the highest-value leads. Park a hard lead rather than stalling.
- **Hints**: 3 per challenge, fewer favoured — spend only after a real attempt; note what you've
  ruled out first.
- Keep the board current so the team never duplicates work or loses a thread.
- **Progress discipline:** apply ctf-triage's "what counts as progress" + submission-governor before spending a hint or a submission.
