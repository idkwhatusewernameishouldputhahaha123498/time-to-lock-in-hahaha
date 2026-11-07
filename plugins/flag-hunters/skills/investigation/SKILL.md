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

**Home & obvious surfaces**
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
