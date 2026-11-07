---
name: ctf-triage
description: >-
  START HERE for any CTF challenge. The entry point and router for Flag Hunters / CTF work:
  intake a challenge (prompt text, screenshot, provided file, URL, or a service), classify its
  category, apply the clue-first method, then route to the right specialist skill (ctf-crypto,
  ctf-web, ctf-forensics, ctf-stego, ctf-osint, ctf-rev, ctf-binary, ctf-misc, or investigation).
  Use this WHENEVER the user mentions a CTF, a flag, flag{...}, a "challenge", a provided
  challenge file/binary/image/capture, a hint, or asks to "solve this" / "find the flag" —
  even if they don't name a category. Loads first; hands off fast.
---

# CTF Triage & Router

You are solving an **authorized** CTF (Flag Hunters 2026, AFKAR / IIT Delhi — Abu Dhabi, or
practice). Work **only** on the organisers' provided challenge systems/files — attacking anything
else is out of scope and a disqualification. Flag format: **`flag{...}`**, and the braces hold
**only letters, numbers, and underscores**. AI tools are allowed; that's why this arsenal exists.

Your job here: classify fast, apply the meta that beats "designed-for-AI" challenges, and hand
off to the specialist skill with a concrete first move. **Speed comes from not re-deriving
tooling**; the specialists bundle ready-to-run scripts. **Correctness comes from clue-first
discipline and verifying offline before you submit.**

---

## 0. The 60-second intake (do this every time)

1. **Read everything given**, in this order: the challenge *title*, the *prompt text*, any
   *hints*, the *filename(s)*, then the file contents. Titles and filenames are chosen by the
   author and frequently leak the trick (a date-stamp filename was literally the RNG seed once).
2. **Identify what you physically have**: a URL/service? a file? a screenshot? plain text? If a
   screenshot of the challenge page, transcribe the prompt, the Download/attachment, and the
   hint buttons.
3. **Fingerprint any file** before guessing:
   ```bash
   file FILENAME; xxd FILENAME | head; stat FILENAME
   exiftool FILENAME 2>/dev/null
   strings -n 8 FILENAME | grep -iE 'flag\{|ctf|pass|secret|key' | head
   ```
4. **Grep for the flag immediately** — some flags sit in plain sight:
   ```bash
   python3 -I scripts/flag_grep.py FILENAME        # raw bytes + encodings + leet variants
   ```
   If that prints a flag, you're done. It often isn't, but it costs 2 seconds.

---

## 1. Classify the category (signal table)

Match the strongest signal; when two fit, run both specialists in parallel (see §4).

| Signal | Category → skill |
|---|---|
| `.pem`, `n =`/`e =`/`c =`, ciphertext blob, "encrypt/decrypt", cipher name, hashes, a seed/timestamp | **ctf-crypto** |
| A URL, login page, cookies, `robots.txt`, API, "admin", HTTP, `nc`-less web service | **ctf-web** |
| `.zip/.7z/.rar/.pcap/.img/.raw/.E01`, disk/memory dump, logs, "recover/hidden file", nested archives, invisible/zero-width text | **ctf-forensics** |
| Image (PNG/JPG/BMP/GIF) or audio (WAV/MP3) that "looks blank"/"has a message", LSB, spectrogram, "listen/hum/frequency" | **ctf-stego** |
| A photo to locate, "where was this", landmark/sign, a username/handle, EXIF GPS, social media | **ctf-osint** |
| An executable (ELF/PE/`.exe`/`.pyc`/`.class`/.NET), crackme, keygen, "what input is correct", obfuscated program | **ctf-rev** |
| An ELF **plus a `nc host port` service**, "pwn", overflow, "get a shell", segfault, ROP | **ctf-binary** |
| A mystery text blob, unknown encoding, esolang, QR/barcode, JSFuck, emoji/symbol cipher | **ctf-misc** |
| A whole system / "victim's computer" to explore, a story/visual-novel, multiple flags across files & accounts | **investigation** |

**Disambiguators:** a binary with *no* network service and a "find the password" prompt → rev,
not binary/pwn. An image whose text is readable but encoded → decode (misc/crypto), not stego.
A log file → forensics. "Looks like noise" audio/image → stego.

---

## 2. The clue-first meta (this is the edge — read `references/clue-first.md`)

These challenges are built assuming every team uses AI, so the naive "ask the model to decrypt
it" path is usually **defended**. The intended solve is a human-spottable **clue or leaked
artifact**. Internalize these principles (full detail + war stories in
`references/clue-first.md`):

- **Mine the artifact before attacking it.** Filename, metadata, timestamps, EXIF, PDF dates,
  object IDs, author fields — the key often leaks here because the *content* is encrypted but the
  *wrapper* isn't. (A PDF whose filename was its creation timestamp = the PRNG seed = the
  password. We'd never crack RC4; we didn't have to.)
- **Misdirection is a signpost.** "don't look here", "nobody should read this", "these files are
  NOT important", a `Trash/` or `dontlook/` folder — the author is pointing at the answer.
- **Error-type is an oracle.** When trying candidates against an encrypted thing, a *different*
  error for one candidate often means it's the right one (the AES-7z that threw `Bad7zFile` for
  every wrong password but a different error for the right one).
- **Translate prose clues literally.** "8 rails", "move up by 5", "seconds ending in :02",
  ordered name fragments → turn each phrase directly into a parameter or one regex.
- **Brute force is the LAST resort**, not the first. If you're about to brute a large space,
  stop: you've probably missed the clue. Re-read the prompt and the artifact.
- **But don't loop on a clue that isn't there.** Clue-first is a *prior, not a guarantee*. The
  finals are harder than prelims and some challenges have **no leaked artifact** — the intended
  path is genuine technique (real cryptanalysis, a full web/exploit chain, reversing the binary).
  Rule of thumb: ~10 min of artifact-mining with no thread → switch to the specialist's core
  method and treat it as a real problem, not a riddle. Mistaking a hard challenge for a trick
  burns the clock.

---

## 3. Time-box & hint strategy (finals are timed; fewer hints score better)

- Each problem has **3 hints**; using fewer is favoured for qualification. Treat a hint as a
  resource you spend only after a **genuine attempt**.
- Suggested budget per challenge: **~8–10 min** of the fast path + the top-2 specialist moves
  before taking **hint 1**; another focused push before **hint 2**; hint 3 only when truly stuck
  or when the clock makes it worth it.
- **Prefer the cheap high-yield checks first** (strings/grep/metadata/view-source) — they solve a
  surprising fraction instantly and cost almost nothing.
- Keep a one-line note of what you've ruled out, so a hint snaps into place instead of restarting.
- Know when to move on: in a 4–6 hr finals with many flags, a stuck hard challenge is worth less
  than two easy ones you haven't opened yet. Park it, bank others, come back.

---

## 4. Route — and parallelize when ambiguous

- **Clear category** → load that specialist skill and execute its FAST-PATH.
- **Ambiguous (2–3 plausible)** → spin up the specialists **in parallel** (sub-agents) on the
  same artifact and take the first that lands a verified flag. This is the time-saver under
  pressure; the user has endorsed fan-out.
- **A provided machine / multi-flag story** → load **investigation** first; it will dispatch the
  specialists per artifact it uncovers.

Hand off with a concrete first move, e.g. *"→ ctf-stego: this is a near-white PNG; run
image_amplify.py with tolerance 3 first."*

---

## 5. The flag: recognize, normalize, verify

- **Recognize**: `flag{...}`, contents are `[A-Za-z0-9_]+`. Other events vary the wrapper
  (`FLAG{}`, `ctf{}`) — here it's `flag{}`. Watch for **ligatures** in extracted text (`ﬂ`/`ﬁ`
  break a `flag\{` regex) and glyph confusion in drawn/faint text (`l/1/!`, `O/0`, `s/5`, `B/8`).
- **Normalize / variants to try** when a flag is rejected: leetspeak swaps (`a↔4 e↔3 o↔0 i↔1
  s↔5 t↔7`), case changes, ASCII-folding accents (`ö→o`), spaces→underscores. `flag_grep.py`
  surfaces these automatically.
- **Verify before submitting.** Build or use an **offline verifier** when possible (test a
  candidate password/key in-process, as the crypto skill does) rather than burning a submission.
  Confirm the whole flag is captured (no truncation, right delimiters).

Bundled helper: `python3 -I scripts/flag_grep.py <file-or-dir>` — recursively greps raw bytes,
common encodings (base64/hex/rot), and leet variants for `flag{...}`.

---

## Reference files
- `references/clue-first.md` — the full methodology + the war-story pattern library. Read it when
  a challenge resists the obvious path.
- `references/playbook.md` — a one-screen **pattern → technique → script** lookup table. Scan it
  to pick a move fast.
