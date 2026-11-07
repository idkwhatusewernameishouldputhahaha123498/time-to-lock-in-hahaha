# CTF FIELD PLAYBOOK — Flag Hunters 2026 (portable, paste-in)

*Self-contained condensed arsenal. Paste into any Claude session / chatbox when the full plugin
isn't available. For the organisers' own challenges only (attacking anything else = DQ). AI tools
are allowed. Flag format: `flag{...}` — letters, numbers, underscores only.*

---

## THE META (why this wins)
Challenges assume every team uses AI, so the naive "ask the AI to decrypt it" path is **defended**.
The intended solve is a **human clue** or a **leaked artifact**. Find that; don't brute force.

1. **Mine the wrapper before attacking the content.** Keys/seeds/passwords leak in filenames,
   metadata (EXIF, PDF dates, author), timestamps, object IDs, zip comments, trailing bytes.
2. **Misdirection = signpost.** "don't look", "not important", `Trash/`, `dontlook/` → look there.
3. **Error-type = oracle.** Testing candidates: success is the usual tell; else the one that
   fails with a different error *type* or at a *later stage* is often right (same error type,
   different message = noise).
4. **Translate prose to parameters literally.** "8 rails", "move up 5", "seconds :02", ordered
   name fragments → exact param / one regex.
5. **Brute force is LAST.** About to brute a big space? You missed the clue. Re-read.

## UNIVERSAL OPENING (every challenge)
```bash
file F; stat F; exiftool F
xxd F | head; xxd F | tail          # headers AND trailers (appended data)
strings -n 8 F | grep -iE 'flag|pass|key|secret|seed|BEGIN|http'
grep -aoE 'flag\{[A-Za-z0-9_]+\}' F
```
Read the **title + filename** as hints — they usually are.

---

## TRIAGE — classify by what you have
| Signal | Category |
|---|---|
| n/e/c, .pem, ciphertext, cipher name, hash, a seed/timestamp | **CRYPTO** |
| URL, login, cookies, robots.txt, API, "admin" | **WEB** |
| .zip/.7z/.pcap/.img/.raw, logs, disk/mem dump, hidden/zero-width text | **FORENSICS** |
| image/audio that "looks blank"/noisy, LSB, spectrogram | **STEGO** |
| photo to locate, landmark/sign, username, EXIF GPS | **OSINT** |
| executable/crackme/.pyc/.class/.NET, "correct input?" | **REV** |
| ELF + `nc host port`, overflow, "get a shell", ROP | **BINARY (pwn)** |
| mystery encoded blob, esolang, QR, JSFuck | **MISC** |
| a whole machine/story, many flags across files/accounts | **INVESTIGATION** |

Ambiguous? Try the top 2 in parallel. Clear plain-sight flag? `grep flag{` wins instantly.

---

## CRYPTO
- **Identify encoding first** (alphabet: A-Za-z0-9+/= → base64; 0-9a-f → hex; `.`/`-` → morse).
- **Classical:** Caesar/ROT (brute 25), Vigenère (Kasiski + known plaintext), substitution
  (frequency), rail-fence (brute rails 2–15 + offset), Atbash, baconian, A1Z26.
- **XOR:** single-byte brute by English scoring; multi-byte via key length + crib-dragging; try
  known-plaintext `flag{`.
- **RSA:** small e → cube root of c; Fermat (close primes); Wiener (small d); common modulus;
  Håstad broadcast; partial key. Fallback: RsaCtfTool. Use sympy/gmpy2.
- **AES:** ECB → repeated 16-byte blocks reveal structure; CBC bit-flip; CTR nonce reuse = XOR.
- **Hashes:** identify by length; crack with wordlist (john/hashcat); length-extension (hashpump).
- **PRNG / seed leak:** if a seed/timestamp is given, reproduce it and **sweep standard
  generators** (Python MT, glibc rand, Java LCG, MSVC/ANSI LCG, **minstd/Park-Miller x=x*16807 %
  2147483647**, PHP mt_rand, numpy) over the first ~8 outputs — match one. *(This exact move,
  minstd output #1, cracked an RC4 PDF whose filename was the epoch seed.)*
- **Discipline:** build a **pure-Python offline verifier** so candidates test in-process; validate
  it against a known sample first.

## WEB (curl-first; a browser is rarely needed)
- **Recon (2 min):** `curl -s URL | grep -i flag`; view-source + HTML comments; `curl .../robots.txt`
  and sitemap; inspect `Set-Cookie` and JS that sets cookies/localStorage; response headers; probe
  `/flag`, `/.git/`, `/.env`, backups.
- **Auth bypass:** flip a client-set privileged value — `Cookie: role=admin` (also isAdmin,
  is_admin, user_type). JWT `alg:none` or crack a weak HS256 secret.
- **SQLi login:** `email=victim@host' -- ` targeting the **specific victim** whose account holds
  the flag (generic `' OR 1=1 -- ` logs in as the wrong, flagless user). Then UNION / blind.
- **XSS:** reflected/stored/DOM (unencoded reflection = reflected XSS).
- **SSTI:** `{{7*7}}`→49 fingerprints the engine → RCE in scope.
- **Gated endpoint (403):** replay browser **fetch-metadata** headers with curl —
  `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Dest: empty`, a same-origin `Referer`/`Origin`. No
  live XSS/bot needed. *(This unlocked a robots.txt-disclosed `/flag`.)*
- Also: LFI/traversal, IDOR (increment IDs), SSRF, command injection, upload bypass.

## FORENSICS
- **Any file:** `file`, `binwalk`, `exiftool`, `strings|grep flag`, and check bytes **after** the
  logical EOF (data appended past PNG IEND / JPEG EOI).
- **Archives:** peel nested ones recursively; dictionary-attack encrypted members and **watch the
  error-type oracle**; AES-7z → `py7zr` (no system 7z binary needed); peel zips in-memory with `zipfile` +
  `io.BytesIO`; grep extracted raw bytes for `flag{`. *(A 3-layer nest hid the flag in a .bin.)*
- **pcap:** tshark/Wireshark — follow TCP stream, export objects, check HTTP/DNS/ICMP exfil, creds.
- **Disk/memory:** `strings|grep flag`; volatility3 (pslist, cmdline, filescan, dumpfiles); mount.
- **Logs:** translate prose clues into **one regex**, then pick the row whose token is a real
  `flag{...}` (ignore `sha1:`/`sess-` decoys).
- **Invisible text:** zero-width chars (U+200B/200C/200D/FEFF/2060) or unicode-tags encode
  **binary→ASCII**; try bit-mappings both ways. Also homoglyphs.
- **git:** `git log --all`, reflog, stash, recover deleted blobs.

## STEGO
- **Always first:** `strings`/`binwalk`/`exiftool`; data appended after image EOF; `unzip` the image.
- **Image:** zsteg (all planes), LSB across channels/planes, **bit-plane view**, **threshold a
  near-white image** (map non-255 pixels to black — text drawn at values 226–254), contrast
  stretch, channel split, PNG chunks, alpha channel, steghide/outguess (password often in the
  prompt), QR hidden inside.
- **Audio:** render a **spectrogram** (STFT, Hann, hop 256, dB, low-freq at bottom; subtract the
  per-frequency median to lift drawn text from noise); DTMF; Morse tone; SSTV; LSB in WAV samples;
  reversed/backmasked; pitch/tempo.
- **Caution:** faint/drawn text confuses `l/1/!`, `O/0`, `s/5`, `B/8`, and ligatures `ﬂ/ﬁ`.

## OSINT (in-scope / game-world targets only)
- **First:** `exiftool` for GPS/metadata. Then reverse image search (Yandex best for places;
  Google Lens; TinEye; Bing).
- **Clue ladder:** script/language on signage → country; architecture + street furniture → city;
  **transit livery** (tram/bus colors, logos) → exact city; license plates, road markings, sun
  position, vegetation, **googleable business names** → pin the spot.
- **Verify** the landmark name, opening year, and coordinates by search before using them.
- **Follow puzzle arithmetic exactly.** For non-ASCII place names, submit **both** accented and
  ASCII-folded flag variants. *(A Zürich station → exact math → an Iceland lake was the flag.)*
- Also: username enumeration across platforms, whois/DNS history, crt.sh, Wayback Machine.

## REV
- **Fast:** `file`; `strings -n 6` (and `strings --encoding=l` / floss) `| grep -i flag`; run it in
  a sandbox; `upx -d` if packed. Many crackmes just embed or runtime-decode the flag.
- **Key insight:** the flag is often **decoded at runtime** → breakpoint **after** the decode
  (gdb at strcmp/memcmp/printf, `x/s`) beats static deobfuscation. **Patch the branch** or
  **solve the input** beats writing a full keygen when you only need the flag.
- **Static:** Ghidra / radare2 / objdump — find main, the comparison on your input, trace it.
- **Dynamic:** gdb+pwndbg, ltrace/strace, break on input-checks and read expected values.
- **angr** symbolic execution: define FIND (success) + AVOID (fail) addresses, solve stdin/argv.
- **By type:** .NET→dnSpy/ILSpy; Java→jd-gui/CFR; Python .pyc→decompyle3/pycdc; Go→Go-aware tools.

## BINARY / PWN (organiser services only)
- **Triage:** `checksec` (RELRO/Canary/NX/PIE), `file`, `strings|grep flag`, look for a
  `win`/backdoor function; find the input + the overflow; test local before remote.
- **Mitigations steer technique:** NX on → reuse code (ROP/ret2libc) not shellcode; PIE → need a
  leak; canary → need a leak or a path that skips it.
- **Bug classes:** stack overflow → ret2win / ret2libc / ROP; format string → arbitrary read
  (leak) + arbitrary write (GOT/return); integer/size; off-by-one; heap UAF/double-free.
- **Tools:** pwntools (`cyclic` for offset, `ELF` for got/plt/sym, `fmtstr_payload`, `ROP`),
  gdb+pwndbg, ROPgadget/ropper, one_gadget, libc-database for remote libc. Build the exploit live.

## MISC
- **Identify the encoding by its alphabet, then cascade-decode** (nested layers are the norm):
  base16/32/58/62/64/85, ascii85, uuencode, binary/octal/decimal, hex, URL%, HTML entities,
  ROT13/47, atbash, A1Z26, baconian, morse, tap code, braille, leetspeak.
- **Esolangs:** Brainfuck (`+-<>[].`), Whitespace (spaces/tabs), Ook, Malbolge, JSFuck
  (`[]()!+`), Piet (image), rockstar.
- **Barcodes/QR:** zbarimg. **Formats:** JWT, protobuf (`--decode_raw`), msgpack, pickle (inspect
  with pickletools, don't blindly unpickle).
- Logic/math puzzles → just write a script. CyberChef "Magic" is the quick manual decoder.

## INVESTIGATION (finals murder-mystery / victim's computer)
- **Case board** from minute one (shared): flags found/expected, characters/dates/places, open
  leads, ruled-out. Teams of 3–5: divide filesystem / browser+accounts / story / scripts.
- **Enumerate** (breadth first): home + Desktop/Documents/Downloads; dotfiles; shell history;
  Trash; recently-modified & large files; browser history/bookmarks/saved logins/cookies; mail,
  chat, notes, password manager; `grep -rIaE 'flag\{[A-Za-z0-9_]+\}' ~`.
- **Tie story to flags:** dialogue naming a file/date/place/password → go use it; branches gate
  content; finding a flag advances the story, which exposes the next lead. Side quests/minigames
  are hidden and count.
- **Dispatch** each artifact to the right category above. Run the universal opening on every file.

---

## FLAG ENDGAME
Recognize `flag{[A-Za-z0-9_]+}`. Watch ligatures `ﬂ/ﬁ` and glyphs `l/1/! O/0 s/5 B/8`. If
rejected, try **leet** (`a4 e3 o0 i1 s5 t7`), case, accent-fold, spaces→underscores. **Verify
offline before submitting** — don't burn attempts.

## TIME DISCIPLINE (finals timed; fewer hints score higher)
Fast path + top-2 moves (~8–10 min) → hint 1 → focused push → hint 2 → hint 3 only if worth it.
Bank easy flags first; park hard ones and return. Note what you've ruled out so a hint snaps in.

---
*This is a condensed, paste-anywhere view. The maintained source of truth is the repo's
`ctf-triage/references/clue-first.md` (full methodology + war stories); update that first, then
regenerate this. Clue-first is a prior, not a law — if ~10 min of clue-hunting finds no thread on
a hard challenge, switch to real technique.*
