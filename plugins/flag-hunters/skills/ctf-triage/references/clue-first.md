# Clue-First Methodology + War-Story Library

The governing idea: **Flag Hunters challenges are designed assuming every team has an AI.** So the
lazy "paste it into Claude and ask it to decrypt" path is deliberately defended. The intended
solution is almost always a **human-spottable clue** or a **leaked artifact** that makes an
otherwise-hard problem trivial. Your edge is finding that clue, then building fast offline tooling
to exploit it. Brute force is the last resort — reaching for it usually means you missed the clue.

---

## The five principles

### 1. Mine the artifact before you attack it
The crypto/encoding is often genuinely strong. The **wrapper** around it is not. Keys, seeds and
passwords leak in the parts the author forgot to encrypt:
- **Filenames** (a date-like name, an ID, a word).
- **Metadata**: EXIF, PDF `/CreationDate` `/ModDate` `/Author` `/Producer`, Office core.xml,
  ID3 tags, PNG text chunks.
- **Timestamps**: file mtime, embedded dates, object IDs — any of these can be a seed.
- **Structure**: PDF object IDs, zip comments, trailing bytes, git history.

Checklist to run on any artifact:
```bash
file F; stat F; exiftool F
xxd F | head -40; xxd F | tail -40        # headers AND trailers (appended data!)
strings -n 6 F | grep -iE 'flag|pass|key|secret|seed|http|BEGIN'
binwalk F                                  # embedded/concatenated files
```

### 2. Misdirection is a signpost
When the author tells you *not* to look somewhere, that's exactly where the material is. Treat
every one of these as an arrow pointing at the answer:
- folder/file names: `dontlook/`, `nothing_here/`, `Trash/`, `private/`, `ignore/`
- text: "nobody should look here", "stop reading", "these files are empty / NOT important",
  "do not open"
Enumerate those first.

### 3. Error-type is an oracle
When testing candidates against something encrypted/validated, don't only look for *success* —
watch the **shape of the failure**. If one candidate throws a *different* error than all the
others, it's probably correct (the decryption got far enough to fail later). This turns a blind
dictionary attack into a signal.

### 4. Translate prose clues literally into parameters
Every descriptive phrase in the prompt is usually a concrete parameter:
- "the key to my lock is 8" → 8 rails / 8-byte key / shift 8
- "move up by 5" → offset 5
- "seconds ending in 02" → regex on the timestamp field
- ordered name fragments ("Am… Ch… th… st") → `Am.*Ch.*th.*st$`
Build the exact filter/parameter the words describe instead of guessing.

### 5. Brute force is the LAST resort
Before brute-forcing a large space, STOP and re-read. The clue almost always shrinks the space to
something tiny (a handful of dictionary entries, one seed, one parameter). If you must brute,
brute the **small, structured** space the clue defines, not the raw keyspace.

---

## War-story pattern library (solved challenges → reusable moves)

Each entry: what it looked like → the clue → the move. Scan these to recognize a pattern fast.

### Crypto / PRNG — "Random Encounter" (Hard)
- **Looked like:** an RC4-128 password-protected PDF named `20070629000000Z.pdf`.
- **Clue:** the filename is a PDF date string = creation timestamp = **epoch 1183075200** = the
  **RNG seed**. The real dates inside were encrypted, so the seed only survived in the filename.
- **Move:** the password was one *output* of a seeded standard PRNG. Reproduce the seed, then
  **sweep the standard generators** (not the password space). Winner: `std::minstd_rand0`
  (Park–Miller, `x = x*16807 % 2147483647`), seed 1183075200, **output index 1** = `32285335`.
  Build a pure-Python **offline verifier** for the PDF Standard Security Handler (`/V 2 /R 3`,
  RC4-128: MD5-based Algorithm 2 + Algorithm 5 over `/O /U /P /ID[0]`) and validate it against a
  self-made pikepdf file before trusting it. → `ctf-crypto`: `prng_sweep.py`, `pdf_rc4_verify.py`.

### Forensics / nested archives — "Linux FS" / "The Good, The Bad, The Binary" (Hard)
- **Looked like:** a fake Linux filesystem in a zip.
- **Clue:** `Trash/dontlook/passwords.txt` (misdirection=signpost) held the 7z password; a log
  ruled out several candidates.
- **Move:** flag was inside a **3-layer nested archive** `challenge.zip.zip → challenge.7z.zip →`
  AES-encrypted `challenge.7z`. The AES-7z gave an **error oracle** (wrong pw → `Bad7zFile`,
  right pw → a different error). `py7zr` extracts AES-7z in pure Python; peel nested zips
  in-memory with `zipfile`+`io.BytesIO`; flag hid in the raw bytes of `challenge.bin`.
  → `ctf-forensics`: `nested_archive_peel.py`.

### Forensics / unicode — "Now You See Me" (Hard)
- **Looked like:** a `field_notes.txt` of mundane prose.
- **Clue:** mention of "ZWSP cafes" (zero-width space) + a huge run of invisible characters.
- **Move:** the invisible chars (U+200B/200C/200D/FEFF/2060) encode **binary → ASCII**. Try
  multiple bit-mappings. → `ctf-forensics`: `zerowidth_decode.py`.

### Forensics / logs — "The Chosen One" (Easy)
- **Looked like:** a 10k-line `server_logs.log` with `TS [[INFO]] IP - UserID=.. Action=.. Token=..`.
- **Clue:** prose conditions (seconds `:02`, ordered UserID fragments).
- **Move:** translate the prose into **one regex**, then pick the row whose Token is an actual
  `flag{...}` (decoys used `sha1:`/`sess-`). → `ctf-forensics`: `log_filter.py`.

### Stego / image — "Pixel Perfect" (Easy)
- **Looked like:** a near-white PNG.
- **Clue:** text drawn in pixels valued 226–254 (barely off 255).
- **Move:** threshold any non-255 pixel to black to reveal clues + ciphertext; the clues were
  Rail Fence parameters ("8 rails", "move up by 5" = offset 5). → `ctf-stego`: `image_amplify.py`
  then `ctf-crypto`: `railfence.py`. Beware `l/!` glyph ambiguity in faint text.

### Stego / audio — "Killer Frequencies" (Easy)
- **Looked like:** `crickets.wav`, cricket noise.
- **Clue:** "frequencies / hidden in the air" → the frequency domain.
- **Move:** render an **STFT spectrogram** (Hann, hop 256), dB scale, low freq at bottom;
  **subtract the per-frequency median** to lift drawn text from noise. → `ctf-stego`:
  `spectrogram.py`. Beware `s/5`, `l/1`, `O/0` in the drawn font.

### Web / fetch-metadata — "Mirror-Code Revisited" (Hard)
- **Looked like:** an Express site reflecting `?q=` unencoded (reflected XSS), no CSP.
- **Clue:** `robots.txt` disclosed `/flag` (403 to normal requests).
- **Move:** `/flag` only answered a request that *looked* like a same-origin in-page fetch —
  gated on `Sec-Fetch-Site: same-origin` + `Sec-Fetch-Dest: empty` + same-origin `Referer`.
  **Replay those headers with curl** — no live XSS/bot needed. → `ctf-web`: `secfetch_replay.py`.
  Always read `robots.txt` first.

### Web / auth — "Elmo Tries an 0" (Easy)
- **Clue:** homepage JS set a `role=user` cookie client-side.
- **Move:** send `Cookie: role=admin` → admin panel + flag. Flip any client-trusted privileged
  value (`role/admin/isAdmin/is_admin/user_type`). → `ctf-web`.

### Web / SQLi — "Be Not Afraid" (Medium)
- **Move:** login bypass `email=victim@host' -- ` (any password) to log in **as the specific
  victim** whose account holds the flag. Note: generic `' OR 1=1 -- ` logs in as the *wrong*
  user with no flag — target the right row. → `ctf-web`.

### Web / plain sight — "Mirro-Code" (Easy)
- **Move:** the flag was a constant in the public HTML. `curl` / view-source and `grep flag{`
  before anything clever. → `ctf-web`.

### OSINT / geo — "How Did We Get Here?" (Easy)
- **Move:** identify the place from transit livery + architecture + a googleable business (Zürich
  Stadelhofen: blue trams, arcade, Starbucks; opened 1894; 47.37N 8.55E), **verify** year+coords,
  then follow the prompt's arithmetic **exactly** to a second location (Askja → Öskjuvatn,
  Iceland). Submit accented + ASCII-folded variants. → `ctf-osint`.

---

## The universal opening move
For *any* new challenge, before classifying deeply:
```bash
file F; exiftool F; xxd F | head; xxd F | tail
strings -n 8 F | grep -iE 'flag|pass|key|secret'
python3 -I <triage>/scripts/flag_grep.py F
```
Read the title + filename as if they were hints — because they are.
