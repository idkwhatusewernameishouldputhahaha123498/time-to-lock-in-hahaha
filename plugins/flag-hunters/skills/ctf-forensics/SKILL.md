---
name: ctf-forensics
description: Reach for this the moment a CTF hands you a FILE to dig into - a .zip/.7z/.rar, a .pcap/.pcapng, a disk/.img/.raw/memory dump, a PDF/office/image with metadata, a log file, or any "hidden file / recover / extract / carve / zero-width / invisible text / archive / binwalk" prompt. Fast, correct forensics triage that always greps the raw bytes for flag{ first.
---

# CTF Forensics

Find the flag in a provided artifact FAST, without brute force. Flags look like
`flag{letters_numbers_underscores}`. The whole game: identify what the file
really is, pull the hidden layer out, and grep the raw bytes.

## FAST PATH - run this in the first 60 seconds, every time

```bash
F=target.bin

# 0) GREP RAW BYTES FOR THE FLAG BEFORE ANYTHING ELSE. It is often just... there.
grep -aobE 'flag\{[^}]+\}' "$F"          # -a=treat binary as text, -b=byte offset
strings -n 8 "$F" | grep -iE 'flag|ctf|pass|secret|key'

# 1) What IS it? (extension lies; magic bytes do not)
file "$F"
xxd "$F" | head -20                       # eyeball the magic bytes yourself

# 2) Hidden metadata / comments (PNG/JPG/PDF/office/mp3 all carry text fields)
exiftool "$F"

# 3) Anything appended / embedded / compressed inside?
binwalk "$F"                              # signature scan
binwalk -e "$F"                           # auto-extract what it found
```

WHY this order: 90% of "easy/medium" forensics flags fall out of `strings`,
`exiftool`, or `binwalk` in under a minute. The byte-grep (`grep -a`) catches
flags sitting in headers, EXIF, appended data, or trailing padding that a naive
`cat`/text view would hide. Only escalate to the per-artifact tools below when
the fast path comes up empty.

## Principles (named - think with these)

- **Clue-first.** The challenge text, filename, and category are instructions,
  not decoration. "ZWSP cafes" -> zero-width stego. "She left a note in the
  photo" -> EXIF/stego. Translate every clue into a concrete command or regex
  BEFORE poking around.

- **Reverse-psychology misdirection = SIGNPOST.** A folder/file named
  `dontlook/`, `nothing_here/`, `NOT_THE_FLAG.txt`, `Stop reading`, `boring/`,
  `THESE ARE NOT IMPORTANT` is the author pointing a neon arrow AT the real
  material. Open those first. (In the "Linux FS" win the 7z password lived in
  `Trash/dontlook/passwords.txt`.)

- **Error-type is an ORACLE.** When dictionary-attacking an encrypted archive,
  the WRONG password and the RIGHT password often throw DIFFERENT errors. On an
  AES-7z with an encrypted header, every wrong password corrupts the header and
  dies the same way (e.g. a `TypeError`/`Bad7zFile`); the right one decrypts the
  header cleanly and either succeeds or fails LATER and differently. Watch for a
  SUCCESS first; failing that, the odd-one-out by error TYPE or by stage -- NOT
  wrong passwords that merely differ in error message (that's noise; e.g. py7zr
  1.1.4 raises `TypeError` with varying messages for every wrong password).
  `nested_archive_peel.py` prints the per-password error type so you can SEE it.

- **The flag hides in raw bytes, not nice files.** Extracted a `challenge.bin`?
  `grep -a 'flag{'` it. Do not assume it must be a `.txt`.

- **No brute force of the flag itself.** Brute force a *small* password wordlist,
  never the flag. If a path needs millions of guesses, you've misread a clue.

## Decision tree - route by what the artifact actually is (per `file`)

| `file` says / extension        | Go to            |
|--------------------------------|------------------|
| Zip/7z/rar/gzip/tar, nested    | ARCHIVES         |
| PNG/JPG/GIF/BMP/PDF/doc/mp3    | IMAGE/DOC FILE   |
| pcap / pcapng / tcpdump        | NETWORK CAPTURE  |
| raw/img/dd/E01, filesystem     | DISK IMAGE       |
| "data", huge, memory dump      | MEMORY DUMP      |
| text/ASCII log, .log, .csv     | LOG ANALYSIS     |
| text but "looks empty"/weird   | TEXT / UNICODE   |
| a `.git` directory present     | GIT FORENSICS    |
| `file` says "data" + fast path empty | CARVING    |

---

## ARCHIVES (zip / 7z / rar / nested / password-protected)

Nested and password-protected archives are the bread-and-butter. The password is
usually NEARBY (a sibling file, a misdirection folder, the challenge text) - find
it, don't crack it.

```bash
# peel nested archives in-memory, harvest passwords from sibling text files,
# run the wordlist with the ERROR-ORACLE visible, grep every blob for flag{
python3 -I scripts/nested_archive_peel.py challenge.zip.zip [wordlist.txt]
```

Manual escalation:
```bash
7z l -slt archive.7z            # list + detail (see if header is encrypted)
7z x -pPASSWORD archive.7z      # extract with password
zipinfo -v archive.zip          # per-member encryption/flags
# AES-zip? stdlib unzip/python zipfile CANNOT; use pyzipper or 7z.
# Dictionary attack hashes with john/hashcat ONLY as a last resort:
zip2john archive.zip > h ; john --wordlist=rockyou.txt h
```
- `nested_archive_peel.py` uses `py7zr` (AES-7z, no system 7z binary needed) when installed, else
  system `7z`. It DEFERS encrypted cracks until it has peeled every unencrypted
  file, so a password in `dontlook/passwords.txt` is in the wordlist before the
  `.7z` is attacked.
- A log alongside the challenge may RULE OUT candidate passwords ("tried X, Y") -
  read it; it narrows the wordlist.
- **No binwalk on the box?** `scripts/carve.py` is a pure-Python carver: it finds
  embedded/appended files (a `.zip` concatenated after a PNG, nested "matryoshka"
  image→zip→image chains), extracts them recursively, and greps each piece for a
  flag — `python3 -I scripts/carve.py <file> [--outdir DIR]`.

## IMAGE / DOC FILE (PNG, JPG, GIF, PDF, office, audio)

Stego-adjacent but still forensics: the data is in metadata, trailing bytes, or
structure - not pixel LSBs (that's the stego skill).
```bash
exiftool -a -u -g1 file.png     # ALL tags, including duplicated/unknown groups
binwalk -e file.png             # extra file appended after IEND/EOI?
pngcheck -v file.png            # PNG chunk-level anomalies, extra chunks
strings -n 6 file.pdf | grep -iE 'flag|/URI|/JS'
pdfinfo file.pdf ; pdf-parser.py file.pdf   # objects, streams, metadata
# office/docx = a zip: unzip and grep
unzip -o file.docx -d dx && grep -arE 'flag\{' dx/
# compare declared vs real: a "png" that is really a zip -> see ARCHIVES
```
WHY: EXIF `Comment`/`Artist`/`XMP`, PDF object metadata, and bytes appended after
a file's logical end (`IEND`, `FFD9`) are the classic hiding spots.

## NETWORK CAPTURE (pcap / pcapng)

```bash
capinfos cap.pcap                                   # overview, # packets
tshark -r cap.pcap -q -z io,phs                     # protocol hierarchy - what's here
tshark -r cap.pcap -q -z conv,tcp                   # conversations (who talks most)

# Follow a stream (the flag is usually IN a reassembled stream, not one packet)
tshark -r cap.pcap -q -z follow,tcp,ascii,0         # stream index 0
tshark -r cap.pcap -z credentials -q                # harvested creds

# Export transferred files (then run them back through the FAST PATH)
tshark -r cap.pcap --export-objects http,./objs
mkdir smb && tshark -r cap.pcap --export-objects smb,./smb

# Exfil channels - decode these:
tshark -r cap.pcap -Y dns -T fields -e dns.qry.name            # DNS exfil (subdomains)
tshark -r cap.pcap -Y icmp -T fields -e data.data              # ICMP payload exfil
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri
```
In Wireshark GUI: Follow > TCP/HTTP Stream, File > Export Objects, and
`Statistics > Protocol Hierarchy`. WHY: HTTP/DNS/ICMP and reassembled TCP are the
usual carriers; exported objects (images, zips) often contain the real flag -
feed them to the FAST PATH and the ARCHIVES/IMAGE sections.

## DISK IMAGE (raw / dd / img / E01 / partition)

```bash
file disk.img ; fdisk -l disk.img              # partition table, offsets
mmls disk.img                                  # sleuthkit partition layout
# mount a partition read-only (offset = start_sector * 512)
sudo mount -o ro,loop,offset=$((2048*512)) disk.img /mnt/x
strings -n 8 disk.img | grep -iE 'flag\{'      # fast, works even unmounted
# deleted files:
fls -rd disk.img                               # list deleted entries (sleuthkit)
icat disk.img <inode> > recovered.bin          # recover by inode
foremost -i disk.img -o out/                   # carve by signature
binwalk -e disk.img
```
WHY: flags live in deleted files, slack space, or unallocated blocks. `strings`
the whole image first; it is the cheapest win. Deleted != gone until overwritten.

## MEMORY DUMP (volatility3)

```bash
# identify the OS/profile first
python3 vol.py -f mem.raw windows.info          # or banners.Banners for linux
# processes & command lines (look for the odd process / its args)
python3 vol.py -f mem.raw windows.pslist
python3 vol.py -f mem.raw windows.cmdline        # args often HOLD the flag/pass
# find and dump files cached in memory
python3 vol.py -f mem.raw windows.filescan | grep -iE 'flag|\.txt|\.png'
python3 vol.py -f mem.raw -o ./out windows.dumpfiles --virtaddr 0xADDR
# other goldmines
python3 vol.py -f mem.raw windows.netscan        # connections
python3 vol.py -f mem.raw windows.clipboard
# Linux targets: linux.pslist / linux.bash (shell history!) / linux.pagecache.Files
python3 vol.py -f mem.raw linux.bash
# and ALWAYS:
strings -n 8 mem.raw | grep -aE 'flag\{'
```
WHY: command-line args, shell history (`linux.bash`), clipboard, and cached files
are where authors stash flags. `strings | grep flag{` on the raw dump frequently
beats the whole plugin chase - try it in parallel.

## LOG ANALYSIS

Translate the prose clues into ONE regex per clue, AND them, read the survivor.
```bash
# e.g. "the :02-second entry for the user whose id has these fragments in order"
python3 -I scripts/log_filter.py app.log \
    -r ':02\s' -r 'UserID=Am.*Ch.*th.*st\b' -e 'Token=(\S+)'
# quick manual passes:
grep -nE 'flag\{[^}]+\}' app.log
awk -F'[][]' '/INFO/{print}' app.log | sort | uniq -c | sort -rn   # frequency/outliers
```
`log_filter.py` ANDs multiple `-r` regexes, auto-surfaces `flag{...}`, and IGNORES
decoy token formats (`sha1:`, `sess-`, bare 32/40/64-hex). WHY: the flag row is
the one whose token is actually flag-shaped among many lookalikes.

## TEXT / UNICODE (zero-width, homoglyph, invisible)

A file that looks empty or like plain prose but the clue hints "invisible",
"between the lines", "ZWSP", "you can't see it":
```bash
python3 -I scripts/zerowidth_decode.py field_notes.txt
# manual: reveal the invisible codepoints
grep -aP '[\x{200b}-\x{200f}\x{2060}\x{feff}]' file.txt && echo "zero-width present"
python3 -c "import sys;[print(hex(ord(c))) for c in open(sys.argv[1]).read() if ord(c)>0x2000]" file.txt
```
`zerowidth_decode.py` extracts the zero-width family (U+200B/C/D, U+2060, U+FEFF),
tries BOTH bit orderings for every symbol pair AND both MSB/LSB bit orders,
decodes the Unicode TAG block (U+E0000..E007F -> ASCII), and reports homoglyphs.
WHY: you rarely know which invisible char is 0 vs 1 - brute the small mapping
space, not the content.

## GIT FORENSICS

A repo (or a loose `.git`) is a time machine; flags hide in history.
```bash
git log --all --oneline --source               # every branch/tag commit
git log -p -S 'flag{'                           # commits that added/removed flag{
git reflog --all                                # dangling/rewritten commits
git stash list ; git stash show -p stash@{0}
git fsck --lost-found                           # dangling blobs/commits
git cat-file -p <dangling-sha>                  # read a recovered blob
git show <commit>:path/to/secret                # file as it was in that commit
```
WHY: `git log -S` and `reflog`/`fsck` recover secrets that were "deleted" but
never truly gone.

## CARVING (file says "data", nothing else worked)

```bash
binwalk -e blob.bin                             # signature extract
foremost -i blob.bin -o carved/                 # recover by header/footer
dd if=blob.bin of=chunk.bin bs=1 skip=$OFFSET count=$LEN   # manual slice at an offset
scalpel -o out blob.bin                         # configurable carver
```
Use the byte offsets `binwalk`/`xxd` give you with `dd` to slice out an embedded
file, then re-run the FAST PATH on the slice.

---

## Scripts (standalone, stdlib-first, `python3 -I` friendly)

| Script | Does | Run |
|--------|------|-----|
| `scripts/nested_archive_peel.py` | recursively peel nested zip/7z in-memory, harvest passwords from sibling files, show the error-oracle, grep every blob for `flag{` | `python3 -I scripts/nested_archive_peel.py <archive> [wordlist.txt]` |
| `scripts/zerowidth_decode.py` | extract zero-width / tag-block / homoglyph chars and brute the bit-mappings to printable ASCII / `flag{` | `python3 -I scripts/zerowidth_decode.py <file>` |
| `scripts/log_filter.py` | AND multiple regex clues over a log, surface the real `flag{}` token, ignore decoy token formats | `python3 -I scripts/log_filter.py <log> -r <re> [-r <re2>] [-e 'Field=(\S+)']` |

Run with `-I` (isolated): extracted artifacts are UNTRUSTED - a planted
`json.py`/`zlib.py` in the working dir must not be importable. Keep the scripts in
a different directory from the artifact and pass the artifact path as an argument.

## Flag extraction & verification (do this last, always)

```bash
# the one grep that ends most challenges - on the FINAL extracted blob:
grep -aoE 'flag\{[^}]+\}' recovered.bin

# ligature trap: authors hide flags using Unicode ligatures that LOOK like 'fl'/'fi'
#   U+FB02 'fl'  U+FB01 'fi'  -> a plain /flag\{/ grep MISSES them. Catch both:
grep -aoP '(flag|\x{fb02}ag|\x{fb01}lag)\{[^}]+\}' recovered.bin
# normalize unicode before final matching if a decode produced odd glyphs:
python3 -c "import unicodedata,sys;print(unicodedata.normalize('NFKC',open(sys.argv[1]).read()))" out.txt
```
- Confirm the format: `flag{...}` with only letters/digits/underscores inside
  (this CTF's rule). If your capture has stray spaces/newlines, you grabbed too
  much - tighten the regex.
- If you see `fl` or `fi` rendered oddly, suspect a ligature and re-grep with the
  pattern above before concluding there is no flag.
