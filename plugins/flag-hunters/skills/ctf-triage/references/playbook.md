# CTF Playbook — pattern → move (one-screen lookup)

Scan this to pick a first move fast. Scripts live in each skill's `scripts/` dir. Full reasoning
is in `clue-first.md` and the per-category `SKILL.md` files.

## Universal opening (every challenge)
`file F` · `exiftool F` · `xxd F | head` + `xxd F | tail` · `strings -n 8 F | grep -iE 'flag|pass|key'` · `flag_grep.py F` · **read the title + filename as hints**.

## By what you're handed

| You have… | First move | Then | Skill / script |
|---|---|---|---|
| A URL / website | `curl -s URL \| grep -i flag`, view-source, `curl robots.txt` | inspect Set-Cookie + JS; flip `role=admin`; try SQLi on login | ctf-web / `secfetch_replay.py` |
| Login form | `email=victim@host' -- ` (target the victim) | UNION / blind; default creds | ctf-web |
| Gated endpoint (403) | replay `Sec-Fetch-*` + same-origin `Referer` | check robots.txt for the path | ctf-web / `secfetch_replay.py` |
| `.zip/.7z/.rar` (esp. nested/encrypted) | peel recursively; wordlist + watch error-type | grep extracted raw bytes | ctf-forensics / `nested_archive_peel.py` |
| `.pcap` | `tshark`/Wireshark: follow TCP stream, export objects | HTTP/DNS/ICMP exfil, creds | ctf-forensics |
| Disk/memory image | `strings\|grep flag`; volatility3 (pslist, filescan, dumpfiles) | mount, carve | ctf-forensics |
| Log file | translate prose clues → one regex | pick the `flag{...}` token (ignore sha1:/sess- decoys) | ctf-forensics / `log_filter.py` |
| Text that looks normal but "off" | check for zero-width / invisible / homoglyph chars | decode bits → ASCII | ctf-forensics / `zerowidth_decode.py` |
| Image "blank"/washed-out | threshold non-white→black; bit-planes; contrast | OCR the revealed text (watch l/1, O/0) | ctf-stego / `image_amplify.py` |
| Image (normal) | `strings`/`binwalk`/data after IEND; zsteg all planes | steghide (pw from prompt) | ctf-stego |
| Audio (noise / "listen") | render spectrogram + median-subtract | DTMF / Morse / SSTV / reversed | ctf-stego / `spectrogram.py` |
| RSA params (n,e,c / .pem) | small-e cube root, Fermat, Wiener, common-modulus | RsaCtfTool as fallback | ctf-crypto |
| Ciphertext / cipher name | identify; Caesar/Vigenère/XOR/rail-fence | frequency analysis; crib-drag | ctf-crypto / `classical_cipher.py` `xor_tools.py` `railfence.py` |
| A seed / timestamp + "random" | reproduce seed; sweep standard PRNGs | match an output | ctf-crypto / `prng_sweep.py` |
| Password-protected PDF | mine metadata/filename for key material | offline verifier + candidate test | ctf-crypto / `pdf_rc4_verify.py` |
| Executable (crackme) | `strings`/`floss`; run it; break after decode | reverse the check / patch the jump / angr | ctf-rev / `angr_template.py` |
| ELF + `nc host port` | `checksec`; find `win`/overflow; cyclic offset | ROP / ret2libc / fmt-string | ctf-binary / `pwn_template.py` |
| Mystery encoded blob | identify alphabet; cascade-decode layers | nested encodings peel | ctf-misc / `decode_cascade.py` |
| QR/barcode | `zbarimg` | decode payload (may be nested) | ctf-misc |
| A whole machine / story | enumerate home, browser, history, hidden/misdirected files | dispatch per-artifact | investigation |

## Flag endgame
Recognize `flag{[A-Za-z0-9_]+}` · watch ligatures `ﬂ/ﬁ` and glyphs `l/1/! O/0 s/5 B/8` · try leet
(`a4 e3 o0 i1 s5 t7`) + case + accent-fold variants · **verify offline before submitting** ·
`flag_grep.py` surfaces variants automatically.

## Time discipline
Fast path + top-2 moves (~8–10 min) → hint 1 → focused push → hint 2 → hint 3 only if worth it.
Bank easy flags first; park hard ones and return.
