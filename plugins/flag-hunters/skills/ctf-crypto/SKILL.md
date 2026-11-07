---
name: ctf-crypto
description: Solve CTF CRYPTO fast and correctly — use the moment you see ciphertext, an encoded/base64 blob, a cipher, "decrypt/decode", hashes, XOR, RSA (n/e/c or .pem keys), AES, or a leaked PRNG seed/timestamp. Runs a decode cascade, mines clues before brute force, and builds an offline verifier. Triggers: ciphertext, encoded blob, base64/hex/base32/base58/ascii85, ROT13, cipher, "decrypt this", RSA, modulus, public/private key, AES, ECB/CBC/CTR, XOR key, hash cracking, length extension, PRNG, seed, flag{...}.
---

# CTF Crypto

Decode first, think second, brute last. Most crypto challenges fall to a cheap
identify-and-decode pass or to a clue leaked in the filename/metadata. Reach for
heavy math (RSA attacks, key recovery) only after the fast path fails.

All helper scripts are stdlib-only and run isolated. Always invoke with `-I`:
```
python3 -I scripts/<name>.py ...
```
Run from this skill directory (or give absolute paths). Each prints its own help
with `-h`.

## Fast path (first 2 minutes — do this before anything clever)

1. **Look at the artifact.** `file blob`, `strings -n6 blob | head`, `xxd blob | head`,
   `wc -c blob`. Magic bytes often reveal a zip/png/pdf hiding inside "ciphertext".
2. **Mine the clues (CLUE-FIRST).** The key is usually *given*, not guessed:
   - Filename, especially timestamps/numbers (a filename like `20070629000000Z`
     is a PDF date = epoch = candidate RNG **seed**). See PRNG section.
   - `exiftool`, PDF `/CreationDate` `/ID`, XMP, zip comments, git history, EXIF.
   - Challenge prose: "8 rails", "move up by 5", "my favourite number", a name.
3. **Identify the encoding, then run the decode cascade** (below). If output is
   still gibberish but looks structured, decode again — encodings stack.
4. **Grep for the flag after every transform:** `... | grep -aiE 'flag\{'`.
   Only when all of that fails do you escalate to the cipher/RSA/XOR sections.

## Identify the encoding (cheapest wins)

| Looks like | Likely | Decode |
|---|---|---|
| `[A-Za-z0-9+/]`, `=` padding, len %4 | base64 | `base64 -d` / CyberChef |
| `[A-Za-z2-7]`, `=` padding | base32 | `python3 -c "import base64,sys;print(base64.b32decode(sys.stdin.read().strip()))"` |
| hex pairs `0-9a-f` | hex | `xxd -r -p` |
| `<~ ... ~>` or dense printable | ascii85/base85 | `python3 -c "import base64,sys;print(base64.a85decode(sys.stdin.buffer.read()))"` |
| `begin 644 ...` | uuencode | `uudecode` |
| no vowels, 1/l/0/O avoided | base58 | bitcoin alphabet (CyberChef) |
| `%41%42` | URL-encode | `python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.stdin.read()))"` |
| `.- / --.` | morse | `classical_cipher.py morse` |
| `01000` groups of 5, A/B | baconian | `classical_cipher.py baconian` |
| `8 5 12 12 15` | A1Z26 | `classical_cipher.py a1z26` |
| letters shifted ~13/looks ROT | ROT13/47/atbash/Caesar | `classical_cipher.py` |

Treat **CyberChef "Magic"** as the manual analogue of this cascade; replicate it
locally so you can script it. Encodings chain — keep decoding until it is text,
an archive, or a flag.

## Classical ciphers — `scripts/classical_cipher.py`

Run the instant ones first (`caesar`, `atbash`, `rot47`) — they are 26 or fewer
tries and each marks any line containing `flag{`.

```
python3 -I scripts/classical_cipher.py caesar   "<ct>"            # all 26 shifts
python3 -I scripts/classical_cipher.py rot13    "<ct>"
python3 -I scripts/classical_cipher.py rot47    "<ct>"
python3 -I scripts/classical_cipher.py atbash   "<ct>"
python3 -I scripts/classical_cipher.py a1z26    "8 5 12 12 15"
python3 -I scripts/classical_cipher.py morse    ".... . .-.. .-.. ---"
python3 -I scripts/classical_cipher.py baconian "AABBBABAAA"
```

**Vigenère** (decision procedure — do these in order):
```
# 1. known key?  decrypt directly:
python3 -I scripts/classical_cipher.py vigenere "<ct>" --key SECRET
# 2. known plaintext (you know it starts with "flag{")? recover key bytes:
python3 -I scripts/classical_cipher.py vig-known "<ct>" --crib "flag"
# 3. unknown key, LONG ciphertext? find length (IoC/Kasiski), then solve columns:
python3 -I scripts/classical_cipher.py vig-kasiski "<ct>"          # IoC ~0.066 wins
python3 -I scripts/classical_cipher.py vig-solve   "<ct>" --keylen 5
```
Kasiski surfaces the true length *and its multiples* — take the smallest of the
low-IoC cluster. Frequency attacks need volume (hundreds of chars); on short text
use a crib instead.

**Substitution / unknown monoalphabetic:** `classical_cipher.py freq "<ct>"`
prints the letter histogram + IoC; map the top ciphertext letters toward English
`etaoin...` as a starting guess, then refine by eye (or use quipqiup online).

**Rail fence / columnar transposition** — see dedicated script below.
**Playfair:** digraph cipher (no doubled letters, even length); solve with an
online Playfair tool or `cipher-solver`; the key is usually a word from the prose.

## Rail fence — `scripts/railfence.py`

Supports a **start offset** because challenges phrase it as prose ("8 rails, move
up by 5" = rails 8, offset 5).
```
python3 -I scripts/railfence.py decode "<ct>" --rails 8 --offset 5
python3 -I scripts/railfence.py brute  "<ct>"            # rails 2..15 × offsets
```
`brute` prints any candidate containing `flag{`. Add `--show` to dump all.

## XOR — `scripts/xor_tools.py`

Input auto-detects hex; override with `--in hex|b64|raw|file`.
```
# single-byte key: brute all 256, ranked by (flag-aware) English score
python3 -I scripts/xor_tools.py single "<hexct>"
# repeating key, unknown length: detect length, then solve each column
python3 -I scripts/xor_tools.py keylen "<ct>" --in b64       # normalized Hamming
python3 -I scripts/xor_tools.py multi  "<ct>" --in b64 --keylen 6
# known plaintext fragment (crib dragging): slide "flag{" to recover key bytes
python3 -I scripts/xor_tools.py crib   "<ct>" --crib "flag{"
# full known prefix: key = ct XOR known
python3 -I scripts/xor_tools.py known  "<ct>" --known "flag{"
```
Decision order: try `single` first; if that fails, `keylen` (low Hamming =
likely length, multiples cluster → take GCD), then `multi`. Crib-dragging `flag{`
beats blind frequency analysis on short flag text.

## RSA attack suite

Gather `n, e, c` (and any `p,q,d,dp,dq`) from the prompt or `.pem`:
```
python3 -c "from cryptography.hazmat.primitives.serialization import load_pem_public_key;\
k=load_pem_public_key(open('key.pem','rb').read());print(k.public_numbers().n, k.public_numbers().e)"
```
Pick the attack from the tell — **never brute a full factorization blindly:**

| Tell | Attack | How |
|---|---|---|
| `e` tiny (3) and `c` small vs `n` | low-exponent / cube root | `m = iroot(c, e)` (gmpy2/sympy) if `m**e < n` |
| same `m`, `e` msgs, `e` moduli | Håstad broadcast | CRT the `c_i` then `e`-th root |
| two users, same `n`, diff `e` (gcd=1) | common modulus | `m = c1^a * c2^b mod n`, `a*e1+b*e2=1` |
| `p`,`q` very close | Fermat | `a=ceil(sqrt(n))`, scan `a²-n` for a square |
| `d` small (`d < n^0.25`) | Wiener | continued-fraction convergents of `e/n` |
| known high/low bits of `p` | partial / Coppersmith | SageMath `small_roots` |
| `n` just small / smooth | factor it | `sympy.factorint`, or factordb.com |

Fast tooling (do **not** auto-install; ask/confirm first):
- **sympy** (`isprime`, `factorint`, `nextprime`, `igcd`) and **gmpy2**
  (`iroot`, `invert`, `gcdext`) cover 90% of hand-written attacks.
- **RsaCtfTool** (github.com/RsaCtfTool/RsaCtfTool, MIT, Python 3.9+, optional
  SageMath) runs the whole menu: `rsactftool --publickey key.pem --uncipher <c>`
  or `-n <n> -e <e> --uncipher <c>`. Try factordb first — many CTF `n` are known.

Quick sanity math (sympy): `from sympy import gcd, mod_inverse; d = mod_inverse(e, (p-1)*(q-1)); m = pow(c, d, n)`.
Then `bytes.fromhex(hex(m)[2:])` or `long_to_bytes` → grep `flag{`.

## AES / symmetric modes

- **ECB** (identical 16-byte plaintext blocks → identical ciphertext blocks):
  detect by duplicate blocks: `python3 -c "import sys;d=open(sys.argv[1],'rb').read();\
b=[d[i:i+16] for i in range(0,len(d),16)];print('dups',len(b)-len(set(b)))" ct.bin`.
  ECB enables cut-and-paste and byte-at-a-time decryption oracles.
- **CBC bit-flipping:** flipping byte `i` of ciphertext block `N` flips the same
  byte of *plaintext* block `N+1` (and corrupts block `N`). Use to forge
  `admin=true` or fix a known-plaintext target. Padding-oracle → full decrypt.
- **CTR / stream nonce reuse:** same key+nonce twice = two-time pad. XOR the two
  ciphertexts to cancel the keystream, then crib-drag (`xor_tools.py crib`).
- Keys/IVs are often leaked in source, env, or are all-zero/`"0"*16` — check first.

## Hashes

1. **Identify by length** (hex): 32→MD5, 40→SHA1, 56→SHA224, 64→SHA256,
   128→SHA512; `$...$` → crypt (bcrypt `$2`, sha512crypt `$6`). Use `hashid`/`hash-identifier`.
2. **Crack** with a wordlist before anything: `hashcat -m <mode> hash.txt rockyou.txt`
   or `john --wordlist=rockyou.txt`. CTF hashes are usually common words/flags.
3. **Length-extension** (`H(secret||msg)` MACs, MD5/SHA1/SHA256, secret length
   known/guessable): forge `H(secret||msg||pad||ext)` with **hashpumpy**
   (`pip install hashpumpy` — confirm before installing) — no secret needed.
4. Unsalted/short → check crackstation.net / hashes.com lookups.

## PRNG seed reconstruction (the "Random Encounter" playbook)

When a secret (password, token, key) is an **output of a seeded standard PRNG**,
and a **seed is leaked** (a timestamp, filename number, PID, "favourite number"):

1. **Find the seed.** A filename `20070629000000Z` is a PDF date →
   `date -u -d '2007-06-29' +%s` = `1183075200`. That epoch is the seed.
2. **Reimplement the generator platform-independently** — do NOT trust local
   `rand()` (macOS rand() ≠ Linux glibc ≠ MSVC). Sweep candidates:
   ```
   python3 -I scripts/prng_sweep.py 1183075200 8          # first 8 outputs, all gens
   python3 -I scripts/prng_sweep.py 1183075200 8 --grep 32285335   # auto-find match
   ```
   It covers: minstd/Park–Miller (a=16807 **and** 48271), glibc TYPE_3, ANSI-C &
   MSVC LCG, Java `Random`, musl, C/C++ MT19937, PHP `mt_rand`, Python `random`,
   numpy. Index 0 = first draw, **index 1 = second draw**.
3. **Match an output to the secret.** In Random Encounter the winner was
   `std::minstd_rand0` (x = x·16807 mod 2³¹−1), seed `1183075200`,
   **output index 1 = 32285335** — the PDF user password. Verify:
   `python3 -I scripts/prng_sweep.py 1183075200 4` → confirms `[1] 32285335`.
4. **Password-protected PDF?** Verify candidates offline (next section).

Python MT19937 note: 624 consecutive 32-bit outputs fully reconstruct the state
(use `randcrack`), and knowing the state lets you predict all future draws.

## Offline verifier pattern (test candidates in-process, fast)

Build a **pure-Python offline verifier** so you can test thousands of candidates
per second with no external tool and no platform surprises — then **validate the
verifier against a known sample before trusting it.**

Password-protected PDF (RC4-128, `/V 2 /R 3`) — `scripts/pdf_rc4_verify.py`:
```
# verify one candidate (reads O/U/P/ID from the PDF automatically):
python3 -I scripts/pdf_rc4_verify.py --pdf secret.pdf --pw '32285335'
# sweep a candidate list (e.g. PRNG outputs) to find the password:
python3 -I scripts/pdf_rc4_verify.py --pdf secret.pdf --wordlist cands.txt
```
It reimplements PDF Algorithms 2 & 5 (MD5 key derivation + RC4) and compares the
computed `/U` to the stored one. **Validate it first** by making your own sample:
```
python3 -c "import pikepdf;p=pikepdf.open('any.pdf');\
p.save('enc.pdf',encryption=pikepdf.Encryption(user='hunter2',owner='o',R=3,aes=False,metadata=False))"
python3 -I scripts/pdf_rc4_verify.py --pdf enc.pdf --pw hunter2   # must say MATCH
```
Same principle for any custom scheme: port the check (not the whole decryptor) to
Python, confirm it accepts a value you encrypted yourself, *then* sweep.

## Flag extraction & verification (do this before submitting)

1. **Grep broadly, bytes mode, case-insensitive:**
   `grep -aiorE 'flag\{[^}]*\}' .` (also try `CTF{`, `AFKAR{`, the event prefix).
2. **Decode once more if the flag looks encoded** (base64 inside the flag, hex,
   ROT). Pipe candidates through the cascade again.
3. **Normalize look-alikes** before trusting a "no match":
   - leetspeak (`3→e 4→a 1→l/i 0→o 5→s 7→t`), case, spacing/underscores.
   - **ligatures:** `ﬂ`→`fl`, `ﬁ`→`fi` (a PDF/stego flag may render `ﬂag{...}`).
     Normalize: `python3 -c "import unicodedata,sys;print(unicodedata.normalize('NFKC',sys.stdin.read()))"`.
   - homoglyphs (Cyrillic `а`, Greek `ο`) — NFKC + visual check.
4. **Format check:** Flag Hunters uses `flag{...}` with letters, digits,
   underscores only. Strip stray whitespace/newlines. If it has spaces or odd
   chars, you probably decoded one layer short or too far.
5. **Sanity before submit:** re-derive the flag a second way if cheap (e.g. the
   offline verifier reproduces it), and confirm the braces are balanced.
