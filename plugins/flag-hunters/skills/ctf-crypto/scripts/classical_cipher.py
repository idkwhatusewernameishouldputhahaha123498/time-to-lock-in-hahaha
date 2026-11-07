#!/usr/bin/env python3
"""classical_cipher.py -- classical cipher swiss-army knife.

Modes:
  caesar   <text>                 print all 26 shifts (brute); flag{ lines marked
  rot13    <text>                 ROT13
  rot47    <text>                 ROT47 (printable-ASCII rotate)
  atbash   <text>                 Atbash (a<->z)
  a1z26    <text>                 decode "1 2 3"/"1-2-3" number->letter
  morse    <text>                 decode morse (. - with / or spaces between words)
  baconian <text>                 decode Baconian (A/B or a/b, 5 per letter)
  vigenere <text> --key KEY       decrypt Vigenere with a known key
  vig-kasiski <text> [--max 20]   estimate key length (Kasiski / IoC)
  vig-solve   <text> --keylen N   recover key via per-column frequency analysis
  vig-known   <text> --crib TEXT  recover key from a known-plaintext fragment at start
  freq        <text>              letter frequency table (substitution starting point)

Text arg may be '-' to read stdin.  Stdlib only.
Tip: when unsure, run `caesar` and `atbash` and `rot47` first -- they are instant.
"""
import sys
from collections import Counter

ALPHA = "abcdefghijklmnopqrstuvwxyz"
ENG_FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"
# IoC of English ~0.066; random ~0.038.
ENG_FREQ = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
}


def shift_text(text, n):
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        elif ch.islower():
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def caesar_brute(text):
    for n in range(26):
        pt = shift_text(text, n)
        mark = "  <<< flag{" if "flag{" in pt.lower() else ""
        print(f"[shift {n:2d}] {pt}{mark}")


def rot13(text):
    return shift_text(text, 13)


def rot47(text):
    out = []
    for ch in text:
        o = ord(ch)
        out.append(chr(33 + (o - 33 + 47) % 94) if 33 <= o <= 126 else ch)
    return "".join(out)


def atbash(text):
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr(90 - (ord(ch) - 65)))
        elif ch.islower():
            out.append(chr(122 - (ord(ch) - 97)))
        else:
            out.append(ch)
    return "".join(out)


def a1z26(text):
    import re
    nums = re.findall(r"\d+", text)
    return "".join(ALPHA[int(n) - 1] if 1 <= int(n) <= 26 else "?" for n in nums)


MORSE = {
    '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e', '..-.': 'f',
    '--.': 'g', '....': 'h', '..': 'i', '.---': 'j', '-.-': 'k', '.-..': 'l',
    '--': 'm', '-.': 'n', '---': 'o', '.--.': 'p', '--.-': 'q', '.-.': 'r',
    '...': 's', '-': 't', '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x',
    '-.--': 'y', '--..': 'z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '-..-.': '/', '-....-': '-', '-.--.': '(', '-.--.-': ')',
}


def morse_decode(text):
    text = text.replace("/", " / ")
    words = text.split(" / ") if " / " in text else [text]
    out_words = []
    for w in words:
        letters = [MORSE.get(tok, "?") for tok in w.split() if tok]
        out_words.append("".join(letters))
    return " ".join(out_words)


def baconian_decode(text):
    # keep only letters; a/A -> 0 bit, b/B -> 1 bit, 5 bits per plaintext letter
    letters = [c for c in text if c.isalpha()]
    bits = "".join("0" if c.lower() == "a" else "1" for c in letters)
    out = []
    for i in range(0, len(bits) - 4, 5):
        chunk = bits[i:i + 5]
        if len(chunk) == 5:
            out.append(chr(int(chunk, 2) + 65))
    return "".join(out)


def vigenere_decrypt(text, key):
    key = [c for c in key.lower() if c.isalpha()]
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = ord(key[ki % len(key)]) - 97
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def index_of_coincidence(s):
    s = [c.lower() for c in s if c.isalpha()]
    n = len(s)
    if n < 2:
        return 0.0
    counts = Counter(s)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def kasiski_keylen(text, max_len=20):
    """Estimate key length: for each candidate length, average the IoC over the
    columns; the best candidate has IoC closest to English (~0.066)."""
    letters = [c.lower() for c in text if c.isalpha()]
    results = []
    for klen in range(1, min(max_len, len(letters) // 2) + 1):
        cols = ["".join(letters[i::klen]) for i in range(klen)]
        avg_ioc = sum(index_of_coincidence(c) for c in cols) / klen
        results.append((klen, avg_ioc))
    results.sort(key=lambda r: abs(r[1] - 0.066))
    return results


def _best_shift_for_column(col):
    """Chi-squared fit of a column against English for each Caesar shift."""
    col = [c.lower() for c in col if c.isalpha()]
    n = len(col)
    best_k, best_chi = 0, float("inf")
    for k in range(26):
        shifted = [chr((ord(c) - 97 - k) % 26 + 97) for c in col]
        counts = Counter(shifted)
        chi = 0.0
        for letter in ALPHA:
            expected = ENG_FREQ[letter] / 100 * n
            observed = counts.get(letter, 0)
            if expected > 0:
                chi += (observed - expected) ** 2 / expected
        if chi < best_chi:
            best_chi, best_k = chi, k
    return best_k


def vig_solve(text, klen):
    letters = [c for c in text if c.isalpha()]
    key = []
    for i in range(klen):
        col = letters[i::klen]
        key.append(chr(_best_shift_for_column(col) + 97))
    key = "".join(key)
    return key, vigenere_decrypt(text, key)


def vig_known(text, crib):
    """Recover key bytes from a known plaintext fragment assumed at the start."""
    ct = [c for c in text if c.isalpha()]
    crib = [c.lower() for c in crib if c.isalpha()]
    key = []
    for c, p in zip(ct, crib):
        base = 65 if c.isupper() else 97
        key.append(chr((ord(c.lower()) - 97 - (ord(p) - 97)) % 26 + 97))
    return "".join(key)


def freq_table(text):
    letters = [c.lower() for c in text if c.isalpha()]
    counts = Counter(letters)
    total = len(letters) or 1
    print(f"# IoC = {index_of_coincidence(text):.4f} "
          f"(English ~0.066, random ~0.038)")
    print("# most common -> guess mapping toward English 'etaoin...'")
    for ch, n in counts.most_common():
        print(f"  {ch}: {n:4d}  {100*n/total:5.2f}%")
    guess = "".join(ch for ch, _ in counts.most_common())
    print(f"\n# cipher-by-frequency: {guess}")
    print(f"# english  order    : {ENG_FREQ_ORDER}")


def _read(arg):
    return sys.stdin.read().rstrip("\n") if arg == "-" else arg


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    mode = argv[0]
    rest = argv[1:]
    opts = {"--key": None, "--keylen": None, "--max": 20, "--crib": None}
    pos = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in opts:
            val = rest[i + 1]
            opts[a] = int(val) if a in ("--keylen", "--max") else val
            i += 2; continue
        pos.append(a); i += 1
    text = _read(pos[0]) if pos else sys.stdin.read().rstrip("\n")

    if mode == "caesar":
        caesar_brute(text)
    elif mode == "rot13":
        print(rot13(text))
    elif mode == "rot47":
        print(rot47(text))
    elif mode == "atbash":
        print(atbash(text))
    elif mode == "a1z26":
        print(a1z26(text))
    elif mode == "morse":
        print(morse_decode(text))
    elif mode == "baconian":
        print(baconian_decode(text))
    elif mode == "vigenere":
        if not opts["--key"]:
            print("vigenere needs --key KEY", file=sys.stderr); return 2
        print(vigenere_decrypt(text, opts["--key"]))
    elif mode == "vig-kasiski":
        for klen, ioc in kasiski_keylen(text, opts["--max"])[:8]:
            print(f"keylen={klen:3d}  avg_IoC={ioc:.4f}")
        print("# IoC closest to 0.066 wins; then: vig-solve --keylen N")
    elif mode == "vig-solve":
        if not opts["--keylen"]:
            print("vig-solve needs --keylen N", file=sys.stderr); return 2
        key, pt = vig_solve(text, opts["--keylen"])
        print(f"# recovered key: {key}")
        print(pt)
    elif mode == "vig-known":
        if not opts["--crib"]:
            print("vig-known needs --crib TEXT", file=sys.stderr); return 2
        print(f"# key fragment: {vig_known(text, opts['--crib'])}")
    elif mode == "freq":
        freq_table(text)
    else:
        print(f"unknown mode {mode!r}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
