#!/usr/bin/env python3
"""xor_tools.py -- the XOR toolkit: single-byte brute, key-length detection,
multi-byte Vigenere-XOR solve, crib dragging, and known-plaintext key recovery.

Input is bytes; choose how to read them with --in:
  --in hex     ciphertext arg is hex          (default if it looks like hex)
  --in b64     ciphertext arg is base64
  --in raw     ciphertext arg is a literal string
  --in file    ciphertext arg is a path to a binary file

Modes:
  single   <ct>                 brute all 256 single-byte keys, rank by English score
  keylen   <ct> [--max 40]      guess key length via normalized Hamming distance
  multi    <ct> [--keylen N]    solve repeating-key XOR (per-column single-byte brute)
  crib     <ct> --crib TEXT     drag a known plaintext fragment across the ciphertext,
                                 print recovered key bytes wherever it yields printable text
  known    <ct> --known TEXT    key = ct XOR known (known-plaintext; aligns at start)

Examples:
  python3 -I xor_tools.py single 1b37373331...  --in hex
  python3 -I xor_tools.py multi  --in file cipher.bin
  python3 -I xor_tools.py crib   --in hex <ct> --crib 'flag{'

Stdlib only.
"""
import sys
import base64

# Relative English letter frequencies (+ space) for scoring plausibility.
_FREQ = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074, ' ': 13.0,
}


def english_score(bs):
    """Higher = more plausible plaintext. Tuned for CTF text (flags, identifiers),
    not just prose: lowercase letters use English frequency, mid-text UPPERCASE is
    down-weighted (unusual), underscore/braces/digits get small credit, and
    non-printable bytes are punished hard. This beats naive frequency on flag
    strings, which have no spaces and many underscores."""
    score = 0.0
    for b in bs:
        c = chr(b)
        if 'a' <= c <= 'z':
            score += _FREQ[c]
        elif 'A' <= c <= 'Z':
            score += _FREQ[c.lower()] * 0.3     # caps rare mid-word
        elif c == ' ':
            score += 13.0
        elif c == '_':
            score += 2.0                         # very common in flags/ids
        elif c in '{}':
            score += 1.0
        elif c.isdigit():
            score += 0.5
        elif 32 <= b < 127:
            score += 0.1                         # other printable punctuation
        elif b in (9, 10, 13):
            score += 0.1
        else:
            score -= 15.0                        # non-printable: strong penalty
    return score / max(1, len(bs))


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def single_byte(ct, top=5):
    """Return top candidate (key, plaintext, score) tuples.

    English frequency alone ranks short flag text (few vowels, many symbols/
    underscores) below vowel-rich garbage, so we add structural bonuses: a decisive
    one for an actual flag/ctf wrapper, a smaller one for brace-wrapped printable
    text. This floats the real flag to the top where a human looks."""
    results = []
    for k in range(256):
        pt = bytes(b ^ k for b in ct)
        sc = english_score(pt)
        low = pt.lower()
        if b"flag{" in low or b"ctf{" in low:
            sc += 100.0                                   # the giveaway
        elif b"{" in pt and b"}" in pt and all(32 <= c < 127 for c in pt):
            sc += 3.0                                     # plausible wrapped flag
        results.append((k, pt, sc))
    results.sort(key=lambda r: r[2], reverse=True)
    return results[:top]


def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keylen(ct, max_len=40, top=5):
    """Rank candidate key lengths by normalized average Hamming distance between
    consecutive blocks (lower = better)."""
    scores = []
    for klen in range(2, min(max_len, len(ct) // 2) + 1):
        blocks = [ct[i:i + klen] for i in range(0, len(ct), klen)]
        full = [b for b in blocks if len(b) == klen]
        if len(full) < 2:
            continue
        pairs = 0
        total = 0.0
        for i in range(len(full) - 1):
            total += hamming(full[i], full[i + 1]) / klen
            pairs += 1
        scores.append((klen, total / pairs))
    scores.sort(key=lambda s: s[1])
    return scores[:top]


def solve_multi(ct, klen):
    """Repeating-key XOR solve: brute each column independently by English score."""
    key = bytearray()
    for col in range(klen):
        column = ct[col::klen]
        best = single_byte(column, top=1)[0]
        key.append(best[0])
    pt = xor_bytes(ct, bytes(key))
    return bytes(key), pt


def crib_drag(ct, crib):
    """Slide crib across ct; at each offset recover candidate key = ct XOR crib
    and show it if it is printable (likely part of the real key)."""
    crib = crib.encode() if isinstance(crib, str) else crib
    hits = []
    for off in range(0, len(ct) - len(crib) + 1):
        seg = ct[off:off + len(crib)]
        cand = bytes(a ^ b for a, b in zip(seg, crib))
        if all(32 <= c < 127 for c in cand):
            hits.append((off, cand))
    return hits


def known_plaintext(ct, known):
    """key = ct XOR known, aligned from the start (classic when flag prefix known)."""
    known = known.encode() if isinstance(known, str) else known
    n = min(len(ct), len(known))
    return bytes(a ^ b for a, b in zip(ct[:n], known[:n]))


def _printable(bs):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bs)


def read_input(mode, value):
    if mode == "file":
        with open(value, "rb") as f:
            return f.read()
    if mode == "b64":
        return base64.b64decode(value)
    if mode == "raw":
        return value.encode("latin-1")
    # hex (default): strip whitespace/0x
    s = value.replace("0x", "").replace(" ", "").replace("\n", "")
    return bytes.fromhex(s)


def _looks_hex(s):
    t = s.replace(" ", "").replace("\n", "").lower()
    return len(t) % 2 == 0 and t and all(c in "0123456789abcdef" for c in t)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    mode = argv[0]
    rest = argv[1:]

    opts = {"--in": None, "--max": 40, "--keylen": None, "--crib": None,
            "--known": None, "--top": 5}
    pos = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in opts:
            val = rest[i + 1]
            opts[a] = int(val) if a in ("--max", "--keylen", "--top") else val
            i += 2; continue
        pos.append(a); i += 1

    raw = pos[0] if pos else sys.stdin.read().strip()
    in_mode = opts["--in"] or ("hex" if _looks_hex(raw) else "raw")
    ct = read_input(in_mode, raw)

    if mode == "single":
        for k, pt, sc in single_byte(ct, opts["--top"]):
            print(f"key=0x{k:02x} ({k:3d}) score={sc:6.2f}  {pt!r}")
    elif mode == "keylen":
        for klen, dist in guess_keylen(ct, opts["--max"], opts["--top"]):
            print(f"keylen={klen:3d}  norm_hamming={dist:.4f}")
        print("# lowest norm_hamming = most likely; then: multi --keylen N")
    elif mode == "multi":
        klens = ([opts["--keylen"]] if opts["--keylen"]
                 else [guess_keylen(ct, opts["--max"], 1)[0][0]])
        for klen in klens:
            key, pt = solve_multi(ct, klen)
            print(f"# keylen={klen}  key={key!r} (hex {key.hex()})")
            print(pt.decode("latin-1"))
    elif mode == "crib":
        if not opts["--crib"]:
            print("crib mode needs --crib TEXT", file=sys.stderr); return 2
        for off, cand in crib_drag(ct, opts["--crib"]):
            print(f"offset={off:4d}  keybytes={cand!r}  (hex {cand.hex()})")
    elif mode == "known":
        if not opts["--known"]:
            print("known mode needs --known TEXT", file=sys.stderr); return 2
        key = known_plaintext(ct, opts["--known"])
        print(f"recovered key = {key!r}  (hex {key.hex()})")
        print(f"ascii: {_printable(key)}")
    else:
        print(f"unknown mode {mode!r}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
