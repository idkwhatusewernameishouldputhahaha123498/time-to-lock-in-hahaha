#!/usr/bin/env python3
"""
flag_grep.py - fast, dependency-free hunt for a flag in a file or directory tree.

Format-agnostic: it matches ANY `word{...}` wrapper (flag{}, FLAG{}, ctf{},
picoCTF{}, a custom name) and reports the FULL token - so picoCTF{...} is never
truncated to CTF{...}. Looks in, in order of confidence:
  1. raw bytes,
  2. NUL-stripped bytes (UTF-16-ish data with interleaved NULs, odd lengths),
  3. UTF-16 LE/BE and UTF-32 LE/BE decoded text,
  4. ligature-normalized text (fi/fl break a naive 'flag{' regex),
  5. one layer of base64 / base32 / hex decoding of substrings,
  6. ROT-n of the text (Caesar-wrapped flags),
  7. a leetspeak-normalized GUESS (clearly labelled - it may be wrong).

Usage:
    python3 -I flag_grep.py <file-or-dir> [more paths...]
    python3 -I flag_grep.py .                      # scan current dir recursively
    python3 -I flag_grep.py f --wrappers flag,ctf  # RESTRICT to these wrappers
    python3 -I flag_grep.py f --deep               # decode-cascade on large files too

By default it reports every `word{...}`; --wrappers narrows to the names you pass
(useful to cut noise when you know the format). Pure standard library; safe with -I.
"""
import sys
import os
import re
import base64
import binascii

INNER = rb"\{[ -~]{0,256}?\}"          # printable ASCII inside braces, non-greedy
# Any identifier immediately followed by {...}: flag, FLAG, ctf, picoCTF, custom.
GENERIC_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,24}\{[ -~]{0,256}?\}")
REVERSED_RE = re.compile(rb"\}[ -~]{0,256}?\{[A-Za-z][A-Za-z0-9_]{1,24}")
# STRICT: a token ending in flag/ctf before the braces. Used for noise-prone passes
# (ROT-n of arbitrary text contains "{" in all 25 rotations, so GENERIC would flood).
STRICT_RE = re.compile(rb"[A-Za-z0-9_]*(?:flag|ctf)\{[ -~]{0,256}?\}", re.IGNORECASE)

LIGATURES = {"ﬁ": "fi", "ﬂ": "fl", "ﬀ": "ff",
             "ﬃ": "ffi", "ﬄ": "ffl"}

LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "0": "o",
                      "1": "i", "!": "i", "5": "s", "$": "s", "7": "t"})

DEEP_SIZE_LIMIT = 2_000_000           # bytes considered for decoding when not --deep
MIN_RUN = 8                           # shortest encoded run worth decoding (b64 of ~6+ bytes)


def _rot(text, n):
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def flag_regexes(wrappers):
    """If wrappers given, restrict to `<wrapper>{...}`; else match any word{...}.
    In restrict mode the wrapper is anchored with a negative look-behind so a short
    wrapper (ctf) does NOT match inside a longer one (picoCTF) and truncate it."""
    if wrappers:
        pats = [re.compile(rb"(?<![A-Za-z0-9_])" + re.escape(w.encode()) + INNER, re.IGNORECASE)
                for w in wrappers]
    else:
        pats = [GENERIC_RE]
    pats.append(REVERSED_RE)
    return pats


def hits(data: bytes, label: str, found: dict, pats=None):
    """Record flag-shaped matches. `found` maps match-text -> first label seen."""
    for pat in (pats if pats is not None else PATS):
        for m in pat.finditer(data):
            try:
                txt = m.group(0).decode("latin-1")
            except Exception:
                txt = repr(m.group(0))
            if txt not in found:
                found[txt] = f"{label} @{m.start()}"


def nul_strip_pass(data: bytes, label: str, found: dict):
    """Strip NUL bytes and re-scan: catches NUL-interleaved / imperfectly-decoded
    wide-char data where the raw pass is broken by the interleaved \\x00s."""
    if b"\x00" in data:
        hits(data.replace(b"\x00", b""), f"{label}:nul-stripped", found)


def wide_char_pass(data: bytes, label: str, found: dict):
    """Decode UTF-16/32 (both endians) and re-scan - a common wide-char hiding spot."""
    for enc in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
        try:
            txt = data.decode(enc, "ignore")
        except Exception:
            continue
        if "{" in txt:
            hits(txt.encode("latin-1", "ignore"), f"{label}:{enc}", found)


def ligature_pass(data: bytes, label: str, found: dict):
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return
    for lig, rep in LIGATURES.items():
        text = text.replace(lig, rep)
    hits(text.encode("utf-8", "ignore"), f"{label}:ligature", found)


def decode_pass(data: bytes, label: str, found: dict, deep: bool):
    """One layer of base64/base32/hex decoding of substrings, then re-scan."""
    sample = data if (deep or len(data) <= DEEP_SIZE_LIMIT) else data[:DEEP_SIZE_LIMIT]
    text = sample.decode("latin-1", "ignore")
    for run in re.findall(r"[A-Za-z0-9+/=]{%d,}" % MIN_RUN, text):
        try:
            hits(base64.b64decode(run + "=" * (-len(run) % 4), validate=False),
                 label + ":b64", found)
        except Exception:
            pass
    for run in re.findall(r"[A-Z2-7=]{%d,}" % MIN_RUN, text):
        try:
            hits(base64.b32decode(run + "=" * (-len(run) % 8)), label + ":b32", found)
        except Exception:
            pass
    for run in re.findall(r"(?:[0-9a-fA-F]{2}){8,}", text):
        try:
            hits(binascii.unhexlify(run[: len(run) - len(run) % 2]), label + ":hex", found)
        except Exception:
            pass
    for n in range(1, 26):
        rot = _rot(text, n)
        if "{" in rot:
            # STRICT: every rotation of arbitrary text still contains "{", so match
            # only rotations that reveal a real flag/ctf wrapper (no 25x flood).
            hits(rot.encode("latin-1", "ignore"), label + f":rot{n}", found, pats=[STRICT_RE])


def leet_pass(data: bytes, label: str, leet_guesses: dict):
    """A leet-normalized GUESS, recorded separately so it's never mistaken for a
    confirmed flag (fl4g{s3cr3t} -> flag{secret} may or may not be the real flag)."""
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return
    leet = text.translate(LEET)
    if leet == text:
        return
    for pat in PATS:
        for m in pat.finditer(leet.encode("latin-1", "ignore")):
            txt = m.group(0).decode("latin-1", "ignore")
            leet_guesses.setdefault(txt, f"{label} (leet-normalized guess)")


def scan_file(path, found, leet_guesses, deep):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"  (skip {path}: {e})", file=sys.stderr)
        return
    label = os.path.relpath(path)
    hits(data, label, found)
    nul_strip_pass(data, label, found)
    wide_char_pass(data, label, found)
    ligature_pass(data, label, found)
    decode_pass(data, label, found, deep)
    leet_pass(data, label, leet_guesses)


def main(argv):
    wrappers = []            # empty => match any word{...}
    deep = False
    targets = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        if a == "--wrappers":
            if i + 1 >= len(argv):
                print("[!] --wrappers needs a value", file=sys.stderr)
                return 2
            wrappers += [w for w in argv[i + 1].split(",") if w]
            i += 2
            continue
        if a == "--deep":
            deep = True
            i += 1
            continue
        targets.append(a)
        i += 1
    if not targets:
        print(__doc__)
        return 2

    global PATS
    PATS = flag_regexes(wrappers)

    found, leet_guesses = {}, {}
    for target in targets:
        if os.path.isdir(target):
            for root, _dirs, files in os.walk(target):
                for name in files:
                    scan_file(os.path.join(root, name), found, leet_guesses, deep)
        else:
            scan_file(target, found, leet_guesses, deep)

    if found:
        print(f"[+] {len(found)} candidate flag(s) (most reliable first):")
        for txt, where in found.items():
            print(f"    {txt}    <- {where}")
    extra = {t: w for t, w in leet_guesses.items() if t not in found}
    if extra:
        print(f"\n[?] {len(extra)} leet-normalized GUESS(es) - may be wrong, verify:")
        for txt, where in extra.items():
            print(f"    {txt}    <- {where}")
    if not found and not extra:
        print("No word{...}-shaped strings found "
              "(raw / nul-stripped / wide-char / ligature / b64 / b32 / hex / rot / leet).")
        print("Next: this is likely NOT plain-sight - classify the challenge and route.")
    else:
        print("\nVerify the real one before submitting (decoded/leet hits can be noise).")
    return 0


PATS = flag_regexes([])

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
