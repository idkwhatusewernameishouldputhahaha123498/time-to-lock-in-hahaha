#!/usr/bin/env python3
"""
flag_grep.py - fast, dependency-free hunt for flag{...} in a file or directory tree.

Looks for the flag in, in order of confidence:
  1. raw bytes (handles odd encodings / embedded blobs),
  2. UTF-16 LE/BE and UTF-32 LE/BE text (classic Windows / wide-char hiding spot),
  3. text with ligatures normalized (fi/fl break a naive 'flag{' regex),
  4. one layer of base64 / base32 / hex decoding of substrings,
  5. ROT-n of the text (Caesar-wrapped flags),
  6. a leetspeak-normalized GUESS (clearly labelled - it may be wrong).

Usage:
    python3 -I flag_grep.py <file-or-dir> [more paths...]
    python3 -I flag_grep.py .                 # scan current dir recursively
    python3 -I flag_grep.py f --wrappers ctf,key   # add more wrappers to look for
    python3 -I flag_grep.py f --deep          # decode-cascade even on large files

Default wrappers: flag{}, FLAG{}, ctf{}, CTF{}. Confirmed, high-confidence hits are
printed first; the leet GUESS and decoded-layer hits are clearly separated so you
know which to trust. Pure standard library; safe with -I.
"""
import sys
import os
import re
import base64
import binascii

DEFAULT_WRAPPERS = ["flag", "FLAG", "ctf", "CTF"]
INNER = rb"\{[ -~]{0,256}?\}"          # printable ASCII inside braces, non-greedy

LIGATURES = {"ﬁ": "fi", "ﬂ": "fl", "ﬀ": "ff",
             "ﬃ": "ffi", "ﬄ": "ffl"}

LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "0": "o",
                      "1": "i", "!": "i", "5": "s", "$": "s", "7": "t"})

# Decode-cascade cost guards: don't churn through huge binaries by default.
DEEP_SIZE_LIMIT = 2_000_000           # bytes considered for decoding when not --deep
MIN_RUN = 16                          # shortest encoded run worth decoding


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
    pats = [re.compile(re.escape(w.encode()) + INNER, re.IGNORECASE) for w in wrappers]
    pats.append(re.compile(rb"\}[ -~]{0,256}?\{galf", re.IGNORECASE))  # reversed flag{}
    return pats


def hits(data: bytes, label: str, found: dict):
    """Record flag-shaped matches. `found` maps match-text -> first label seen."""
    for pat in PATS:
        for m in pat.finditer(data):
            try:
                txt = m.group(0).decode("latin-1")
            except Exception:
                txt = repr(m.group(0))
            if txt not in found:
                found[txt] = f"{label} @{m.start()}"


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
            hits(rot.encode("latin-1", "ignore"), label + f":rot{n}", found)


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
    wide_char_pass(data, label, found)
    ligature_pass(data, label, found)
    decode_pass(data, label, found, deep)
    leet_pass(data, label, leet_guesses)


def main(argv):
    wrappers = list(DEFAULT_WRAPPERS)
    deep = False
    targets = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        if a == "--wrappers":
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
    # Only surface leet guesses that aren't already confirmed verbatim.
    extra = {t: w for t, w in leet_guesses.items() if t not in found}
    if extra:
        print(f"\n[?] {len(extra)} leet-normalized GUESS(es) - may be wrong, verify:")
        for txt, where in extra.items():
            print(f"    {txt}    <- {where}")
    if not found and not extra:
        print("No flag{...}-shaped strings found "
              "(raw / wide-char / ligature / b64 / b32 / hex / rot / leet).")
        print("Next: this is likely NOT plain-sight - classify the challenge and route.")
    else:
        print("\nVerify the real one before submitting (decoded/leet hits can be noise).")
    return 0


PATS = flag_regexes(DEFAULT_WRAPPERS)

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
