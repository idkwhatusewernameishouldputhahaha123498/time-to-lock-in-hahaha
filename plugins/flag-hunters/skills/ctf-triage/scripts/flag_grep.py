#!/usr/bin/env python3
"""
flag_grep.py - fast, dependency-free hunt for flag{...} in a file or directory tree.

Looks for the flag in:
  * raw bytes (handles odd encodings / embedded blobs),
  * text with ligatures normalized (fi/fl break a naive 'flag{' regex),
  * common wrappers (flag{}, FLAG{}, ctf{}, and reversed }galf),
  * base64 / base32 / hex substrings decoded one layer,
  * ROT-n of the decoded text,
  * leetspeak-normalized text (so fl4g{...} / fl@g{...} still match).

Usage:
    python3 -I flag_grep.py <file-or-dir> [more paths...]
    python3 -I flag_grep.py .                      # scan current dir recursively

Pure standard library. Safe to run with -I.
"""
import sys
import os
import re
import base64
import binascii
import codecs

# Flag wrappers to look for. Keep the inner class permissive so we still catch
# near-miss / decoy / leet flags for a human to eyeball.
WRAPPERS = [b"flag", b"FLAG", b"ctf", b"CTF", b"key", b"KEY"]
INNER = rb"\{[ -~]{0,256}?\}"          # printable ASCII inside braces, non-greedy

LIGATURES = {"ﬁ": "fi", "ﬂ": "fl", "ﬀ": "ff",
             "ﬃ": "ffi", "ﬄ": "ffl"}

LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "0": "o",
                      "1": "i", "!": "i", "5": "s", "$": "s", "7": "t"})


def flag_regexes():
    pats = []
    for w in WRAPPERS:
        pats.append(re.compile(re.escape(w) + INNER, re.IGNORECASE))
    # reversed "flag{...}" -> "}...galf"
    pats.append(re.compile(rb"\}[ -~]{0,256}?\{galf", re.IGNORECASE))
    return pats


PATS = flag_regexes()


def hits(data: bytes, label: str, found: set):
    for pat in PATS:
        for m in pat.finditer(data):
            s = m.group(0)
            try:
                txt = s.decode("latin-1")
            except Exception:
                txt = repr(s)
            key = (label, txt)
            if key not in found:
                found.add(key)
                off = m.start()
                print(f"[{label}] @{off}: {txt}")


def try_text_transforms(data: bytes, base_label: str, found: set):
    # Normalize ligatures + leet on a best-effort text view, re-scan.
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return
    for lig, rep in LIGATURES.items():
        text = text.replace(lig, rep)
    hits(text.encode("utf-8", "ignore"), base_label + ":ligature", found)
    leet = text.translate(LEET)
    if leet != text:
        hits(leet.encode("utf-8", "ignore"), base_label + ":leet", found)


def try_decodings(data: bytes, base_label: str, found: set):
    sample = data if len(data) < 2_000_000 else data[:2_000_000]
    text = sample.decode("latin-1", "ignore")

    # base64-looking runs
    for run in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        try:
            dec = base64.b64decode(run + "=" * (-len(run) % 4), validate=False)
            hits(dec, base_label + ":b64", found)
        except Exception:
            pass
    # base32-looking runs
    for run in re.findall(r"[A-Z2-7=]{16,}", text):
        try:
            dec = base64.b32decode(run + "=" * (-len(run) % 8))
            hits(dec, base_label + ":b32", found)
        except Exception:
            pass
    # hex runs
    for run in re.findall(r"(?:[0-9a-fA-F]{2}){8,}", text):
        try:
            hits(binascii.unhexlify(run[: len(run) - len(run) % 2]),
                 base_label + ":hex", found)
        except Exception:
            pass
    # ROT-n of the whole text (cheap; catches Caesar-wrapped flags)
    for n in range(1, 26):
        rot = "".join(
            chr((ord(c) - b + n) % 26 + b) if (b := 65 if c.isupper() else 97) and c.isalpha()
            else c
            for c in text
        )
        if "{" in rot:
            hits(rot.encode("latin-1", "ignore"), base_label + f":rot{n}", found)


def scan_file(path: str, found: set):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"  (skip {path}: {e})", file=sys.stderr)
        return
    label = os.path.relpath(path)
    hits(data, label, found)
    try_text_transforms(data, label, found)
    try_decodings(data, label, found)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    found = set()
    for target in argv[1:]:
        if os.path.isdir(target):
            for root, _dirs, files in os.walk(target):
                for name in files:
                    scan_file(os.path.join(root, name), found)
        else:
            scan_file(target, found)
    if not found:
        print("No flag{...}-shaped strings found (raw/ligature/leet/b64/b32/hex/rot).")
        print("Next: this is likely NOT plain-sight - classify the challenge and route.")
    else:
        print(f"\n{len(found)} candidate(s). Verify the real one before submitting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
