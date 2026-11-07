#!/usr/bin/env python3
"""
decode_cascade.py - CyberChef "Magic"-style recursive decoder for CTF MISC.

Given a text blob (file path, argv, or stdin), DETECT likely encodings from the
character set / alphabet and try to peel them layer by layer, recursing a few
levels deep. PRINT every intermediate or final result that contains `flag{`
(configurable), with the chain of transforms that produced it.

Pure stdlib. `python3 -I` friendly (no imports from CWD). Bounded: a wall-clock
--timeout and a node cap guarantee it returns even on large high-entropy input;
cipher transforms (rot/atbash/reverse) are checked for a hit but NOT recursed
into, so there is no combinatorial blow-up.

Usage:
    python3 -I decode_cascade.py <file>
    python3 -I decode_cascade.py "<blob string>"
    cat blob.txt | python3 -I decode_cascade.py
    python3 -I decode_cascade.py <file> --pattern 'CTF\\{' --depth 10 --timeout 20 --all

Flags:
    --pattern RE   regex for a "hit" (default: flag\\{ ... \\}, case-insensitive)
    --depth N      max recursion depth (default 12)
    --timeout S    wall-clock budget in seconds (default 20)
    --all          also print promising printable leaves even without a hit
"""
import sys, os, re, base64, binascii, codecs, html, string, time, hashlib
import urllib.parse as _url

# ----------------------------------------------------------------------------
# Config / helpers
# ----------------------------------------------------------------------------
DEFAULT_PATTERN = re.compile(r"flag\{[^}]*\}", re.IGNORECASE)
PRINTABLE = set(bytes(string.printable, "ascii"))
B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62_ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
NODE_CAP = 200000
MORSE = {
    ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G",
    "....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N",
    "---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U",
    "...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",
    ".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6",
    "--...":"7","---..":"8","----.":"9","-..-.":"/","-....-":"-",".-.-.-":".",
    "--..--":",","..--..":"?","-.-.--":"!","-.--.":"(","-.--.-":")",
}

def norm(x):
    """Return str view for inspection."""
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8")
        except Exception:
            return x.decode("latin-1")
    return x

def is_mostly_printable(b, thresh=0.90):
    if not b:
        return False
    if isinstance(b, str):
        b = b.encode("utf-8", "replace")
    good = sum(1 for c in b if c in PRINTABLE)
    return good / len(b) >= thresh

def strip_ws(s):
    return "".join(s.split())

def only(s, alphabet):
    sset = set(alphabet)
    return bool(s) and all(c in sset for c in s)

# ----------------------------------------------------------------------------
# Individual decoders. Each takes a str, returns bytes/str or raises/returns None.
# ----------------------------------------------------------------------------
def d_base64(s):
    t = strip_ws(s)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t):
        return None
    if len(t) < 4:
        return None
    pad = "=" * (-len(t) % 4)
    return base64.b64decode(t + pad, validate=False)

def d_base64url(s):
    t = strip_ws(s)
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", t) or ("-" not in t and "_" not in t):
        return None
    pad = "=" * (-len(t) % 4)
    return base64.urlsafe_b64decode(t + pad)

def d_base32(s):
    t = strip_ws(s).upper()
    if not re.fullmatch(r"[A-Z2-7]+={0,6}", t) or len(t) < 8:
        return None
    pad = "=" * (-len(t) % 8)
    return base64.b32decode(t + pad)

def d_base85(s):
    t = strip_ws(s)
    try:
        return base64.b85decode(t)
    except Exception:
        return None

def d_ascii85(s):
    t = s.strip()
    try:
        return base64.a85decode(t, adobe=t.startswith("<~"))
    except Exception:
        return None

def d_hex(s):
    t = re.sub(r"(0x|\\x|%)", "", strip_ws(s), flags=re.IGNORECASE)
    if not re.fullmatch(r"[0-9a-fA-F]+", t) or len(t) % 2 or len(t) < 4:
        return None
    return bytes.fromhex(t)

def d_binary(s):
    t = re.sub(r"[^01]", "", s)
    if len(t) < 8 or len(t) % 8:
        return None
    return bytes(int(t[i:i+8], 2) for i in range(0, len(t), 8))

def d_octal(s):
    toks = re.findall(r"[0-7]{1,3}", s.strip())
    if not toks or re.sub(r"[0-7\s]", "", s):
        return None
    try:
        vals = [int(t, 8) for t in toks]
    except ValueError:
        return None
    if any(v > 255 for v in vals):
        return None
    return bytes(vals)

def d_decimal(s):
    toks = re.findall(r"\d{1,3}", s.strip())
    if not toks or re.sub(r"[\d\s,]", "", s):
        return None
    vals = [int(t) for t in toks]
    if any(v > 255 for v in vals) or len(vals) < 2:
        return None
    return bytes(vals)

def d_b58(s):
    t = strip_ws(s)
    if not only(t, B58_ALPH) or len(t) < 4:
        return None
    num = 0
    for c in t:
        num = num * 58 + B58_ALPH.index(c)
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(t) - len(t.lstrip("1"))
    return b"\x00" * pad + full

def d_b62(s):
    t = strip_ws(s)
    if not only(t, B62_ALPH) or len(t) < 4 or t.isdigit() or t.isalpha():
        return None
    num = 0
    for c in t:
        num = num * 62 + B62_ALPH.index(c)
    return num.to_bytes((num.bit_length() + 7) // 8, "big") if num else None

def d_url(s):
    if "%" not in s:
        return None
    out = _url.unquote_plus(s)
    return out if out != s else None

def d_html(s):
    if "&" not in s or ";" not in s:
        return None
    out = html.unescape(s)
    return out if out != s else None

def d_rot13(s):
    if not re.search(r"[A-Za-z]", s):
        return None
    out = codecs.encode(s, "rot_13")
    return out if out != s else None

def d_rot47(s):
    out = []
    changed = False
    for ch in s:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + (o - 33 + 47) % 94)); changed = True
        else:
            out.append(ch)
    r = "".join(out)
    return r if changed else None

def d_atbash(s):
    def f(c):
        if c.isupper(): return chr(ord("Z") - (ord(c) - ord("A")))
        if c.islower(): return chr(ord("z") - (ord(c) - ord("a")))
        return c
    if not re.search(r"[A-Za-z]", s):
        return None
    return "".join(f(c) for c in s)

def d_morse(s):
    t = s.strip()
    if not re.fullmatch(r"[.\-/ \t\n]+", t) or "." not in t and "-" not in t:
        return None
    # words separated by / or multiple spaces; letters by single space
    words = re.split(r"\s*/\s*|\s{2,}", t)
    out = []
    for w in words:
        letters = [MORSE.get(c, "?") for c in w.split()]
        out.append("".join(letters))
    return " ".join(out)

def d_reverse(s):
    return s[::-1]

def d_a1z26(s):
    toks = re.findall(r"\d{1,2}", s)
    if not toks or re.sub(r"[\d\s,.\-_]", "", s):
        return None
    vals = [int(t) for t in toks]
    if any(v < 1 or v > 26 for v in vals) or len(vals) < 2:
        return None
    return "".join(chr(ord("a") + v - 1) for v in vals)

# ROT-N brute (0..25), only reported if it produces a hit (handled in walk)
def rotn(s, n):
    res = []
    for c in s:
        if c.isupper(): res.append(chr((ord(c) - 65 + n) % 26 + 65))
        elif c.islower(): res.append(chr((ord(c) - 97 + n) % 26 + 97))
        else: res.append(c)
    return "".join(res)

# ----------------------------------------------------------------------------
# Detection order: cheap/unambiguous transforms first.
# STRUCTURAL decoders change/shrink the data and are safe to recurse into.
# CIPHER transforms (rot/atbash/reverse) keep length+entropy, so recursing into
# them on high-entropy input explodes combinatorially -- we apply them and check
# for a hit, but never recurse into their output.
# ----------------------------------------------------------------------------
DECODERS = [
    ("url", d_url), ("html", d_html), ("morse", d_morse),
    ("binary", d_binary), ("hex", d_hex),
    ("base64", d_base64), ("base64url", d_base64url), ("base32", d_base32),
    ("ascii85", d_ascii85), ("base85", d_base85),
    ("base58", d_b58), ("base62", d_b62),
    ("octal", d_octal), ("decimal", d_decimal), ("a1z26", d_a1z26),
    ("rot13", d_rot13), ("rot47", d_rot47), ("atbash", d_atbash),
    ("reverse", d_reverse),
]
CIPHER_NAMES = {"rot13", "rot47", "atbash", "reverse"}

# ----------------------------------------------------------------------------
# Recursive walk (bounded by depth, a node cap, and a wall-clock deadline)
# ----------------------------------------------------------------------------
def walk(blob, st, chain=(), depth=0):
    if time.time() > st["deadline"]:
        st["timed_out"] = True
        return
    st["nodes"] += 1
    if st["nodes"] > NODE_CAP:
        return
    s = norm(blob)
    if s is None:
        return
    pattern = st["pattern"]
    # Record any hit on the current layer (depth>0 means it was decoded).
    if depth > 0 and pattern.search(s):
        key = (s, chain)
        if key not in st["hits"]:
            st["hits"].add(key)
            print("\n[HIT] via " + " -> ".join(chain))
            print("  FLAG:", pattern.search(s).group(0))
            ctx = s if len(s) < 400 else s[:400] + "..."
            print("  text:", repr(ctx))
        return  # flag already readable; don't peel reversible layers further
    if depth >= st["max_depth"]:
        return
    # Full-content dedup (prefix-only dedup could not collapse high-entropy input).
    skey = hashlib.sha1(s.encode("utf-8", "ignore")).digest()
    if skey in st["seen"]:
        return
    st["seen"].add(skey)

    for name, fn in DECODERS:
        if time.time() > st["deadline"]:
            st["timed_out"] = True
            return
        try:
            out = fn(s)
        except Exception:
            out = None
        if out is None:
            continue
        outs = norm(out)
        if outs is None or outs == s or not outs:
            continue
        new_chain = chain + (name,)
        if pattern.search(outs):
            walk(out, st, new_chain, depth + 1)
        elif name not in CIPHER_NAMES and is_mostly_printable(out, 0.85):
            # Only STRUCTURAL decoders recurse; cipher transforms are hit-checked
            # above but never recursed (that was the exponential-blowup bug).
            if st["show_all"]:
                disp = outs if len(outs) < 120 else outs[:120] + "..."
                print(f"  [{'->'.join(new_chain)}] {disp!r}")
            walk(out, st, new_chain, depth + 1)

    # ROT-N brute only at shallow depth to find Caesar-shifted flags.
    if depth <= 2 and re.search(r"[A-Za-z]", s):
        for n in range(1, 26):
            r = rotn(s, n)
            if pattern.search(r):
                nc = chain + (f"rot{n}",)
                key = (r, nc)
                if key not in st["hits"]:
                    st["hits"].add(key)
                    print("\n[HIT] via " + " -> ".join(nc))
                    print("  FLAG:", pattern.search(r).group(0))

# ----------------------------------------------------------------------------
def _opt_value(argv, i, name):
    if i + 1 >= len(argv):
        sys.exit(f"[!] {name} needs a value")
    return argv[i + 1]


def read_input(argv):
    args, opts = [], {"pattern": None, "depth": 12, "all": False, "timeout": 20.0}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__); sys.exit(0)
        elif a == "--pattern":
            opts["pattern"] = _opt_value(argv, i, "--pattern"); i += 2
        elif a == "--depth":
            opts["depth"] = int(_opt_value(argv, i, "--depth")); i += 2
        elif a == "--timeout":
            opts["timeout"] = float(_opt_value(argv, i, "--timeout")); i += 2
        elif a == "--all":
            opts["all"] = True; i += 1
        else:
            args.append(a); i += 1
    data = None
    if args:
        cand = args[0]
        if os.path.isfile(cand):
            with open(cand, "r", errors="replace") as f:
                data = f.read()
        else:
            data = " ".join(args)
    else:
        data = sys.stdin.read()
    return data, opts

def main():
    data, opts = read_input(sys.argv[1:])
    if not data or not data.strip():
        print("No input. Provide a file, a string arg, or pipe via stdin.")
        return 1
    pattern = re.compile(opts["pattern"], re.IGNORECASE) if opts["pattern"] else DEFAULT_PATTERN
    print(f"[*] input {len(data)} chars; pattern /{pattern.pattern}/; "
          f"depth {opts['depth']}; timeout {opts['timeout']}s")
    # Also try the raw blob itself (sometimes the flag is plaintext / rotated).
    if pattern.search(data):
        print("[HIT] flag present in RAW input:", pattern.search(data).group(0))
    st = {"pattern": pattern, "max_depth": opts["depth"], "show_all": opts["all"],
          "hits": set(), "seen": set(), "nodes": 0,
          "deadline": time.time() + opts["timeout"], "timed_out": False}
    walk(data.strip(), st)
    hits = st["hits"]
    if st["timed_out"]:
        print(f"\n[!] stopped at the {opts['timeout']}s timeout "
              f"({st['nodes']} nodes explored). Narrow the input or raise --timeout.")
    if not hits:
        print("\n[!] No flag found via automatic cascade.")
        print("    Try: --all to see printable layers, --pattern 'CTF\\{', or")
        print("    CyberChef Magic / manual esolang (Brainfuck, Whitespace, JSFuck) / zbarimg for QR.")
    else:
        print(f"\n[+] {len(hits)} hit(s) found.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
