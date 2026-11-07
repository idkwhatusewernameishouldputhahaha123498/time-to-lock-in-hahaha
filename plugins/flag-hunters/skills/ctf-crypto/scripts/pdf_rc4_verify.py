#!/usr/bin/env python3
"""pdf_rc4_verify.py -- pure-Python OFFLINE verifier for a PDF Standard Security
Handler, /V 2 /R 3, RC4-128 (the classic password-protected PDF).

WHY: once you suspect a password (e.g. it's an output of a seeded PRNG, see
prng_sweep.py), you want to test THOUSANDS of candidates in-process, fast, with
no external tool and no platform surprises. This reimplements PDF Algorithms 2
(compute encryption key) and 5 (compute /U) from the PDF spec, so a candidate is
verified by MD5+RC4 math alone -- milliseconds each, no library required.

CLUE-FIRST: before brute forcing anything, mine the filename / PDF /CreationDate /
/ID / XMP metadata. The winning password is frequently derived from a leaked
timestamp used as a PRNG seed. Only sweep candidates once you have the generator.

HOW VERIFICATION WORKS (R=3, 128-bit):
  Algorithm 2 -- encryption key from user password:
    key = MD5( pad(pwd)[:32] || O[:32] || P_le4 || ID0 )  then 50x MD5 of first 16 bytes
  Algorithm 5 -- expected /U from that key:
    x  = MD5( PAD || ID0 )                       (16 bytes)
    x  = RC4(key, x)
    for i in 1..19: x = RC4(key XOR i, x)
    expected_U = x                               (compare to stored U[:16])
  Password is correct iff computed U[:16] == stored U[:16].

Usage:
  # read O/U/P/ID straight from the PDF (regex parse; pikepdf used if present):
  python3 -I pdf_rc4_verify.py --pdf secret.pdf --pw 'candidate'

  # or supply fields explicitly (hex for O/U/ID, decimal for P):
  python3 -I pdf_rc4_verify.py --pw 'candidate' \
      --O <64-hex> --U <64-hex> --P -3904 --id0 <hex>

  # sweep a candidate list (one per line) against a PDF, print the winner:
  python3 -I pdf_rc4_verify.py --pdf secret.pdf --wordlist cands.txt

VALIDATE THE VERIFIER before trusting it (make your own known-answer sample):
  >>> import pikepdf
  >>> pdf = pikepdf.open('plain.pdf')                 # any unencrypted pdf
  >>> pdf.save('enc.pdf', encryption=pikepdf.Encryption(
  ...         user='hunter2', owner='owner', R=3, aes=False, metadata=False))
  then:  python3 -I pdf_rc4_verify.py --pdf enc.pdf --pw hunter2   -> MATCH
         python3 -I pdf_rc4_verify.py --pdf enc.pdf --pw wrong     -> no match
  (R=3 aes=False forces the RC4-128 /V2/R3 handler this script implements.)

Stdlib only (hashlib); pikepdf is used only as an optional convenience for reading
and is never required.
"""
import sys
import re
import hashlib

# PDF standard 32-byte padding string (PDF spec, Algorithm 2 step a).
PAD = bytes([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
    0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
])


def rc4(key, data):
    """Textbook RC4 (KSA + PRGA), pure Python."""
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def pad_password(pw):
    """Pad/truncate password to 32 bytes per Algorithm 2 step a."""
    pw = pw.encode("latin-1") if isinstance(pw, str) else pw
    return (pw + PAD)[:32]


def compute_key(pw, O, P, id0, keylen=16, R=3):
    """Algorithm 2: 128-bit encryption key from user password."""
    p_le = (P & 0xFFFFFFFF).to_bytes(4, "little")  # /P as signed 32-bit, low byte first
    h = hashlib.md5()
    h.update(pad_password(pw))
    h.update(O[:32])
    h.update(p_le)
    h.update(id0)
    digest = h.digest()
    if R >= 3:
        for _ in range(50):
            digest = hashlib.md5(digest[:keylen]).digest()
    return digest[:keylen]


def compute_U(pw, O, P, id0, keylen=16, R=3):
    """Algorithm 5 (R>=3): expected /U (first 16 bytes are the meaningful check)."""
    key = compute_key(pw, O, P, id0, keylen, R)
    x = hashlib.md5(PAD + id0).digest()
    x = rc4(key, x)
    for i in range(1, 20):
        xored = bytes(b ^ i for b in key)
        x = rc4(xored, x)
    return x  # 16 bytes


def verify(pw, O, U, P, id0, keylen=16, R=3):
    """True iff candidate password matches the stored /U (first 16 bytes)."""
    return compute_U(pw, O, P, id0, keylen, R)[:16] == U[:16]


# --------------------------------------------------------------------------- #
# Reading /O /U /P /ID[0] out of a PDF.  The Encrypt dict and trailer /ID are
# NOT themselves encrypted, so a raw parse works even without the password.
# --------------------------------------------------------------------------- #

def _unescape_pdf_string(s):
    """Decode a PDF literal string body (between parens) to bytes."""
    out = bytearray()
    i = 0
    esc = {b"n": 10, b"r": 13, b"t": 9, b"b": 8, b"f": 12,
           b"(": 40, b")": 41, b"\\": 92}
    s = s.encode("latin-1") if isinstance(s, str) else s
    while i < len(s):
        c = s[i:i + 1]
        if c == b"\\":
            nxt = s[i + 1:i + 2]
            if nxt in esc:
                out.append(esc[nxt]); i += 2; continue
            if nxt.isdigit():  # up to 3 octal digits
                oct_digits = nxt
                i += 2
                while len(oct_digits) < 3 and s[i:i + 1].isdigit():
                    oct_digits += s[i:i + 1]; i += 1
                out.append(int(oct_digits, 8) & 0xFF); continue
            out.append(s[i + 1]); i += 2; continue
        out.append(s[i]); i += 1
    return bytes(out)


def _parse_pdf_obj_string(data, key):
    """Find `/key ( ... )` or `/key < hex >` after it in raw PDF bytes -> bytes."""
    kb = re.escape(key.encode() if isinstance(key, str) else key)
    # hex string form
    m = re.search(rb"/" + kb + rb"\s*<([0-9A-Fa-f\s]*)>", data)
    if m:
        hx = re.sub(rb"\s", b"", m.group(1))
        return bytes.fromhex(hx.decode())
    # literal string form (balance parens, allow escaped parens)
    m = re.search(rb"/" + kb + rb"\s*\(", data)
    if m:
        i = m.end()
        depth = 1
        buf = bytearray()
        while i < len(data) and depth:
            c = data[i:i + 1]
            if c == b"\\":
                buf += data[i:i + 2]; i += 2; continue
            if c == b"(":
                depth += 1
            elif c == b")":
                depth -= 1
                if depth == 0:
                    break
            buf += c; i += 1
        return _unescape_pdf_string(bytes(buf))
    return None


def extract_from_pdf(path):
    """Return dict(O, U, P, id0) parsed from the PDF. Tries pikepdf first (robust),
    falls back to a raw regex parse that needs no password and no library."""
    # pikepdf path (if the lib is present AND it can open without a password it
    # still exposes the encryption dict; we mostly rely on the raw parse below).
    try:
        import pikepdf  # noqa: F401
        # pikepdf refuses to open an encrypted file without the password, so we
        # don't use it to pull O/U here; the raw parse below is authoritative.
    except Exception:
        pass

    with open(path, "rb") as f:
        data = f.read()

    O = _parse_pdf_obj_string(data, "O")
    U = _parse_pdf_obj_string(data, "U")
    # /P is an integer (often negative)
    mP = re.search(rb"/P\s+(-?\d+)", data)
    P = int(mP.group(1)) if mP else None
    # /ID [ <id0> <id1> ]  -- take the first element
    id0 = None
    mID = re.search(rb"/ID\s*\[\s*(<[0-9A-Fa-f\s]*>|\([^)]*\))", data)
    if mID:
        tok = mID.group(1)
        if tok.startswith(b"<"):
            id0 = bytes.fromhex(re.sub(rb"\s", b"", tok[1:-1]).decode())
        else:
            id0 = _unescape_pdf_string(tok[1:-1])
    if None in (O, U, P, id0):
        missing = [k for k, v in (("O", O), ("U", U), ("P", P), ("ID0", id0)) if v is None]
        raise ValueError(f"could not parse from PDF: {missing}. Pass them explicitly.")
    return {"O": O, "U": U, "P": P, "id0": id0}


def _hexarg(s):
    return bytes.fromhex(s.strip())


def main(argv):
    if not argv or "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0

    args = {}
    i = 0
    flags = {"--pdf", "--pw", "--O", "--U", "--P", "--id0", "--wordlist"}
    while i < len(argv):
        a = argv[i]
        if a in flags:
            if i + 1 >= len(argv):
                print(f"[!] {a} needs a value", file=sys.stderr); return 2
            args[a] = argv[i + 1]; i += 2; continue
        i += 1

    if "--pdf" in args:
        fields = extract_from_pdf(args["--pdf"])
        O, U, P, id0 = fields["O"], fields["U"], fields["P"], fields["id0"]
        print(f"# parsed PDF: O[:4]={O[:4].hex()} U[:4]={U[:4].hex()} "
              f"P={P} ID0={id0.hex()}")
    else:
        need = [k for k in ("--O", "--U", "--P", "--id0") if k not in args]
        if need:
            print(f"[!] supply --pdf, or all of --O/--U/--P/--id0 "
                  f"(missing: {', '.join(need)})", file=sys.stderr)
            return 2
        O = _hexarg(args["--O"]); U = _hexarg(args["--U"])
        P = int(args["--P"]); id0 = _hexarg(args["--id0"])

    if "--wordlist" in args:
        with open(args["--wordlist"], "r", errors="replace") as f:
            for line in f:
                pw = line.rstrip("\n")
                if verify(pw, O, U, P, id0):
                    print(f"[+] PASSWORD FOUND: {pw!r}")
                    return 0
        print("[-] no candidate in wordlist matched")
        return 1

    pw = args.get("--pw", "")
    if verify(pw, O, U, P, id0):
        print(f"[+] MATCH -- password is correct: {pw!r}")
        return 0
    print(f"[-] no match for {pw!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
