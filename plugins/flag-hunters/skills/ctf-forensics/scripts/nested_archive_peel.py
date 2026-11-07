#!/usr/bin/env python3
"""
nested_archive_peel.py - recursively peel nested zip/7z archives and hunt flag{...}.

WHY: CTF forensics loves "matryoshka" archives (challenge.zip.zip ->
challenge.7z.zip -> AES challenge.7z). This peels them IN-MEMORY where it can,
tries a wordlist against encrypted members, and PRINTS the per-password error
type so the "error-oracle" is visible: with an AES-7z, every WRONG password
usually throws the SAME error (e.g. a header-decrypt TypeError / Bad7zFile), and
the RIGHT one throws a DIFFERENT error or succeeds -- that odd-one-out is your
password. Every extracted blob's RAW BYTES are grepped for flag{...} (flags are
often stuffed into an inner .bin, not a .txt).

KEY TRICK (the "Linux FS" win): the password is often sitting in a sibling file
(e.g. Trash/dontlook/passwords.txt). So we PEEL EVERYTHING UNENCRYPTED FIRST,
harvesting password candidates from every text blob, and only THEN attack the
encrypted members with the now-complete wordlist. Encrypted cracks are DEFERRED.

Stdlib-first. Uses py7zr if importable (pure-Python AES-7z, no system 7z needed);
otherwise falls back to the system `7z`/`7za`/`7zz` binary only if present.

Usage:
    python3 -I nested_archive_peel.py <archive> [wordlist.txt]

Run with -I so a planted zlib.py / lzma.py in the CWD cannot hijack imports.
"""
import io
import os
import re
import sys
import shutil
import string
import tempfile
import zipfile
import subprocess

FLAG_RE = re.compile(rb"flag\{[^}]{0,200}\}", re.IGNORECASE)
# Ligature-aware: some flags are hidden using U+FB02 (fl) / U+FB01 (fi).
FLAG_LIGATURE_RE = re.compile(
    "(?:flag|ﬂag|ﬁlag)\\{[^}]{0,200}\\}".encode("utf-8"), re.IGNORECASE
)

try:
    import py7zr  # noqa: F401
    HAVE_PY7ZR = True
except Exception:
    HAVE_PY7ZR = False

MAGIC = {
    b"PK\x03\x04": "zip",
    b"PK\x05\x06": "zip",       # empty-zip EOCD
    b"PK\x07\x08": "zip",       # spanned
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ\x00": "xz",
    b"Rar!\x1a\x07": "rar",
}

DEFAULT_WORDLIST = [
    "password", "Password", "password123", "123456", "12345678",
    "admin", "root", "toor", "letmein", "secret", "changeme",
    "qwerty", "flag", "ctf", "infected", "malware", "hunter2",
    "P@ssw0rd", "iitd", "flaghunters", "flaghunters2026",
]

MAX_DEPTH = 12
MAX_BLOBS = 5000


def sniff(data: bytes):
    """Return a coarse archive type from magic bytes, or None."""
    for sig, kind in MAGIC.items():
        if data.startswith(sig):
            return kind
    if len(data) > 262 and data[257:262] == b"ustar":  # tar magic at offset 257
        return "tar"
    return None


def grep_flags(name: str, data: bytes):
    """Print any flag{...} found in raw bytes (plus ligature variants)."""
    hits = set(FLAG_RE.findall(data)) | set(FLAG_LIGATURE_RE.findall(data))
    for h in sorted(hits):
        print(f"  [FLAG?] in {name!r}: {h.decode('utf-8', 'replace')}")
    return hits


def harvest_passwords(data: bytes, pool: list):
    """Scrape plausible passwords from a small text blob into the pool."""
    if len(data) > 200_000:
        return
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return
    sample = text[:4000]
    if sample and sum(c in string.printable for c in sample) < len(sample) * 0.85:
        return  # not really text
    for line in text.splitlines():
        line = line.strip()
        m = re.search(r"(?:pass(?:word)?|pwd|pw|key)\s*[:=]\s*(\S+)", line, re.I)
        if m:
            cand = m.group(1)
        elif 0 < len(line) <= 64 and " " not in line:
            cand = line
        else:
            continue
        if cand and cand not in pool:
            pool.append(cand)


def build_wordlist(path):
    words = []
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            words = [ln.rstrip("\n") for ln in fh if ln.rstrip("\n")]
        print(f"[*] Loaded {len(words)} passwords from {path}")
    else:
        if path:
            print(f"[!] Wordlist {path!r} not found; using built-in list.")
        words = list(DEFAULT_WORDLIST)
    return words


# ---------------------------------------------------------------------------
# 7z helpers
# ---------------------------------------------------------------------------
def _py7zr_extract(data, pw):
    """Open+read a 7z from bytes with py7zr. Returns {name: bytes} or raises.

    Works across py7zr versions: old ones expose readall()/read() (in-memory
    BytesIO dict); 1.1.x dropped those, so we fall back to extractall() into a
    temp dir and read the files back. A WRONG password raises here (during
    header parse or during extraction) -- that is the error-oracle.
    """
    import py7zr
    with py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=pw) as z:
        if hasattr(z, "readall"):
            out = {}
            for fname, bobj in z.readall().items():
                try:
                    out[fname] = bobj.read()
                except Exception:
                    out[fname] = b""
            return out
        with tempfile.TemporaryDirectory() as td:
            z.extractall(path=td)
            out = {}
            for rootd, _dirs, files in os.walk(td):
                for f in files:
                    p = os.path.join(rootd, f)
                    with open(p, "rb") as fh:
                        out[os.path.relpath(p, td)] = fh.read()
            return out


def _system7z_extract(data, pw):
    """Extract via system 7z binary. Returns {relpath: bytes} or raises."""
    exe = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
    if not exe:
        raise RuntimeError("no py7zr and no system 7z/7za/7zz")
    with tempfile.TemporaryDirectory() as td:
        arc = os.path.join(td, "arc.7z")
        with open(arc, "wb") as fh:
            fh.write(data)
        outdir = os.path.join(td, "out")
        os.makedirs(outdir, exist_ok=True)
        pflag = f"-p{pw}" if pw is not None else "-p"
        r = subprocess.run([exe, "x", "-y", pflag, f"-o{outdir}", arc],
                           capture_output=True, timeout=120)
        if r.returncode != 0:
            tail = (r.stderr or r.stdout).decode("utf-8", "ignore").strip()
            raise RuntimeError(f"7z rc={r.returncode}: {tail.splitlines()[-1:] or ['']}")
        out = {}
        for rootd, _dirs, files in os.walk(outdir):
            for f in files:
                p = os.path.join(rootd, f)
                with open(p, "rb") as fh:
                    out[os.path.relpath(p, outdir)] = fh.read()
        return out


def sevenz_extract(data, pw):
    if HAVE_PY7ZR:
        return _py7zr_extract(data, pw)
    return _system7z_extract(data, pw)


# ---------------------------------------------------------------------------
# peelers  (enqueue = add plaintext child; defer = register an encrypted crack)
# ---------------------------------------------------------------------------
def peel_zip(name, data, depth, enqueue, defer):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        print(f"  [zip] cannot open {name!r}: {type(e).__name__}: {e}")
        return
    for info in zf.infolist():
        if info.is_dir():
            continue
        child = f"{name}::{info.filename}"
        if not (info.flag_bits & 0x1):
            try:
                enqueue(child, zf.read(info.filename), depth + 1)
            except Exception as e:
                print(f"  [zip] read {child!r} failed: {type(e).__name__}: {e}")
            continue

        # Encrypted member -> defer the crack until the wordlist is complete.
        print(f"  [zip] {child!r} is ENCRYPTED -- deferring crack.")
        fname = info.filename
        tried = set()

        def attempt(wl, _zf=zf, _fname=fname, _child=child, _tried=tried):
            for pw in wl:
                if pw in _tried:
                    continue
                _tried.add(pw)
                try:
                    blob = _zf.read(_fname, pwd=pw.encode())
                    print(f"    [+] zip password OK: {pw!r}  ({_child})")
                    return [(_child, blob)]
                except Exception as e:
                    print(f"    [zip pw {pw!r}] -> {type(e).__name__}: {e}")
            return None

        defer(child, depth, attempt,
              hint="AES-zip? stdlib can't; retry member with `pyzipper`.")


def peel_7z(name, data, depth, enqueue, defer):
    # Unencrypted (or plaintext-header) 7z: try no-password synchronously.
    try:
        for fname, blob in sevenz_extract(data, None).items():
            enqueue(f"{name}::{fname}", blob, depth + 1)
        return
    except Exception as e:
        print(f"  [7z] {name!r} no-password open -> {type(e).__name__}: {e}  (deferring crack)")

    tried = set()

    def attempt(wl, _data=data, _name=name, _tried=tried):
        for pw in wl:
            if pw in _tried:
                continue
            _tried.add(pw)
            try:
                members = sevenz_extract(_data, pw)
                print(f"    [+] 7z password OK: {pw!r}  ({_name})")
                return [(f"{_name}::{fn}", b) for fn, b in members.items()]
            except Exception as e:
                # ERROR-ORACLE: print the type so the odd-one-out is obvious.
                print(f"    [7z pw {pw!r}] -> {type(e).__name__}: {e}")
        return None

    defer(name, depth, attempt,
          hint="The password whose ERROR TYPE differs from all the others is the one.")


def peel_stream(name, data, kind, depth, enqueue):
    try:
        if kind == "gzip":
            import gzip
            enqueue(name + "::gunzip", gzip.decompress(data), depth + 1)
        elif kind == "bzip2":
            import bz2
            enqueue(name + "::bunzip2", bz2.decompress(data), depth + 1)
        elif kind == "xz":
            import lzma
            enqueue(name + "::unxz", lzma.decompress(data), depth + 1)
        elif kind == "tar":
            import tarfile
            tf = tarfile.open(fileobj=io.BytesIO(data))
            for m in tf.getmembers():
                if m.isfile():
                    f = tf.extractfile(m)
                    if f:
                        enqueue(f"{name}::{m.name}", f.read(), depth + 1)
    except Exception as e:
        print(f"  [{kind}] {name!r} failed: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    target = argv[1]
    if not os.path.isfile(target):
        print(f"[!] not a file: {target}")
        return 2
    wordlist = build_wordlist(argv[2] if len(argv) > 2 else None)
    print(f"[*] 7z backend: {'py7zr' if HAVE_PY7ZR else 'system 7z (if present)'}")

    with open(target, "rb") as fh:
        root = fh.read()

    queue = [(os.path.basename(target), root, 0)]
    deferred = []          # jobs: {'name','depth','attempt','hint','done'}
    found, seen = set(), set()
    processed = 0

    def enqueue(child_name, blob, depth):
        queue.append((child_name, blob, depth))

    def defer(name, depth, attempt, hint=""):
        deferred.append({"name": name, "depth": depth, "attempt": attempt,
                         "hint": hint, "done": False})

    def drain():
        nonlocal processed
        while queue:
            name, data, depth = queue.pop(0)
            if processed >= MAX_BLOBS:
                print("[!] blob cap reached; stopping.")
                return
            processed += 1
            digest = (len(data), hash(data[:8192]))
            if digest in seen:
                continue
            seen.add(digest)

            kind = sniff(data)
            print(f"[peel d{depth}] {name!r} ({len(data)} bytes) type={kind or 'blob'}")
            found.update(grep_flags(name, data))
            harvest_passwords(data, wordlist)
            if depth >= MAX_DEPTH:
                print("  [!] max depth reached; not descending.")
                continue
            if kind == "zip":
                peel_zip(name, data, depth, enqueue, defer)
            elif kind == "7z":
                peel_7z(name, data, depth, enqueue, defer)
            elif kind in ("gzip", "bzip2", "xz", "tar"):
                peel_stream(name, data, kind, depth, enqueue)
            elif kind == "rar":
                print("  [rar] not handled; try `unrar`/`rarfile`.")

    # Phase 1: peel everything unencrypted, harvest all passwords.
    drain()

    # Phase 2: attack deferred encrypted members with the full (grown) wordlist,
    # re-draining after each success so freshly revealed files feed the hunt.
    rounds = 0
    while any(not j["done"] for j in deferred) and rounds < MAX_DEPTH + 2:
        rounds += 1
        progressed = False
        prev_words = len(wordlist)
        print(f"\n[*] --- crack round {rounds}: {sum(1 for j in deferred if not j['done'])} "
              f"deferred, {len(wordlist)} passwords ---")
        for job in deferred:
            if job["done"]:
                continue
            print(f"[crack] {job['name']!r}  ({job['hint']})")
            children = job["attempt"](wordlist)
            if children is not None:
                job["done"] = True
                for cn, blob in children:
                    enqueue(cn, blob, job["depth"] + 1)
                progressed = True
        if progressed:
            drain()                       # may harvest MORE passwords
        if not progressed and len(wordlist) == prev_words:
            break                         # no success and no new passwords -> stuck

    print("\n==================== RESULT ====================")
    stuck = [j["name"] for j in deferred if not j["done"]]
    if found:
        print(f"[+] {len(found)} flag-shaped hit(s):")
        for h in sorted(found):
            print("   ", h.decode("utf-8", "replace"))
    else:
        print("[-] No flag{...} in raw bytes. Innermost blob may need stego / "
              "strings / xxd, or you need a real wordlist.")
    if stuck:
        print(f"[!] {len(stuck)} archive(s) still encrypted (no working password): "
              + ", ".join(repr(s) for s in stuck))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
