#!/usr/bin/env python3
"""
carve.py - pure-Python file carver (a binwalk/foremost stand-in for a bare machine).

Scans a blob for embedded/appended file signatures, carves each one out, recurses
into the carved pieces (so image -> appended zip -> inner image -> ... "matryoshka"
chains peel automatically), and greps every piece for a flag ({...} wrapper).

WHY: CTF forensics constantly appends a ZIP/PNG after an image's real EOF, or
nests files. binwalk does this but is often NOT installed on a provided machine;
this needs only the stdlib.

Usage:
    python3 -I carve.py <file> [--outdir DIR] [--depth N]

Writes carved pieces to DIR (default: <file>_carved/) and prints a tree + any flags.
"""
import sys
import os
import re
import io
import zipfile
import gzip
import bz2
import lzma

FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,24}\{[ -~]{0,200}?\}")

# name, magic bytes, file extension. End of a region is computed per-format where
# possible, else carved to the next signature / EOF.
SIGS = [
    ("png",  b"\x89PNG\r\n\x1a\n", "png"),
    ("jpg",  b"\xff\xd8\xff",      "jpg"),
    ("gif",  b"GIF8",              "gif"),
    ("bmp",  b"BM",                "bmp"),
    ("zip",  b"PK\x03\x04",        "zip"),
    ("gzip", b"\x1f\x8b\x08",      "gz"),
    ("bzip2", b"BZh",              "bz2"),
    ("xz",   b"\xfd7zXZ\x00",      "xz"),
    ("7z",   b"7z\xbc\xaf\x27\x1c", "7z"),
    ("rar",  b"Rar!\x1a\x07",      "rar"),
    ("pdf",  b"%PDF",              "pdf"),
    ("elf",  b"\x7fELF",           "elf"),
]


def region_end(data, name, start):
    """Best-effort end offset (exclusive) for a known container; else None."""
    if name == "png":
        i = data.find(b"IEND", start)
        return i + 8 if i != -1 else None
    if name == "jpg":
        i = data.find(b"\xff\xd9", start + 2)
        return i + 2 if i != -1 else None
    if name == "gif":
        i = data.find(b"\x00;", start)
        return i + 2 if i != -1 else None
    if name == "zip":
        i = data.rfind(b"PK\x05\x06")  # end-of-central-directory
        if i != -1 and i >= start:
            # EOCD is 22 bytes + comment length (2 bytes at i+20)
            clen = int.from_bytes(data[i + 20:i + 22], "little") if i + 22 <= len(data) else 0
            return i + 22 + clen
        return None
    if name == "pdf":
        i = data.rfind(b"%%EOF")
        return i + 5 if i != -1 else None
    return None


def find_signatures(data):
    """Yield (offset, name, ext) for every signature occurrence (sorted by offset)."""
    found = []
    for name, magic, ext in SIGS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i == -1:
                break
            found.append((i, name, ext))
            start = i + 1
    found.sort()
    return found


def carve(data, outdir, depth, maxdepth, prefix, tree, flags):
    if depth > maxdepth:
        return
    sigs = find_signatures(data)
    # Emit pieces: each signature region, plus a "trailing" piece after the last
    # known region end (classic "appended data after EOF").
    pieces = []
    for idx, (off, name, ext) in enumerate(sigs):
        end = region_end(data, name, off)
        if end is None:
            nxt = sigs[idx + 1][0] if idx + 1 < len(sigs) else len(data)
            end = nxt
        if end > off:
            pieces.append((off, end, name, ext))
    # Deduplicate overlapping identical-start pieces; keep the first.
    seen_spans = set()
    for off, end, name, ext in pieces:
        if (off, end) in seen_spans:
            continue
        seen_spans.add((off, end))
        blob = data[off:end]
        note = "" if off == 0 else "  (APPENDED/embedded - not at offset 0)"
        fn = os.path.join(outdir, f"{prefix}off{off}_{name}.{ext}")
        try:
            with open(fn, "wb") as fh:
                fh.write(blob)
        except OSError:
            continue
        line = f"{'  ' * depth}[{name}] off={off} len={len(blob)} -> {os.path.basename(fn)}{note}"
        tree.append(line)
        for m in FLAG_RE.findall(blob):
            flags.add(m.decode("latin-1", "replace"))
        # Recurse: decompress containers and re-carve their contents.
        _recurse_container(blob, name, outdir, depth, maxdepth, f"{prefix}off{off}_", tree, flags)


def _recurse_container(blob, name, outdir, depth, maxdepth, prefix, tree, flags):
    try:
        if name == "zip":
            zf = zipfile.ZipFile(io.BytesIO(blob))
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    inner = zf.read(info.filename)
                except Exception:
                    continue
                for m in FLAG_RE.findall(inner):
                    flags.add(m.decode("latin-1", "replace"))
                carve(inner, outdir, depth + 1, maxdepth, f"{prefix}zip_", tree, flags)
        elif name in ("gzip", "bzip2", "xz"):
            dec = {"gzip": gzip.decompress, "bzip2": bz2.decompress,
                   "xz": lzma.decompress}[name](blob)
            for m in FLAG_RE.findall(dec):
                flags.add(m.decode("latin-1", "replace"))
            carve(dec, outdir, depth + 1, maxdepth, f"{prefix}dec_", tree, flags)
    except Exception:
        pass  # not a valid container at this offset; that's fine


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0 if (len(argv) >= 2 and argv[1] in ("-h", "--help")) else 2
    path = argv[1]
    outdir, maxdepth = None, 6
    i = 2
    while i < len(argv):
        if argv[i] == "--outdir":
            if i + 1 >= len(argv):
                print("[!] --outdir needs a value", file=sys.stderr); return 2
            outdir = argv[i + 1]; i += 2
        elif argv[i] == "--depth":
            if i + 1 >= len(argv):
                print("[!] --depth needs a value", file=sys.stderr); return 2
            maxdepth = int(argv[i + 1]); i += 2
        else:
            i += 1
    if not os.path.isfile(path):
        print(f"[!] not a file: {path}", file=sys.stderr)
        return 2
    outdir = outdir or (os.path.splitext(path)[0] + "_carved")
    os.makedirs(outdir, exist_ok=True)
    with open(path, "rb") as f:
        data = f.read()

    tree, flags = [], set()
    for m in FLAG_RE.findall(data):
        flags.add(m.decode("latin-1", "replace"))
    carve(data, outdir, 0, maxdepth, "", tree, flags)

    print(f"[*] carved into {outdir}")
    for line in tree:
        print(line)
    if flags:
        print("\n[+] flag-shaped strings found:")
        for fl in sorted(flags):
            print("   ", fl)
    else:
        print("\n[-] no flag in carved pieces; eyeball the images / run flag_grep.py on them.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
