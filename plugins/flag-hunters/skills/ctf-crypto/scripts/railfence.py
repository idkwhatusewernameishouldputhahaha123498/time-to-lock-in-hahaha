#!/usr/bin/env python3
"""railfence.py -- rail fence (zigzag) transposition: encode, decode, brute force.

Supports a START OFFSET (phase) into the zigzag, because real challenges hide the
parameter in prose: "8 rails, move up by 5" means rails=8, offset=5. The offset
shifts where in the up/down cycle the first character lands.

Model: the rail index of position i is a triangle wave of period 2*(rails-1).
With offset o:  t = (i + o) % period ;  rail = t if t < rails else period - t.

Usage:
  python3 -I railfence.py decode  "<ciphertext>" --rails 8 --offset 5
  python3 -I railfence.py encode  "<plaintext>"  --rails 8 --offset 5
  python3 -I railfence.py brute   "<ciphertext>" [--rails-max 15] [--show]
      brute tries rails 2..RAILS_MAX and every offset, printing any output that
      contains 'flag{' (case-insensitive). --show prints ALL candidates.

Reads from stdin if the text arg is '-'.  Stdlib only.
"""
import sys


def rail_sequence(n, rails, offset):
    """Rail index for each of n positions, given rails and a phase offset."""
    if rails < 2:
        return [0] * n
    period = 2 * (rails - 1)
    seq = []
    for i in range(n):
        t = (i + offset) % period
        seq.append(t if t < rails else period - t)
    return seq


def encode(text, rails, offset=0):
    seq = rail_sequence(len(text), rails, offset)
    buckets = [[] for _ in range(rails)]
    for ch, r in zip(text, seq):
        buckets[r].append(ch)
    return "".join("".join(b) for b in buckets)


def decode(cipher, rails, offset=0):
    n = len(cipher)
    seq = rail_sequence(n, rails, offset)
    # how many chars land on each rail, in reading order
    counts = [0] * rails
    for r in seq:
        counts[r] += 1
    # slice the ciphertext into per-rail strings (rails read top->bottom)
    chunks = []
    pos = 0
    for c in counts:
        chunks.append(list(cipher[pos:pos + c]))
        pos += c
    # walk the zigzag, pulling the next char off each rail in turn
    it = [iter(chunk) for chunk in chunks]
    out = []
    for r in seq:
        out.append(next(it[r]))
    return "".join(out)


def brute(cipher, rails_max=15, show=False):
    found = []
    for rails in range(2, rails_max + 1):
        period = 2 * (rails - 1)
        for offset in range(period):
            try:
                pt = decode(cipher, rails, offset)
            except StopIteration:
                continue
            tag = "flag{" in pt.lower()
            if tag or show:
                marker = "  <<< flag{" if tag else ""
                print(f"[rails={rails:2d} offset={offset:2d}] {pt}{marker}")
            if tag:
                found.append((rails, offset, pt))
    if found:
        print("\n# HITS:")
        for rails, offset, pt in found:
            print(f"#   rails={rails} offset={offset}: {pt}")
    elif not show:
        print("# no 'flag{' found; re-run with --show to see every candidate")
    return found


def _read_text(arg):
    if arg == "-":
        return sys.stdin.read().rstrip("\n")
    return arg


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    mode = argv[0]
    rest = argv[1:]

    # parse flags
    opts = {"--rails": None, "--offset": 0, "--rails-max": 15, "--show": False}
    pos = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--show":
            opts["--show"] = True; i += 1; continue
        if a in opts:
            if i + 1 >= len(rest):
                print(f"{a} needs a value", file=sys.stderr); return 2
            opts[a] = int(rest[i + 1]); i += 2; continue
        pos.append(a); i += 1
    text = _read_text(pos[0]) if pos else _read_text("-")

    if mode in ("encode", "decode") and opts["--rails"] is None:
        print(f"{mode} needs --rails N (use `brute` if you don't know the rail count)",
              file=sys.stderr)
        return 2
    if mode == "encode":
        print(encode(text, opts["--rails"], opts["--offset"]))
    elif mode == "decode":
        print(decode(text, opts["--rails"], opts["--offset"]))
    elif mode == "brute":
        brute(text, opts["--rails-max"], opts["--show"])
    else:
        print(f"unknown mode {mode!r}; use encode|decode|brute", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
